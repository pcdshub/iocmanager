from __future__ import annotations

import collections
import copy
import fcntl
import functools
import glob
import io
import logging
import os
import re
import stat
import subprocess
import telnetlib
import threading
import time
import typing
from pathlib import Path

logger = logging.getLogger(__name__)


# Environment-variable settings: allow us to reset/reload these
def set_env_var_globals():
    """
    Initialize global variables from the shell environment.

    Can be called multiple times in a session for e.g. testing purposes.
    """
    global PROCSERV_EXE
    global EPICS_SITE_TOP
    global EPICS_DEV_TOP
    global CAMRECORDER
    global TMP_DIR
    global STARTUP_DIR
    global CONFIG_DIR
    global CONFIG_FILE
    global NOSSH_FILE
    global AUTH_FILE
    global SPECIAL_FILE
    global STATUS_DIR
    global HOST_DIR
    global LOGBASE
    global PVFILE
    global NETCONFIG
    global PSIPMI
    global HIOC_POWER
    global HIOC_CONSOLE
    global HIOC_STARTUP
    # Raw env vars with defaults
    CAMRECORD_ROOT = os.getenv("CAMRECORD_ROOT", "/cds/group/pcds/controls/camrecord")
    PROCSERV_EXE = os.getenv("PROCSERV_EXE", "procServ").split()[0]
    PYPS_ROOT = os.getenv("PYPS_ROOT", "/cds/group/pcds/pyps")
    IOC_DATA = os.getenv("IOC_DATA", "/cds/data/iocData")
    IOC_COMMON = os.getenv("IOC_COMMON", "/cds/data/iocCommon")
    TOOLS_SITE_TOP = os.getenv("TOOLS_SITE_TOP", "/cds/sw/tools")
    EPICS_SITE_TOP = os.getenv("EPICS_SITE_TOP", "/cds/group/pcds/epics")
    EPICS_DEV_TOP = os.getenv("EPICS_DEV_TOP", EPICS_SITE_TOP + "-dev")
    EPICS_SITE_TOP += "/"  # Code somewhere expects the trailing /, TODO clean this up

    # Use env vars to build config strings
    CAMRECORDER = CAMRECORD_ROOT
    # Note: TMP_DIR and CONFIG_FILE should be on the same file system so os.rename works
    TMP_DIR = f"{PYPS_ROOT}/config/.status/tmp"
    STARTUP_DIR = f"{PYPS_ROOT}/config/%s/iocmanager/"
    CONFIG_DIR = f"{PYPS_ROOT}/config/"
    CONFIG_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.cfg"
    NOSSH_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.nossh"
    AUTH_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.auth"
    SPECIAL_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.special"
    STATUS_DIR = f"{PYPS_ROOT}/config/.status/%s"
    HOST_DIR = f"{PYPS_ROOT}/config/.host"
    LOGBASE = f"{IOC_DATA}/%s/iocInfo/ioc.log"
    PVFILE = f"{IOC_DATA}/%s/iocInfo/IOC.pvlist"
    NETCONFIG = f"{TOOLS_SITE_TOP}/bin/netconfig"
    PSIPMI = f"{TOOLS_SITE_TOP}/bin/psipmi"
    HIOC_POWER = f"{TOOLS_SITE_TOP}/bin/power"
    HIOC_CONSOLE = f"{TOOLS_SITE_TOP}/bin/console"
    HIOC_STARTUP = f"{IOC_COMMON}/hioc/%s/startup.cmd"


set_env_var_globals()

# Constants
BASEPORT = 39050
COMMITHOST = "psbuild-rhel7"


STATUS_INIT = "INITIALIZE WAIT"
STATUS_NOCONNECT = "NOCONNECT"
STATUS_RUNNING = "RUNNING"
STATUS_SHUTDOWN = "SHUTDOWN"
STATUS_DOWN = "HOST DOWN"
STATUS_ERROR = "ERROR"

CONFIG_NORMAL = 0
CONFIG_ADDED = 1
CONFIG_DELETED = 2

# messages expected from procServ
# need to be bytes type for telnetlib
MSG_BANNER_END = b"server started at"
MSG_ISSHUTDOWN = b"is SHUT DOWN"
MSG_ISSHUTTING = b"is shutting down"
MSG_KILLED = b"process was killed"
MSG_RESTART = b"new child"
MSG_PROMPT_OLD = b"\x0d\x0a[$>] "
MSG_PROMPT = b"\x0d\x0a> "
MSG_SPAWN = b"procServ: spawning daemon"
MSG_AUTORESTART_MODE = b"auto restart mode"
MSG_AUTORESTART_IS_ON = b"auto restart( mode)? is ON,"
MSG_AUTORESTART_IS_ONESHOT = b"auto restart( mode)? is ONESHOT,"
MSG_AUTORESTART_CHANGE = b"auto restart to "
MSG_AUTORESTART_MODE_CHANGE = b"auto restart mode to "

SPAM_LEVEL = 5

stpaths = [
    "%s/children/build/iocBoot/%s/st.cmd",
    "%s/build/iocBoot/%s/st.cmd",
    "%s/iocBoot/%s/st.cmd",
]

hosttype = {}


def add_spam_level(lgr: logging.Logger):
    """
    Patch a "spam" function onto a logger instance.

    This function will log a message at the spam level,
    so that it won't appear in normal verbose mode but will appear
    in double verbose mode.
    """
    lgr.spam = functools.partial(lgr.log, SPAM_LEVEL)


add_spam_level(logger)

######################################################################
#
# Name and Directory Utilities
#


def getBaseName(ioc: str) -> str | None:
    """
    Return the basename of the iocAdmin PVs for a given IOC name.

    Upon failure, returns None instead of raising.

    Parameters
    ----------
    ioc : str
        The ioc name

    Returns
    -------
    pvbase : str or None
    """
    pvInfoPath = PVFILE % ioc
    if not os.path.isfile(pvInfoPath):
        return None
    try:
        with open(pvInfoPath, "r") as fd:
            lines = fd.readlines()
    except Exception:
        print(f"Error reading pvlist file {pvInfoPath}")
        return
    try:
        for ln in lines:
            pv = ln.split(",")[0]
            if pv.endswith(":HEARTBEAT"):
                return pv.removesuffix(":HEARTBEAT")
    except Exception:
        print(f"Error parsing {pvInfoPath} for base PV name!")


def fixdir(dir: str, id: str) -> str:
    """
    Return a truncated path to a IOC directory.

    - Makes the path relative to EPICS_SITE_TOP
    - Removes .. from the path
    - Removes the final "iocBoot" or "build/iocBoot", etc. and
      the accompanying IOC name

    For example, if we pass in:
    $EPICS_SITE_TOP/ioc/common/example/R1.0.0/children/build/iocBoot/ioc_name
    This will return
    ioc/common/example/R1.0.0

    Note: some of the features require a somewhat standard-looking path.
    Malformed paths may be returned with few or no changes.

    Parameters
    ----------
    dir : str
        The full path to a running IOC
    id : str
        The IOC name

    Returns
    -------
    path : str
    """
    # Remove ".."
    part = [pth for pth in dir.split("/") if pth != ".."]
    dir = "/".join(part)
    dir = dir.removeprefix(EPICS_SITE_TOP)
    for pth in stpaths:
        ext = pth % ("", id)
        ext = ext.removesuffix("/st.cmd")
        dir = dir.removesuffix(ext)
    return dir


######################################################################
#
# Telnet/Procserv Utilities
#


def readLogPortBanner(tn: telnetlib.Telnet) -> dict[str, str | bool]:
    """
    Read and parse the connection information from a new telnet connection.

    Parameters
    ----------
    tn : telnetlib.Telnet
        A brand-new Telnet object that has otherwise been unused.

    Returns
    -------
    info : dict
        Various information about the connection and procServ status.
    """
    try:
        response = tn.read_until(MSG_BANNER_END, 1)
    except Exception:
        response = b""
    if not response.count(MSG_BANNER_END):
        return {
            "status": STATUS_ERROR,
            "pid": "-",
            "rid": "-",
            "autorestart": False,
            "autooneshot": False,
            "autorestartmode": False,
            "rdir": "/tmp",
        }
    if re.search(b"SHUT DOWN", response):
        tmpstatus = STATUS_SHUTDOWN
        pid = "-"
    else:
        tmpstatus = STATUS_RUNNING
        pid = (
            re.search(b'@@@ Child "(.*)" PID: ([0-9]*)', response)
            .group(2)
            .decode("ascii")
        )
    match = re.search(b'@@@ Child "(.*)" start', response)
    getid = "-"
    if match:
        getid = match.group(1).decode("ascii")
    match = re.search(b"@@@ Server startup directory: (.*)", response)
    dir = "/tmp"
    if match:
        dir = match.group(1).decode("ascii")
        if dir[-1] == "\r":
            dir = dir[:-1]
    # Note: This means that ONESHOT counts as OFF!
    if re.search(MSG_AUTORESTART_IS_ON, response):
        arst = True
    else:
        arst = False
    if re.search(MSG_AUTORESTART_IS_ONESHOT, response):
        arst1 = True
    else:
        arst1 = False
    # procServ 2.8 changed "auto restart" to "auto restart mode"
    if re.search(MSG_AUTORESTART_MODE, response):
        arstm = True
    else:
        arstm = False

    return {
        "status": tmpstatus,
        "pid": pid,
        "rid": getid,
        "autorestart": arst,
        "autooneshot": arst1,
        "autorestartmode": arstm,
        "rdir": fixdir(dir, getid),
    }


pdict = {}
lockdict = collections.defaultdict(threading.RLock)


def check_status(host: str, port: int, id: str) -> dict[str, str | bool]:
    """
    Returns the status of an IOC via information from ping and telnet.

    Pings the host first if it hasn't been pinged recently.
    If the ping succeeds or has succeeded recently, telnet to the procServ port.
    If telnet succeeds, uses readLogPortBanner to determine the procServ status.

    Parameters
    ----------
    host : str
        The network hostname the IOC runs on.
    port : int
        The port the procServ process listens for telnet on.
    id : str
        The name of the IOC.

    Returns
    -------
    status : dict
        Various information about the IOC health and status.
    """
    # Lock to ensure only 1 ping at a time per host
    with lockdict[host]:
        logger.spam(f"check_status({host}, {port}, {id})")
        now = time.monotonic()
        try:
            (last, pingrc) = pdict[host]
            havestat = now - last < 10
        except Exception:
            havestat = False
        if not havestat:
            # Ping the host to see if it is up!
            logger.spam(f"Pinging {host}")
            pingrc = os.system(
                "ping -c 1 -w 1 -W 0.002 %s >/dev/null 2>/dev/null" % host
            )
            pdict[host] = (now, pingrc)
    if pingrc != 0:
        logger.spam(f"{host} is down")
        return {
            "status": STATUS_DOWN,
            "rid": id,
            "pid": "-",
            "autorestart": False,
            "rdir": "/tmp",
        }
    logger.spam(f"Check telnet to {host}:{port}")
    try:
        tn = telnetlib.Telnet(host, port, 1)
    except Exception:
        logger.spam(f"{host}:{port} is down")
        return {
            "status": STATUS_NOCONNECT,
            "rid": id,
            "pid": "-",
            "autorestart": False,
            "autorestartmode": False,
            "rdir": "/tmp",
        }
    result = readLogPortBanner(tn)
    tn.close()
    logger.spam(f"Done checking {host}:{port}")
    return result


def openTelnet(host: str, port: int) -> telnetlib.Telnet | None:
    """
    Try multiple times to open a telnet connection.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.

    Returns
    -------
    telnet : telnetlib.Telnet or None
        The Telnet object if successful, otherwise None
    """
    connected = False
    telnetCount = 0
    while (not connected) and (telnetCount < 2):
        telnetCount += 1
        try:
            tn = telnetlib.Telnet(host, port, 1)
        except Exception:
            time.sleep(0.25)
        else:
            connected = True
    if connected:
        return tn
    else:
        return None


def fixTelnetShell(host: str, port: int) -> None:
    """
    Connect to a telnet port running sh and set the prompt to >

    This makes it easier to parse and separate inputs vs outputs
    when dealing with telnet bytes.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    """
    tn = openTelnet(host, port)
    tn.write(b"\x15\x0d")
    tn.expect([MSG_PROMPT_OLD], 2)
    tn.write(b"export PS1='> '\n")
    tn.read_until(MSG_PROMPT, 2)
    tn.close()


def checkTelnetMode(
    host: str,
    port: int,
    onOK: bool = True,
    offOK: bool = False,
    oneshotOK: bool = False,
    verbose: bool = False,
) -> bool:
    """
    Ensure the procServ is in an acceptable state among on/off/oneshot.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    onOk : bool
        True if the "on" state is acceptable, False otherwise.
        Defaults to True.
    offOk : bool
        True if the "off" state is acceptable, False otherwise.
        Defaults to False.
    oneshotOk : bool
        True if the "oneshot" state is acceptable, False otherwise.
        Defaults to False.
    verbose : bool
        Set to True to get more debug prints.
        Defaults to False.

    Returns
    -------
    status : bool
        True if everything went well.
    """
    while True:
        tn = openTelnet(host, port)
        if not tn:
            print("ERROR: checkTelnetMode() telnet to %s port %s failed" % (host, port))
            return False
        try:
            statd = readLogPortBanner(tn)
        except Exception:
            logger.debug("checkTelnetMode() failed to readLogPortBanner", exc_info=True)
            print(
                "ERROR: checkTelnetMode() failed to readLogPortBanner on %s port %s"
                % (host, port)
            )
            tn.close()
            return False
        try:
            if verbose:
                print(
                    "checkTelnetMode: %s port %s status is %s"
                    % (host, port, statd["status"])
                )
            if statd["autorestart"]:
                if onOK:
                    tn.close()
                    return True
            elif statd["autooneshot"]:
                if oneshotOK:
                    tn.close()
                    return True
            else:
                if offOK:
                    tn.close()
                    return True
            if verbose:
                print(
                    "checkTelnetMode: turning off autorestart on %s port %s"
                    % (host, port)
                )
            # send ^T to toggle off auto restart.
            tn.write(b"\x14")
            # wait for toggled message
            if statd["autorestartmode"]:
                tn.read_until(MSG_AUTORESTART_MODE_CHANGE, 1)
            else:
                tn.read_until(MSG_AUTORESTART_CHANGE, 1)
            time.sleep(0.25)
            tn.close()
        except Exception:
            logger.debug(
                "checkTelnetMode() failed to turn off autorestart", exc_info=True
            )
            print(
                "ERROR: checkTelnetMode() failed to turn off autorestart on %s port %s"
                % (host, port)
            )
            tn.close()
            return False


def killProc(host: str, port: int, verbose: bool = False) -> None:
    """
    Kills a procServ process entirely, including the subshell it controls.

    This is implemented kindly, e.g. without actually running a kill command,
    The procServ's return code should be 0.

    Internally this sends a ctrl+X if the subprocess is alive (to end it),
    then a ctrl+Q to ask the procServ process to terminate.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    verbose : bool
        Set to True for more detailed debug prints
    """
    print("Killing IOC on host %s, port %s..." % (host, port))
    if not checkTelnetMode(
        host, port, onOK=False, offOK=True, oneshotOK=False, verbose=verbose
    ):
        return
    # Now, reconnect to actually kill it!
    tn = openTelnet(host, port)
    if tn:
        statd = readLogPortBanner(tn)
        if statd["status"] == STATUS_RUNNING:
            try:
                if verbose:
                    print("killProc: Sending Ctrl-X to %s port %s" % (host, port))
                # send ^X to kill child process
                tn.write(b"\x18")
                # wait for killed message
                tn.read_until(MSG_KILLED, 1)
                time.sleep(0.25)
            except Exception:
                logger.debug("killProc() failed to kill process", exc_info=True)
                print(
                    "ERROR: killProc() failed to kill process on %s port %s"
                    % (host, port)
                )
                tn.close()
                return
        try:
            if verbose:
                print("killProc: Sending Ctrl-Q to %s port %s" % (host, port))
            # send ^Q to kill procServ
            tn.write(b"\x11")
        except Exception:
            logger.debug("killProc() failed to kill procServ", exc_info=True)
            print(
                "ERROR: killProc() failed to kill procServ on %s port %s" % (host, port)
            )
            tn.close()
            return
        tn.close()
    else:
        print("ERROR: killProc() telnet to %s port %s failed" % (host, port))


def restartProc(host: str, port: int) -> bool:
    """
    Restarts a procServ's contained process.

    Internally, this is implemented by sending ctrl+X and ctrl+T
    commands to the procServ port via telnet.

    We first force the procServ into "no restart" mode using
    as many ctrl+T presses as possible, then we ctrl+X to
    stop the process if necessary, finally we ctrl+X one final
    time. Afterwards we ctrl+T back to the initial mode.

    Doing this in oneshot mode is not possible because killing the
    process will kill the procServ itself.

    Doing this in autorestart mode is not wise because it can take
    up to 15 seconds for the automatic restart to kick in, so
    we would need to wait at least that long to verify that
    everything works. It can also happen quickly in autorestart mode,
    and this is also problematic because it can restart when we aren't
    expecting which will cause our "start" command to turn the IOC
    back off.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.

    Returns
    -------
    success : bool
        True if we managed to restart the process successfully.
    """
    print("Restarting IOC on host %s, port %s..." % (host, port))
    tn = openTelnet(host, port)
    if tn is None:
        print("ERROR: restartProc() telnet to %s port %s failed" % (host, port))
        return False
    started = False
    with tn:
        # Check initial status
        statd = readLogPortBanner(tn)
        # Force into no restart mode
        if not checkTelnetMode(host, port, onOK=False, offOK=True, oneshotOK=False):
            return False
        # Manual kill if necessary
        if statd["status"] == STATUS_RUNNING:
            # send ^X to kill child process
            tn.write(b"\x18")

            # wait for killed message
            tn.read_until(MSG_KILLED, 1)
            time.sleep(0.25)

        # send ^X to start child process
        tn.write(b"\x18")

        # wait for restart message
        rsp = tn.read_until(MSG_RESTART, 1)
        if MSG_RESTART in rsp:
            started = True
        else:
            print("ERROR: no restart message... ")

    # Finally, force back to original mode
    if statd["autorestart"]:
        checkTelnetMode(host, port, onOK=True, offOK=False, oneshotOK=False)
    elif statd["autooneshot"]:
        checkTelnetMode(host, port, onOK=False, offOK=False, oneshotOK=True)
    else:
        checkTelnetMode(host, port, onOK=False, offOK=True, oneshotOK=False)
    return started


def startProc(cfg: str, entry: dict[str, str | int], local=False) -> None:
    """
    Starts a new procServ process from our config entry information.

    Parameters
    ----------
    cfg : str
        The name of the area, such as xpp or tmo.
    entry : dict
        Config dict with the following required keys:
        - "host": str server hostname
        - "port": int procServ port
        - "id": str ioc name
        And the following optional keys:
        - "cmd": str command to run if not st.cmd
        - "flags": deprecated
    """
    # Hopefully, we can dispose of this soon!
    platform = "1"
    if cfg == "xrt":
        platform = "2"
    if cfg == "las":
        platform = "3"

    if local:
        host = "localhost"
    else:
        host = entry["host"]
    port = entry["port"]
    name = entry["id"]
    try:
        cmd = entry["cmd"]
    except Exception:
        cmd = "./st.cmd"
    try:
        if "u" in entry["flags"]:
            # The Old Regime: add u to flags to append the ID to the command.
            cmd += " -u " + name
    except Exception:
        pass

    sr = os.getenv("SCRIPTROOT")
    if sr is None:
        sr = STARTUP_DIR % cfg
    elif sr[-1] != "/":
        sr += "/"
    cmd = "%sstartProc %s %d %s %s" % (sr, name, port, cfg, cmd)
    log = LOGBASE % name
    ctrlport = BASEPORT + 2 * (int(platform) - 1)
    print(
        "Starting %s on port %s of host %s, platform %s..."
        % (name, port, host, platform)
    )
    cmd = "%s --logfile %s --name %s --allow --coresize 0 --savelog %d %s" % (
        PROCSERV_EXE,
        log,
        name,
        port,
        cmd,
    )
    try:
        tn = telnetlib.Telnet(host, ctrlport, 1)
    except Exception:
        logger.debug("telnet to procmgr failed", exc_info=True)
        print("ERROR: telnet to procmgr (%s port %d) failed" % (host, ctrlport))
        print(">>> Please start the procServ process on host %s!" % host)
        return
    # telnet succeeded
    with tn:
        # send ^U followed by carriage return to safely reach the prompt
        tn.write(b"\x15\x0d")

        # wait for prompt (procServ)
        statd = tn.read_until(MSG_PROMPT, 2)
        if not bytes.count(statd, MSG_PROMPT):
            print("ERROR: no prompt at %s port %s" % (host, ctrlport))

        # send command
        tn.write(b"%s\n" % bytes(cmd, "utf-8"))

        # wait for prompt
        statd = tn.read_until(MSG_PROMPT, 2)
        if not bytes.count(statd, MSG_PROMPT):
            print("ERR: no prompt at %s port %s" % (host, ctrlport))


######################################################################
#
# Configuration/Status Utilities
#


def readConfig(
    cfg: str, last_mtime: float | None = None, do_os: bool = False
) -> tuple[float, list[dict], list[str], dict[str, typing.Any]] | None:
    """
    Read the configuration file for a given hutch if newer than time.

    Returns None on failure or no change,
    otherwise returns a tuple of various config information.

    Parameters
    ----------
    cfg : str
        A path to a config file or the name of a hutch.
    last_mtime : float, optional
        The last file modification timestamp.
    do_os : bool
        If True, scan the .hosts directory to rebuild a host type lookup table.

    Returns
    -------
    filetime, configlist, hostlist, varlist: tuple or None
        - filetime: float, last modified time of the config file
        - configlist: list of dict, the various ioc configs
        - hostlist: list of str, the hostnames valid for the hutch
        - vardict: dict with str keys, other variables set in the config file
    """
    # Check if we have a file or a hutch name
    if os.sep in cfg:
        cfgfn = cfg
    else:
        cfgfn = CONFIG_FILE % cfg

    try:
        mtime = os.stat(cfgfn).st_mtime
    except Exception as exc:
        logger.debug("os.stat exception in readConfig", exc_info=True)
        logger.error(f"readConfig: could not read {cfgfn}: {exc}")
        return
    # Skip if no modifications
    if last_mtime == mtime:
        return

    try:
        with open(cfgfn, "rb") as fd:
            cfgbytes = fd.read()
    except Exception as exc:
        logger.debug("readConfig file io exception", exc_info=True)
        logger.error("readConfig file error: %s" % str(exc))
        return

    # This dict gets filled by exec based on the cfg file contents
    config = {
        "procmgr_config": None,
        "hosts": None,
        "dir": "dir",
        "id": "id",
        "cmd": "cmd",
        "flags": "flags",
        "port": "port",
        "host": "host",
        "disable": "disable",
        "history": "history",
        "delay": "delay",
        "alias": "alias",
        "hard": "hard",
    }
    stardard_vars_names = set(config)
    try:
        exec(compile(cfgbytes, cfgfn, "exec"), {}, config)
        cfg_unique_vars = set(config).difference(stardard_vars_names)
        vdict = {}
        for v in cfg_unique_vars:
            vdict[v] = config[v]
        res = (mtime, config["procmgr_config"], config["hosts"], vdict)
    except Exception as exc:
        logger.debug("readConfig parsing exception", exc_info=True)
        logger.error("readConfig error: %s" % str(exc))
        return

    # Add some malformed config checks for better errors
    # and to help the IDE type checkers
    procmgr_config = res[1]
    if not isinstance(procmgr_config, list):
        logger.error("procmgr_config must be a list of dictionaries!")
        return

    hosts_list = res[2]
    if not isinstance(hosts_list, list):
        logger.error("hosts must be a list of str!")
        return

    for ioc in procmgr_config:
        if not isinstance(ioc, dict):
            logger.error("Each ioc in procmgr_config must be a dict!")
            return
        ioc.setdefault("disable", False)
        ioc.setdefault("hard", False)
        ioc.setdefault("history", [])
        ioc.setdefault("alias", "")
        ioc["cfgstat"] = CONFIG_NORMAL
        if ioc["hard"]:
            ioc["base"] = getBaseName(ioc["id"])
            ioc["dir"] = getHardIOCDir(ioc["id"])
            ioc["host"] = ioc["id"]
            ioc["port"] = -1
            ioc["rhost"] = ioc["id"]
            ioc["rport"] = -1
            ioc["rdir"] = ioc["dir"]
            ioc["newstyle"] = False
            ioc["pdir"] = ""
        else:
            ioc["rid"] = ioc["id"]
            ioc["rdir"] = ioc["dir"]
            ioc["rhost"] = ioc["host"]
            ioc["rport"] = ioc["port"]
            ioc["newstyle"] = False
            ioc["pdir"] = findParent(ioc["id"], ioc["dir"])

    # hosttype is used to display which OS each host is running
    if do_os:
        global hosttype
        hosttype = {}
        for fn in hosts_list:
            try:
                with open("%s/%s" % (HOST_DIR, fn)) as fd:
                    hosttype[fn] = fd.readlines()[0].strip()
            except Exception:
                ...

    return res


#
# Writes a hutch configuration file, dealing with possible changes ("new*" fields).
#
def writeConfig(
    hutch: str,
    hostlist: list[str],
    cfglist: list[dict[str, str | int]],
    vars: dict[str, str | bool | int],
    f: io.TextIOWrapper | None = None,
) -> None:
    """
    Write the configuration file for a given hutch.

    Deals with the existence of uncomitted changes ("new*" fields).

    Parameters
    ----------
    hutch : str
        Unused. Probably was used in a past version of this function.
    hostlist : list of str
        Hosts that are available for the hutch to include in the config.
    cfglist : list of dict
        List of dictionaries that each correspond to an IOC's config.
    vars: dict mapping of string to value
        Dictionary mapping of additional variables to include in the
        config file. These each must be literal strings "True", "False",
        or something that can be converted to an integer.
    f: open file
        A file-like object such as the one returned by the open built-in.
    """
    if f is None:
        raise Exception("Must specify output file!")
    f.truncate()
    for k, v in list(vars.items()):
        try:
            if v not in ["True", "False"]:
                int(v)
            f.write("%s = %s\n" % (k, str(v)))
        except Exception:
            f.write('%s = "%s"\n' % (k, str(v)))
    f.write("\nhosts = [\n")
    for h in hostlist:
        f.write("   '%s',\n" % h)
    f.write("]\n\n")
    f.write("procmgr_config = [\n")
    cl = sorted(cfglist, key=lambda x: x["id"])
    for entry in cl:
        if entry["cfgstat"] == CONFIG_DELETED:
            continue
        try:
            id = entry[
                "newid"
            ].strip()  # Bah.  Sometimes we add a space so this becomes blue!
        except Exception:
            id = entry["id"]
        try:
            alias = entry["newalias"]
        except Exception:
            alias = entry["alias"]
        if entry["hard"]:
            if alias != "":
                extra = ", alias: '%s'" % alias
            else:
                extra = ""
            f.write(" {id:'%s', hard: True%s},\n" % (id, extra))
            continue
        try:
            host = entry["newhost"]
        except Exception:
            host = entry["host"]
        try:
            port = entry["newport"]
        except Exception:
            port = entry["port"]
        try:
            dir = entry["newdir"]
        except Exception:
            dir = entry["dir"]
        extra = ""
        try:
            disable = entry["newdisable"]
        except Exception:
            disable = entry["disable"]
        if disable:
            extra += ", disable: True"
        if alias != "":
            extra += ", alias: '%s'" % alias
        try:
            h = entry["history"]
            if h != []:
                extra += (
                    ",\n  history: ["
                    + ", ".join(["'" + path + "'" for path in h])
                    + "]"
                )
        except Exception:
            pass
        try:
            extra += ", delay: %d" % entry["delay"]
        except Exception:
            pass
        try:
            extra += ", cmd: '%s'" % entry["cmd"]
        except Exception:
            pass
        f.write(
            " {id:'%s', host: '%s', port: %s, dir: '%s'%s},\n"
            % (id, host, port, dir, extra)
        )
    f.write("]\n")
    f.close()
    os.chmod(
        f.name, stat.S_IRUSR | stat.S_IRGRP | stat.S_IWUSR | stat.S_IWGRP | stat.S_IROTH
    )


def installConfig(hutch: str, file: str, fd: None = None) -> None:
    """
    Install an existing file as the hutch configuration file.

    Parameters
    ----------
    hutch : str
        The name of the hutch, such as tmo or xpp.
    file : str
        Path to the file to use as the new hutch configuration file.
    fd : None
        Unused.
    """
    os.rename(file, CONFIG_FILE % hutch)


def readStatusDir(cfg: str) -> list[dict[str, str | int | bool]]:
    """
    Update a status directory for a hutch and return its information.

    Each hutch has a status directory, nominally at
    /cds/group/pcds/pyps/config/.status/$hutchname

    This directory contains one file per IOC process, which stores:
    - PID
    - hostname
    - procServ port
    - path to IOC

    The file stores this info in a single line, for example:
    14509 ctl-tmo-misc-01 30305 ioc/tmo/pvNotepad/R1.1.5

    This function will open each of these files and do the following:
    - If the file doesn't have 4 parts, delete the file
    - If we encounter multiple files with the same host/port combination,
      delete all but the newest such file.
    - Collect information about the files that remain and return it all

    Parameters
    ----------
    cfg : str
        The hutch name associated with the config, such as xpp or tmo.

    Returns
    -------
    status : list of dict
        A list of dictionaries containing all information about each
        IOC from the status dir.
    """
    info = {}
    for filename in os.listdir(STATUS_DIR % cfg):
        full_path = (STATUS_DIR % cfg) + "/" + filename
        with open(full_path, "r") as fd:
            lines = fd.readlines()
        if not lines:
            continue
        # Must be after we open the file to ensure up-to-date on NFS
        mtime = os.stat(full_path).st_mtime
        try:
            pid, host, port, directory = lines[0].strip().split()
        except Exception:
            # Must be the unpack error, file has corrupt data
            _lazy_delete_file(full_path)
            continue
        port = int(port)
        key = (host, port)
        if key in info:
            # Duplicate
            if info[key]["mtime"] < mtime:
                # Duplicate, but newer, so delete other!
                logger.info(
                    "Deleting obsolete %s in favor of %s",
                    info[key]["rid"],
                    filename,
                )
                _lazy_delete_file((STATUS_DIR % cfg) + "/" + info[key]["rid"])
                new_entry = True
            else:
                # Duplicate, but older, so delete this!
                logger.info(
                    "Deleting obsolete %s in favor of %s",
                    filename,
                    info[key]["rid"],
                )
                _lazy_delete_file(full_path)
                new_entry = False
        else:
            new_entry = True

        if new_entry:
            info[key] = {
                "rid": filename,
                "pid": pid,
                "rhost": host,
                "rport": port,
                "rdir": directory,
                "newstyle": True,
                "mtime": mtime,
                "hard": False,
            }

    return list(info.values())


def _lazy_delete_file(filename: str):
    """
    Try to delete the file, but give up easily in case of errors.

    Usually a filesystem permissions thing, no need to crash the GUI for this.
    """
    try:
        os.remove(filename)
    except Exception:
        logger.debug("Delete file error", exc_info=True)
        logger.error("Error while trying to delete file %s!" % filename)


#
# Apply the current configuration.
#
def applyConfig(
    cfg: str,
    verify: typing.Callable[
        [dict, dict, list[str], list[str], list[str]],
        tuple[list[str], list[str], list[str]],
    ]
    | None = None,
    ioc: str | None = None,
) -> int:
    """
    Starts, restarts, and kills IOCs to match the saved configuration.

    If a verify function is provided, it will be called first to let the
    user confirm that they want to take all of these actions.

    Note:
    - This relies on the status directory being populated
      correctly, which is handled by startProc.
    - This may implicitly modify/clean up the status directory via
      calling readStatusDir

    Parameters
    ----------
    cfg : str
        The name of the hutch, or a full filepath to the config file.
    verify : callable, optional
        An optionally provided function that expects to recieve the following.
        - current: dict of current state (pre-apply)
        - config: dict of desired state (post-apply)
        - kill_list: list[str] of ioc names that should be killed
        - start_list: list[str] of ioc names that should be started
        - restart_list: list[str] of ioc names that should be restarted
        The function must return a tuple of its own kill_list, start_list, and
        restart_list, which should be subset of or equal to the input lists.
    ioc : str, optional
        The name of a single IOC to apply to, if provided.
        If not provided, we'll apply the entire configuration.

    Returns
    -------
    return_code : int
        Zero if completed successfully.
    """
    result = readConfig(cfg)
    if result is None:
        print("Cannot read configuration for %s!" % cfg)
        return -1
    (mtime, cfglist, hostlist, vdict) = result

    config = {}
    for line in cfglist:
        if ioc is None or ioc == line["id"]:
            config[line["id"]] = line

    runninglist = readStatusDir(cfg)

    current = {}
    notrunning = {}
    for line in runninglist:
        if ioc is None or ioc == line["rid"]:
            result = check_status(line["rhost"], line["rport"], line["rid"])
            rdir = line["rdir"]
            line.update(result)
            if line["rdir"] == "/tmp":
                line["rdir"] = rdir
            else:
                line["newstyle"] = False
            if result["status"] == STATUS_RUNNING:
                current[line["rid"]] = line
            else:
                notrunning[line["rid"]] = line

    running = list(current.keys())
    wanted = list(config.keys())

    # Double-check for old-style IOCs that don't have an indicator file!
    for line in wanted:
        if line not in running:
            result = check_status(
                config[line]["host"], int(config[line]["port"]), config[line]["id"]
            )
            if result["status"] == STATUS_RUNNING:
                result.update(
                    {
                        "rhost": config[line]["host"],
                        "rport": config[line]["port"],
                        "newstyle": False,
                    }
                )
                current[line] = result

    running = list(current.keys())
    neww = []
    notw = []
    for line in wanted:
        try:
            if not config[line]["hard"]:
                if not config[line]["newdisable"]:
                    neww.append(line)
                else:
                    notw.append(line)
        except Exception:
            if not config[line]["hard"]:
                if not config[line]["disable"]:
                    neww.append(line)
                else:
                    notw.append(line)
    wanted = neww

    #
    # Note the hard IOC handling... we don't want to start them, but they
    # don't have entries in the running directory anyway so we don't think
    # we need to!
    #

    # Camera recorders always seem to be in the wrong directory, so cheat!
    for line in cfglist:
        if line["dir"] == CAMRECORDER:
            try:
                current[line["id"]]["rdir"] = CAMRECORDER
            except Exception:
                pass

    #
    # Now, we need to make three lists: kill, restart, and start.
    #

    # Kill anyone who we don't want, or is running on the wrong host or port, or is
    # oldstyle and needs an upgrade.
    kill_list = [
        line
        for line in running
        if line not in wanted
        or current[line]["rhost"] != config[line]["host"]
        or current[line]["rport"] != config[line]["port"]
        or (
            (not current[line]["newstyle"])
            and current[line]["rdir"] != config[line]["dir"]
        )
    ]

    #
    # Now there is a problem if an IOC is bad and repeatedly crashing.  The running
    # state may not be accurate, as it is oscillating between RUNNING and SHUTDOWN.
    # If it's enabled, not much we can do but let it spin... but if it's disabled, we
    # need to be certain to kill it.
    #
    # We don't want to just add *everything* though... this makes the screen too
    # verbose!  So, we compromise... if the status file is *new*, then maybe it's
    # crashing and needs to be killed again.  If it's old though, let's assume that
    # it's dead and we can leave it alone...
    #
    # If it's dead, it might not *have* a status file, hence the try.
    #
    now = time.time()
    for line in notw:
        try:
            if line not in running and now - notrunning[line]["mtime"] < 600:
                kill_list.append(line)
        except Exception:
            pass

    # Start anyone who wasn't running, or was running on the wrong host or port,
    # or is oldstyle and needs an upgrade.
    start_list = [
        line
        for line in wanted
        if line not in running
        or current[line]["rhost"] != config[line]["host"]
        or current[line]["rport"] != config[line]["port"]
        or (
            not current[line]["newstyle"]
            and current[line]["rdir"] != config[line]["dir"]
        )
    ]

    # Anyone running the wrong version, newstyle, on the right host and port
    # just needs a restart.
    restart_list = [
        line
        for line in wanted
        if line in running
        and current[line]["rhost"] == config[line]["host"]
        and current[line]["newstyle"]
        and current[line]["rport"] == config[line]["port"]
        and current[line]["rdir"] != config[line]["dir"]
    ]

    if verify is not None:
        (kill_list, start_list, restart_list) = verify(
            current, config, kill_list, start_list, restart_list
        )

    for line in kill_list:
        try:
            killProc(current[line]["rhost"], int(current[line]["rport"]))
        except Exception:
            killProc(config[line]["host"], int(config[line]["port"]))
        try:
            # This is dead, so get rid of the status file!
            os.unlink((STATUS_DIR % cfg) + "/" + line)
        except Exception:
            print(
                "Error while trying to delete file %s" % (STATUS_DIR % cfg)
                + "/"
                + line
                + "!"
            )

    for line in start_list:
        startProc(cfg, config[line])

    for line in restart_list:
        restartProc(current[line]["rhost"], int(current[line]["rport"]))

    time.sleep(1)
    return 0


######################################################################
#
# Miscellaneous utilities
#


def check_auth(user: str, hutch: str) -> bool:
    """
    Check if a user is authorized to apply changes.

    Parameters
    ----------
    user : str
        Username to check
    hutch : str
        Hutch to check for, such as xpp or tmo

    Returns
    -------
    auth_ok : bool
        True if the user is authorized, False otherwise.
    """
    with open(AUTH_FILE % hutch) as fd:
        lines = fd.readlines()
    lines = [ln.strip() for ln in lines]
    for ln in lines:
        if ln == user:
            return True
    return False


def check_special(
    req_ioc: str, req_hutch: str, req_version: str = "no_upgrade"
) -> bool:
    """
    Check the iocmanager.special file to see if an ioc is toggleable between versions.

    The iocmanager.special file should contain lines of the form
    ioc_name:permittedversion1,permittedversion2,etc

    And can be found in the hutch's pyps config directory.

    Parameters
    ----------
    req_ioc : str
        The name of the IOC to check
    req_hutch : str
        The hutch whose iocmanager.special file we will search through
    req_version : str
        The version to check is in the list, if provided.
        If not provided, the default "no_upgrade" string will be used to
        match any version.

    Returns
    -------
    is_special -> bool
        True if the IOC is toggleable between versions.
    """
    with open(SPECIAL_FILE % req_hutch) as fp:
        lines = fp.readlines()
        lines = [ln.strip() for ln in lines]
        for entry in lines:
            ioc_vers_list = entry.split(":")
            ioc_name = ioc_vers_list[0]

            # check that the ioc is in permissioned list before moving forward
            if ioc_name != req_ioc:
                continue  # not the ioc we are looking for

            if req_version == "no_upgrade":
                # NOTE(josh): this does assume that the only place check_special is
                # invoked without overloading the default argument is in the raw
                # enable / disable case
                return True

            # if there is information after the colon, parse it
            if len(ioc_vers_list) > 1:
                perm_version = ioc_vers_list[-1].split(",")
                for vers in perm_version:
                    if vers == req_version:
                        return (
                            True  # return True if the requested version is in the list
                        )
            # if the entry has no colon, assumed just ioc name

        return False


def check_ssh(user: str, hutch: str) -> bool:
    """
    Return True if the user is permitted to SSH, and False otherwise.

    This is tracked in an iocmanager.nossh file in the
    hutch's pyps config folder, which can be used to
    make this function return false for specific users.

    Parameters
    ----------
    user : str
        Username to check
    hutch : str
        Hutch to check, such as xpp or tmo

    Returns
    -------
    ok_to_ssh : bool
        True if the user is not in the nossh file
    """
    try:
        lines = open(NOSSH_FILE % hutch).readlines()
    except Exception:
        return True
    lines = [ln.strip() for ln in lines]
    for ln in lines:
        if ln == user:
            return False
    return True


# Used in findParent to find "RELEASE = /some/filepath" lines
# RELEASE = path
eq = re.compile("^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*?)[ \t]*$")
# RELEASE = "path"
eqq = re.compile('^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*"([^"]*)"[ \t]*$')
# RELEASE = 'path'
eqqq = re.compile("^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*'([^']*)'[ \t]*$")
# RELEASE path
sp = re.compile("^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+(.+?)[ \t]*$")
# RELEASE "path"
spq = re.compile('^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+"([^"]*)"[ \t]*$')
# RELEASE 'path'
spqq = re.compile("^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+'([^']*)'[ \t]*$")


def readAll(fn: str) -> list[str]:
    """
    Return the contents of a filename.

    The filename can either be an absolute path or it can be relative to
    EPICS_SITE_TOP.

    Parameters
    ----------
    fn : str
        Filename

    Returns
    -------
    text : list of str
        The contents of the file
    """
    if fn[0] != "/":
        fn = EPICS_SITE_TOP + fn
    try:
        with open(fn, "r") as fd:
            return fd.readlines()
    except Exception:
        return []


def findParent(ioc: str, dir: str) -> str:
    """
    Return the parent (common) ioc path for a templated ioc.

    Parameters
    ----------
    ioc : str
        The name of the ioc
    dir : str
        The ioc directory

    Returns
    -------
    parent : str
        The full path to the parent IOC release, or an empty
        string if one could not be determined.
    """
    fn = dir + "/" + ioc + ".cfg"
    lines = readAll(fn)
    if lines == []:
        fn = dir + "/children/" + ioc + ".cfg"
        lines = readAll(fn)
    if lines == []:
        return ""
    lines.reverse()
    for ln in lines:
        m = eqqq.search(ln)
        if m is None:
            m = eqq.search(ln)
            if m is None:
                m = eq.search(ln)
                if m is None:
                    m = spqq.search(ln)
                    if m is None:
                        m = spq.search(ln)
                        if m is None:
                            m = sp.search(ln)
        if m is not None:
            var = m.group(1)
            val = m.group(2)
            if var == "RELEASE":
                val = val.replace("$$PATH/", dir + "/" + ioc + ".cfg").replace(
                    "$$UP(PATH)", dir
                )
                return fixdir(val, ioc)
    return ""


def read_until(fd: int, expr: str) -> re.Match[str] | None:
    """
    Read an open file descriptor until regular expression expr finds a match.

    Parameters
    ----------
    fd : int
        The file descriptor number
    expr : str
        Regular expression to match

    Returns
    -------
    match : re.Match or None
        The match if we have one, or None if there was never a match.
    """
    exp = re.compile(expr, re.S)
    data = ""
    while True:
        v = os.read(fd, 1024).decode("utf-8")
        # print "<<< %s" % v.encode("string-escape")
        data += v
        m = exp.search(data)
        if m is not None:
            return m


def flush_input(fd: int) -> None:
    """
    Completely empty a file descriptor

    Parameters
    ----------
    fd : int
        The file descriptor number
    """
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    while True:
        try:
            os.read(fd, 1024)
        except Exception:
            fcntl.fcntl(fd, fcntl.F_SETFL, 0)
            return


def do_write(fd: int, msg: bytes) -> None:
    """Alias for os.write."""
    os.write(fd, msg)


def commit_config(hutch: str, comment: bytes, fd: int):
    """
    Send the git commit command through our ssh file descriptor.

    Parameters
    ----------
    hutch : str
        The name of the hutch to commit, such as xpp or tmo
    comment : bytes
        The commit message
    fd : int
        The number of an open file descriptor to an ssh process
        on the commit host
    """
    config = CONFIG_FILE % hutch
    flush_input(fd)
    do_write(fd, "cat >" + config + ".comment <<EOFEOFEOF\n")
    do_write(fd, comment)
    do_write(fd, "\nEOFEOFEOF\n")
    read_until(fd, "> ")
    # Sigh.  This does nothing but read the file, which makes NFS get the latest.
    do_write(fd, "set xx=`mktemp`\n")
    read_until(fd, "> ")
    do_write(fd, "cp " + config + " $xx\n")
    read_until(fd, "> ")
    do_write(fd, "rm -f $xx\n")
    read_until(fd, "> ")
    do_write(fd, "umask 2; git commit -F " + config + ".comment " + config + "\n")
    read_until(fd, "> ")
    do_write(fd, "rm -f " + config + ".comment\n")
    read_until(fd, "> ")


def find_iocs(**kwargs) -> list[tuple[str, dict]]:
    """
    Find IOCs matching the inputs in any hutch config.

    Examples:
    find_iocs(host='ioc-xcs-mot1')
    find_iocs(host='ioc-xcs-imb3')

    Parameters
    ----------
    **kwargs :
        Any field in an IOC config, mapped to any value

    Returns
    -------
    iocs : list of tuple
        Each IOC's source config file path and config information
    """
    cfgs = glob.glob(CONFIG_FILE % "*")
    configs = []
    for cfg in cfgs:
        config = readConfig(cfg)[1]
        for ioc in config:
            for k in list(kwargs.items()):
                if ioc.get(k[0]) != k[1]:
                    break
            else:
                configs.append([cfg, ioc])
                pass
    return configs


def netconfig(host: str) -> dict[str, str]:
    """
    Return the netconfig information for a host.

    Parameters
    ----------
    host : str
        The hostname

    Returns
    -------
    info : dict of str
        The information about the hostname from netconfig,
        or an empty dict if there was no information.
    """
    try:
        r = [line.strip().split(": ") for line in _netconfig(host).split("\n")]
        d = {}
        for line in r:
            if len(line) == 2:
                d[line[0].lower()] = line[1]
        return d
    except Exception:
        return {}


def _netconfig(host: str) -> str:
    """
    Part of the netconfig helper that shells out to netconfig.

    Keep this separate to test netconfig helper logic without ldap.

    Parameters
    ----------
    host : str
        The hostname

    Returns
    -------
    text : str
        The raw text output from netconfig.
    """
    env = copy.deepcopy(os.environ)
    del env["LD_LIBRARY_PATH"]
    return subprocess.check_output(
        [NETCONFIG, "view", host],
        env=env,
        universal_newlines=True,
    )


def rebootServer(host: str) -> bool:
    """Reboot a server, returning True if successful."""
    return os.system(f"{PSIPMI} %s power cycle" % host) == 0


def getHardIOCDir(host: str) -> str:
    """Return the hard IOC directory for a given hard IOC host."""
    dir = "Unknown"
    try:
        lines = [ln.strip() for ln in open(HIOC_STARTUP % host).readlines()]
    except Exception:
        logger.error("Error while trying to read HIOC startup file for %s!" % host)
        return "Unknown"
    for ln in lines:
        if ln[:5] == "chdir":
            try:
                dir = "ioc/" + re.search('"/iocs/(.*)/iocBoot', ln).group(1)
            except Exception:
                pass  # Having dir show "Unknown" should suffice.
    return dir


def restartHIOC(host: str) -> bool:
    """Console into a HIOC and reboot it via the shell, return True if successful."""
    try:
        for line in netconfig(host)["console port dn"].split(","):
            if line[:7] == "cn=port":
                port = 2000 + int(line[7:])
            if line[:7] == "cn=digi":
                host = line[3:]
    except Exception:
        logger.debug("Netconfig error", exc_info=True)
        print("Error parsing netconfig for HIOC %s console info!" % host)
        return False
    try:
        tn = telnetlib.Telnet(host, port, 1)
    except Exception:
        logger.debug("Telnet error", exc_info=True)
        print("Error making telnet connection to HIOC %s!" % host)
        return False
    tn.write(b"\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"exit\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"rtemsReboot()\x0a")
    tn.close()
    return True


def rebootHIOC(host: str) -> bool:
    """Power cycle a HIOC via the PDU entry in netconfig, return True if successful."""
    try:
        env = copy.deepcopy(os.environ)
        del env["LD_LIBRARY_PATH"]
        print(
            subprocess.check_output(
                [HIOC_POWER, host, "cycle"],
                env=env,
                universal_newlines=True,
            )
        )
        return True
    except Exception:
        logger.debug("Power cycle error", exc_info=True)
        print("Error while trying to power cycle HIOC %s!" % host)
        return False


def findPV(regexp: re.Pattern, ioc: str) -> list[str]:
    """Return all PVs belonging to an IOC that match a regular expression."""
    try:
        lines = [ln.split(",")[0] for ln in open(PVFILE % ioc).readlines()]
    except Exception:
        return []
    return list(filter(regexp.search, lines))


def getHutchList() -> list[str]:
    """Return the list of all supported hutches."""
    try:
        config_paths = Path(CONFIG_DIR).glob("*/iocmanager.cfg")
        return [pth.parent.name for pth in config_paths]
    except Exception:
        return []


def validateConfig(cl: list[dict]) -> bool:
    """
    Returns True if the list of IOC configurations looks valid.

    Currently, just checks if there is a duplicate host/port combination.
    """
    for i in range(len(cl)):
        try:
            h = cl[i]["newhost"]
        except Exception:
            h = cl[i]["host"]
        try:
            p = cl[i]["newport"]
        except Exception:
            p = cl[i]["port"]
        for j in range(i + 1, len(cl)):
            try:
                h2 = cl[j]["newhost"]
            except Exception:
                h2 = cl[j]["host"]
            try:
                p2 = cl[j]["newport"]
            except Exception:
                p2 = cl[j]["port"]
            if h == h2 and p == p2:
                return False
    #
    # Anything else we want to check here?!?
    #
    return True


def validateDir(dir: str, ioc: str) -> bool:
    """
    Returns True if we can find a st.cmd file in the filetree.

    Parameters
    ----------
    dir : str
        Path to the IOC, either an absolute path or a path relative
        to EPICS_SITE_TOP
    ioc : str
        The name of the IOC

    Returns
    -------
    has_stcmd : bool
        True if we found the st.cmd file at one of the standard locations.
    """
    if dir[0] != "/":
        dir = EPICS_SITE_TOP + dir
    for p in stpaths:
        if os.path.exists(p % (dir, ioc)):
            return True
    if os.path.exists(dir + "/st.cmd"):
        return True
    return False
