"""
The procserv_tools module defines helper functions for interfacing with procServ.

procServ (https://github.com/ralphlange/procServ) is a program that
runs other programs inside of it, making stdin/stdout/stderr available
for reading/writing via telnet connection.

It is typically used to run EPICS IOCs.

Managing these procServ processes is the key role of iocmanager.
"""

import collections
import logging
import os
import re
import telnetlib
import threading
import time
import typing

from . import env_paths
from .config import readConfig, readStatusDir
from .epics_paths import normalize_path
from .log_setup import add_spam_level

# For procmgrd
BASEPORT = 39050

# Process status options
# TODO enum-ify?
STATUS_INIT = "INITIALIZE WAIT"
STATUS_NOCONNECT = "NOCONNECT"
STATUS_RUNNING = "RUNNING"
STATUS_SHUTDOWN = "SHUTDOWN"
STATUS_DOWN = "HOST DOWN"
STATUS_ERROR = "ERROR"

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

logger = logging.getLogger(__name__)
add_spam_level(logger)


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
        "rdir": normalize_path(dir, getid),
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
        sr = env_paths.STARTUP_DIR % cfg
    elif sr[-1] != "/":
        sr += "/"
    cmd = "%sstartProc %s %d %s %s" % (sr, name, port, cfg, cmd)
    log = env_paths.LOGBASE % name
    ctrlport = BASEPORT + 2 * (int(platform) - 1)
    print(
        "Starting %s on port %s of host %s, platform %s..."
        % (name, port, host, platform)
    )
    cmd = "%s --logfile %s --name %s --allow --coresize 0 --savelog %d %s" % (
        env_paths.PROCSERV_EXE,
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
        if line["dir"] == env_paths.CAMRECORDER:
            try:
                current[line["id"]]["rdir"] = env_paths.CAMRECORDER
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
            os.unlink((env_paths.STATUS_DIR % cfg) + "/" + line)
        except Exception:
            print(
                "Error while trying to delete file %s" % (env_paths.STATUS_DIR % cfg)
                + "/"
                + line
                + "!"
            )

    for line in start_list:
        startProc(cfg, config[line])

    for line in restart_list:
        restartProc(current[line]["rhost"], int(current[line]["rport"]))

    # TODO figure out why this sleep was here and decide what to do about it
    # Remove it for now to make test suite faster
    # time.sleep(1)
    return 0
