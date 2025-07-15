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
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum, StrEnum
from itertools import chain

from .config import IOCProc, IOCStatusFile, read_config, read_status_dir
from .env_paths import env_paths
from .epics_paths import normalize_path
from .log_setup import log_spam

# For procmgrd
BASEPORT = 39050

logger = logging.getLogger(__name__)


class ProcServStatus(StrEnum):
    """
    procServ Process status options

    The variants are:
    - INIT: a placeholder to use when we have not checked status yet.
    - NOCONNECT: procServ process is not running, but the host is up
    - RUNNING: the IOC is running inside the procServ
    - SHUTDOWN: the IOC is not running, but the procServ process is
    - DOWN: the host is not accessible
    - ERROR: we connected to telnet, but the status could not be determined,
        sometimes this means we connected right before the IOC was killed,
        but it can also mean there's not a procServ running on the port
        or something similar.
    """

    INIT = "INITIALIZE WAIT"
    NOCONNECT = "NOCONNECT"
    RUNNING = "RUNNING"
    SHUTDOWN = "SHUTDOWN"
    DOWN = "HOST DOWN"
    ERROR = "ERROR"


class AutoRestartMode(Enum):
    """
    procServ Process autorestart modes

    The variants are:
    - ON: restart the process when it terminates
    - ONESHOT: close the procServ instance when the process terminates
    - OFF: do nothing when the process terminates
    """

    ON = 0
    ONESHOT = 1
    OFF = 2


@dataclass(eq=True)
class IOCStatusLive:
    """
    Information about an IOC from inspecting the live process.

    Attributes
    ----------
    name : str
        The name of the IOC as reported by procServ.
    port : int
        The port that the procServ instance was running on.
    host : str
        The name of the server that the procServ instance was running on.
    path : str
        The startup path of the IOC as reported by procServ.
        This should essentially always be /tmp, unless we've
        replaced it with the real path e.g. augmented by IOCStatusFile.
    pid : int | None
        The process id of the IOC process as reported by procServ,
        or None if no process is running.
    status : ProcServStatus
        The status of the procServ IOC. See enum documentation above.
    autorestart_mode : AutoRestartMode
        How the procServ will behave when the IOC crashes or is stopped.
        See enum documentation above.
    """

    name: str
    port: int
    host: str
    path: str
    pid: int | None
    status: ProcServStatus
    autorestart_mode: AutoRestartMode


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
MSG_AUTORESTART_MODE_CHANGE = b"@@@ Toggled auto restart"


def read_port_banner(tn: telnetlib.Telnet) -> IOCStatusLive:
    """
    Read and parse the connection information from a new telnet connection.

    This works by reading bytes from the banner.
    The banner is the first part of the telnet output from procServ
    itself rather than the stdout/stderr of the IOC.

    This is the part of check_status that collects information from a
    telnet session. Usually you'd call check_status directly which includes
    other checks too.

    The resulting status here won't have information about the
    hostname or port. These should be added by the caller.

    Parameters
    ----------
    tn : telnetlib.Telnet
        A brand-new Telnet object that has otherwise been unused.

    Returns
    -------
    ioc_status_live : IOCStatusLive
        Various information about the connection and procServ status.
    """
    ioc_status_live = IOCStatusLive(
        name="",
        port=0,
        host="",
        path="",
        pid=None,
        status=ProcServStatus.ERROR,
        autorestart_mode=AutoRestartMode.OFF,
    )
    try:
        response = tn.read_until(MSG_BANNER_END, 1)
    except Exception:
        response = b""
    if not response.count(MSG_BANNER_END):
        return ioc_status_live
    if re.search(b"SHUT DOWN", response):
        ioc_status_live.status = ProcServStatus.SHUTDOWN
    else:
        ioc_status_live.status = ProcServStatus.RUNNING
        try:
            ioc_status_live.pid = int(
                re.search(b'@@@ Child "(.*)" PID: ([0-9]*)', response)
                .group(2)  # type: ignore
                .decode("ascii")
            )
        except AttributeError:
            ioc_status_live.pid = None
    match = re.search(b'@@@ Child "(.*)" start', response)
    if match:
        ioc_status_live.name = match.group(1).decode("ascii")
    match = re.search(b"@@@ Server startup directory: (.*)", response)
    if match:
        ioc_status_live.path = normalize_path(
            match.group(1).decode("ascii").removesuffix("\r"), ioc_status_live.name
        )

    # Note: This means that ONESHOT counts as OFF!
    if re.search(MSG_AUTORESTART_IS_ON, response):
        ioc_status_live.autorestart_mode = AutoRestartMode.ON
    elif re.search(MSG_AUTORESTART_IS_ONESHOT, response):
        ioc_status_live.autorestart_mode = AutoRestartMode.ONESHOT

    # Note: this function doesn't know the host or port information.
    # The caller of this function will need to add this information to the result.
    return ioc_status_live


pdict: dict[str, tuple[float, int]] = {}
lockdict = collections.defaultdict(threading.RLock)


def check_status(host: str, port: int, name: str) -> IOCStatusLive:
    """
    Returns the status of an IOC via information from ping and telnet.

    Pings the host first if it hasn't been pinged recently.
    If the ping succeeds or has succeeded recently, telnet to the procServ port.
    If telnet succeeds, uses read_port_banner to determine the procServ status.

    Parameters
    ----------
    host : str
        The network hostname the IOC runs on.
    port : int
        The port the procServ process listens for telnet on.
    name : str
        The name of the IOC.

    Returns
    -------
    status : IOCStatusLive
        Various information about the IOC health and status.
    """
    # Lock to ensure only 1 ping at a time per host
    with lockdict[host]:
        log_spam(logger, f"check_status({host}, {port}, {name})")
        now = time.monotonic()
        try:
            (last, pingrc) = pdict[host]
            havestat = now - last < 10
        except Exception:
            havestat = False
        if not havestat:
            # Ping the host to see if it is up!
            log_spam(logger, f"Pinging {host}")
            pingrc = os.system(
                "ping -c 1 -w 1 -W 0.002 %s >/dev/null 2>/dev/null" % host
            )
            pdict[host] = (now, pingrc)
    if pingrc != 0:  # type: ignore
        log_spam(logger, f"{host} is down")
        return IOCStatusLive(
            name=name,
            port=port,
            host=host,
            path="",
            pid=None,
            status=ProcServStatus.DOWN,
            autorestart_mode=AutoRestartMode.OFF,
        )
    log_spam(logger, f"Check telnet to {host}:{port}")
    try:
        with telnetlib.Telnet(host, port, 1) as tn:
            status = read_port_banner(tn)
    except Exception:
        log_spam(logger, f"{host}:{port} is down")
        return IOCStatusLive(
            name=name,
            port=port,
            host=host,
            path="",
            pid=None,
            status=ProcServStatus.NOCONNECT,
            autorestart_mode=AutoRestartMode.OFF,
        )
    log_spam(logger, f"Done checking {host}:{port}")
    # Fill in some aux info that read_port_banner doesn't know
    status.host = host
    status.port = port
    return status


def open_telnet(host: str, port: int) -> telnetlib.Telnet:
    """
    Try multiple times to open a telnet connection.

    Raises if unsuccessful.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.

    Returns
    -------
    telnet : telnetlib.Telnet
        The Telnet object if successful, otherwise None
    """
    tn = None
    for num in range(3):
        if num > 0:
            time.sleep(0.25)
        try:
            tn = telnetlib.Telnet(host, port, 1)
        except Exception:
            ...
        else:
            break
    if tn is not None:
        return tn
    else:
        raise RuntimeError(f"Unable to open telnet to {host}:{port}")


def fix_telnet_shell(host: str, port: int) -> None:
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
    with open_telnet(host, port) as tn:
        tn.write(b"\x15\x0d")
        tn.expect([MSG_PROMPT_OLD], 2)
        tn.write(b"export PS1='> '\n")
        tn.read_until(MSG_PROMPT, 2)


def set_telnet_mode(
    host: str,
    port: int,
    mode: AutoRestartMode,
) -> AutoRestartMode:
    """
    Ensure the procServ is in an acceptable state among on/off/oneshot.

    Raises if something went wrong with telnet or if we can't get to the
    desired state within five toggles.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    mode: AutoRestartMode
        One of ON, ONESHOT, or OFF from the enum options

    Returns
    -------
    mode : AutoRestartMode
        The final mode after all operations.
        In the current implemenation, this will always match the input
        because we'll raise when this fails.
    """
    status = check_status(host=host, port=port, name="")
    if status.status == ProcServStatus.DOWN:
        raise RuntimeError(f"host {host} is down, cannot set_telnet_mode")
    if status.status == ProcServStatus.NOCONNECT:
        raise RuntimeError(f"IOC at {host}:{port} is down, cannot set_telnet_mode")

    att_remaining = 5
    start_att_remaining = att_remaining

    while status.autorestart_mode != mode:
        if att_remaining <= 0:
            raise RuntimeError(
                f"Unable to change telnet mode to {mode.name} "
                f"within {start_att_remaining} attempts, "
                f"ended at {status.autorestart_mode.name}."
            )
        logger.debug(
            "set_telnet_mode: %s port %s status is %s",
            host,
            port,
            status.status.value,
        )
        with open_telnet(host, port) as tn:
            # send ^T to toggle off auto restart.
            tn.write(b"\x14")
            tn.read_until(MSG_AUTORESTART_MODE_CHANGE)

        status = check_status(host=host, port=port, name="")
        att_remaining -= 1

    return status.autorestart_mode


def kill_proc(host: str, port: int) -> None:
    """
    Kills a procServ process entirely, including the subshell it controls.

    This is implemented kindly, e.g. without actually running a kill command.
    The procServ's return code should be 0.

    Internally this changes autorestart to OFF, sends a ctrl+X if the subprocess
    is alive (to end it), then a ctrl+Q to ask the procServ process to terminate.

    This may raise if there is some sort of connection issue.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    """
    logger.info("Killing IOC on host %s, port %s...", host, port)

    # Make sure it doesn't restart while we're doing this
    mode = set_telnet_mode(host=host, port=port, mode=AutoRestartMode.OFF)
    if mode != AutoRestartMode.OFF:
        raise RuntimeError("Unable to change autorestart mode to OFF in kill_proc")

    # Now, reconnect to actually kill it!
    with open_telnet(host, port) as tn:
        status = read_port_banner(tn)
        if status.status == ProcServStatus.RUNNING:
            logger.debug("kill_proc: Sending Ctrl-X to %s port %s", host, port)
            # send ^X to kill child process
            tn.write(b"\x18")
            # wait for killed message
            tn.read_until(MSG_KILLED, 1)
        logger.debug("kill_proc: Sending Ctrl-Q to %s port %s", host, port)
        # send ^Q to ask procServ to quit
        tn.write(b"\x11")


def restart_proc(host: str, port: int) -> None:
    """
    Restarts a procServ's contained process.

    Internally, this is implemented by sending ctrl+X and ctrl+T
    commands to the procServ port via telnet.

    We first force the procServ into "no restart" mode using
    as many ctrl+T presses as needed, then we ctrl+X to
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

    Raises on failure.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port on the hostname to connect to.
    """
    logger.info("Restarting IOC on host %s, port %s..." % (host, port))
    # We don't want it to restart on it's own schedule, we want to pick the timing
    original_status = check_status(host=host, port=port, name="")
    try:
        set_telnet_mode(host=host, port=port, mode=AutoRestartMode.OFF)

        with open_telnet(host, port) as tn:
            # Check initial status
            status = read_port_banner(tn)
            # Double-check autorestart is OFF while we're here
            if status.autorestart_mode != AutoRestartMode.OFF:
                raise RuntimeError(
                    "Unable to change autorestart mode to OFF in restart_proc"
                )
            # Manual kill if necessary
            if status.status == ProcServStatus.RUNNING:
                # send ^X to kill child process
                tn.write(b"\x18")
                # wait for killed message
                tn.read_until(MSG_KILLED, 1)

            # send ^X to start child process
            tn.write(b"\x18")

            # wait for restart message
            rsp = tn.read_until(MSG_RESTART, 1)
            if MSG_RESTART not in rsp:
                raise RuntimeError("ERROR: no restart message received in restart_proc")
    finally:
        # Force back to original mode
        set_telnet_mode(host=host, port=port, mode=original_status.autorestart_mode)


def start_proc(cfg: str, ioc_proc: IOCProc, local: bool = False) -> None:
    """
    Starts a new procServ process from our config entry information.

    Parameters
    ----------
    cfg : str
        The name of the area, such as xpp or tmo.
    entry : IOCProc
        The configuration information for our IOC process.
        The important values we'll need are "name", "host", and "port".
        "cmd" is respected as an optional value.
    localhost : bool, optional
        If True, run on localhost instead of the host defined in ioc_proc.
    """
    # Hopefully, we can dispose of this soon!
    if cfg == "xrt":
        platform = "2"
    elif cfg == "las":
        platform = "3"
    else:
        platform = "1"

    if local:
        host = "localhost"
    else:
        host = ioc_proc.host

    name = ioc_proc.name
    port = ioc_proc.port
    cmd = ioc_proc.cmd or "./st.cmd"

    sr = os.getenv("SCRIPTROOT") or env_paths.STARTUP_DIR % cfg
    if sr[-1] != "/":
        sr += "/"
    cmd = f"{sr}startProc {name} {port} {cfg} {cmd}"
    log = env_paths.LOGBASE % name
    ctrlport = BASEPORT + 2 * (int(platform) - 1)
    logger.info(
        "Starting %s on port %s of host %s, platform %s...",
        name,
        port,
        host,
        platform,
    )
    cmd = (
        f"{env_paths.PROCSERV_EXE} "
        f"--logfile {log} "
        f"--name {name} "
        "--allow --coresize 0 --savelog "
        f"{port} {cmd}"
    )
    try:
        tn = open_telnet(host, ctrlport)
    except Exception as exc:
        raise RuntimeError(
            f"Telnet to procmgr ({host}:{ctrlport}) failed. "
            f"Please start the procServ process on host {host}."
        ) from exc
    # telnet succeeded
    with tn:
        # send ^U followed by carriage return to safely reach the prompt
        tn.write(b"\x15\x0d")

        # wait for prompt (procServ)
        statd = tn.read_until(MSG_PROMPT, 2)
        if MSG_PROMPT not in statd:
            logger.error(f"ERROR: no prompt at {host}:{ctrlport}")

        # send command
        tn.write(b"%s\n" % bytes(cmd, "utf-8"))

        # wait for prompt
        statd = tn.read_until(MSG_PROMPT, 2)
        if MSG_PROMPT not in statd:
            logger.error(f"ERROR: no prompt at {host}:{ctrlport}")

    # One last check, did we start?
    status = check_status(host=ioc_proc.host, port=ioc_proc.port, name=ioc_proc.name)
    if status.status in (ProcServStatus.DOWN or ProcServStatus.NOCONNECT):
        raise RuntimeError(
            f"Failed to start ioc process {ioc_proc.name} "
            f"on {ioc_proc.host}:{ioc_proc.port}"
        )


@dataclass(frozen=True)
class ApplyConfigContext:
    """
    Contextual information sent to an apply_config "verify" function.

    Attributes
    ----------
    status_files : dict[str, IOCStatusFile]
        Information about the running IOCs prior to apply_config.
        Keys are the IOC name.
    proc_config : dict[str, IOCProc]
        Information about the desired new state to apply.
        Keys are the IOC name.
    """

    status_files: dict[str, IOCStatusFile]
    proc_config: dict[str, IOCProc]


@dataclass
class VerifyPlan:
    """
    The payload expected from an external "verify" function in apply_config.

    This is provided to the "verify" function in apply_config.
    The "verify" function should mutate, replace, or leave these lists
    as they are, depending on which actions it needs to veto.

    The lists returned by the "verify" function are the final authority
    for which changes are allowed to be made.
    For example, you can return empty lists to veto applying any changes,
    or return the full object again to agree to all changes,
    or remove a single element from a list to skip only one change.
    """

    kill_list: list[str]
    start_list: list[str]
    restart_list: list[str]


def apply_config(
    cfg: str,
    verify: typing.Callable[[ApplyConfigContext, VerifyPlan], VerifyPlan] | None = None,
    ioc: str | None = None,
) -> None:
    """
    Starts, restarts, and kills IOCs to match the saved configuration.

    If a verify function is provided, it will be called first to let the
    user confirm that they want to take all of these actions, or if they
    only would like to take a subset of them.

    Raises on failure.

    Note:
    - This relies on the status directory being populated
      correctly, which is handled by start_proc.
    - This may implicitly modify/clean up the status directory via
      calling read_status_dir

    Parameters
    ----------
    cfg : str
        The name of the hutch, or a full filepath to the config file.
    verify : callable, optional
        An optionally provided function that is expected to take an
        ApplyConfigContext and a VerifyPlan and return a VerifyPlan.
        You can create a new VerifyPlan or mutate the provided object.
    ioc : str, optional
        The name of a single IOC to apply to, if provided.
        If not provided, we'll apply the entire configuration.
    """
    config = read_config(cfg)

    if ioc is None:
        # All IOCs that should be on
        desired_iocs = config.procs
    elif ioc in config.procs:
        # One IOC that should be on
        desired_iocs = {config.procs[ioc].name: config.procs[ioc]}
    else:
        # No IOCs to turn on
        desired_iocs = {}

    status_files = read_status_dir(cfg)

    running: dict[str, IOCStatusFile] = {}
    shutdown: dict[str, IOCStatusFile] = {}
    not_running: dict[str, IOCStatusFile] = {}
    all_status: dict[str, IOCStatusFile] = {}
    for ioc_status in status_files:
        if ioc is None or ioc == ioc_status.name:
            result = check_status(ioc_status.host, ioc_status.port, ioc_status.name)
            if result.status == ProcServStatus.RUNNING:
                running[ioc_status.name] = ioc_status
            elif result.status == ProcServStatus.SHUTDOWN:
                # We either want to kill or restart these always
                # Depending on config context
                shutdown[ioc_status.name] = ioc_status
            else:
                not_running[ioc_status.name] = ioc_status
            all_status[ioc_status.name] = ioc_status

    wanted: dict[str, IOCProc] = {}
    not_wanted: dict[str, IOCProc] = {}
    for ioc_name, ioc_proc in desired_iocs.items():
        # Can ignore HIOCs (e.g. non-linux stuff)
        # because we can't start or stop them anyway
        if ioc_proc.hard:
            continue
        if ioc_proc.disable:
            not_wanted[ioc_name] = ioc_proc
        else:
            wanted[ioc_name] = ioc_proc

    # Camera recorders always seem to be in the wrong directory, so cheat!
    for iocproc in config.procs.values():
        if iocproc.path == env_paths.CAMRECORD_ROOT:
            try:
                running[iocproc.name].name = env_paths.CAMRECORD_ROOT
            except KeyError:
                pass

    #
    # We need to make three lists: kill, restart, and start.
    #

    # Kill anyone who we don't want, or is running on the wrong host or port
    kill_list = [
        ioc_name
        for ioc_name, running_status in chain(running.items(), shutdown.items())
        if ioc_name not in wanted
        or running_status.host != desired_iocs[ioc_name].host
        or running_status.port != desired_iocs[ioc_name].port
    ]

    # Start anyone who wasn't running, or was running on the wrong host or port
    start_list = [
        ioc_name
        for ioc_name, wanted_proc in wanted.items()
        if ioc_name not in chain(running, shutdown)
        or wanted_proc.host != all_status[ioc_name].host
        or wanted_proc.port != all_status[ioc_name].port
    ]

    # Anyone running the wrong version, on the right host and port needs a restart.
    # IOCs in shutdown state also need a restart if we're not killing them.
    restart_list = [
        ioc_name
        for ioc_name, wanted_proc in wanted.items()
        if (
            ioc_name in running
            and wanted_proc.host == running[ioc_name].host
            and wanted_proc.port == running[ioc_name].port
            and wanted_proc.path != running[ioc_name].path
        )
        or (ioc_name in shutdown and ioc_name not in kill_list)
    ]

    if verify is not None:
        verify_result = verify(
            ApplyConfigContext(
                status_files=deepcopy(running),
                proc_config=deepcopy(desired_iocs),
            ),
            VerifyPlan(
                kill_list=kill_list,
                start_list=start_list,
                restart_list=restart_list,
            ),
        )
        kill_list = verify_result.kill_list
        start_list = verify_result.start_list
        restart_list = verify_result.restart_list

    errors = []

    for ioc_name in kill_list:
        try:
            kill_proc(all_status[ioc_name].host, int(all_status[ioc_name].port))
        except Exception as exc:
            errors.append(exc)
        try:
            # This is dead, so get rid of the status file!
            # TODO this fails if cfg given as full path, needs fix
            os.remove(all_status[ioc_name].get_file_location(hutch=cfg))
        except Exception as exc:
            errors.append(exc)

    for ioc_name in start_list:
        try:
            start_proc(cfg, desired_iocs[ioc_name])
        except Exception as exc:
            errors.append(exc)

    for ioc_name in restart_list:
        try:
            restart_proc(all_status[ioc_name].host, int(all_status[ioc_name].port))
        except Exception as exc:
            errors.append(exc)

    if errors:
        raise errors[0]
    elif len(errors) > 1:
        raise ExceptionGroup(f"{len(errors)} errors in apply_config", errors)
