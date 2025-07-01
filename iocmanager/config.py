"""
The config module defines functions for reading and writing config files.

iocmanager has several config files,
all located at $PYPS_ROOT/config/$hutch/

The files handled here and their main functions are:
- iocmanager.auth (r): defines which users are authorized to make changes
- iocmanager.cfg (rw): defines which IOCs will be run
- iocmanager.nossh (r): defines which special (opr) users cannot ssh, so we won't try
- iocmanager.special (r): defines which IOCs can be enabled/disabled
      or have their variants changed and applied by non-authenticated users.

This module also helps manage the files at
$PYPS_ROOT/config/.status/$hutch

Which are created by the startProc script.
"""

import glob
import logging
import os
import stat
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile

from .env_paths import env_paths
from .epics_paths import get_parent

logger = logging.getLogger(__name__)

DEFAULT_COMMITHOST = "psbuild-rhel7"


@dataclass(eq=True)
class IOCProc:
    """
    Information about a single IOC process in the config file.

    Attributes
    ----------
    name : str
        The name of the ioc. This is used in many, many places
        such as filepaths, process names, and more.
        Note that this may be distinct from the name of the
        github repository that contains the IOC, which could
        contain multiple IOCs. Since it is used in these contexts,
        it should generally be all lowercase and with underscores
        instead of spaces.
    port : int
        The procServ port to use for running this IOC.
        Each IOC on the same host needs a unique procServ port.
        This port will be used to debug and manage the IOC later.
    host : str
        The hostname of the server to run the IOC on.
    path : str
        A path to the IOC's repository or startup file location.
        If using standard directory structures from the standard template,
        the root directory of the tagged IOC is enough to find
        the startup files.
    alias : str, optional
        Another name to use to refer to the IOC, perhaps a user-formatted
        and human-readable variant. If provided this will be displayed in
        the GUI and CLI (sometimes along with the original name too).
    disable : bool, optional
        If True, this IOC should be turned off!
    cmd : str, optional
        If provided, an alternate command to run to start the IOC process.
        This is normally just ./st.cmd.
    history : list[str], optional
        Past known good versions of the IOC. This can be used to allow
        a system owner to quickly revert the IOC to a known, working version.
    delay : int, optional
        Time to sleep in seconds after starting this IOC before starting the
        next IOC during start_all (at server boot).
    parent : str, automatic
        The IOC that supplies the executable for this one, if this IOC
        is a templated IOC.
        This will be automatically determined at object creation and
        does not need to be manually included.
    hard : bool, automatic
        True if this is a hard ioc on some embedded system.
        False if this is a soft ioc running on standard linux.
        This must be manually included.
    """

    name: str
    port: int
    host: str
    path: str
    alias: str = ""
    disable: bool = False
    cmd: str = ""
    history: list[str] = field(default_factory=list)
    delay: int = 0
    parent: str = ""
    hard: bool = False

    def __post_init__(self):
        try:
            self.parent = get_parent(self.path, self.name)
        except Exception:
            ...


@dataclass(eq=True)
class Config:
    """
    The entire contents of the config file.

    Attributes
    ----------
    path : str
        The full filepath of the iocmanager.cfg config file,
        including the filename.
    commithost : str
        The host that commits are to be made on.
        Always doing this on the same host avoids
        NFS synchronization issues.
    allow_console : bool
        If True (the default), all users will be able to open telnet sessions
        to the IOCs through the GUI.
        If False, only authenticated users will be able to do this.
    hosts : list[str]
        All of the hosts that have previously been included in the config.
        This is added to automatically during self.add_proc and is used by
        various utilities internally as a convenience tool, e.g. for a user
        drop-down of host options in the GUI.
    procs : dict[str, IOCProc]
        A mapping of IOC name to the IOCProc instance associated with that IOC.
        Internally, this dictionary should be added to using the add_proc
        method.
    mtime : float
        The last modification time of the config file at the time of reading
        as a unix timestamp.
    """

    path: str
    commithost: str = DEFAULT_COMMITHOST
    allow_console: bool = True
    hosts: list[str] = field(default_factory=list)
    procs: dict[str, IOCProc] = field(default_factory=dict)
    mtime: float = 0.0

    def add_proc(self, proc: IOCProc) -> None:
        """Include a new IOC process in the config."""
        if proc.name in self.procs:
            raise ValueError(f"IOC named {proc.name} already exists!")
        self.update_proc(proc)

    def update_proc(self, proc: IOCProc) -> None:
        """Update an existing IOC process in the config."""
        self.procs[proc.name] = proc
        if proc.host not in self.hosts:
            self.hosts.append(proc.host)
            self.hosts.sort()

    def delete_proc(self, ioc_name: str) -> None:
        """Remove an IOC from the config."""
        del self.procs[ioc_name]

    def validate(self) -> bool:
        """
        Returns True if the configuration looks valid.

        Currently, just checks if there is a duplicate host/port combination.
        """
        host_ports = set()
        for proc in self.procs.values():
            host_ports.add((proc.host, proc.port))
        return len(host_ports) == len(self.procs)

    def get_unused_port(self, host: str, closed: bool):
        """
        Return the smallest valid unused port for the host.

        Parameters
        ----------
        host : str
            The name of the host
        closed : bool
            True to use the closed range (30001-38999),
            False to use the open range (39100-39199).
        """
        used_ports = set()
        for proc in self.procs.values():
            if proc.host == host:
                used_ports.add(proc.port)
        if closed:
            new_port_options = range(30001, 39000)
        else:
            new_port_options = range(39100, 39200)
        for new_port in new_port_options:
            if new_port not in used_ports:
                return new_port
        raise RuntimeError("No unused ports found in range!")


config_cache: dict[str, Config] = {}


# TODO bring back hard ioc configuration somehow (through whole app)
# TODO No IOCs in live config have the "hard" tag
def read_config(cfgname: str) -> Config:
    """
    Read the configuration file for a given hutch.

    Skips the reading and returns a cached config if the file
    has not been modified since the last call to readConfig.

    In all cases, the config we receive is a deepcopy and
    modifying it will not affect the cache.

    May raise in case of failure.

    Parameters
    ----------
    cfgname : str
        A path to a config file or the name of a hutch.

    Returns
    -------
    config: Config
        The configuration data.
    """
    # Check if we have a file or a hutch name
    cfgfn = env_paths.CONFIG_FILE % cfgname
    if not os.path.exists(cfgfn):
        cfgfn = cfgname

    mtime = os.stat(cfgfn).st_mtime
    try:
        cached = config_cache[cfgfn]
    except KeyError:
        ...
    else:
        # Skip if no modifications
        if cached.mtime == mtime:
            return deepcopy(config_cache[cfgfn])

    with open(cfgfn, "rb") as fd:
        cfgbytes = fd.read()

    # This dict gets filled by exec based on the cfg file contents
    # It also contains some strings, apparently so that these
    # variables can be included without putting quotes around them
    # in the config file
    cfg_env = {
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
    exec(compile(cfgbytes, cfgfn, "exec"), {}, cfg_env)
    config = Config(
        path=cfgfn,
        commithost=cfg_env.get("COMMITHOST", DEFAULT_COMMITHOST),
        allow_console=cfg_env.get("allow_console", True),
        hosts=cfg_env["hosts"],
        mtime=mtime,
    )
    for procmgr_cfg in cfg_env["procmgr_config"]:
        procmgr_cfg: dict
        config.add_proc(
            IOCProc(
                name=procmgr_cfg["id"],
                port=procmgr_cfg["port"],
                host=procmgr_cfg["host"],
                path=procmgr_cfg["dir"],
                alias=procmgr_cfg.get("alias", ""),
                disable=procmgr_cfg.get("disable", False),
                cmd=procmgr_cfg.get("cmd", ""),
                delay=procmgr_cfg.get("delay", 0),
                history=procmgr_cfg.get("history", []),
            )
        )

    config_cache[cfgfn] = config
    return deepcopy(config)


def get_host_os(hosts_list: list[str]) -> dict[str, str]:
    """
    Returns the OS of each host.

    This is used to display which OS each host is running
    in the GUI.

    Parameters
    ----------
    hosts_list: list[str]
        The hosts to check.

    Returns
    -------
    host_os : dict[str, str]
        Dictionary from hostname to OS.
    """
    host_os = {}
    for fn in hosts_list:
        try:
            with open("%s/%s" % (env_paths.HOST_DIR, fn)) as fd:
                host_os[fn] = fd.readlines()[0].strip()
        except Exception:
            ...
    return host_os


def _cfg_file_lines(config: Config) -> list[str]:
    """
    Given some config data, return the lines of the file to write.

    Parameters
    ----------
    config : Config
        The configuration data to write.

    Returns
    -------
    lines : list[str]
        The "serialization" of the config file, without newlines.
        This is written to disk in write_config.
    """
    lines = []

    lines.append(f'COMMITHOST = "{config.commithost}"')
    lines.append(f"allow_console = {config.allow_console}")
    lines.append("")

    lines.append("hosts = [")
    for host in config.hosts:
        lines.append(f"   '{host}',")
    lines.append("]")
    lines.append("")

    lines.append("procmgr_config = [")

    for ioc in sorted(config.procs.values(), key=lambda x: x.name):
        extra = ""
        if ioc.disable:
            extra += ", disable: True"
        if ioc.alias:
            extra += f", alias: '{ioc.alias}'"
        if ioc.history:
            extra += (
                ",\n  history: ["
                + ", ".join(["'" + path + "'" for path in ioc.history])
                + "]"
            )
        if ioc.delay:
            extra += f", delay: {ioc.delay}"
        if ioc.cmd:
            extra += f", cmd: '{ioc.cmd}'"
        lines.append(
            " {"
            f"id:'{ioc.name}', "
            f"host: '{ioc.host}', "
            f"port: {ioc.port}, "
            f"dir: '{ioc.path}'"
            f"{extra}"
            "},"
        )
    lines.append("]")

    return lines


def write_config(cfgname: str, config: Config) -> None:
    """
    Write the configuration file for a given hutch.

    Writes to a temp file first, then copies over to the prod location
    to give us an atomic write.

    Parameters
    ----------
    cfgname : str
        A path to a config file or the name of a hutch.
    config : Config
        The configuration data to write.
    """
    # Check if we have a file or a hutch name
    cfgfn = env_paths.CONFIG_FILE % cfgname
    if not os.path.exists(os.path.dirname(cfgfn)):
        cfgfn = cfgname
    lines = _cfg_file_lines(config=config)
    with NamedTemporaryFile("w", dir=env_paths.TMP_DIR, delete_on_close=False) as fd:
        fd.writelines(ln + "\n" for ln in lines)
        fd.close()
        os.chmod(
            fd.name,
            stat.S_IRUSR | stat.S_IRGRP | stat.S_IWUSR | stat.S_IWGRP | stat.S_IROTH,
        )
        os.rename(fd.name, cfgfn)


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
    with open(env_paths.AUTH_FILE % hutch) as fd:
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
    with open(env_paths.SPECIAL_FILE % req_hutch) as fp:
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
        lines = open(env_paths.NOSSH_FILE % hutch).readlines()
    except Exception:
        return True
    lines = [ln.strip() for ln in lines]
    for ln in lines:
        if ln == user:
            return False
    return True


old_keymap = {
    "id": "name",
    "dir": "path",
}


def find_iocs(**kwargs) -> list[tuple[str, IOCProc]]:
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
    # Translate from old format
    kw = kwargs.copy()
    for old, new in old_keymap.items():
        try:
            kw[new] = kw.pop(old)
        except KeyError:
            ...

    cfgs = glob.glob(env_paths.CONFIG_FILE % "*")
    configs = []
    for cfg in cfgs:
        config = read_config(cfg)
        for ioc in config.procs.values():
            for k in list(kw.items()):
                if getattr(ioc, k[0]) != k[1]:
                    break
            else:
                configs.append([cfg, ioc])
                pass
    return configs


def get_hutch_list() -> list[str]:
    """Return the list of all supported hutches."""
    try:
        config_paths = Path(env_paths.CONFIG_DIR).glob("*/iocmanager.cfg")
        return [pth.parent.name for pth in config_paths]
    except Exception:
        return []


@dataclass(eq=True)
class IOCStatusFile:
    """
    Information about the IOC based on the IOC status file.

    Attributes
    ----------
    name : str
        The name of the IOC. This is pulled from the filename
        of the status file.
    port : int
        The procServ port this IOC was using when the process started.
    host : str
        The host this IOC was running on when the process started.
    path : str
        The path to this IOC's repo directory or executable file
        that is was using when the process started.
    pid : int
        The process id of the process as running on the server.
    mtime : str
        The last modification time of the ioc status file at time of reading.
    """

    name: str
    port: int
    host: str
    path: str
    pid: int
    mtime: float = 0.0

    def get_file_location(self, hutch: str) -> str:
        """
        Return the filepath to where this status file came from.

        Parameters
        ----------
        hutch : str
            The hutch that owns this IOC.
        """
        return env_paths.STATUS_DIR % hutch + "/" + self.name


# Used in read_status_dir to uniquely identify a host, port combination
unique_id = tuple[str, str]


def read_status_dir(cfg: str) -> list[IOCStatusFile]:
    """
    Update a status directory for a hutch and return its information.

    This can remove outdated info in the status directory, but it
    will not add new information. The new information is provided
    by start_proc.

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
    status : list of IOCStatus
        A list of structured data containing all information about each
        IOC from the status dir.
    """
    # Each host, port combination should be used exactly once
    # When the keys collide, we know that one of the files is out of date
    info: dict[unique_id, IOCStatusFile] = {}

    for filename in os.listdir(env_paths.STATUS_DIR % cfg):
        full_path = (env_paths.STATUS_DIR % cfg) + "/" + filename
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
        key: unique_id = (host, port)
        if key in info:
            # Duplicate
            if info[key].mtime < mtime:
                # Duplicate, but newer, so delete other!
                logger.info(
                    "Deleting obsolete %s in favor of %s",
                    info[key].name,
                    filename,
                )
                _lazy_delete_file((env_paths.STATUS_DIR % cfg) + "/" + info[key].name)
                new_entry = True
            else:
                # Duplicate, but older, so delete this!
                logger.info(
                    "Deleting obsolete %s in favor of %s",
                    filename,
                    info[key].name,
                )
                _lazy_delete_file(full_path)
                new_entry = False
        else:
            new_entry = True

        if new_entry:
            info[key] = IOCStatusFile(
                name=filename,
                port=int(port),
                host=host,
                path=directory,
                pid=int(pid),
                mtime=mtime,
            )

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
