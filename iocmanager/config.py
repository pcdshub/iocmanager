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
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from tempfile import NamedTemporaryFile

from . import env_paths
from .epics_paths import get_parent

logger = logging.getLogger(__name__)

DEFAULT_COMMITHOST = "psbuild-rhel7"


class ConfigStat(IntEnum):
    NORMAL = 0
    ADDED = 1
    DELETED = 2


@dataclass(eq=True)
class IOCProc:
    name: str
    port: int
    host: str
    path: str
    alias: str = ""
    status: ConfigStat = ConfigStat.NORMAL
    disable: bool = False
    cmd: str = ""
    history: list[str] = None
    parent: str = ""
    hard: bool = False

    def __post_init__(self):
        if self.name == self.host:
            self.hard = True
        else:
            try:
                self.parent = get_parent(self.path, self.name)
            except Exception:
                ...
        if self.history is None:
            self.history = []


@dataclass(eq=True)
class Config:
    path: str
    commithost: str = DEFAULT_COMMITHOST
    allow_console: bool = True
    hosts: list[str] = None
    procs: list[IOCProc] = None
    mtime: float = 0.0

    def __post_init__(self):
        if self.hosts is None:
            self.hosts = []
        if self.procs is None:
            self.procs = []


config_cache: dict[str, Config] = {}


def read_config(cfgname: str) -> Config:
    """
    Read the configuration file for a given hutch.

    Skips the reading and returns a cached config if the file
    has not been modified since the last call to readConfig.

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
    procs = []
    for procmgr_cfg in cfg_env["procmgr_config"]:
        procmgr_cfg: dict
        procs.append(
            IOCProc(
                name=procmgr_cfg["id"],
                port=procmgr_cfg["port"],
                host=procmgr_cfg["host"],
                path=procmgr_cfg["dir"],
                alias=procmgr_cfg.get("alias", ""),
                status=ConfigStat.NORMAL,
                disable=procmgr_cfg.get("disable", False),
                hard=procmgr_cfg.get("hard", False),
                cmd=procmgr_cfg.get("cmd", ""),
                history=procmgr_cfg.get("history", []),
            )
        )
    config = Config(
        path=cfgfn,
        commithost=cfg_env.get("COMMITHOST", DEFAULT_COMMITHOST),
        allow_console=cfg_env.get("allow_console", True),
        hosts=cfg_env["hosts"],
        procs=procs,
        mtime=mtime,
    )

    config_cache[cfgfn] = config
    return deepcopy(config)


def get_host_os(hosts_list: list[str]) -> dict[str, str]:
    """
    Returns the OS of each host.

    Results are available in the global hosttype variable.
    This is used to display which OS each host is running.

    Parameters
    ----------
    hosts_list: list[str]
        The hosts to check.

    Returns
    -------
    hosttype : dict[str, str]
        Dictionary from hostname to OS.
    """
    hosttype = {}
    for fn in hosts_list:
        try:
            with open("%s/%s" % (env_paths.HOST_DIR, fn)) as fd:
                hosttype[fn] = fd.readlines()[0].strip()
        except Exception:
            ...
    return hosttype


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

    for ioc in sorted(config.procs, key=lambda x: x.name):
        if ioc.status == ConfigStat.DELETED:
            continue
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
        for ioc in config.procs:
            for k in list(kw.items()):
                if getattr(ioc, k[0]) != k[1]:
                    break
            else:
                configs.append([cfg, ioc])
                pass
    return configs


def getHutchList() -> list[str]:
    """Return the list of all supported hutches."""
    try:
        config_paths = Path(env_paths.CONFIG_DIR).glob("*/iocmanager.cfg")
        return [pth.parent.name for pth in config_paths]
    except Exception:
        return []


def validateConfig(iocproc: list[IOCProc]) -> bool:
    """
    Returns True if the list of IOC configurations looks valid.

    Currently, just checks if there is a duplicate host/port combination.
    """
    for idx in range(len(iocproc)):
        host1 = iocproc[idx].host
        port1 = iocproc[idx].port
        for jdx in range(idx + 1, len(iocproc)):
            host2 = iocproc[jdx].host
            port2 = iocproc[jdx].port
            if host1 == host2 and port1 == port2:
                return False
    #
    # Anything else we want to check here?!?
    #
    return True


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
                _lazy_delete_file((env_paths.STATUS_DIR % cfg) + "/" + info[key]["rid"])
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
