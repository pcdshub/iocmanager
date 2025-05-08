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

from __future__ import annotations

import glob
import io
import logging
import os
import stat
import typing
from pathlib import Path

from . import env_paths
from .epics_paths import get_parent
from .ioc_info import get_base_name
from .utils import getHardIOCDir

CONFIG_NORMAL = 0
CONFIG_ADDED = 1
CONFIG_DELETED = 2

logger = logging.getLogger(__name__)
hosttype = {}


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
        cfgfn = env_paths.CONFIG_FILE % cfg

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
            try:
                base = get_base_name(ioc["id"])
            except Exception:
                base = None
            ioc["base"] = base
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
            try:
                ioc["pdir"] = get_parent(ioc["dir"], ioc["id"])
            except Exception:
                ioc["pdir"] = ""

    # hosttype is used to display which OS each host is running
    if do_os:
        global hosttype
        hosttype = {}
        for fn in hosts_list:
            try:
                with open("%s/%s" % (env_paths.HOST_DIR, fn)) as fd:
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
    os.rename(file, env_paths.CONFIG_FILE % hutch)


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
    cfgs = glob.glob(env_paths.CONFIG_FILE % "*")
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


def getHutchList() -> list[str]:
    """Return the list of all supported hutches."""
    try:
        config_paths = Path(env_paths.CONFIG_DIR).glob("*/iocmanager.cfg")
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
