from __future__ import annotations

import copy
import fcntl
import logging
import os
import re
import subprocess
import telnetlib

from . import env_paths
from .log_setup import add_spam_level

logger = logging.getLogger(__name__)
add_spam_level(logger)

# Constants
COMMITHOST = "psbuild-rhel7"


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


######################################################################
#
# Miscellaneous utilities
#


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
    config = env_paths.CONFIG_FILE % hutch
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
        [env_paths.NETCONFIG, "view", host],
        env=env,
        universal_newlines=True,
    )


def rebootServer(host: str) -> bool:
    """Reboot a server, returning True if successful."""
    return os.system(f"{env_paths.PSIPMI} %s power cycle" % host) == 0


def getHardIOCDir(host: str) -> str:
    """Return the hard IOC directory for a given hard IOC host."""
    dir = "Unknown"
    try:
        lines = [ln.strip() for ln in open(env_paths.HIOC_STARTUP % host).readlines()]
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
                [env_paths.HIOC_POWER, host, "cycle"],
                env=env,
                universal_newlines=True,
            )
        )
        return True
    except Exception:
        logger.debug("Power cycle error", exc_info=True)
        print("Error while trying to power cycle HIOC %s!" % host)
        return False
