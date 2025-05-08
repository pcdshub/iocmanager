"""
The utils module contains deprecated functions scheduled for removal and replacement.
"""

from __future__ import annotations

import fcntl
import os
import re

from . import env_paths

# Constants
COMMITHOST = "psbuild-rhel7"


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
