"""
The epics_paths module defines helper functions for paths in the EPICS filetree.

This is everything under EPICS_SITE_TOP.
"""

from __future__ import annotations

import os
import re

from . import env_paths

# Search paths for st.cmd files
stpaths = [
    "%s/children/build/iocBoot/%s/st.cmd",
    "%s/build/iocBoot/%s/st.cmd",
    "%s/iocBoot/%s/st.cmd",
]


def normalize_path(directory: str, ioc_name: str) -> str:
    """
    Return a truncated path to a IOC directory.

    - Makes the path relative to EPICS_SITE_TOP, if possible
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
    directory : str
        Path to the IOC release, either an absolute path or a path relative
        to EPICS_SITE_TOP. An IOC release may contain multiple IOCs.
    ioc_name : str
        The name of the IOC to find within the IOC release directory.

    Returns
    -------
    path : str
        The truncated path.
    """
    part = [pth for pth in directory.split(os.sep) if pth != ".."]
    directory = os.sep.join(part)
    if directory.startswith(env_paths.EPICS_SITE_TOP):
        directory = os.path.relpath(directory, env_paths.EPICS_SITE_TOP)
    for pth in stpaths:
        ext = pth % ("", ioc_name)
        ext = ext.removesuffix("/st.cmd")
        directory = directory.removesuffix(ext)
    return directory


def has_stcmd(directory: str, ioc_name: str) -> bool:
    """
    Returns True if we can find an IOC's st.cmd file in the filetree.

    Parameters
    ----------
    directory : str
        Path to the IOC release, either an absolute path or a path relative
        to EPICS_SITE_TOP. An IOC release may contain multiple IOCs.
    ioc_name : str
        The name of the IOC to find within the IOC release directory.

    Returns
    -------
    has_stcmd : bool
        True if we found the st.cmd file at one of the standard locations.
    """
    if not os.path.isabs(directory):
        directory = os.path.join(env_paths.EPICS_SITE_TOP, directory)
    for pth in stpaths:
        if os.path.exists(pth % (directory, ioc_name)):
            return True
    if os.path.exists(os.path.join(directory, "st.cmd")):
        return True
    return False


# Used in get_parent to match "RELEASE = /some/filepath" lines
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


def get_parent(directory: str, ioc_name: str) -> str:
    """
    Return the parent (common) ioc path for a templated ioc.

    To do this, we find and read the .cfg file, looking for the
    RELEASE variable.

    If the IOC has no parent, returns an empty string.
    The file could not be read, raises an appropriate OSError.

    Parameters
    ----------
    directory : str
        Path to the IOC release, either an absolute path or a path relative
        to EPICS_SITE_TOP. An IOC release may contain multiple IOCs.
    ioc_name : str
        The name of the IOC to find within the IOC release directory.

    Returns
    -------
    parent : str
        The possibly truncated path to the parent IOC release,
        or an empty string if one could not be determined.
    """
    filename = os.path.join(directory, ioc_name + ".cfg")
    try:
        lines = epics_readlines(filename)
    except Exception:
        filename = os.path.join(directory, "children", ioc_name + ".cfg")
        lines = epics_readlines(filename)

    # Only the last RELEASE variable counts
    for ln in reversed(lines):
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
                val = val.replace(
                    "$$PATH/", directory + "/" + ioc_name + ".cfg"
                ).replace("$$UP(PATH)", directory)
                return normalize_path(val, ioc_name)
    return ""


def epics_readlines(filename: str) -> list[str]:
    """
    Thin wrapper around readlines.

    Opens a file and returns a list of the lines.

    The filename can either be an absolute path or it can be relative to
    EPICS_SITE_TOP.

    Raises an appropriate exception if something goes wrong.

    Parameters
    ----------
    filename : str
        Filename

    Returns
    -------
    lines : list[str]
        The contents of the file
    """
    if not os.path.isabs(filename):
        filename = os.path.join(env_paths.EPICS_SITE_TOP, filename)
    with open(filename, "r") as fd:
        return fd.readlines()
