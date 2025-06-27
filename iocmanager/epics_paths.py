"""
The epics_paths module defines helper functions for paths in the EPICS filetree.

This is everything under EPICS_SITE_TOP.
"""

import glob
import os
import re

from .env_paths import env_paths

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
    try:
        get_stcmd(directory=directory, ioc_name=ioc_name)
    except RuntimeError:
        return False
    return True


def get_stcmd(directory: str, ioc_name: str) -> str:
    """
    Find a return the path to an IOC's st.cmd file.

    Raises if one could not be found.

    Parameters
    ----------
    directory : str
        Path to the IOC release, either an absolute path or a path relative
        to EPICS_SITE_TOP. An IOC release may contain multiple IOCs.
    ioc_name : str
        The name of the IOC to find within the IOC release directory.

    Returns
    -------
    stcmd : str
        The st.cmd file.
    """
    if not os.path.isabs(directory):
        directory = os.path.join(env_paths.EPICS_SITE_TOP, directory)
    for pth in stpaths:
        candidate = pth % (directory, ioc_name)
        if os.path.exists(candidate):
            return candidate
    candidate = os.path.join(directory, "st.cmd")
    if os.path.exists(candidate):
        return candidate
    raise RuntimeError(f"{ioc_name} in {directory} does not have a st.cmd file.")


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

# Match shebang e.g. #!/some/path/to/ioc/bin/arch/exe
shbg = re.compile(r"^#!(.*)/bin/[A-Za-z0-9_]*-x86.*/.*$")


def get_parent(directory: str, ioc_name: str) -> str:
    """
    Return the parent (common) ioc path for a child ioc.

    There are two possible sources.

    For templated IOCs, we find and read the .cfg file,
    looking for the RELEASE variable.

    Otherwise, we locate the st.cmd file and use the path
    in the shebang line to locate the parent.

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
    parent = _get_parent(directory=directory, ioc_name=ioc_name)
    if os.pathsep in parent:
        return normalize_path(directory=parent, ioc_name=ioc_name)
    return parent


def _get_parent(directory: str, ioc_name: str) -> str:
    try:
        return cfg_parent(directory=directory, ioc_name=ioc_name)
    except Exception:
        ...
    try:
        return stcmd_parent(directory=directory, ioc_name=ioc_name)
    except Exception:
        ...
    try:
        return pyioc_parent(directory=directory, ioc_name=ioc_name)
    except Exception:
        ...
    try:
        return self_parent(directory=directory)
    except Exception:
        ...
    return ""


def cfg_parent(directory: str, ioc_name: str) -> str:
    """
    Get the parent assuming this is a templated IOC directory with .cfg files.
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
                return val
    raise RuntimeError(f"Can not find cfg parent for {ioc_name} in {directory}")


def stcmd_parent(directory: str, ioc_name: str) -> str:
    """
    Get the parent assuming we have a st.cmd with a shebang that includes the parent.
    """
    stcmd = get_stcmd(directory=directory, ioc_name=ioc_name)
    with open(stcmd, "r") as fd:
        line = fd.readline()
    # Try to find a shebang like #!/some/path/bin/rhel7-x86_64/exe
    match = shbg.match(line)
    if match:
        path = match.group(1)
        if path.startswith(os.sep):
            # Absolute path
            return path
        # Relative path: relative to this file location?
        return os.path.abspath(os.path.join(os.path.dirname(stcmd), path))
    # Try to identify python iocs
    raise RuntimeError(f"Invalid shebang {line}")


def pyioc_parent(directory: str, ioc_name: str) -> str:
    """
    Get the parent assuming this is a python IOC.

    Unlike the other parent getters, this returns the library and python environment
    used to run the IOC, e.g.:
    caproto conda pcds-5.8.1
    pyioc pspkg xpp-1.2.0
    """
    stcmd = get_stcmd(directory=directory, ioc_name=ioc_name)
    with open(stcmd, "r") as fd:
        lines = fd.readlines()
    # We want to figure out if we're using PSPKG or pcds_conda and at which version?
    env_kind = "python"
    env_version = ""
    for line in lines:
        text = line.strip()
        if text.startswith("#"):
            continue
        if "PSPKG_RELEASE" in text:
            env_kind = "pspkg"
            env_version = text.split("=")[-1].strip("'\"")
        elif "PSPKG_ROOT" in text:
            env_kind = "pspkg"
        elif "PCDS_CONDA_VER" in text:
            env_kind = "conda"
            env_version = text.split("=")[-1].strip("'\"")
        elif "pcds_conda" in text:
            env_kind = "conda"
            if not env_version:
                env_version = "latest"
    if not env_version:
        env_version = "unknown"
    # Check the python files in the same repo for some keywords
    python_ioc_frameworks = ("caproto", "pyioc", "pcaspy")
    for filepath in glob.glob(os.path.join(os.path.dirname(stcmd), "*.py")):
        with open(filepath, "r") as fd:
            lines = fd.readlines()
        for package in python_ioc_frameworks:
            for line in lines:
                if package in line:
                    return f"{package} {env_kind} {env_version}"
    return f"unknown {env_kind} {env_version}"


def self_parent(directory: str) -> str:
    """
    Check if directory is already a parent-like IOC
    """
    if os.path.exists(os.path.join(directory, "bin")):
        return directory
    raise RuntimeError(f"{directory} definitely not self parented")


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


def standard_ioc_paths(hutch: str) -> list[str]:
    """
    Return the standard paths to check when looking for IOCs.
    """
    result = []
    home_dir = os.getenv("HOME")
    if home_dir is not None:
        result.append(home_dir)
    result.append(os.path.join(env_paths.EPICS_SITE_TOP, "ioc", hutch))
    result.append(os.path.join(env_paths.EPICS_SITE_TOP, "ioc", "common"))
    result.append(env_paths.EPICS_DEV_TOP)
    return result
