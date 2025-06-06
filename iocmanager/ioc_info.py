"""
The ioc_info module defines utilities for parsing the iocInfo directories.

These are located at $IOC_DATA/$iocname/iocInfo and contain
pv lists, ioc log files, caput logs, and more.
"""

import re

from .env_paths import env_paths


def get_base_name(ioc: str) -> str:
    """
    Returns the basename of the iocAdmin PVs for a given IOC name.

    Raises an appropriate exception if something goes wrong.

    Parameters
    ----------
    ioc : str
        The ioc name

    Returns
    -------
    pvbase : str
    """
    pv_info_path = env_paths.PVFILE % ioc

    with open(pv_info_path, "r") as fd:
        lines = fd.readlines()

    for ln in lines:
        # PVNAME, "record_type"\n
        pv = ln.split(",")[0]
        if pv.endswith(":HEARTBEAT"):
            return pv.removesuffix(":HEARTBEAT")

    raise RuntimeError(f"Did not find :HEARTBEAT PV in {pv_info_path}")


def find_pv(regexp: re.Pattern, ioc: str) -> list[str]:
    """
    Returns all PVs belonging to an IOC that match a regular expression.

    Raises an appropriate exception if something goes wrong.

    Parameters
    ----------
    regexp : Pattern
        A compiled regular expression pattern, returned by re.compile.
    ioc : str
        The name of the IOC to check. This will be used to locate an
        appropriate IOC.pvlist file.

    Returns
    -------
    pvs : list[str]
        The PVs from this IOC that match the pattern.
    """
    with open(env_paths.PVFILE % ioc, "r") as fd:
        pvlist_lines = fd.readlines()

    # PVNAME, "record_type"\n
    pv_names = [ln.split(",")[0] for ln in pvlist_lines if ln]
    return list(filter(regexp.search, pv_names))
