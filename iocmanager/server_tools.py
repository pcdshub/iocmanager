"""
The server_tools module defines functions for working with servers.

IOCs run on servers, so getting information about servers on the
network or e.g. rebooting the whole server can useful.
"""

import copy
import os
import subprocess

from .env_paths import env_paths


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


def reboot_server(host: str) -> bool:
    """Reboot a server, returning True if successful."""
    return os.system(f"{env_paths.PSIPMI} %s power cycle" % host) == 0
