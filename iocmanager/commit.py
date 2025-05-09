"""
The commit module contains utilities for safe git commits.

Unlike a normal developer situation:
- Many users might commit at once
- The filesystem is distributed (NFS)

This causes some synchronization issues if different users
commit at the same time but on different hosts.

The strategy is then to always commit on the same host via ssh.

Set the COMMITHOST variable in your iocmanager.cfg file to
configure a different host from the default.

If COMMITHOST is localhost we'll commit without ssh-ing.
"""

import os
from socket import gethostname

from fabric import Connection, Result

from . import env_paths
from .config import readConfig

DEFAULT_COMMITHOST = "psbuild-rhel7"


def commit_config(hutch: str, comment: str) -> Result:
    """
    Open a connection to COMMITHOST and commit the iocmanager.cfg file.

    Runs locally if COMMITHOST is localhost.

    May raise if e.g. there is an auth or connection error.

    Parameters
    ----------
    hutch : str
        The name of the hutch to commit, such as xpp or tmo
    comment : str
        The commit message

    Returns
    -------
    result : Result
        The result of the git operation as returned by fabric.
    """
    commit_host = get_commithost()
    config_file = env_paths.CONFIG_FILE % hutch
    # Quotation marks in comment will break us
    comment = comment.replace('"', "'")

    with Connection(
        commit_host,
        connect_kwargs={"gss_auth": True, "gss_deleg_creds": True, "gss_kex": True},
    ) as conn:
        if commit_host in ("localhost", gethostname()):
            cmd = conn.local
        else:
            cmd = conn.run
        cmd(f"cat {config_file}")
        return cmd(
            f"cd {os.path.dirname(config_file)}; "
            "umask 2; "
            f'git commit -m "{comment}" {config_file}'
        )


def get_commithost(hutch: str) -> str:
    """
    For a specific hutch, get the server we're supposed to commit on.

    Parameters
    ----------
    hutch : str
        The name of the hutch

    Returns
    -------
    commithost : str
        Which host to commit on.
    """
    _, _, _, extra_settings = readConfig(hutch)
    return extra_settings.get("COMMITHOST", DEFAULT_COMMITHOST)
