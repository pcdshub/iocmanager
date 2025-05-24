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

import subprocess
from pathlib import Path
from socket import gethostname

from . import env_paths
from .config import read_config

COMMIT_SCRIPT = str(Path(__file__).parent / "commit.sh")


def commit_config(hutch: str, comment: str) -> subprocess.CompletedProcess:
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
    result : CompletedProcess
        The result of the git operation as returned by subprocess.run.
    """
    commit_host = get_commithost()
    config_file = env_paths.CONFIG_FILE % hutch

    if commit_host in ("localhost", gethostname()):
        cmd = [COMMIT_SCRIPT, config_file, comment]
    else:
        cmd = ["ssh", commit_host, f"{COMMIT_SCRIPT} {config_file} '{comment}'"]
    return subprocess.run(cmd, universal_newlines=True, check=True)


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
    config = read_config(hutch)
    return config.commithost
