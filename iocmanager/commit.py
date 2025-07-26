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

from .config import read_config
from .env_paths import env_paths

COMMIT_SCRIPT = str(Path(__file__).parent / "commit.sh")


def commit_config(
    hutch: str,
    comment: str,
    show_output: bool = True,
    ssh_verbose: int = 0,
    script: str = "",
) -> subprocess.CompletedProcess:
    """
    Open a connection to COMMITHOST and commit the iocmanager.cfg file.

    Runs locally if COMMITHOST is localhost.

    May raise if e.g. there is an auth or connection error.
    Requires the user to be able to ssh without further user input,
    such as by using kerberos or ssh keys.

    Parameters
    ----------
    hutch : str
        The name of the hutch to commit, such as xpp or tmo
    comment : str
        The commit message
    show_output : bool
        If True, show the command output in terminal. Otherwise, hide it.
    ssh_verbose: int
        The number of -v args to pass to ssh for more verbose output.
    script: str
        If provided, an alternate script to use. Useful for testing.

    Returns
    -------
    result : CompletedProcess
        The result of the git operation as returned by subprocess.run.
    """
    commit_host = get_commithost(hutch=hutch)
    config_file = env_paths.CONFIG_FILE % hutch
    commit_script = script or COMMIT_SCRIPT

    if commit_host in ("localhost", gethostname()):
        cmd = [commit_script, config_file, comment]
    else:
        cmd = ["ssh"]
        if ssh_verbose:
            cmd.append("-" + "v" * ssh_verbose)
        cmd.extend(
            [
                "-o",
                "BatchMode=yes",
                commit_host,
                f"{commit_script} {config_file} '{comment}'",
            ]
        )
    if show_output:
        output_opt = None
    else:
        output_opt = subprocess.DEVNULL
    if show_output:
        print("Running ", " ".join(cmd))
    return subprocess.run(
        cmd,
        universal_newlines=True,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=output_opt,
        stderr=output_opt,
    )


def check_commit_possible(hutch: str) -> bool:
    """
    Returns True if an ssh to the commithost is possible, False otherwise.

    This can be called before we prompt a user to make a commit to save
    them the trouble of figuring out their commit message.

    It can also help us disambiguate issues relating to commiting: is the
    ssh failing, or is the commit itself failing?
    """
    try:
        # : is a built-in command that does nothing with exit status 0
        commit_config(hutch=hutch, comment="", show_output=False, script=":")
    except Exception:
        return False
    return True


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
