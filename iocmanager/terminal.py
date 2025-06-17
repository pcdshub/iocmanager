"""
The terminal module implements functions for opening floating terminal windows.

These are useful in the GUI for e.g. helping the user telnet to a host
or tail a logfile.

Note: this file needs to be tested manually on various operating systems.
e.g.
from iocmanager.terminal import run_in_gnome_terminal
run_in_gnome_terminal("my_title", "bash")
"""

import getpass
import os
import shutil
import subprocess
import time
import uuid

from .env_paths import env_paths


def run_in_floating_terminal(title: str, cmd: str) -> None:
    """
    Helper function for running a command in a compatible floating terminal.

    Depending on the OS, different terminal emulators might be installed.
    In order of priority, we'll choose:
    - gnome-terminal if the gnome-terminal-server is available
    - xterm
    """
    if os.path.exists(env_paths.GNOME_TERMINAL_SERVER):
        run_in_gnome_terminal(title, cmd)
    elif shutil.which("xterm") is not None:
        run_in_xterm(title, cmd)
    else:
        raise RuntimeError("Did not find gnome-terminal-server or xterm!")


def run_in_gnome_terminal(title: str, cmd: str) -> None:
    """
    Subfunction of run_in_floating_terminal implemented for gnome-terminal.

    This is the original iocmanager implementation with some bugfixes.
    This is no longer the only implementation because some of our rocky9
    images do not have gnome-terminal and/or gnome-terminal-server.

    Very few machines that are missing gnome-terminal-server
    allow us to run gnome-terminal properly without it, so we'll no
    longer consider this case.
    """
    app_id = f"{getpass.getuser()}.{uuid.uuid4()}"
    subprocess.Popen(
        [env_paths.GNOME_TERMINAL_SERVER, "--app-id", app_id],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Need to wait some unknown small time for this to work
    # Try a few times
    time.sleep(0.1)
    for _ in range(5):
        proc = subprocess.Popen(
            [
                "gnome-terminal",
                "--wait",
                "--app-id",
                app_id,
                f"--title={title}",
                "--",
                cmd,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        # Note: gnome-terminal's return code is always zero...
        if proc.returncode is not None:
            # Still running
            break


def run_in_xterm(title: str, cmd: str) -> None:
    """
    Subfunction of run_in_floating_terminal implemented for xterm.

    This is much simpler than the gnome-terminal scheme but the result
    is less nice-looking.
    """
    subprocess.Popen(
        ["xterm", "-bg", "black", "-fg", "white", "--hold", "-title", title, "-c", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
