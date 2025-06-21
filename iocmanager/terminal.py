"""
The terminal module implements functions for opening floating terminal windows.

These are useful in the GUI for e.g. helping the user telnet to a host
or tail a logfile.

Note: this file needs to be tested manually on various operating systems.

e.g.
python -m iocmanager.tests.interactive floating_terminal command
python -m iocmanager.tests.interactive gnome_terminal command
python -m iocmanager.tests.interactive xterm_terminal command
"""

import getpass
import os
import shutil
import subprocess
import time
import uuid

from .env_paths import env_paths


def run_in_floating_terminal(
    title: str, cmd: str, out: int | None = subprocess.DEVNULL
) -> subprocess.Popen:
    """
    Helper function for running a command in a compatible floating terminal.

    Depending on the OS, different terminal emulators might be installed.
    In order of priority, we'll choose:
    - xterm if it is available
    - gnome-terminal if the gnome-terminal-server is available

    In older versions of iocmanager, we used gnome-terminal for everything.
    Unfortunately, this is a poorly-behaving app:
    - On some servers it isn't installed
    - On some it is installed, but gnome-terminal-server must be run first
    - On others there is no such requirement
    - gnome-terminal-server takes something like 0.1-0.5 seconds to get ready
      and there's no way to know when it is except just trying
    - gnome-terminal-server closes itself if you don't create your gnome-terminal
      fast enough (5 secs?)
    - Sometimes, gnome-terminal-server crashes with a variety of error messages
    - gnome-terminal-server's process doesn't exit promptly after dying (3 secs?)
    - gnome-terminal's return code is ALWAYS 0 if it fails to open at all

    I gave it a good try. The code for this is still here.
    I want these windows to open promptly and reliably so we'll
    default to xterm.
    """
    args = cmd.split(" ")
    if shutil.which("xterm") is not None:
        return run_in_xterm(title, args, out)
    elif os.path.exists(env_paths.GNOME_TERMINAL_SERVER):
        return run_in_gnome_terminal(title, args, out)
    else:
        raise RuntimeError("Did not find gnome-terminal-server or xterm!")


def run_in_gnome_terminal(
    title: str, args: list[str], out: int | None = subprocess.DEVNULL
) -> subprocess.Popen:
    """
    Subfunction of run_in_floating_terminal implemented for gnome-terminal.

    This is the original iocmanager implementation with some bugfixes.
    This is no longer the only implementation because some of our rocky9
    images do not have gnome-terminal and/or gnome-terminal-server.

    Very few machines that are missing gnome-terminal-server
    allow us to run gnome-terminal properly without it, so we'll no
    longer consider this case.
    """
    # a: after ., must not start with a digit. Pick "a".
    app_id = f"{getpass.getuser()}.a{uuid.uuid4()}"
    popen = subprocess.Popen(
        [env_paths.GNOME_TERMINAL_SERVER, "--app-id", app_id],
        stdout=out,
        stderr=out,
    )
    # Need to wait some unknown small time for this to work
    # I tried dozens of ways to do this more robustly, it can't be done
    time.sleep(0.3)
    subp_args = ["gnome-terminal", "--wait"]
    if popen.returncode is None:
        # Still running, use the app id
        subp_args += ["--app-id", app_id]
    # If it didn't run, assume we're set up to not need app id
    subp_args += [f"--title={title}", "--"]
    subp_args += args
    return subprocess.Popen(subp_args, stdout=out, stderr=out)


def run_in_xterm(
    title: str, args: list[str], out: int | None = subprocess.DEVNULL
) -> subprocess.Popen:
    """
    Subfunction of run_in_floating_terminal implemented for xterm.

    This is much simpler than the gnome-terminal scheme but the result
    is less nice-looking.
    """
    return subprocess.Popen(
        [
            "xterm",
            "-bg",
            "black",
            "-fg",
            "white",
            "-title",
            title,
            "-geometry",
            "160x80",
            "-e",
        ]
        + args,
        stdout=out,
        stderr=out,
    )
