from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterator

import pytest

from iocmanager.utils import set_env_var_globals

EPICS_HOST_ARCH = os.getenv("EPICS_HOST_ARCH")
TESTS_PATH = Path(__file__).parent.resolve()
ROOT_PATH = TESTS_PATH.parent.parent.resolve()
PROCSERV_BUILD = ROOT_PATH / "procserv" / "build"


@pytest.fixture(scope="function", autouse=True)
def prepare_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Set environment variables appropriately for the unit tests.
    """
    monkeypatch.setenv("CAMRECORD_ROOT", str(tmp_path))
    try:
        monkeypatch.setenv("PROCSERV_EXE", str(get_procserv_bin_path()))
    except RuntimeError:
        monkeypatch.delenv("PROCSERV_EXE")
    monkeypatch.setenv("PYPS_ROOT", str(tmp_path))
    monkeypatch.setenv("IOC_DATA", str(TESTS_PATH / "ioc_data"))
    monkeypatch.setenv("IOC_COMMON", str(tmp_path))
    monkeypatch.setenv("TOOLS_SITE_TOP", str(tmp_path))
    EPICS_SITE_TOP = str(tmp_path)
    if not EPICS_SITE_TOP.endswith("/"):
        EPICS_SITE_TOP += "/"
    monkeypatch.setenv("EPICS_SITE_TOP", EPICS_SITE_TOP)

    set_env_var_globals()

    yield

    set_env_var_globals()


@pytest.fixture(scope="function")
def procserv() -> Iterator[TestProcServ]:
    """
    Start procServ with a "counter" IOC.

    Yields the port to connect to on localhost to access the procServ.

    Closes the procServ afterwards.
    """
    # Hard-code port for now, maybe we can pick this more intelligently in the future
    port = 34567

    with TestProcServ(port=port) as pserv:
        yield pserv


class TestProcServ:
    """
    Test helper.

    Acts as a context manager that launches a procServ process
    with an attached terminal.

    Can be used to send commands directly to the process without
    telnet.

    Closes the process cleanly on context exit.
    """

    def __init__(self, port: int):
        self.port = port
        self.proc = None
        self.startup_dir = str(TESTS_PATH / "iocs" / "counter" / "st.cmd")

    def __enter__(self) -> TestProcServ:
        self.open_procserv()
        return self

    def __exit__(self, *args, **kwargs):
        self.close_procserv()

    def open_procserv(self) -> subprocess.Popen:
        """
        Start a dummy procServ subprocess for unit test interaction.

        It will begin with no process running and autorestart disabled,
        so that the state is always known at the beginning of the test
        (without relying on things like subprocess startup speed).
        """
        self.close_procserv()
        self.proc = subprocess.Popen(
            [
                str(get_procserv_bin_path()),
                # Keep connected to this subprocess stdin/stdout
                "--foreground",
                # Start in no restart mode for predictable init
                "--noautorestart",
                # Start with no process running for predictable init
                "--wait",
                str(self.port),
                self.startup_dir,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return self.proc

    def close_procserv(self):
        """
        Stop and clean up the procServ subprocess.

        We need to ask procServ to kill its own subprocess
        if one is running, then turn off procServ itself.
        We will always finish by killing the process just in case.
        """
        if self.proc is not None:
            # If nothing is running, this is all we need
            self._close_cmd()
            # If something was running, the previous command is ignored.
            self.toggle_running()
            # Now that nothing is running, we can try to close again.
            self._close_cmd()
            # Always kill just in case
            self.proc.kill()
            self.proc = None

    def _close_cmd(self):
        """
        Send the command to close the procServ instance.

        This is the equivalent of pressing ctrl+Q

        Requres the subprocess to be closed first.
        """
        if self.proc is not None:
            if self.proc.stdin is not None:
                self.proc.stdin.write(ctrl("Q"))

    def toggle_autorestart(self):
        """
        Iterate through the three autorestart options.

        This is the equivalent of pressing ctrl+T

        The options are cycled through in a specific order:
        - start in OFF
        - ONESHOT after first toggle
        - ON after second toggle
        - OFF again after third toggle
        - repeat
        """
        if self.proc is not None:
            if self.proc.stdin is not None:
                self.proc.stdin.write(ctrl("T"))

    def toggle_running(self):
        """
        Stop or start the subprocess controlled by procServ.

        If the process is not running, this starts the process.
        If the process is running, this stops the process.

        After stopping a process, the behavior of what to do
        next depends on the autorestart mode:
        - ON = start the process again
        - OFF = keep the process off
        - ONESHOT = restart the process once, but not again

        This is the equivalent of pressing ctrl+X
        """
        if self.proc is not None:
            if self.proc.stdin is not None:
                self.proc.stdin.write(ctrl("X"))


def get_procserv_bin_path() -> Path:
    """
    Get a Path to the most correct procServ binary built in this repo.
    """
    if not PROCSERV_BUILD.exists():
        raise RuntimeError("f{PROCSERV_BUILD} not found")
    if EPICS_HOST_ARCH is not None:
        return PROCSERV_BUILD / EPICS_HOST_ARCH / "bin" / "procServ"
    # No host arch, just pick one
    for pth in PROCSERV_BUILD.glob("*"):
        bin_path = pth / "bin" / "procServ"
        if bin_path.exists():
            return bin_path
    raise RuntimeError("No procServ binary found")


def ctrl(char: str) -> bytes:
    """
    Get the bytes code for a ctrl+char combination, to be sent to a subprocess.
    """
    if len(char) != 1:
        raise ValueError("Expected a length 1 string")
    return bytes([ord(char.lower()) - ord("a") + 1])
