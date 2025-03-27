from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from telnetlib import Telnet
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
def procserv() -> Iterator[ProcServHelper]:
    """
    Start procServ with a "counter" IOC.

    Yields the port to connect to on localhost to access the procServ.

    Closes the procServ afterwards.
    """
    proc_name = "counter"
    startup_dir = str(TESTS_PATH / "iocs" / "counter")
    command = "./st.cmd"
    port = 34567

    with ProcServHelper(
        proc_name=proc_name, startup_dir=startup_dir, command=command, port=port
    ) as pserv:
        yield pserv


@pytest.fixture(scope="function")
def procmgrd() -> Iterator[ProcServHelper]:
    """
    Start a procmgrd procServ instance.

    Yields the port to connect to on localhost to access the procServ.

    Closes the procServ afterwards.
    """
    proc_name = "procmgrd"
    startup_dir = str(TESTS_PATH)
    command = "./not_procmgrd.sh"
    port = 36666

    with ProcServHelper(
        proc_name=proc_name, startup_dir=startup_dir, command=command, port=port
    ) as pserv:
        yield pserv


class ProcServHelper:
    """
    Test helper.

    Acts as a context manager that launches an attached procServ
    process (not a daemon), which helps us clean up afterwards.

    Closes the process cleanly on context exit.
    """

    def __init__(self, proc_name: str, startup_dir: str, command: str, port: int):
        self.proc = None
        self.tn = None
        self.proc_name = proc_name
        self.startup_dir = startup_dir
        self.command = command
        self.port = port

    def __enter__(self) -> ProcServHelper:
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
                # Keep connected to this subprocess rather than daemonize
                "--foreground",
                # Start in no restart mode for predictable init
                "--noautorestart",
                # Start with no process running for predictable init
                "--wait",
                # Select a name to show to people who connect
                f"--name={self.proc_name}",
                str(self.port),
                self.command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.startup_dir,
        )
        # This is rude but it makes it more consistent...
        # TODO be better
        time.sleep(0.1)
        self.tn = Telnet("localhost", self.port, 1)
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
            self.close_cmd()
            # If something was running, the previous command is ignored.
            self.toggle_running()
            # Now that nothing is running, we can try to close again.
            self.close_cmd()
            # Always kill just in case
            self.proc.kill()
            self.proc = None
        if self.tn is not None:
            self.tn.close()
            self.tn = None

    def _ctrl_char(self, char: str):
        """
        Send a control character to the procServ process.
        """
        if self.tn is not None:
            try:
                self.tn.write(ctrl(char))
            except OSError:
                # telnet connection is dead, probably ok to skip
                ...

    def close_cmd(self):
        """
        Send the command to close the procServ instance.

        This is the equivalent of pressing ctrl+Q

        Requres the subprocess to be closed first.
        """
        self._ctrl_char("q")

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
        self._ctrl_char("t")

    def toggle_running(self):
        """
        Stop or start the subprocess controlled by procServ.

        If the process is not running, this starts the process.
        If the process is running, this stops the process.

        After stopping a process, the behavior of what to do
        next depends on the autorestart mode:
        - ON = start the process again
        - OFF = keep the process off, but keep procServ running
        - ONESHOT = shutdown procServ when the process ends

        This is the equivalent of pressing ctrl+X
        """
        self._ctrl_char("x")


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
