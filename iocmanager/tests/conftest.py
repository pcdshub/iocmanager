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

    def __enter__(self) -> TestProcServ:
        self.close_procserv()
        self.proc = subprocess.Popen(
            [
                str(get_procserv_bin_path()),
                "--foreground",
                self.port,
                str(TESTS_PATH / "iocs" / "counter" / "st.cmd"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return self

    def __exit__(self, *args, **kwargs):
        self.close_procserv()

    def close_procserv(self):
        if self.proc is not None:
            self.stop_child()
            self.proc.stdin.write(ctrl("Q"))
            self.proc.kill()
            self.proc = None

    def toggle_mode(self):
        if self.proc is not None:
            self.proc.stdin.write(ctrl("T"))

    def stop_child(self):
        if self.proc is not None:
            self.proc.stdin.write(ctrl("X"))


def get_procserv_bin_path() -> Path:
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
