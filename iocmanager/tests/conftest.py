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


@pytest.fixture(scope="session")
def procserv_port() -> Iterator[int]:
    """
    Start procServ with a "counter" IOC.

    Yields the port to connect to on localhost to access the procServ.

    Closes the procServ afterwards.
    """
    procserv_bin_path = get_procserv_bin_path()
    # Hard-code for now, maybe we can pick this more intelligently in the future
    port = 34567

    proc = subprocess.Popen(
        [
            str(procserv_bin_path),
            "--foreground",
            port,
            str(TESTS_PATH / "iocs" / "counter" / "st.cmd"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    yield port

    # Ctrl+X followed by Ctrl+Q kills the procServ
    # The byte codes are their placement in the alphabet, but in hex
    proc.stdin.write(b"\x18")
    proc.stdin.write(b"\x11")
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        # TODO should I just do this from the start? Not sure
        proc.kill()
