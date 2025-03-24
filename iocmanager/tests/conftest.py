from pathlib import Path

import pytest

from iocmanager.utils import set_env_var_globals


@pytest.fixture(scope="function", autouse=True)
def prepare_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Set environment variables appropriately for the unit tests.
    """
    monkeypatch.setenv("CAMRECORD_ROOT", str(tmp_path))
    monkeypatch.setenv("PROCSERV_EXE", "echo")
    monkeypatch.setenv("PYPS_ROOT", str(tmp_path))
    monkeypatch.setenv("IOC_DATA", str(Path(__file__).parent / "ioc_data"))
    monkeypatch.setenv("IOC_COMMON", str(tmp_path))
    monkeypatch.setenv("TOOLS_SITE_TOP", str(tmp_path))
    EPICS_SITE_TOP = str(tmp_path)
    if not EPICS_SITE_TOP.endswith("/"):
        EPICS_SITE_TOP += "/"
    monkeypatch.setenv("EPICS_SITE_TOP", EPICS_SITE_TOP)

    set_env_var_globals()

    yield

    set_env_var_globals()
