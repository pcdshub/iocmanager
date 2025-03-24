from pathlib import Path

import pytest

from iocmanager.utils import set_env_var_globals


@pytest.fixture(scope="function", autouse=True)
def prepare_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Set environment variables appropriately for the unit tests.
    """
    monkeypatch.setenv("CAMRECORD_ROOT", str(tmp_path))
    monkeypatch.setenv("PYPS_ROOT", str(tmp_path))
    monkeypatch.setenv("IOC_DATA", str(Path(__file__).parent / "ioc_data"))
    monkeypatch.setenv("PROCSERV_EXE", "echo")

    set_env_var_globals()

    yield

    set_env_var_globals()
