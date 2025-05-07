import pytest

from .. import env_paths
from ..env_paths import set_env_var_globals


def test_env_var_globals(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PROCSERV_EXE")
    set_env_var_globals()
    assert env_paths.PROCSERV_EXE == "procServ"
    monkeypatch.setenv("PROCSERV_EXE", "/some/path/to/procServ --allow --logfile name")
    set_env_var_globals()
    assert env_paths.PROCSERV_EXE == "/some/path/to/procServ"
    monkeypatch.setenv("PROCSERV_EXE", "/another/path/to/procServ")
    set_env_var_globals()
    assert env_paths.PROCSERV_EXE == "/another/path/to/procServ"
