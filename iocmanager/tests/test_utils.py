from __future__ import annotations

import logging
from pathlib import Path
from telnetlib import Telnet

import pytest

from .. import utils
from ..utils import (
    SPAM_LEVEL,
    add_spam_level,
    fixdir,
    getBaseName,
    readConfig,
    readLogPortBanner,
    set_env_var_globals,
    writeConfig,
)
from . import CFG_FOLDER
from .conftest import TestProcServ


def test_env_var_globals(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PROCSERV_EXE")
    set_env_var_globals()
    assert utils.PROCSERV_EXE == "procServ"
    monkeypatch.setenv("PROCSERV_EXE", "/some/path/to/procServ --allow --logfile name")
    set_env_var_globals()
    assert utils.PROCSERV_EXE == "/some/path/to/procServ"
    monkeypatch.setenv("PROCSERV_EXE", "/another/path/to/procServ")
    set_env_var_globals()
    assert utils.PROCSERV_EXE == "/another/path/to/procServ"


def test_add_spam_level(caplog: pytest.LogCaptureFixture):
    logger = logging.getLogger(f"{__file__}.test_add_spam_level")
    assert not hasattr(logger, "spam")
    add_spam_level(logger)
    caplog.set_level(SPAM_LEVEL)
    caplog.clear()
    assert not caplog.get_records(when="call")
    logger.spam("test")
    records = caplog.get_records(when="call")
    assert records
    assert records[0].message == "test"


@pytest.mark.parametrize(
    "ioc_name,pv_base",
    [("ioc1", "IOC:PYTEST:01"), ("notanioc", None), ("iocbad", None)],
)
def test_getBaseName(ioc_name: str, pv_base: str | None):
    assert getBaseName(ioc_name) == pv_base


# Possible pieces to normalize
test_fixdir_prefix = ("", "../", "../../", "EPICS_SITE_TOP")
test_fixdir_iocdir = "ioc/common/ci/R1.0.0/"
test_fixdir_extra_parts = ("", "iocBoot/", "build/iocBoot/", "children/build/iocBoot/")
test_fixdir_iocnames = ("fake_ioc1", "fake_ioc2")

# Build all the variants
test_fix_dir_params = []
for prefix in test_fixdir_prefix:
    for ext in test_fixdir_extra_parts:
        for ioc in test_fixdir_iocnames:
            test_fix_dir_params.append((f"{prefix}{test_fixdir_iocdir}{ext}{ioc}", ioc))


@pytest.mark.parametrize("ioc_dir,ioc_name", test_fix_dir_params)
def test_fixdir(ioc_dir: str, ioc_name: str):
    ioc_dir = ioc_dir.replace("EPICS_SITE_TOP", utils.EPICS_SITE_TOP)
    if "iocBoot" in ioc_dir:
        answer = test_fixdir_iocdir.removesuffix("/")
    else:
        # Implementation does no special suffix removal if iocBoot isn't here
        # So the trailing ioc dir remains, but the other processing is done
        answer = f"{test_fixdir_iocdir}{ioc_name}"
    assert fixdir(ioc_dir, ioc_name) == answer


def test_readLogPortBanner(procserv: TestProcServ):
    # Always starts with restart = on and process running
    with Telnet("localhost", procserv.port, 1) as tn:
        info = readLogPortBanner(tn)

    def basic_checks():
        assert info["status"] == utils.STATUS_RUNNING
        # These could be many things, check as much as we can
        assert int(info["pid"]) > 0
        assert "rid" in info
        # Only true in old procServ versions
        assert not info["autorestart"]

    basic_checks(info, utils.STATUS_RUNNING)
    assert not info["autooneshot"]
    assert info["autorestartmode"]

    # Toggle to one shot
    procserv.toggle_mode()
    basic_checks(info, utils.STATUS_RUNNING)
    assert info["autooneshot"]
    assert not info["autorestartmode"]

    # Toggle to restart off
    procserv.toggle_mode()
    basic_checks(info, utils.STATUS_RUNNING)
    assert not info["autooneshot"]
    assert not info["autorestartmode"]

    # Turn off the child and check for shutdown
    procserv.stop_child()
    basic_checks(info, utils.STATUS_SHUTDOWN)

    # Get a new info dict to check the no connect case
    with Telnet() as tn:
        bad_info = readLogPortBanner(tn)

    assert bad_info["status"] == utils.STATUS_ERROR


def test_read_config():
    _, iocs, hosts, _ = readConfig(str(CFG_FOLDER / "example.cfg"))

    assert iocs == [
        {
            "id": "ioc-shouter",
            "host": "test-server1",
            "port": 30001,
            "dir": "iocs/shouter",
            "alias": "SHOUTER",
            "disable": False,
            "hard": False,
            "history": [],
            "cfgstat": 0,
            "rid": "ioc-shouter",
            "rdir": "iocs/shouter",
            "rhost": "test-server1",
            "rport": 30001,
            "newstyle": False,
            "pdir": "",
        },
        {
            "id": "ioc-counter",
            "host": "test-server2",
            "port": 30002,
            "dir": "iocs/counter",
            "history": ["iocs/old"],
            "disable": False,
            "hard": False,
            "alias": "",
            "cfgstat": 0,
            "rid": "ioc-counter",
            "rdir": "iocs/counter",
            "rhost": "test-server2",
            "rport": 30002,
            "newstyle": False,
            "pdir": "",
        },
    ]

    assert hosts == [
        "test-server1",
        "test-server2",
    ]


def test_write_config(tmp_path: Path):
    # Just write back our example config, it should be the same
    _, iocs, hosts, vars = readConfig(str(CFG_FOLDER / "example.cfg"))
    with open(tmp_path / "example.cfg", "w") as fd:
        writeConfig(hutch="unit_test", hostlist=hosts, cfglist=iocs, vars=vars, f=fd)

    with open(CFG_FOLDER / "example.cfg", "r") as fd:
        expected = fd.readlines()

    with open(tmp_path / "example.cfg", "r") as fd:
        actual = fd.readlines()

    assert actual == expected
