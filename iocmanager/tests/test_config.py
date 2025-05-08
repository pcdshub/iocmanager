from __future__ import annotations

import os
from pathlib import Path

import pytest

from ..config import (
    check_auth,
    check_special,
    check_ssh,
    find_iocs,
    getHutchList,
    readConfig,
    validateConfig,
    writeConfig,
)
from . import CFG_FOLDER


@pytest.mark.parametrize(
    "cfg", (str(CFG_FOLDER / "pytest" / "iocmanager.cfg"), "pytest")
)
def test_read_config(cfg: str):
    ftime, iocs, hosts, extra_vars = readConfig(cfg)

    if Path(cfg).is_file():
        filename = cfg
    else:
        filename = str(CFG_FOLDER / cfg / "iocmanager.cfg")

    assert ftime == os.stat(filename).st_mtime

    assert iocs == [
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
    ]

    assert hosts == [
        "test-server1",
        "test-server2",
    ]

    assert extra_vars == {
        "COMMITHOST": "localhost",
    }


def test_write_config(tmp_path: Path):
    # Just write back our example config, it should be the same
    _, iocs, hosts, vars = readConfig("pytest")
    with open(tmp_path / "iocmanager.cfg", "w") as fd:
        writeConfig(hutch="unit_test", hostlist=hosts, cfglist=iocs, vars=vars, f=fd)

    with open(CFG_FOLDER / "pytest" / "iocmanager.cfg", "r") as fd:
        expected = fd.readlines()

    with open(tmp_path / "iocmanager.cfg", "r") as fd:
        actual = fd.readlines()

    assert actual == expected


def test_check_auth():
    assert check_auth("user_for_test_check_auth", "pytest")
    assert not check_auth("some_rando", "pytest")


def test_check_special_two_variants():
    # We should get True for the two versions we have but not for others
    assert check_special("has_two_variants", "pytest", "ioc/pytest/normal")
    assert check_special("has_two_variants", "pytest", "ioc/pytest/other")
    assert not check_special("has_two_variants", "pytest", "what_the_heck")


def test_check_special_just_name():
    # With just a name and no variants, we should get true with no version arg
    assert check_special("just_a_name", "pytest")
    assert not check_special("any_other_name", "pytest")


def test_check_ssh():
    assert check_ssh("most_users", "pytest")
    assert not check_ssh("tstopr", "pytest")


def test_find_iocs():
    search1 = find_iocs(id="ioc-counter")
    assert len(search1) == 1
    assert search1[0][1]["host"] == "test-server2"

    search2 = find_iocs(host="test-server1")
    assert len(search2) == 1
    assert search2[0][1]["id"] == "ioc-shouter"


def test_get_hutch_list():
    # See folders in pyps_root/config
    assert sorted(getHutchList()) == [
        "pytest",
        "second_hutch",
    ]


def test_validate_config():
    # Only checks for port conflicts at time of writing
    good_config = [
        {"host": "host1", "port": 10000},
        {"host": "host1", "port": 20000},
        {"host": "host2", "port": 20000},
    ]
    bad_config = [
        {"host": "host1", "port": 10000},
        {"host": "host1", "port": 10000},
        {"host": "host2", "port": 20000},
    ]
    assert validateConfig(good_config)
    assert not validateConfig(bad_config)
