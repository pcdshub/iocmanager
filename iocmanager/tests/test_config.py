from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ..config import (
    check_auth,
    check_special,
    check_ssh,
    find_iocs,
    getHutchList,
    readConfig,
    readStatusDir,
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


def test_read_status_dir():
    # Status directory is at $PYPS_ROOT/config/.status/$HUTCH
    # During this test suite, that's a temp dir
    # Which is filled with the contents of the local tests/pyps_root
    # Note: this never matches a prod dir, even if PYPS_ROOT is set to a prod value
    status_dir = Path(os.getenv("PYPS_ROOT")) / "config" / ".status" / "pytest"
    if not status_dir.is_dir():
        raise RuntimeError(
            f"Error in test writing: status dir {status_dir} does not exist."
        )

    # Set up some expectations/starting state
    counter_path = status_dir / "ioc-counter"
    counter_info = {
        "rid": counter_path.name,
        "pid": "12345",
        "rhost": "test-server2",
        "rport": 30002,
        "rdir": "iocs/counter",
        "newstyle": True,
        "mtime": os.stat(counter_path).st_mtime,
        "hard": False,
    }
    shouter_path = status_dir / "ioc-shouter"
    shouter_info = {
        "rid": shouter_path.name,
        "pid": "23456",
        "rhost": "test-server1",
        "rport": 30001,
        "rdir": "iocs/shouter",
        "newstyle": True,
        "mtime": os.stat(shouter_path).st_mtime,
        "hard": False,
    }

    def assert_dict_info_in_list(info, lst):
        for dct in lst:
            if dct["rdir"] == info["rdir"]:
                assert info == dct
                return
        raise RuntimeError("No matching rdir in list.")

    # Run once: files should not change, result should be complete
    iocs1 = readStatusDir("pytest")
    assert len(iocs1) == 2
    assert_dict_info_in_list(counter_info, iocs1)
    assert_dict_info_in_list(shouter_info, iocs1)
    assert counter_path.is_file()
    assert shouter_path.is_file()

    # Make two new status files, before/after alphabetically.
    # These should supercede the old ones
    new_counter_path = status_dir / "ioc-a-counter"
    shutil.copy(counter_path, new_counter_path)
    new_counter_info = counter_info.copy()
    new_counter_info["rid"] = new_counter_path.name
    new_counter_info["mtime"] = os.stat(new_counter_path).st_mtime

    new_shouter_path = status_dir / "ioc-z-counter"
    shutil.copy(shouter_path, new_shouter_path)
    new_shouter_info = shouter_info.copy()
    new_shouter_info["rid"] = new_shouter_path.name
    new_shouter_info["mtime"] = os.stat(new_shouter_path).st_mtime

    # Make some bad files, it should be deleted and no info returned
    bad_file_path = status_dir / "not-an-ioc"
    with open(bad_file_path, "w") as fd:
        fd.write("12345 PIZZA SODA")

    assert bad_file_path.is_file()

    # Empty files are ignored and not deleted, for whatever reason
    empty_file_path = status_dir / "empty"
    empty_file_path.touch()
    assert empty_file_path.is_file()

    # Run again: should have new info, the old and bad files should be gone
    iocs2 = readStatusDir("pytest")
    assert len(iocs2) == 2
    assert_dict_info_in_list(new_counter_info, iocs2)
    assert_dict_info_in_list(new_shouter_info, iocs2)
    assert not counter_path.exists()
    assert not shouter_path.exists()
    assert not bad_file_path.exists()
    assert new_counter_path.is_file()
    assert new_shouter_path.is_file()
    assert empty_file_path.is_file()
