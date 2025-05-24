from __future__ import annotations

import os
import shutil
from copy import copy
from pathlib import Path

import pytest

from ..config import (
    Config,
    IOCProc,
    IOCStatusFile,
    check_auth,
    check_special,
    check_ssh,
    find_iocs,
    get_hutch_list,
    read_config,
    read_status_dir,
    write_config,
)
from . import CFG_FOLDER


@pytest.mark.parametrize(
    "cfg", (str(CFG_FOLDER / "pytest" / "iocmanager.cfg"), "pytest")
)
def test_read_config(cfg: str):
    config = read_config(cfg)

    if Path(cfg).is_file():
        filename = cfg
    else:
        filename = str(CFG_FOLDER / cfg / "iocmanager.cfg")

    assert config.mtime == os.stat(filename).st_mtime

    assert config.procs == {
        "ioc-counter": IOCProc(
            name="ioc-counter",
            host="test-server2",
            port=30002,
            path="iocs/counter",
            alias="",
            disable=False,
            cmd="",
            history=["iocs/old"],
            parent="",
            hard=False,
        ),
        "ioc-shouter": IOCProc(
            name="ioc-shouter",
            host="test-server1",
            port=30001,
            path="iocs/shouter",
            alias="SHOUTER",
            disable=False,
            cmd="",
            history=[],
            parent="",
            hard=False,
        ),
    }

    assert config.hosts == [
        "test-server1",
        "test-server2",
    ]

    assert config.commithost == "localhost"
    assert config.allow_console


def test_write_config(tmp_path: Path):
    # Just write back our example config, it should be the same
    config = read_config("pytest")
    write_config(cfgname=str(tmp_path / "iocmanager.cfg"), config=config)

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
    assert search1[0][1].host == "test-server2"

    search2 = find_iocs(host="test-server1")
    assert len(search2) == 1
    assert search2[0][1].name == "ioc-shouter"


def test_get_hutch_list():
    # See folders in pyps_root/config
    assert sorted(get_hutch_list()) == [
        "pytest",
        "second_hutch",
    ]


def test_validate_config():
    # Only checks for port conflicts at time of writing
    good_config = Config(path="")
    good_config.add_proc(IOCProc(name="one", host="host1", port=10000, path=""))
    good_config.add_proc(IOCProc(name="two", host="host1", port=20000, path=""))
    good_config.add_proc(IOCProc(name="thr", host="host2", port=20000, path=""))

    bad_config = Config(path="")
    bad_config.add_proc(IOCProc(name="one", host="host1", port=10000, path=""))
    bad_config.add_proc(IOCProc(name="two", host="host1", port=10000, path=""))
    bad_config.add_proc(IOCProc(name="thr", host="host2", port=20000, path=""))
    assert good_config.validate()
    assert not bad_config.validate()


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
    counter_info = IOCStatusFile(
        name=counter_path.name,
        port=30002,
        host="test-server2",
        path="iocs/counter",
        pid=12345,
        mtime=os.stat(counter_path).st_mtime,
    )
    shouter_path = status_dir / "ioc-shouter"
    shouter_info = IOCStatusFile(
        name=shouter_path.name,
        port=30001,
        host="test-server1",
        path="iocs/shouter",
        pid=23456,
        mtime=os.stat(shouter_path).st_mtime,
    )

    # Run once: files should not change, result should be complete
    iocs1 = read_status_dir("pytest")
    assert len(iocs1) == 2
    assert counter_info in iocs1
    assert shouter_info in iocs1
    assert counter_path.is_file()
    assert shouter_path.is_file()

    # Make two new status files, before/after alphabetically.
    # These should supercede the old ones
    new_counter_path = status_dir / "ioc-a-counter"
    shutil.copy(counter_path, new_counter_path)
    new_counter_info = copy(counter_info)
    new_counter_info.name = new_counter_path.name
    new_counter_info.mtime = os.stat(new_counter_path).st_mtime

    new_shouter_path = status_dir / "ioc-z-counter"
    shutil.copy(shouter_path, new_shouter_path)
    new_shouter_info = copy(shouter_info)
    new_shouter_info.name = new_shouter_path.name
    new_shouter_info.mtime = os.stat(new_shouter_path).st_mtime

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
    iocs2 = read_status_dir("pytest")
    assert len(iocs2) == 2
    assert new_counter_info in iocs2
    assert new_shouter_info in iocs2
    assert not counter_path.exists()
    assert not shouter_path.exists()
    assert not bad_file_path.exists()
    assert new_counter_path.is_file()
    assert new_shouter_path.is_file()
    assert empty_file_path.is_file()
