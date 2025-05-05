from __future__ import annotations

import itertools
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from telnetlib import Telnet

import pytest

from .. import utils
from ..utils import (
    SPAM_LEVEL,
    add_spam_level,
    check_status,
    checkTelnetMode,
    fixdir,
    fixTelnetShell,
    getBaseName,
    killProc,
    openTelnet,
    readConfig,
    readLogPortBanner,
    readStatusDir,
    restartProc,
    set_env_var_globals,
    startProc,
    writeConfig,
)
from . import CFG_FOLDER
from .conftest import ProcServHelper


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


def test_readLogPortBanner(procserv: ProcServHelper):
    def get_info() -> dict[str, str | bool]:
        with Telnet("localhost", procserv.port, 1) as tn:
            return readLogPortBanner(tn)

    # Always starts with restart = off and process stopped
    assert get_info() == {
        "status": utils.STATUS_SHUTDOWN,
        "pid": "-",
        "rid": procserv.proc_name,
        "autorestart": False,
        "autooneshot": False,
        "autorestartmode": True,
        "rdir": procserv.startup_dir,
    }

    # Start the process
    procserv.toggle_running()

    def wait_status(status: str, errmsg: str) -> dict[str, str | bool]:
        timeout = 10
        # 1s seems big, but if you connect too often the process never starts!
        # Probably a procServ performance issue
        sleep_time = 1
        start_time = time.monotonic()
        wait_info = get_info()
        while wait_info["status"] != status and time.monotonic() - start_time < timeout:
            time.sleep(sleep_time)
            # Connect even less often after each failure as a performance workaround
            sleep_time *= 2
            wait_info = get_info()

        assert wait_info["status"] == status, errmsg
        return wait_info

    def basic_checks():
        assert info["status"] == utils.STATUS_RUNNING
        assert int(info["pid"]) > 0
        assert info["rid"] == procserv.proc_name
        # True if procServ's version is high enough
        assert info["autorestartmode"]
        assert info["rdir"] == procserv.startup_dir

    info = wait_status(utils.STATUS_RUNNING, "Subprocess did not start")
    basic_checks()
    assert not info["autooneshot"]
    assert not info["autorestart"]

    # Toggle to one shot
    procserv.toggle_autorestart()
    info = get_info()
    basic_checks()
    assert info["autooneshot"]
    assert not info["autorestart"]

    # Toggle to restart on
    procserv.toggle_autorestart()
    info = get_info()
    basic_checks()
    assert not info["autooneshot"]
    assert info["autorestart"]

    # Back to no autorestart
    procserv.toggle_autorestart()
    # Turn off the process and check for shutdown
    procserv.toggle_running()
    wait_status(utils.STATUS_SHUTDOWN, "Unable to shutdown")

    # Get a new info dict to check the no connect case
    with Telnet() as tn:
        bad_info = readLogPortBanner(tn)

    assert bad_info["status"] == utils.STATUS_ERROR


def test_check_status_good(procserv: ProcServHelper):
    # Should have a similar result to the readLogPortBanner initial test
    server = "localhost"
    assert check_status(server, procserv.port, procserv.proc_name) == {
        "status": utils.STATUS_SHUTDOWN,
        "pid": "-",
        "rid": procserv.proc_name,
        "autorestart": False,
        "autooneshot": False,
        "autorestartmode": True,
        "rdir": procserv.startup_dir,
    }
    # ping's exit code
    assert utils.pdict[server][1] == 0


def test_check_status_no_procserv():
    # Ping succeeds but telnet fails
    server = "localhost"
    ioc = "blarg"
    assert check_status(server, 31111, ioc) == {
        "status": utils.STATUS_NOCONNECT,
        "pid": "-",
        "rid": ioc,
        "autorestart": False,
        "autorestartmode": False,
        "rdir": "/tmp",
    }
    # ping's exit code
    assert utils.pdict[server][1] == 0


def test_check_status_no_host():
    # Ping fails
    server = "please-never-name-a-server-this"
    ioc = "blarg2"
    assert check_status(server, 31111, ioc) == {
        "status": utils.STATUS_DOWN,
        "pid": "-",
        "rid": ioc,
        "autorestart": False,
        "rdir": "/tmp",
    }
    # ping's exit code
    assert utils.pdict[server][1] > 0


def test_open_telnet_good(procserv: ProcServHelper):
    tn = openTelnet("localhost", procserv.port)
    try:
        tn.close()
    except Exception:
        ...
    assert isinstance(tn, Telnet)


def test_open_telnet_bad():
    tn = openTelnet("localhost", 31111)
    try:
        tn.close()
    except Exception:
        ...
    assert tn is None


def test_fix_telnet_shell(procmgrd: ProcServHelper):
    procmgrd.toggle_running()
    procmgrd.tn.read_until(utils.MSG_RESTART)
    fixTelnetShell("localhost", procmgrd.port)
    with Telnet("localhost", procmgrd.port, 1) as tn:
        tn.write(b"\n")
        bts = tn.read_until(b"> ", 1)
    assert b"> " in bts


autorestart_states = ("on", "off", "oneshot")
check_telnet_params = list(
    itertools.product(autorestart_states, autorestart_states, (True, False))
)


@pytest.mark.parametrize(
    "start_state,end_state,verbose",
    check_telnet_params,
)
def test_check_telnet_mode_good(
    procserv: ProcServHelper, start_state: str, end_state: str, verbose: bool
):
    # We should be able to change from any starting mode to any other mode.
    def set_state_and_assert(state: str):
        on_ok = False
        off_ok = False
        os_ok = False
        if state == "on":
            on_ok = True
        elif state == "off":
            off_ok = True
        elif state == "oneshot":
            os_ok = True
        else:
            raise ValueError(f"Invalid parameterized test input state={state}")
        assert checkTelnetMode(
            "localhost",
            procserv.port,
            onOK=on_ok,
            offOK=off_ok,
            oneshotOK=os_ok,
            verbose=verbose,
        )
        with Telnet("localhost", procserv.port, 1) as tn:
            info = readLogPortBanner(tn)
        assert info["autorestart"] == on_ok
        assert info["autooneshot"] == os_ok

    set_state_and_assert(start_state)
    set_state_and_assert(end_state)


def test_check_telnet_mode_bad():
    # Expected to fail via returning False and then not raising
    assert not checkTelnetMode("localhost", 31111)


# For killing procServ, let's try to cover all combinations of:
#   - Already running vs not running
#   - The three autorestart options
#   - verbose vs not verbose


@pytest.mark.parametrize(
    "running,autorestart,verbose",
    list(itertools.product((True, False), autorestart_states, (True, False))),
)
def test_kill_proc_good(
    procserv: ProcServHelper, running: bool, autorestart: str, verbose: bool
):
    # Start by setting us to the correct state
    # fixture begins as not running, autorestart off
    if running:
        # Not running -> running
        procserv.toggle_running()
    if autorestart == "oneshot":
        # Off -> Oneshot
        procserv.toggle_autorestart()
    elif autorestart == "on":
        # Off -> Oneshot -> On
        procserv.toggle_autorestart()
        procserv.toggle_autorestart()
    elif autorestart != "off":
        raise ValueError(f"Invalid value autorestart={autorestart} in test parameters")
    # Wait 1s for status to stabilize
    # TODO make helpers for robust waiting in ProcServHelper
    time.sleep(1)
    with Telnet("localhost", procserv.port, 1) as tn:
        info = readLogPortBanner(tn)
    # Subprocess should exist and have a pid
    if running:
        assert info["status"] == utils.STATUS_RUNNING
        subproc_pid = info["pid"]
        assert int(subproc_pid) > 0
        # Check that the pid is alive
        assert not subprocess.run(["ps", "--pid", str(subproc_pid)]).returncode
    else:
        assert info["status"] == utils.STATUS_SHUTDOWN
    killProc("localhost", procserv.port, verbose=verbose)
    # We need to wait again, gross
    time.sleep(1)
    if running:
        # We expect the subprocess pid and the procserv to be dead.
        # Telnet should fail too.
        assert subprocess.run(["ps", "--pid", str(subproc_pid)]).returncode
    return_code = procserv.proc.poll()
    assert return_code is not None, "procserv still running"
    assert return_code == 0, "procserv errored out without our help"
    with pytest.raises(OSError):
        with Telnet("localhost", procserv.port, 1):
            ...


@pytest.mark.parametrize("verbose", (True, False))
def test_kill_proc_bad(verbose: bool):
    # Note: I don't know how to reach some of the failure modes
    # For example, under what circumstances would the subprocess survive a kill?
    # We will test at least the case where the telnet can't connect
    # The expected behavior is unfortunately "just do nothing"
    killProc("localhost", 31111, verbose=verbose)


@pytest.mark.parametrize(
    "running,autorestart",
    list(itertools.product((True, False), autorestart_states)),
)
def test_restart_proc_good(procserv: ProcServHelper, running: bool, autorestart: str):
    # Start by setting us to the correct state
    # fixture begins as not running, autorestart off
    # TODO refactor this block into a function/helper instead of copy/paste
    if running:
        # Not running -> running
        procserv.toggle_running()
    if autorestart == "oneshot":
        # Off -> Oneshot
        procserv.toggle_autorestart()
    elif autorestart == "on":
        # Off -> Oneshot -> On
        procserv.toggle_autorestart()
        procserv.toggle_autorestart()
    elif autorestart != "off":
        raise ValueError(f"Invalid value autorestart={autorestart} in test parameters")
    time.sleep(1)
    # We need to observe either SHUTDOWN -> RUNNING or RUNNING -> SHUTDOWN -> RUNNING
    with Telnet("localhost", procserv.port, 1) as tn:
        info = readLogPortBanner(tn)
        # Starting state
        if running:
            assert info["status"] == utils.STATUS_RUNNING
        else:
            assert info["status"] == utils.STATUS_SHUTDOWN
        time.sleep(1)
        assert restartProc("localhost", procserv.port)
        # Now we can read the log of our open telnet
        if running:
            assert utils.MSG_ISSHUTTING in tn.read_until(utils.MSG_ISSHUTTING)
            assert utils.MSG_KILLED in tn.read_until(utils.MSG_KILLED)
        # Whether we started running or shutdown, now we should see it come online
        assert utils.MSG_RESTART in tn.read_until(utils.MSG_RESTART)
    # At the very end we should have come back to our original autorestart setting
    with Telnet("localhost", procserv.port, 1) as tn:
        info = readLogPortBanner(tn)
    if autorestart == "on":
        assert info["autorestart"]
        assert not info["autooneshot"]
    elif autorestart == "off":
        assert not info["autorestart"]
        assert not info["autooneshot"]
    elif autorestart == "oneshot":
        assert not info["autorestart"]
        assert info["autooneshot"]


def test_restart_proc_bad():
    assert not restartProc("localhost", 31111)


def test_start_proc(procmgrd: ProcServHelper):
    procmgrd.toggle_running()
    time.sleep(1)
    fixTelnetShell("localhost", procmgrd.port)
    time.sleep(1)
    name = "counter"
    port = 36420
    try:
        startProc(
            cfg="tst",
            entry={
                "host": "localhost",
                "port": port,
                "id": name,
            },
        )
        time.sleep(1)
        # The process should be running and accessible via telnet like any other
        with Telnet("localhost", port, 1) as tn:
            info = readLogPortBanner(tn)
        assert info["status"] == utils.STATUS_RUNNING
        assert int(info["pid"]) > 0
        assert info["rid"] == name
        assert info["autorestart"]
        assert not info["autooneshot"]
        assert info["autorestartmode"]
    finally:
        # Try to clean up
        killProc("localhost", port)


def test_read_config():
    filename = str(CFG_FOLDER / "example.cfg")
    ftime, iocs, hosts, extra_vars = readConfig(filename)

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
    _, iocs, hosts, vars = readConfig(str(CFG_FOLDER / "example.cfg"))
    with open(tmp_path / "example.cfg", "w") as fd:
        writeConfig(hutch="unit_test", hostlist=hosts, cfglist=iocs, vars=vars, f=fd)

    with open(CFG_FOLDER / "example.cfg", "r") as fd:
        expected = fd.readlines()

    with open(tmp_path / "example.cfg", "r") as fd:
        actual = fd.readlines()

    assert actual == expected


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

    # Make a bad file, it should be deleted and no info returned
    bad_file_path = status_dir / "not-an-ioc"
    with open(bad_file_path, "w") as fd:
        fd.write("12345 PIZZA SODA")

    assert bad_file_path.is_file()

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
