from __future__ import annotations

import itertools
import logging
import os
import re
import shutil
import subprocess
import telnetlib
import time
from itertools import product
from pathlib import Path
from telnetlib import Telnet
from unittest.mock import Mock

import pytest

from .. import utils
from ..utils import (
    SPAM_LEVEL,
    _netconfig,
    add_spam_level,
    applyConfig,
    check_auth,
    check_special,
    check_ssh,
    check_status,
    checkTelnetMode,
    find_iocs,
    findParent,
    findPV,
    fixdir,
    fixTelnetShell,
    getBaseName,
    getHardIOCDir,
    getHutchList,
    killProc,
    netconfig,
    openTelnet,
    readAll,
    readConfig,
    readLogPortBanner,
    readStatusDir,
    rebootHIOC,
    rebootServer,
    restartHIOC,
    restartProc,
    set_env_var_globals,
    startProc,
    validateConfig,
    validateDir,
    writeConfig,
)
from . import CFG_FOLDER, IOC_FOLDER, TESTS_FOLDER
from .conftest import ProcServHelper

# All options for booleans for parameterizing tests
bopts = (True, False)


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


vopts = ("allow", "deny", "skip", "one_ioc")


@pytest.mark.parametrize(
    "do_verify,do_kill,do_start,do_restart", list(product(vopts, bopts, bopts, bopts))
)
def test_apply_config(
    monkeypatch: pytest.MonkeyPatch,
    do_verify: str,
    do_kill: bool,
    do_start: bool,
    do_restart: bool,
):
    if do_verify not in vopts:
        raise ValueError(f"Invalid do_verify {do_verify} from programmers.")
    # This function does a lot of things
    # We'll make heavy use of monkeypatch and mock here to see what args
    # killProc, startProc, and restartProc are called with.
    CFG = "pytest"

    mock = Mock()
    monkeypatch.setattr(utils, "killProc", mock.killProc)
    monkeypatch.setattr(utils, "startProc", mock.startProc)
    monkeypatch.setattr(utils, "restartProc", mock.restartProc)

    # We'll monkeypatch readConfig, readStatusDir, check_status too
    # We don't want to mess around with real processes in this test
    read_config_list = []
    read_config_result = (0, read_config_list, [], {})
    read_status_dir_result = []

    def fake_read_config(*args, **kwargs):
        return read_config_result

    def fake_read_status_dir(*args, **kwargs):
        return read_status_dir_result

    def fake_check_status(host: str, port: int, id: str):
        # Simplify: presume status dir is correct, all hosts up
        status = utils.STATUS_SHUTDOWN
        for res in read_status_dir_result:
            if (res["rhost"], res["rport"]) == (host, port):
                status = utils.STATUS_RUNNING
                break
        return {
            "status": status,
            "rid": id,
            "pid": "-",
            "autorestart": True,
            "autorestartmode": False,
            "rdir": "/tmp",
        }

    monkeypatch.setattr(utils, "readConfig", fake_read_config)
    monkeypatch.setattr(utils, "readStatusDir", fake_read_status_dir)
    monkeypatch.setattr(utils, "check_status", fake_check_status)

    # Change our verify approach based on the input arg
    if do_verify == "allow":

        def verify(current, config, kill_list, start_list, restart_list):
            return (kill_list, start_list, restart_list)
    elif do_verify == "deny":

        def verify(current, config, kill_list, start_list, restart_list):
            return ([], [], [])
    else:
        verify = None

    def basic_fake_config(
        name: str,
        host: str | None = None,
        port: int | None = None,
        disable: bool = False,
        directory: str | None = None,
    ):
        config = {
            "id": name,
            "dir": directory or f"ioc/pytest/{name}",
            "host": host or f"ctl-pytest-{name}",
            "port": port or 20000,
            "disable": disable,
            "hard": False,
            "history": [],
            "alias": "",
            "newstyle": False,
            "pdir": f"ioc/common/{name}",
        }
        config["rid"] = config["id"]
        config["rdir"] = config["dir"]
        config["rhost"] = config["host"]
        config["rport"] = config["port"]
        return config

    def basic_fake_status(
        name: str,
        host: str | None = None,
        port: int | None = None,
        directory: str | None = None,
    ):
        return {
            "rid": name,
            "pid": "10000",
            "rhost": host or f"ctl-pytest-{name}",
            "rport": port or 20000,
            "rdir": directory or f"ioc/pytest/{name}",
            "newstyle": True,
            "mtime": 0,
            "hard": False,
        }

    # killProc(host, port)
    kill_args = []
    not_kill_args = []
    # startProc(cfg, {"host": host, "port": port, others})
    # but we'll just do (host, port) and deal with it later
    start_args = []
    not_start_args = []
    # restartProc(host, port)
    restart_args = []
    not_restart_args = []

    # Set up IOCs that we expect to kill
    kill_1_args = ("ctl-pytest-kill_1", 20000)
    if do_kill:
        # Disabled, do kill
        read_config_list.append(
            basic_fake_config(
                name="kill_1",
                disable=True,
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_1",
            )
        )
        kill_args.append(kill_1_args)
    else:
        # Enabled, don't kill
        read_config_list.append(
            basic_fake_config(
                name="kill_1",
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_1",
            )
        )
        not_kill_args.append(kill_1_args)

    # Set up IOCs that we expect to kill and then start somewhere else
    kill_2_args = ("kill_2_old_server", 20000)
    kill_3_args = ("ctl-pytest-kill_3", 20000)
    start_2_args = ("kill_2_new_server", 20000)
    start_3_args = ("ctl-pytest-kill_3", 10000)
    if do_kill and do_start:
        # New host, kill and start
        read_config_list.append(
            basic_fake_config(
                name="kill_2",
                host="kill_2_new_server",
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_2",
                host="kill_2_old_server",
            )
        )
        kill_args.append(kill_2_args)
        start_args.append(start_2_args)
        # New port, kill and start
        read_config_list.append(
            basic_fake_config(
                name="kill_3",
                port=10000,
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_3",
                port=20000,
            )
        )
        kill_args.append(kill_3_args)
        start_args.append(start_3_args)
    else:
        # Same host, same port, don't kill
        read_config_list.append(
            basic_fake_config(
                name="kill_2",
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_2",
            )
        )
        not_kill_args.append(kill_2_args)
        not_start_args.append(start_2_args)
        read_config_list.append(
            basic_fake_config(
                name="kill_3",
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="kill_3",
            )
        )
        not_kill_args.append(kill_3_args)
        not_start_args.append(start_3_args)

    # Set up IOCs that we expect to start
    start_1_args = ("ctl-pytest-start_1", 20000)
    if do_start:
        # New or newly enabled IOC
        read_config_list.append(
            basic_fake_config(
                name="start_1",
            )
        )
        start_args.append(start_1_args)
    else:
        not_start_args.append(start_1_args)

    # Set up IOCs that we expect to restart
    restart_1_args = ("ctl-pytest-restart_1", 20000)
    if do_restart:
        # New version, do restart
        read_config_list.append(
            basic_fake_config(name="restart_1", directory="ioc/new/version")
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="restart_1",
                directory="ioc/old/version",
            )
        )
        restart_args.append(restart_1_args)
    else:
        # Same version, no need to restart
        read_config_list.append(
            basic_fake_config(
                name="restart_1",
            )
        )
        read_status_dir_result.append(
            basic_fake_status(
                name="restart_1",
            )
        )
        not_restart_args.append(restart_1_args)

    # Always include a hard ioc, it should be ignored
    hioc_cfg = basic_fake_config("hioc-pytest")
    hioc_cfg["hard"] = True
    read_config_list.append(hioc_cfg)
    not_start_args.append((hioc_cfg["host"], hioc_cfg["port"]))
    not_kill_args.append((hioc_cfg["host"], hioc_cfg["port"]))
    not_restart_args.append((hioc_cfg["host"], hioc_cfg["port"]))

    ioc = None
    if do_verify == "deny":
        # If the user denies action, we should take no actions!
        not_kill_args.extend(kill_args)
        kill_args.clear()
        not_start_args.extend(start_args)
        start_args.clear()
        not_restart_args.extend(restart_args)
        restart_args.clear()
    elif do_verify == "one_ioc":
        # In one_ioc mode, we'll test the ioc argument.
        # Pick the first IOC in the chain that we expect to take action on.
        if do_kill:
            ioc = "kill_1"
        elif do_start:
            ioc = "start_1"
        elif do_restart:
            ioc = "restart_1"
        else:
            ioc = "misc"

    if ioc is not None:
        # Move everything into the not lists except for our one IOC
        new_kill_args = []
        for args in kill_args:
            if args[0] == f"ctl-pytest-{ioc}":
                new_kill_args.append(args)
            else:
                not_kill_args.append(args)
        kill_args = new_kill_args

        new_start_args = []
        for args in start_args:
            if args[0] == f"ctl-pytest-{ioc}":
                new_start_args.append(args)
            else:
                not_start_args.append(args)
        start_args = new_start_args

        new_restart_args = []
        for args in restart_args:
            if args[0] == f"ctl-pytest-{ioc}":
                new_restart_args.append(args)
            else:
                not_restart_args.append(args)
        restart_args = new_restart_args

    # The situation is set up. Let's run the function.
    assert applyConfig(CFG, verify=verify, ioc=ioc) == 0

    # Verify which things were killed vs not killed
    for args in kill_args:
        mock.killProc.assert_any_call(*args)
    for args in not_kill_args:
        for this_arg_call in mock.killProc.call_args_list:
            assert args != this_arg_call
    assert mock.killProc.call_count == len(kill_args)

    for args in restart_args:
        mock.restartProc.assert_any_call(*args)
    for args in not_restart_args:
        for this_arg_call in mock.restartProc.call_args_list:
            assert args != this_arg_call
    assert mock.restartProc.call_count == len(restart_args)

    # Slightly different for startProc, it's expecting a dict
    # Our args are (host, port)
    # Real args are (cfg, {"host": host, "port": port, **kw})
    for args in start_args:
        found_match = False
        for sp_call in mock.startProc.call_args_list:
            if (
                args[0] == sp_call.args[1]["host"]
                and args[1] == sp_call.args[1]["port"]
            ):
                found_match = True
                break
        assert found_match
    for args in not_start_args:
        found_match = False
        for sp_call in mock.startProc.call_args_list:
            if (
                args[0] == sp_call.args[1]["host"]
                and args[1] == sp_call.args[1]["port"]
            ):
                found_match = True
                break
        assert not found_match
    assert mock.startProc.call_count == len(start_args)


def test_apply_config_early_fail(monkeypatch: pytest.MonkeyPatch):
    def fake_read_config(*args, **kwargs):
        return None

    monkeypatch.setattr(utils, "readConfig", fake_read_config)

    assert applyConfig("pytest", ioc="notarealiocpleasedontpbreakproc") != 0


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


def test_read_all(tmp_path: Path):
    # This is pretty dumb but whatever
    my_lines = [
        "hey\n",
        "this is an epics thing\n",
        "I guess\n",
    ]
    with open(tmp_path / "test_read_all", "w") as fd:
        fd.writelines(my_lines)

    assert readAll("test_read_all") == my_lines
    assert readAll(str(tmp_path / "test_read_all")) == my_lines
    assert readAll("defo_not_a_path") == []


def test_find_parent(monkeypatch: pytest.MonkeyPatch):
    # NOTE: skip testing $$PATH, which is an unused feature

    # Normal template IOC
    assert (
        findParent("hutch_ioc", str(IOC_FOLDER / "templated_ioc"))
        == "/some/absolute/path"
    )

    # Typical common/children structure
    common_path = IOC_FOLDER / "common_ioc"
    assert findParent("child_ioc", str(common_path)) == str(IOC_FOLDER / "common_ioc")

    # A real file without this pattern
    name1 = "malformed_ioc"
    assert (common_path / "children" / f"{name1}.cfg").exists()
    assert findParent(name1, str(common_path)) == ""

    # Not a real file
    name2 = "asdfasefef"
    assert not (common_path / "children" / f"{name2}.cfg").exists()
    assert findParent(name2, str(common_path)) == ""

    # Set up fake readAll for more specific regex testing
    release_line = ""

    def fake_read_all(*args, **kwargs):
        return [release_line + "\n"]

    monkeypatch.setattr(utils, "readAll", fake_read_all)

    # Variants to exercise each regex in the original implementation
    answer = "/true/parent/path"
    sp_opts = ("", " ", "\t")
    rel_ops = ("RELEASE",)
    eq_opts = ("=", " ")
    answer_opts = (answer, f'"{answer}"', f"'{answer}'")

    lines = product(sp_opts, rel_ops, sp_opts, eq_opts, sp_opts, answer_opts, sp_opts)

    for trial_parts in lines:
        release_line = "".join(trial_parts)
        assert (
            findParent("some_ioc", "/some/dir") == answer
        ), f"Issue with {release_line}"


# Skip testing the following functions which will be removed:
# read_until
# flush_input
# do_write
# commit_config (needs to be replaced with fabric version)


def test_find_iocs():
    search1 = find_iocs(id="ioc-counter")
    assert len(search1) == 1
    assert search1[0][1]["host"] == "test-server2"

    search2 = find_iocs(host="test-server1")
    assert len(search2) == 1
    assert search2[0][1]["id"] == "ioc-shouter"


_example_netconfig_text = """
        name: ctl-pytest-cam-01
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Description: Ciara AMD7282
        DHCP parameters:
                filename "pxe/uefi/shim.efi";
        Puppet Classes:
"""


def test_netconfig_text_processing(monkeypatch: pytest.MonkeyPatch):
    def fake_netconfig(host: str):
        return _example_netconfig_text

    monkeypatch.setattr(utils, "_netconfig", fake_netconfig)
    info = netconfig("ctl-pytest-cam-01")
    assert info["name"] == "ctl-pytest-cam-01"
    assert info["subnet"] == "cds-pytest.pcdsn"
    assert info["pc#"] == "99999"


def test_netconfig_call():
    host = "asdfsdf"
    assert _netconfig(host).strip() == f"netconfig view {host}"


def test_reboot_server(capfd: pytest.CaptureFixture):
    # Fake reboot script tools/bin/psipmi just echoes our command
    host = "asdfsdfasdf"
    assert rebootServer(host)
    captured = capfd.readouterr()
    assert captured.out.strip() == f"psipmi {host} power cycle"
    assert captured.err == ""


def test_get_hard_ioc_dir():
    assert getHardIOCDir("test-hioc") == "ioc/pytest/the-pytest-hiocs-folder/R1.0.0"
    assert getHardIOCDir("not-a-real-name") == "Unknown"


_hioc_netconfig_no_console_info = """
        name: ioc-pytest-hioc1
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Description: RTEMS Gas Detector Crate
        DHCP parameters:
                filename "rtems-4.9.4/rtems.ralf";
        Puppet Classes:
"""

_hioc_netconfig_yes_console_info = """
        name: ioc-pytest-hioc2
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Console Port DN: cn=port1,cn=digi-pytest-01,dc=cds-pytest.pcdsn,ou=Subnets,dc=reg,o=slac
        Description: VME High Voltage Crate in Pulse Lab
        DHCP parameters:
                filename "rtems-4.9.4/rtems.ralf";
        Puppet Classes:
"""  # noqa: E501


def test_restart_hioc(monkeypatch: pytest.MonkeyPatch):
    # This will be a bit silly, we'll mock netconfig and the Telnet class
    # and check that the results make sense
    def fake_netconfig(host: str):
        if host == "ioc-pytest-hioc1":
            return _hioc_netconfig_no_console_info
        elif host == "ioc-pytest-hioc2":
            return _hioc_netconfig_yes_console_info
        else:
            raise RuntimeError("Not a host")

    monkeypatch.setattr(utils, "_netconfig", fake_netconfig)

    class FakeTelnet:
        registry: list[FakeTelnet] = []

        def __init__(self, host: str, port: int, timeout: float):
            self.host = host
            self.port = port
            self.call_order = []
            self.registry.append(self)

        def write(self, msg: bytes):
            assert isinstance(msg, bytes), "Telnetlib requires bytes"
            self.call_order.append(("write", msg))

        def read_until(self, msg: bytes, count: int | None = None):
            assert isinstance(msg, bytes), "Telnetlib requires bytes"
            self.call_order.append(("read_until", msg))

        def close(self):
            self.call_order.append(("close",))

    monkeypatch.setattr(telnetlib, "Telnet", FakeTelnet)

    # Invalid host -> returns False I guess, netconfig should have no info for us
    assert not netconfig("asdfsdf")
    assert not restartHIOC("asdfsdf")

    # Host without port should also return False, even though netconfig doesn't error
    assert netconfig("ioc-pytest-hioc1")
    assert not restartHIOC("ioc-pytest-hioc1")

    # Host with proper info should create the correct Telnet and use it appropriately
    assert restartHIOC("ioc-pytest-hioc2")
    assert len(FakeTelnet.registry) == 1
    tn = FakeTelnet.registry[0]
    assert tn.host == "digi-pytest-01"
    assert tn.port == 2001
    # Yeah, this is silly, but I don't have a better idea right now.
    # Not robust to small changes in function implementation.
    assert tn.call_order == [
        ("write", b"\x0a"),  # Line feed
        ("read_until", b"> "),  # Wait for prompt
        ("write", b"exit\x0a"),  # Stop the process, line feed
        ("read_until", b"> "),  # Wait for prompt
        ("write", b"rtemsReboot()\x0a"),  # Force a reboot
        ("close",),  # End telnet connection
    ]


def test_reboot_hioc(capsys: pytest.CaptureFixture):
    # Fake reboot script tools/bin/power just echoes our command
    host = "asdfsdfasdf"
    assert rebootHIOC(host)
    captured = capsys.readouterr()
    assert captured.out.strip() == f"power {host} cycle"
    assert captured.err == ""


def test_find_pv():
    # See tests/ioc_data/ioc1/iocInfo/IOC.pvlist
    assert sorted(findPV(re.compile("TST:.*"), "ioc1")) == [
        "TST:FLOAT",
        "TST:INT",
        "TST:STRING",
    ]
    assert len(findPV(re.compile("IOC:PYTEST:.*"), "ioc1")) > 10
    assert not findPV(re.compile(".*BIG:CAT.*"), "ioc1")


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


dname_opts = (
    "iocs/common_ioc",
    "iocs/common_ioc/children",
    "iocs/common_ioc/children/build",
    "iocs/common_ioc/children/build/iocBoot/child_ioc",
)


@pytest.mark.parametrize(
    "dirname,abs_path",
    list(product(dname_opts, bopts)),
)
def test_validate_dir(dirname: str, abs_path: bool):
    # See tests/iocs, valid dirs have st.cmd
    # Need to cover every case in utils.stpaths:
    # "%s/children/build/iocBoot/%s/st.cmd"
    # "%s/build/iocBoot/%s/st.cmd"
    # "%s/iocBoot/%s/st.cmd"
    # Plus directory/st.cmd
    # Also needs to cover abs paths and relative paths to
    # EPICS_SITE_TOP (Which is set to the tests folder)
    if abs_path:
        dirname = str(TESTS_FOLDER / dirname)
    assert validateDir(dirname, "child_ioc")


def test_validate_dir_neg():
    assert not validateDir(str(TESTS_FOLDER), "child_ioc")
