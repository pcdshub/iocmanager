from __future__ import annotations

import itertools
import subprocess
import time
from itertools import product
from pathlib import Path
from telnetlib import Telnet
from unittest.mock import Mock

import pytest

from .. import procserv_tools as pt
from ..config import Config, IOCProc
from ..procserv_tools import (
    applyConfig,
    check_status,
    checkTelnetMode,
    fixTelnetShell,
    killProc,
    openTelnet,
    readLogPortBanner,
    restartProc,
    startProc,
)
from . import TESTS_FOLDER
from .conftest import ProcServHelper

bopts = (True, False)


def test_readLogPortBanner(procserv: ProcServHelper):
    def get_info() -> dict[str, str | bool]:
        with Telnet("localhost", procserv.port, 1) as tn:
            return readLogPortBanner(tn)

    # readLogPortBanner truncates the running dir
    startup_dir = str(Path(procserv.startup_dir).relative_to(TESTS_FOLDER))

    # Always starts with restart = off and process stopped
    assert get_info() == {
        "status": pt.STATUS_SHUTDOWN,
        "pid": "-",
        "rid": procserv.proc_name,
        "autorestart": False,
        "autooneshot": False,
        "autorestartmode": True,
        "rdir": startup_dir,
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
        assert info["status"] == pt.STATUS_RUNNING
        assert int(info["pid"]) > 0
        assert info["rid"] == procserv.proc_name
        # True if procServ's version is high enough
        assert info["autorestartmode"]
        assert info["rdir"] == startup_dir

    info = wait_status(pt.STATUS_RUNNING, "Subprocess did not start")
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
    wait_status(pt.STATUS_SHUTDOWN, "Unable to shutdown")

    # Get a new info dict to check the no connect case
    with Telnet() as tn:
        bad_info = readLogPortBanner(tn)

    assert bad_info["status"] == pt.STATUS_ERROR


def test_check_status_good(procserv: ProcServHelper):
    # Should have a similar result to the readLogPortBanner initial test
    server = "localhost"
    # check_status truncates the running dir
    startup_dir = str(Path(procserv.startup_dir).relative_to(TESTS_FOLDER))
    assert check_status(server, procserv.port, procserv.proc_name) == {
        "status": pt.STATUS_SHUTDOWN,
        "pid": "-",
        "rid": procserv.proc_name,
        "autorestart": False,
        "autooneshot": False,
        "autorestartmode": True,
        "rdir": startup_dir,
    }
    # ping's exit code
    assert pt.pdict[server][1] == 0


def test_check_status_no_procserv():
    # Ping succeeds but telnet fails
    server = "localhost"
    ioc = "blarg"
    assert check_status(server, 31111, ioc) == {
        "status": pt.STATUS_NOCONNECT,
        "pid": "-",
        "rid": ioc,
        "autorestart": False,
        "autorestartmode": False,
        "rdir": "/tmp",
    }
    # ping's exit code
    assert pt.pdict[server][1] == 0


def test_check_status_no_host():
    # Ping fails
    server = "please-never-name-a-server-this"
    ioc = "blarg2"
    assert check_status(server, 31111, ioc) == {
        "status": pt.STATUS_DOWN,
        "pid": "-",
        "rid": ioc,
        "autorestart": False,
        "rdir": "/tmp",
    }
    # ping's exit code
    assert pt.pdict[server][1] > 0


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
    procmgrd.tn.read_until(pt.MSG_RESTART)
    fixTelnetShell("localhost", procmgrd.port)
    with Telnet("localhost", procmgrd.port, 1) as tn:
        tn.write(b"\n")
        bts = tn.read_until(b"> ", 1)
    assert b"> " in bts


autorestart_states = ("on", "off", "oneshot")
check_telnet_params = list(
    itertools.product(autorestart_states, autorestart_states, bopts)
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
    list(itertools.product(bopts, autorestart_states, bopts)),
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
        assert info["status"] == pt.STATUS_RUNNING
        subproc_pid = info["pid"]
        assert int(subproc_pid) > 0
        # Check that the pid is alive
        assert not subprocess.run(["ps", "--pid", str(subproc_pid)]).returncode
    else:
        assert info["status"] == pt.STATUS_SHUTDOWN
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


@pytest.mark.parametrize("verbose", bopts)
def test_kill_proc_bad(verbose: bool):
    # Note: I don't know how to reach some of the failure modes
    # For example, under what circumstances would the subprocess survive a kill?
    # We will test at least the case where the telnet can't connect
    # The expected behavior is unfortunately "just do nothing"
    killProc("localhost", 31111, verbose=verbose)


@pytest.mark.parametrize(
    "running,autorestart",
    list(itertools.product(bopts, autorestart_states)),
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
            assert info["status"] == pt.STATUS_RUNNING
        else:
            assert info["status"] == pt.STATUS_SHUTDOWN
        time.sleep(1)
        assert restartProc("localhost", procserv.port)
        # Now we can read the log of our open telnet
        if running:
            assert pt.MSG_ISSHUTTING in tn.read_until(pt.MSG_ISSHUTTING)
            assert pt.MSG_KILLED in tn.read_until(pt.MSG_KILLED)
        # Whether we started running or shutdown, now we should see it come online
        assert pt.MSG_RESTART in tn.read_until(pt.MSG_RESTART)
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
        assert info["status"] == pt.STATUS_RUNNING
        assert int(info["pid"]) > 0
        assert info["rid"] == name
        assert info["autorestart"]
        assert not info["autooneshot"]
        assert info["autorestartmode"]
    finally:
        # Try to clean up
        killProc("localhost", port)


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
    monkeypatch.setattr(pt, "killProc", mock.killProc)
    monkeypatch.setattr(pt, "startProc", mock.startProc)
    monkeypatch.setattr(pt, "restartProc", mock.restartProc)

    # We'll monkeypatch read_config, readStatusDir, check_status too
    # We don't want to mess around with real processes in this test
    read_config_result = Config(path="")
    read_status_dir_result = []

    def fake_read_config(*args, **kwargs):
        return read_config_result

    def fake_read_status_dir(*args, **kwargs):
        return read_status_dir_result

    def fake_check_status(host: str, port: int, id: str):
        # Simplify: presume status dir is correct, all hosts up
        status = pt.STATUS_SHUTDOWN
        for res in read_status_dir_result:
            if (res["rhost"], res["rport"]) == (host, port):
                status = pt.STATUS_RUNNING
                break
        return {
            "status": status,
            "rid": id,
            "pid": "-",
            "autorestart": True,
            "autorestartmode": False,
            "rdir": "/tmp",
        }

    monkeypatch.setattr(pt, "read_config", fake_read_config)
    monkeypatch.setattr(pt, "readStatusDir", fake_read_status_dir)
    monkeypatch.setattr(pt, "check_status", fake_check_status)

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
        return IOCProc(
            name=name,
            port=port or 20000,
            host=host or f"ctl-pytest-{name}",
            path=directory or f"ioc/pytest/{name}",
            disable=disable,
        )

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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
        read_config_result.procs.append(
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
    hioc_cfg = basic_fake_config(name="hioc-pytest", host="hioc-pytest")
    read_config_result.procs.append(hioc_cfg)
    not_start_args.append((hioc_cfg.host, hioc_cfg.port))
    not_kill_args.append((hioc_cfg.host, hioc_cfg.port))
    not_restart_args.append((hioc_cfg.host, hioc_cfg.port))

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
            if args[0] == sp_call.args[1].host and args[1] == sp_call.args[1].port:
                found_match = True
                break
        assert found_match
    for args in not_start_args:
        found_match = False
        for sp_call in mock.startProc.call_args_list:
            if args[0] == sp_call.args[1].host and args[1] == sp_call.args[1].port:
                found_match = True
                break
        assert not found_match
    assert mock.startProc.call_count == len(start_args)


def test_apply_config_early_fail(monkeypatch: pytest.MonkeyPatch):
    def fake_read_config(*args, **kwargs):
        return None

    monkeypatch.setattr(pt, "readConfig", fake_read_config)

    assert applyConfig("pytest", ioc="notarealiocpleasedontpbreakproc") != 0
