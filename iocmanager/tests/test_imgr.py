import dataclasses
import io
import itertools
import logging
import socket
import sys
import time
from unittest.mock import Mock

import pytest
from epics import PV

from .. import imgr, log_setup
from ..config import Config, IOCProc, read_config
from ..imgr import (
    ImgrArgs,
    add_cmd,
    args_backcompat,
    connect_cmd,
    disable_cmd,
    enable_cmd,
    ensure_auth,
    ensure_iocname,
    get_proc,
    guess_hutch,
    info_cmd,
    list_cmd,
    main,
    move_cmd,
    parse_args,
    parse_host_port,
    reboot_cmd,
    run_command,
    status_cmd,
    upgrade_cmd,
)
from ..procserv_tools import AutoRestartMode, ProcServStatus, check_status
from .conftest import ProcServHelper


@pytest.mark.parametrize(
    "cli_text,expected",
    (
        # Normal cases
        ("imgr IOCNAME status", ImgrArgs(ioc_name="IOCNAME", command="status")),
        (
            "imgr --hutch HUTCH IOCNAME status",
            ImgrArgs(ioc_name="IOCNAME", hutch="HUTCH", command="status"),
        ),
        (
            "imgr --verbose IOCNAME status",
            ImgrArgs(ioc_name="IOCNAME", verbose=1, command="status"),
        ),
        (
            "imgr -v IOCNAME status",
            ImgrArgs(ioc_name="IOCNAME", verbose=1, command="status"),
        ),
        (
            "imgr -vv IOCNAME status",
            ImgrArgs(ioc_name="IOCNAME", verbose=2, command="status"),
        ),
        ("imgr IOCNAME info", ImgrArgs(ioc_name="IOCNAME", command="info")),
        ("imgr IOCNAME connect", ImgrArgs(ioc_name="IOCNAME", command="connect")),
        (
            "imgr IOCNAME reboot soft",
            ImgrArgs(ioc_name="IOCNAME", command="reboot", reboot_mode="soft"),
        ),
        (
            "imgr IOCNAME reboot hard",
            ImgrArgs(ioc_name="IOCNAME", command="reboot", reboot_mode="hard"),
        ),
        ("imgr IOCNAME enable", ImgrArgs(ioc_name="IOCNAME", command="enable")),
        ("imgr IOCNAME disable", ImgrArgs(ioc_name="IOCNAME", command="disable")),
        (
            "imgr IOCNAME upgrade RELEASE",
            ImgrArgs(ioc_name="IOCNAME", command="upgrade", upgrade_dir="RELEASE"),
        ),
        (
            "imgr IOCNAME dir RELEASE",
            ImgrArgs(ioc_name="IOCNAME", command="dir", upgrade_dir="RELEASE"),
        ),
        (
            "imgr IOCNAME move HOSTPORT",
            ImgrArgs(ioc_name="IOCNAME", command="move", move_host_port="HOSTPORT"),
        ),
        (
            "imgr IOCNAME loc HOSTPORT",
            ImgrArgs(ioc_name="IOCNAME", command="loc", move_host_port="HOSTPORT"),
        ),
        (
            "imgr IOCNAME add --loc HOSTPORT --dir RELEASE --enable",
            ImgrArgs(
                ioc_name="IOCNAME",
                command="add",
                add_loc="HOSTPORT",
                add_dir="RELEASE",
                add_enable=True,
            ),
        ),
        (
            "imgr IOCNAME add --loc HOSTPORT --dir RELEASE --disable",
            ImgrArgs(
                ioc_name="IOCNAME",
                command="add",
                add_loc="HOSTPORT",
                add_dir="RELEASE",
                add_disable=True,
            ),
        ),
        ("imgr list", ImgrArgs(command="list")),
        ("imgr list --host HOST", ImgrArgs(command="list", list_host="HOST")),
        ("imgr list --enabled-only", ImgrArgs(command="list", list_enabled=True)),
        ("imgr list --disabled-only", ImgrArgs(command="list", list_disabled=True)),
        # Invocations from old docs (backcompat)
        # Copy block above and edit to:
        # delete --verbose checks
        # add -- to the commands
        # transpose IOCNAME and --hutch
        # revert e.g. --enabled-only -> --enabled_only
        ("imgr IOCNAME --status", ImgrArgs(ioc_name="IOCNAME", command="status")),
        (
            "imgr IOCNAME --hutch HUTCH --status",
            ImgrArgs(ioc_name="IOCNAME", hutch="HUTCH", command="status"),
        ),
        ("imgr IOCNAME --info", ImgrArgs(ioc_name="IOCNAME", command="info")),
        ("imgr IOCNAME --connect", ImgrArgs(ioc_name="IOCNAME", command="connect")),
        (
            "imgr IOCNAME --reboot soft",
            ImgrArgs(ioc_name="IOCNAME", command="reboot", reboot_mode="soft"),
        ),
        (
            "imgr IOCNAME --reboot hard",
            ImgrArgs(ioc_name="IOCNAME", command="reboot", reboot_mode="hard"),
        ),
        ("imgr IOCNAME --enable", ImgrArgs(ioc_name="IOCNAME", command="enable")),
        ("imgr IOCNAME --disable", ImgrArgs(ioc_name="IOCNAME", command="disable")),
        (
            "imgr IOCNAME --upgrade RELEASE",
            ImgrArgs(ioc_name="IOCNAME", command="upgrade", upgrade_dir="RELEASE"),
        ),
        (
            "imgr IOCNAME --dir RELEASE",
            ImgrArgs(ioc_name="IOCNAME", command="dir", upgrade_dir="RELEASE"),
        ),
        (
            "imgr IOCNAME --move HOSTPORT",
            ImgrArgs(ioc_name="IOCNAME", command="move", move_host_port="HOSTPORT"),
        ),
        (
            "imgr IOCNAME --loc HOSTPORT",
            ImgrArgs(ioc_name="IOCNAME", command="loc", move_host_port="HOSTPORT"),
        ),
        (
            "imgr IOCNAME --add --loc HOSTPORT --dir RELEASE --enable",
            ImgrArgs(
                ioc_name="IOCNAME",
                command="add",
                add_loc="HOSTPORT",
                add_dir="RELEASE",
                add_enable=True,
            ),
        ),
        (
            "imgr IOCNAME --add --loc HOSTPORT --dir RELEASE --disable",
            ImgrArgs(
                ioc_name="IOCNAME",
                command="add",
                add_loc="HOSTPORT",
                add_dir="RELEASE",
                add_disable=True,
            ),
        ),
        ("imgr --list", ImgrArgs(command="list")),
        ("imgr --list --host HOST", ImgrArgs(command="list", list_host="HOST")),
        ("imgr --list --enabled_only", ImgrArgs(command="list", list_enabled=True)),
        ("imgr --list --disabled_only", ImgrArgs(command="list", list_disabled=True)),
    ),
)
def test_parse_args_good(cli_text: str, expected: ImgrArgs):
    """parse_args should succeed and behave as expected for well-formed args"""
    assert _parse_test_invocation(cli_text) == expected


@pytest.mark.parametrize(
    "cli_text",
    (
        # IOCNAME must be before command
        "imgr list IOCNAME",
        # Use exactly one command
        "imgr IOCNAME info connect",
        # Some commands require an arg
        "imgr IOCNAME reboot",
        "imgr IOCNAME upgrade",
        "imgr IOCNAME dir",
        "imgr IOCNAME move",
        "imgr IOCNAME loc",
        # Add requires some arguments and exactly one of --enable, --disable
        "imgr IOCNAME add",
        "imgr IOCNAME add --loc HOSTPORT --dir RELEASE",
        "imgr IOCNAME add --loc HOSTPORT --dir RELEASE --enable --disable",
        # List can have at most one of --enabled-only, --disabled-only
        "imgr list --enabled-only --disabled-only",
    ),
)
def test_parse_args_errors(cli_text: str):
    """parse_args should fail if the user passes invalid args"""
    with pytest.raises(SystemExit):
        _parse_test_invocation(cli_text)


def _parse_test_invocation(cli_text: str) -> ImgrArgs:
    """
    If both parse_args tests share code, we can make sure we're testing them fairly.
    """
    return parse_args(cli_text.split(" ")[1:])


@pytest.mark.parametrize(
    "args,expected",
    (
        # Permute ioc_name and --hutch
        (
            ["name", "--hutch", "hutch", "CMD1", "arg"],
            ["--hutch", "hutch", "name", "CMD1", "arg"],
        ),
        # Strip -- from command names
        (["name", "--CMD2", "arg"], ["name", "CMD2", "arg"]),
        # Pass normal things through as-is
        (["name", "CMD3", "arg1", "arg2"], ["name", "CMD3", "arg1", "arg2"]),
        (["--hutch", "hutch", "name", "CMD1"], ["--hutch", "hutch", "name", "CMD1"]),
        (["CMD3", "arg1"], ["CMD3", "arg1"]),
    ),
)
def test_args_backcompat(args: list[str], expected: list[str]):
    """args_backcompat should rearrange the args to make old varaints like new"""
    assert args_backcompat(args=args, commands={"CMD1", "CMD2", "CMD3"}) == expected


@pytest.mark.parametrize(
    "host,ioc_name,expected",
    (
        # Guessable from both, host wins
        ("pytest-console", "ioc-second_hutch-test", "pytest"),
        # Guessable from host only
        ("pytest-console", "ioc-dumb-test", "pytest"),
        # Guessable from ioc_name only
        ("psbuild-rocky9-01", "ioc-second_hutch-test", "second_hutch"),
        # Not guessable
        ("psbuild-rocky9-01", "ioc-dumb-test", ""),
    ),
)
def test_guess_hutch(host: str, ioc_name: str, expected: str):
    """
    guess_hutch should pick valid hutches from the available options

    Note: this relies on there being valid hutches "pytest" and "second_hutch"
    as defined by the contents of the pyps_root/config folder.
    """
    if expected:
        assert guess_hutch(host=host, ioc_name=ioc_name) == expected
    else:
        with pytest.raises(RuntimeError):
            guess_hutch(host=host, ioc_name=ioc_name)


def test_get_proc_valid():
    """get_proc should find the process"""
    config = Config(path="")
    proc = IOCProc(name="test", port=0, host="", path="")
    config.add_proc(proc)
    assert get_proc(config, "test") == proc


def test_get_proc_invalid():
    """get_proc should raise if it cannot find the process"""
    config = Config(path="")
    with pytest.raises(ValueError):
        get_proc(config, "test")


def test_ensure_iocname_valid():
    """ensure_iocname should pass for a generic name"""
    ensure_iocname("test")


def test_ensure_iocname_invalid():
    """ensure_iocname should fail for empty string"""
    with pytest.raises(ValueError):
        ensure_iocname("")


def setup_user(username: str, monkeypatch: pytest.MonkeyPatch):
    """Helper for all the tests that need to spoof a username."""

    def fake_get_user():
        return username

    monkeypatch.setattr(imgr, "getuser", fake_get_user)


# Compare parameters to pyps_root/config/iocmanager.auth and iocmanager.special
good_user = "imgr_test"
bad_user = "not_authorized"
special_ioc = "has_two_variants"
normal_ioc = "nonono"
special_version = "ioc/variant/opt1"
normal_version = "badbadbad"


@pytest.mark.parametrize(
    "user,ioc_name,special_ok,special_version,expect_pass",
    (
        # Good users always are authorized
        (good_user, normal_ioc, False, "anything", True),
        (good_user, special_ioc, False, "should", True),
        (good_user, normal_ioc, True, "be", True),
        (good_user, special_ioc, True, "good", True),
        # Bad users are only authorized for special modes
        (bad_user, normal_ioc, False, normal_version, False),
        (bad_user, special_ioc, False, normal_version, False),
        (bad_user, normal_ioc, True, normal_version, False),
        (bad_user, special_ioc, True, normal_version, False),
        (bad_user, normal_ioc, False, special_version, False),
        (bad_user, special_ioc, False, special_version, False),
        (bad_user, normal_ioc, True, special_version, False),
        # Allowed: ioc is special, special is allowed, special version
        (bad_user, special_ioc, True, special_version, True),
        (bad_user, normal_ioc, False, "", False),
        (bad_user, special_ioc, False, "", False),
        (bad_user, normal_ioc, True, "", False),
        # Allowed: ioc is special, special is allowed, generic version
        (bad_user, special_ioc, True, "", True),
    ),
)
def test_ensure_auth(
    user: str,
    ioc_name: str,
    special_ok: bool,
    special_version: str,
    expect_pass: bool,
    monkeypatch: pytest.MonkeyPatch,
):
    """ensure_auth should raise if the user is not authorized"""
    setup_user(username=user, monkeypatch=monkeypatch)

    hutch = "pytest"
    if expect_pass:
        ensure_auth(
            hutch=hutch,
            ioc_name=ioc_name,
            special_ok=special_ok,
            special_version=special_version,
        )
    else:
        with pytest.raises(RuntimeError):
            ensure_auth(
                hutch=hutch,
                ioc_name=ioc_name,
                special_ok=special_ok,
                special_version=special_version,
            )


@pytest.mark.parametrize(
    "host_port,expected_host,port_range",
    (
        ("host1:35000", "host1", [35000, 35000]),
        ("host2:39160", "host2", [39160, 39160]),
        ("host1:closed", "host1", [30001, 38999]),
        ("host2:closed", "host2", [30001, 38999]),
        ("host1:open", "host1", [39100, 39199]),
        ("host2:open", "host2", [39100, 39199]),
    ),
)
def test_parse_host_port(
    host_port: str, expected_host: str, port_range: tuple[int, int]
):
    """parse_host_port should unpack host, port tuples and pick unused ports"""
    config = Config("")
    # Fill up some junk configs, try to cover a lot of the port range
    for port in range(30001, 31000):
        config.add_proc(
            IOCProc(
                name=f"ioc{port}",
                port=port,
                host="host1",
                path="",
            )
        )
    for port in range(39100, 39150):
        config.add_proc(
            IOCProc(
                name=f"ioc{port}",
                port=port,
                host="host2",
                path="",
            )
        )
    host, port = parse_host_port(config, host_port)
    assert host == expected_host
    assert port_range[0] <= port <= port_range[1]
    # Make sure that the automatically chosen port doesn't
    # conflict with existing ports
    assert config.validate()


def test_status_cmd(procserv: ProcServHelper, capsys: pytest.CaptureFixture):
    """
    status_cmd should give us the ioc status in stdout.

    No need to test tons of cases, check_status is sufficiently tested elsewhere.
    """
    config = Config("")
    config.add_proc(
        IOCProc(
            name=procserv.proc_name,
            port=procserv.port,
            host="localhost",
            path=procserv.startup_dir,
        )
    )
    capsys.readouterr()
    status_cmd(config=config, ioc_name=procserv.proc_name)
    result = capsys.readouterr()
    assert result.out == "SHUTDOWN\n"


@pytest.mark.parametrize(
    "alias,disable",
    (
        ("", False),
        ("Coolest Counter Ever", False),
        ("", True),
        ("Even Cooler Counter", True),
    ),
)
def test_info_cmd(
    alias: str, disable: bool, procserv: ProcServHelper, capsys: pytest.CaptureFixture
):
    """
    info_cmd should give us verbose ioc status in stdout.

    No need to test tons of cases, (see test_status_cmd), but there are some
    special branches for disabled IOCs and IOCs with aliases.
    """
    config = Config("")
    config.add_proc(
        IOCProc(
            name=procserv.proc_name,
            port=procserv.port,
            host="localhost",
            path=procserv.startup_dir,
            alias=alias,
            disable=disable,
        )
    )
    # This gets us to some of the interesting behavior for disable
    procserv.set_state_from_start(running=True, mode=AutoRestartMode.OFF)
    capsys.readouterr()
    info_cmd(config=config, ioc_name=procserv.proc_name)
    result = capsys.readouterr()
    # Let's not tie this test to precise output formats
    # But let's check to make sure the key info is present
    assert procserv.proc_name in result.out
    assert "localhost" in result.out
    assert str(procserv.port) in result.out
    assert str(procserv.startup_dir) in result.out
    if alias:
        assert alias in result.out
    assert "RUNNING" in result.out
    if disable:
        # This is a flabbergasted DISABLED, BUT RUNNING?!? message
        # But the specifics are subject to change
        assert "DISABLE" in result.out
        # One more case: if the IOC goes down it should say
        # DISABLED still, but not say running, and not NO CONNECT
        procserv.close_procserv()
        procserv.wait_procserv_closed(timeout=1.0)
        capsys.readouterr()
        info_cmd(config=config, ioc_name=procserv.proc_name)
        result2 = capsys.readouterr()
        assert "RUNNING" not in result2.out
        assert "DISABLE" in result2.out


def test_connect_cmd_good(
    procserv: ProcServHelper,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary: pytest.CaptureFixture,
):
    """
    connect_cmd should telnet us to the ioc's port
    """
    config = Config("")
    config.add_proc(
        IOCProc(
            name=procserv.proc_name,
            port=procserv.port,
            host="localhost",
            path=procserv.startup_dir,
        )
    )
    local_input = io.BytesIO()

    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdin", local_input)
        capfdbinary.readouterr()
        try:
            connect_cmd(config=config, ioc_name=procserv.proc_name)
        except RuntimeError:
            # Original idea was to ask for a quit but couldn't get anything to work
            # It should be sufficient to verify some form of connection
            ...

    result = capfdbinary.readouterr()
    assert b"Connected to localhost" in result.out


def test_connect_cmd_bad(capfdbinary: pytest.CaptureFixture):
    """
    connect_cmd should raise if the host or port can't be reached
    """
    ioc_name = "ioc_name"
    config = Config("")
    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=35000,
            host="localhost",
            path="",
        )
    )
    capfdbinary.readouterr()
    with pytest.raises(RuntimeError):
        connect_cmd(config=config, ioc_name=ioc_name)
    result = capfdbinary.readouterr()
    assert b"Connected to localhost" not in result.out


def test_reboot_cmd_soft(pvs):
    """
    reboot_cmd should write to the SYSRESET PV in soft mode
    """
    config = Config("")
    config.add_proc(
        IOCProc(
            name="ioc1",
            port=0,
            host="localhost",
            path="",
        )
    )
    # PV starts at 0
    pvname = [pv for pv in pvs if "SYSRESET" in pv][0]
    pv = PV(pvname)
    # Chill and wait for test IOC to start
    assert pv.get(timeout=10.0) == 0
    # Restart
    reboot_cmd(config=config, ioc_name="ioc1", reboot_mode="soft")
    for _ in range(10):
        if pv.get() == 1:
            break
        time.sleep(0.1)
    assert pv.get() == 1


@pytest.mark.parametrize(
    "running,mode",
    (
        (True, AutoRestartMode.OFF),
        (True, AutoRestartMode.ON),
        (True, AutoRestartMode.ONESHOT),
        (False, AutoRestartMode.OFF),
        (False, AutoRestartMode.ON),
        (False, AutoRestartMode.ONESHOT),
    ),
)
def test_reboot_cmd_hard(
    procserv: ProcServHelper, running: bool, mode: AutoRestartMode
):
    """
    reboot_cmd should telnet and send commands in hard mode

    This could probably be more thorough, but I'll trust that
    restart_proc is sufficiently tested elsewhere.
    """
    procserv.set_state_from_start(running=running, mode=mode)
    config = Config("")
    config.add_proc(
        IOCProc(
            name=procserv.proc_name,
            port=procserv.port,
            host="localhost",
            path=procserv.startup_dir,
        )
    )
    # Check that we're as we expect
    status = check_status(host="localhost", port=procserv.port, name=procserv.proc_name)
    assert status.autorestart_mode == mode
    if running:
        assert status.status == ProcServStatus.RUNNING
    else:
        assert status.status == ProcServStatus.SHUTDOWN
    # Reboot
    reboot_cmd(config=config, ioc_name=procserv.proc_name, reboot_mode="hard")
    # Wait for the dust to settle
    time.sleep(1.0)
    new_status = check_status(
        host="localhost", port=procserv.port, name=procserv.proc_name
    )
    # Check that we're running and in the same mode
    assert new_status.autorestart_mode == mode
    assert new_status.status == ProcServStatus.RUNNING


def test_reboot_cmd_other():
    """any other option should raise a ValueError"""
    with pytest.raises(ValueError):
        reboot_cmd(config=Config(""), ioc_name="anything", reboot_mode="wild")


def setup_mock_write_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[Config, str, str]]:
    """
    Test subroutine for all commands that would write the config and apply.

    It's really slow to do this a lot and it takes a lot of overhead.
    Trust that write_config and apply_config were tested sufficiently elsewhere,
    instead use this to keep track of how many times _write_apply was called
    and with what arguments.

    Parameters
    ----------
    monkeypatch : MonkeyPatch
        The monkeypatch test fixture for the current test.

    returns
    -------
    call_history : list[tuple[Config, str, str]]
        The arguments used to call _write_apply.
    """
    call_history = []

    def mock_write_apply(config: Config, ioc_name: str, hutch: str):
        call_history.append((config, ioc_name, hutch))

    monkeypatch.setattr(imgr, "_write_apply", mock_write_apply)
    return call_history


# Pick one failure case and a few simple success cases, not as thorough as auth test
@pytest.mark.parametrize(
    "user,ioc_name,should_run",
    (
        ("any_user", "any_ioc", False),
        ("imgr_test", "any_ioc", True),
        ("any_user", "just_a_name", True),
    ),
)
def test_enable_cmd(
    user: str, ioc_name: str, should_run: bool, monkeypatch: pytest.MonkeyPatch
):
    """
    enable_cmd should enable the ioc.

    Authentication can be done either by user or by special
    """
    setup_user(username=user, monkeypatch=monkeypatch)
    call_history = setup_mock_write_apply(monkeypatch=monkeypatch)

    hutch = "pytest"

    config = Config("")
    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=30001,
            host="localhost",
            path="",
            disable=True,
        )
    )
    assert config.procs[ioc_name].disable
    if should_run:
        enable_cmd(config=config, ioc_name=ioc_name, hutch=hutch)
        assert not config.procs[ioc_name].disable
        assert len(call_history) == 1
        assert call_history[0][0] == config
        assert call_history[0][1] == ioc_name
        assert call_history[0][2] == hutch
    else:
        with pytest.raises(RuntimeError):
            enable_cmd(config=config, ioc_name=ioc_name, hutch=hutch)
        assert config.procs[ioc_name].disable
        assert len(call_history) == 0


@pytest.mark.parametrize(
    "user,ioc_name,should_run",
    (
        ("any_user", "any_ioc", False),
        ("imgr_test", "any_ioc", True),
        ("any_user", "just_a_name", True),
    ),
)
def test_disable_cmd(
    user: str, ioc_name: str, should_run: bool, monkeypatch: pytest.MonkeyPatch
):
    """
    disable_cmd should disable the ioc.

    Authentication can be done either by user or by special
    """
    setup_user(username=user, monkeypatch=monkeypatch)
    call_history = setup_mock_write_apply(monkeypatch=monkeypatch)

    hutch = "pytest"

    config = Config("")
    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=30001,
            host="localhost",
            path="",
            disable=False,
        )
    )
    assert not config.procs[ioc_name].disable
    if should_run:
        disable_cmd(config=config, ioc_name=ioc_name, hutch=hutch)
        assert config.procs[ioc_name].disable
        assert len(call_history) == 1
        assert call_history[0][0] == config
        assert call_history[0][1] == ioc_name
        assert call_history[0][2] == hutch
    else:
        with pytest.raises(RuntimeError):
            disable_cmd(config=config, ioc_name=ioc_name, hutch=hutch)
        assert not config.procs[ioc_name].disable
        assert len(call_history) == 0


# Some complications here:
# - super special directory-specific special auth
# - the ioc actually needs a real st.cmd file or this will be mad at you
# - we can only change paths for things that already exist in the config
auth_user = "imgr_test"  # Can do any change (to a real dir)
other_user = "asdfsdf"  # Can only do special permitted changes
good_ioc = "has_two_variants"  # In special, opt1 and opt2 are permitted
bad_ioc1 = "just_a_name"  # In special, but not for dir changes!
bad_ioc2 = "asdfsdf"  # Not in special
real_ver = "ioc/variant/real"  # Should pass for auth (st.cmd)
good_ver = "ioc/variant/opt1"  # Should pass for special (st.cmd)
bad_ver1 = "ioc/variant/opt2"  # This dir doesn't have st.cmd so it must be rejected
bad_ver2 = "ioc/variant/asdfsdf"  # Does not exist


@pytest.mark.parametrize(
    "user,ioc_name,upgrade_dir,should_run",
    (
        # Variants with authenticated user: real IOCs should pass, fake should not
        (auth_user, good_ioc, real_ver, True),
        (auth_user, good_ioc, good_ver, True),
        (auth_user, good_ioc, bad_ver1, False),
        (auth_user, good_ioc, bad_ver2, False),
        (auth_user, bad_ioc1, real_ver, True),
        (auth_user, bad_ioc1, good_ver, True),
        (auth_user, bad_ioc1, bad_ver1, False),
        (auth_user, bad_ioc1, bad_ver2, False),
        (auth_user, bad_ioc2, real_ver, True),
        (auth_user, bad_ioc2, good_ver, True),
        (auth_user, bad_ioc2, bad_ver1, False),
        (auth_user, bad_ioc2, bad_ver2, False),
        # Variants with other user: real IOCs on the special list with dir should pass
        (other_user, good_ioc, real_ver, False),
        (other_user, good_ioc, good_ver, True),  # Note: only one that's all good
        (other_user, good_ioc, bad_ver1, False),
        (other_user, good_ioc, bad_ver2, False),
        (other_user, bad_ioc1, real_ver, False),
        (other_user, bad_ioc1, good_ver, False),
        (other_user, bad_ioc1, bad_ver1, False),
        (other_user, bad_ioc1, bad_ver2, False),
        (other_user, bad_ioc2, real_ver, False),
        (other_user, bad_ioc2, good_ver, False),
        (other_user, bad_ioc2, bad_ver1, False),
        (other_user, bad_ioc2, bad_ver2, False),
    ),
)
def test_upgrade_cmd(
    user: str,
    ioc_name: str,
    upgrade_dir: str,
    should_run: bool,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    upgrade_cmd should change the ioc's directory.

    Authentication can be done either by user or by special with the specified version
    present in the special file.

    Expect failures on bad auth or on picking a release without a st.cmd
    """
    setup_user(username=user, monkeypatch=monkeypatch)
    call_history = setup_mock_write_apply(monkeypatch=monkeypatch)

    hutch = "pytest"
    starting_dir = "original"

    config = Config("")
    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=30001,
            host="localhost",
            path=starting_dir,
        )
    )
    assert config.procs[ioc_name].path == starting_dir
    if should_run:
        upgrade_cmd(
            config=config, ioc_name=ioc_name, hutch=hutch, upgrade_dir=upgrade_dir
        )
        assert config.procs[ioc_name].path == upgrade_dir
        assert len(call_history) == 1
        assert call_history[0][0] == config
        assert call_history[0][1] == ioc_name
        assert call_history[0][2] == hutch
    else:
        with pytest.raises(RuntimeError):
            upgrade_cmd(
                config=config, ioc_name=ioc_name, hutch=hutch, upgrade_dir=upgrade_dir
            )
        assert config.procs[ioc_name].path == starting_dir
        assert len(call_history) == 0


@pytest.mark.parametrize(
    "user,host_port,host,port,should_run",
    (
        ("imgr_test", "pstest:40000", "pstest", 40000, True),
        ("imgr_test", "original:40000", "original", 40000, True),
        ("imgr_test", "pstest:30001", "pstest", 30001, True),
        ("asdfsd", "pstest:40000", "pstest", 40000, False),
    ),
)
def test_move_cmd(
    user: str,
    host_port: str,
    host: str,
    port: int,
    should_run: bool,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    move_cmd should move an IOC's host and port

    Only authenticated users can do this
    """

    setup_user(username=user, monkeypatch=monkeypatch)
    call_history = setup_mock_write_apply(monkeypatch=monkeypatch)

    ioc_name = "move_me"
    hutch = "pytest"
    starting_host = "original"
    starting_port = 30001

    config = Config("")
    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=starting_port,
            host=starting_host,
            path="",
        )
    )
    assert config.procs[ioc_name].host == starting_host
    assert config.procs[ioc_name].port == starting_port
    if should_run:
        move_cmd(
            config=config,
            ioc_name=ioc_name,
            hutch=hutch,
            move_host_port=host_port,
        )
        assert config.procs[ioc_name].host == host
        assert config.procs[ioc_name].port == port
        assert len(call_history) == 1
        assert call_history[0][0] == config
        assert call_history[0][1] == ioc_name
        assert call_history[0][2] == hutch
    else:
        with pytest.raises(RuntimeError):
            move_cmd(
                config=config,
                ioc_name=ioc_name,
                hutch=hutch,
                move_host_port=host_port,
            )
        assert config.procs[ioc_name].host == starting_host
        assert config.procs[ioc_name].port == starting_port
        assert len(call_history) == 0


@pytest.mark.parametrize(
    "user,add_enable,add_disable,same_port,same_name,should_run",
    (
        # The normal good cases
        ("imgr_test", True, False, False, False, True),
        ("imgr_test", False, True, False, False, True),
        # Each possible bad case in isolation
        # Everything is right except the user
        ("bad_user", True, False, False, False, False),
        # Neither enable nor disable
        ("imgr_test", False, False, False, False, False),
        # Both enable and disable
        ("imgr_test", True, True, False, False, False),
        # Port conflict
        ("imgr_test", True, False, True, False, False),
        # Name conflict
        ("imgr_test", True, False, False, True, False),
    ),
)
def test_add_cmd(
    user: str,
    add_enable: bool,
    add_disable: bool,
    same_port: bool,
    same_name: bool,
    should_run: bool,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    add_cmd should create a new IOC

    Only authenticated users can do this

    This should fail for various inputs, such as:
    - ambiguous enable/disable
    - re-using an existing host/port combination
    - adding something without a stcmd
    - addding the same name again
    """

    setup_user(username=user, monkeypatch=monkeypatch)
    call_history = setup_mock_write_apply(monkeypatch=monkeypatch)

    ioc_name = "add_me"
    ioc_dir = "ioc/counter"
    hutch = "pytest"
    host = "test_host"
    other_port = 30001
    if same_port:
        new_port = other_port
    else:
        new_port = other_port + 1
    if same_name:
        other_name = ioc_name
    else:
        other_name = "already_there"

    config = Config("")
    config.add_proc(
        IOCProc(
            name=other_name,
            port=other_port,
            host=host,
            path="",
        )
    )
    if same_name:
        assert ioc_name in config.procs
    else:
        assert ioc_name not in config.procs
    if should_run:
        add_cmd(
            config=config,
            ioc_name=ioc_name,
            hutch=hutch,
            add_loc=f"{host}:{new_port}",
            add_dir=ioc_dir,
            add_enable=add_enable,
            add_disable=add_disable,
        )
        assert config.procs[ioc_name].name == ioc_name
        assert config.procs[ioc_name].host == host
        assert config.procs[ioc_name].port == new_port
        assert len(call_history) == 1
        assert call_history[0][0] == config
        assert call_history[0][1] == ioc_name
        assert call_history[0][2] == hutch
    else:
        with pytest.raises((RuntimeError, ValueError)):
            add_cmd(
                config=config,
                ioc_name=ioc_name,
                hutch=hutch,
                add_loc=f"{host}:{new_port}",
                add_dir=ioc_dir,
                add_enable=add_enable,
                add_disable=add_disable,
            )
        if same_name:
            assert ioc_name in config.procs
        else:
            assert ioc_name not in config.procs
        assert len(call_history) == 0


@pytest.mark.parametrize(
    "list_host,list_enabled,list_disabled",
    (
        ("", True, False),
        ("", False, True),
        ("", False, False),
        ("one", True, False),
        ("one", False, True),
        ("one", False, False),
    ),
)
def test_list_cmd(
    list_host: str,
    list_enabled: bool,
    list_disabled: bool,
    capsys: pytest.CaptureFixture,
):
    """
    list_cmd shows the names of configured IOCs

    We can filter the list by host, by enabled, by disabled or not at all.
    Combinations of filters except enabled + disabled are valid.
    """
    config = Config("")

    config.add_proc(
        IOCProc(
            name="basic1",
            port=30001,
            host="one",
            path="",
        )
    )
    config.add_proc(
        IOCProc(
            name="basic2",
            port=30001,
            host="two",
            path="",
        )
    )
    config.add_proc(
        IOCProc(
            name="disa1",
            port=30002,
            host="one",
            path="",
        )
    )
    config.add_proc(
        IOCProc(
            name="disa2",
            port=30002,
            host="two",
            path="",
        )
    )
    config.add_proc(
        IOCProc(
            name="aliased1",
            port=30003,
            host="one",
            path="",
            alias="COOL",
        )
    )
    config.add_proc(
        IOCProc(
            name="aliased2",
            port=30003,
            host="two",
            path="",
            alias="BEANS",
        )
    )
    capsys.readouterr()
    list_cmd(
        config=config,
        list_host=list_host,
        list_enabled=list_enabled,
        list_disabled=list_disabled,
    )
    result = capsys.readouterr()
    all_names = set(config.procs)
    exclude_names = set()
    for proc in config.procs.values():
        if list_host and list_host != proc.host:
            exclude_names.add(proc.name)
        if list_disabled and not proc.disable:
            exclude_names.add(proc.name)
        if list_enabled and proc.disable:
            exclude_names.add(proc.name)
    include_names = all_names - exclude_names
    for name in include_names:
        assert name in result.out
        if config.procs[name].alias:
            assert config.procs[name].alias in result.out
    for name in exclude_names:
        assert name not in result.out
        if config.procs[name].alias:
            assert config.procs[name].alias not in result.out


# Settings for test_run_command
all_commands = (
    "status",
    "info",
    "connect",
    "reboot",
    "enable",
    "disable",
    "upgrade",
    "move",
    "add",
    "list",
)

command_aliases = {
    "dir": "upgrade",
    "loc": "move",
}

requires_ioc_name = [cmd for cmd in all_commands if cmd != "list"]

requires_hutch = (
    "enable",
    "disable",
    "upgrade",
    "move",
    "add",
)


@pytest.mark.parametrize(
    "cmd_alias",
    list(all_commands) + list(command_aliases),
)
def test_run_command(cmd_alias: str, monkeypatch: pytest.MonkeyPatch):
    """
    run_command resolves the hutch, reads the config file, and runs the correct cmd

    This will need to make heavy use of mocks and monkeypatches to avoid re-testing
    all the previous functions tested above.

    This test assumes that we have some naming consistency between the ImgrArgs
    fields and the keyword arguments in our functions.
    """
    mocks: dict[str, Mock] = {}
    for cmd in all_commands:
        mocks[cmd] = Mock()
        monkeypatch.setattr(imgr, f"{cmd}_cmd", mocks[cmd])

    # The specifics don't matter, except we may need to check them later
    imgr_args = ImgrArgs(
        ioc_name="ioc_name",
        hutch="pytest",
        command=cmd_alias,
        reboot_mode="reboot_mode",
        upgrade_dir="upgrade_dir",
        move_host_port="move_host_port",
        add_loc="add_loc",
        add_dir="add_dir",
        add_enable=True,
        add_disable=True,
        list_host="list_host",
        list_enabled=True,
        list_disabled=True,
    )

    run_command(imgr_args=imgr_args)

    try:
        command = command_aliases[cmd_alias]
    except KeyError:
        command = cmd_alias

    # Generic check, did we call the right command?
    for cmd in all_commands:
        if cmd == command:
            mocks[cmd].assert_called_once()
        else:
            mocks[cmd].assert_not_called()

    # Specific checks (command-specific)
    args: tuple
    kwargs: dict
    args, kwargs = mocks[command].call_args
    assert not args
    expected_config = read_config(imgr_args.hutch)
    assert kwargs["config"] == expected_config
    expected_kw_count = 1  # Config
    if command in requires_ioc_name:
        assert kwargs["ioc_name"] == imgr_args.ioc_name
        expected_kw_count += 1
    else:
        assert "ioc_name" not in kwargs
    if command in requires_hutch:
        assert kwargs["hutch"] == imgr_args.hutch
        expected_kw_count += 1
    else:
        assert "hutch" not in kwargs
    # For each cmd-prefixed field in ImgrArgs, check that it passes through
    for field_name, value in dataclasses.asdict(imgr_args).items():
        if field_name.startswith(f"{command}_"):
            assert kwargs[field_name] == value
            expected_kw_count += 1

    # Ensure no extra kw
    assert len(kwargs) == expected_kw_count


@pytest.mark.parametrize(
    "guess",
    (True, False),
)
def test_run_command_guess_hutch(guess: bool, monkeypatch: pytest.MonkeyPatch):
    """
    run_command should call guess_hutch if hutch was not provided
    """
    for cmd in all_commands:
        monkeypatch.setattr(imgr, f"{cmd}_cmd", Mock())
    guess_hutch_mock = Mock()
    monkeypatch.setattr(imgr, "guess_hutch", guess_hutch_mock)
    monkeypatch.setattr(imgr, "read_config", Mock())
    if guess:
        imgr_args = ImgrArgs(ioc_name="ioc_name", command="status")
    else:
        imgr_args = ImgrArgs(hutch="hutch", command="status")
    run_command(imgr_args=imgr_args)
    if guess:
        guess_hutch_mock.assert_called_with(
            host=socket.gethostname(), ioc_name="ioc_name"
        )
    else:
        guess_hutch_mock.assert_not_called()


def test_run_command_bad_command(monkeypatch: pytest.MonkeyPatch):
    """
    run_command should raise if the command is not valid
    """
    for cmd in all_commands:
        monkeypatch.setattr(imgr, f"{cmd}_cmd", Mock())
    monkeypatch.setattr(imgr, "read_config", Mock())
    imgr_args = ImgrArgs(hutch="pytest", command="asdfasdf")
    with pytest.raises(RuntimeError):
        run_command(imgr_args=imgr_args)


@pytest.mark.parametrize(
    "verbosity,succeed", itertools.product((0, 1, 2), (True, False))
)
def test_main(verbosity: int, succeed: bool, monkeypatch: pytest.MonkeyPatch):
    """
    main is the entrypoint, it parses args, sets up logging, and calls run_command.

    When run_command fails, it should give a nonzero return code, or raise in
    the verbose modes to give us the full tracebacks.
    """
    basic_config_mock = Mock()
    run_command_mock = Mock()

    monkeypatch.setattr(logging, "basicConfig", basic_config_mock)
    monkeypatch.setattr(imgr, "run_command", run_command_mock)

    argv = ["imgr"]
    if verbosity:
        verb_arg = "-" + verbosity * "v"
        argv.append(verb_arg)
    argv.append("list")
    if not succeed:
        run_command_mock.side_effect = RuntimeError

    monkeypatch.setattr(sys, "argv", argv)
    if verbosity and not succeed:
        with pytest.raises(RuntimeError):
            main()
    elif succeed:
        assert main() == 0
    else:
        assert main() > 0

    if verbosity == 0:
        basic_config_mock.assert_called_with(level=logging.INFO)
    elif verbosity == 1:
        basic_config_mock.assert_called_with(level=logging.DEBUG)
    elif verbosity == 2:
        basic_config_mock.assert_called_with(level=log_setup.SPAM_LEVEL)
    else:
        raise RuntimeError("Test writer error")
