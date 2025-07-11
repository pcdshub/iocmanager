import itertools
import logging
import sys
from unittest.mock import Mock

import pytest

from .. import imgr, log_setup
from ..cli import args_backcompat, main, parse_args
from ..imgr import ImgrArgs


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
    return ImgrArgs(**vars(parse_args(cli_text.split(" ")[1:])))


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
