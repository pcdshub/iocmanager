import pytest

from ..imgr import ImgrArgs, parse_args


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
    """Test all normal and backcompat uses of the parser alone."""
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
    """Test that certain cli invocations are errors."""
    with pytest.raises(SystemExit):
        _parse_test_invocation(cli_text)


def _parse_test_invocation(cli_text: str) -> ImgrArgs:
    """Ensure both parser tests invoke the same way."""
    return parse_args(cli_text.split(" ")[1:])
