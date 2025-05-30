import pytest

from .. import imgr
from ..config import Config, IOCProc
from ..imgr import (
    ImgrArgs,
    args_backcompat,
    ensure_auth,
    ensure_iocname,
    get_proc,
    guess_hutch,
    parse_args,
    parse_host_port,
    status_cmd,
)
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


# Compare parameters to pyps_root/config/iocmanager.auth and iocmanager.special
good_user = "imgr_test"
bad_user = "not_authorized"
special_ioc = "has_two_variants"
normal_ioc = "nonono"
special_version = "ioc/pytest/normal"
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

    def fake_get_user():
        return user

    monkeypatch.setattr(imgr, "getuser", fake_get_user)
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
    status_cmd should give us the ioc status in stdout

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
