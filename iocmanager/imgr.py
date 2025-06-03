#!/usr/bin/env python
"""
The imgr module contains CLI-specific code for the imgr CLI tool.

imgr is a convenience cli script for accessing iocmanager's functions,
for example listing IOCs or moving them between hosts.
"""

import argparse
import logging
import socket
import subprocess
import sys
from dataclasses import dataclass
from getpass import getuser

from epics import caput

from . import log_setup
from . import procserv_tools as pt
from .config import (
    Config,
    IOCProc,
    check_auth,
    check_special,
    get_hutch_list,
    read_config,
    write_config,
)
from .epics_paths import has_stcmd
from .ioc_info import get_base_name
from .procserv_tools import ProcServStatus, apply_config, check_status, restart_proc

logger = logging.getLogger(__name__)


@dataclass(eq=True)
class ImgrArgs:
    """
    Internal representation of argparse namespace for type checking
    """

    # Main arguments
    ioc_name: str = ""
    hutch: str = ""
    verbose: int = 0
    # Mutually-exclusive commands.
    # If no specific args (--status, --info, --connect --enable, --disable)
    # Just the command name is enough.
    # Note this will be the variant without -- due to the preprocessing
    command: str = ""
    # --reboot soft, --reboot hard
    reboot_mode: str = ""
    # --upgrade ioc/lfe/gigECam/R6.0.0 (or --dir)
    upgrade_dir: str = ""
    # --move ctl-lfe-cam-02:CLOSED
    move_host_port: str = ""
    # --add --loc host:port --dir /some/dir --enable (or --disable)
    add_loc: str = ""
    add_dir: str = ""
    add_enable: bool = False
    add_disable: bool = False
    # --list [--host host] [(--enabled-only, --disabled-only)]
    list_host: str = ""
    list_enabled: bool = False
    list_disabled: bool = False


def get_parser() -> tuple[argparse.ArgumentParser, set[str]]:
    """
    Return the ArgumentParser object used by imgr and the command set.

    Returns
    -------
    parser, commands : Argumentparser, set[str]
        The parser object and all of the allowed subcommands.
    """
    port_help_text = (
        "Port can also be provided as closed or open "
        "to automatically select an available port in the "
        "closed range (30001-38999) or open range (39100-39199)."
    )
    parser = argparse.ArgumentParser(
        prog="imgr",
        description=(
            "Command-line utilities for iocmanager. "
            "These allow to you make changes to your iocmanager configuration "
            "And start/stop IOCs without opening the full GUI."
        ),
        epilog=(
            "For backwards compatibility with older versions of imgr, "
            "all commands can be prepended with -- and some liberties are "
            "taken to allow various argument permutations. "
        ),
    )
    parser.add_argument(
        "ioc_name",
        nargs="?",
        default="",
        help=(
            "The name of the IOC to act on, when applicable. "
            "Any action that targets a specific IOC "
            "will require an ioc_name argument."
        ),
    )
    parser.add_argument(
        "--hutch",
        default="",
        help=(
            "The name of the hutch to act on or read from. "
            "If not provided, there will be a best-effort "
            "attempt to guess which hutch to use."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help=(
            "Increase debug verbosity. "
            "-v or --verbose shows debug messages, "
            "-vv shows spammy debug messages."
        ),
    )
    subp = parser.add_subparsers(
        dest="command",
        title="commands",
        # description="Choose one command to run:",
        help="Use imgr {command} --help for more info about a command.",
        metavar="{command}",
    )
    subp.add_parser(
        "status",
        help="Show a one-line status for an IOC",
        description=(
            "Show a one-line status for an IOC "
            "that matches what is in the iocmanager status field. "
            f'It will be one of "{'", "'.join(st.value for st in ProcServStatus)}".'
        ),
    )
    subp.add_parser(
        "info",
        help="Show a more verbose status for an IOC",
        description=(
            "Show a more verbose for an IOC, "
            "including the host, port, and ioc directory. "
            "In some cases, this will also show additional annotations."
        ),
    )
    subp.add_parser(
        "connect",
        help="Open a terminal telnet session for this IOC",
        description=(
            "Open a terminal telnet session for this IOC. "
            "Remember: ctrl+[, then quit to exit."
        ),
    )
    reboot_cmd = subp.add_parser(
        "reboot",
        help="Reboot an IOC",
        description=(
            "Reboot an IOC. "
            "You must choose between a soft reboot, "
            "which turns off the IOC via the SYSRESET PV, "
            "allowing procServ to turn it back on, "
            "or a hard reboot, "
            "which stops and starts the IOC manually via telnet."
        ),
    )
    reboot_cmd.add_argument(
        "reboot_mode",
        choices=("soft", "hard"),
        help="Whether to do a soft reboot or a hard reboot.",
    )
    subp.add_parser(
        "enable",
        help="Enable and start an IOC",
        description=(
            "Mark an IOC as enabled in the config file. Start the IOC if needed."
        ),
    )
    subp.add_parser(
        "disable",
        help="Disable and kill an IOC",
        description=(
            "Mark an IOC as disabled in the config file. Kill the IOC if needed."
        ),
    )
    upgrade_cmd = subp.add_parser(
        "upgrade",
        help="Change an IOC's release or directory",
        description=(
            "Change an IOC's release or directory in the config file. "
            "Restart the IOC if needed. "
        ),
    )
    dir_cmd = subp.add_parser(
        "dir",
        help="Alias of upgrade",
        description=upgrade_cmd.description,
    )
    for cmd in (upgrade_cmd, dir_cmd):
        cmd.add_argument(
            "upgrade_dir",
            help="The release or directory to use for the IOC.",
        )
    move_cmd = subp.add_parser(
        "move",
        help="Move an IOC to a different host",
        description=(
            "Move an IOC to a different host, "
            "or to a different port on the same host. "
            "Expects either a HOST or a HOST:PORT specification. "
            "If no port is provided, keep the same port as before. "
            f"{port_help_text}"
        ),
    )
    loc_cmd = subp.add_parser(
        "loc",
        help="Alias of move",
        description=move_cmd.description,
    )
    for cmd in (move_cmd, loc_cmd):
        cmd.add_argument(
            "move_host_port",
            help="The HOST or HOST:PORT destination of the move.",
        )
    add_cmd = subp.add_parser(
        "add",
        help="Add a new IOC to the iocmanager configuration",
        description=(
            "Add a new IOC to the iocmanager configuration. "
            "Note that both --loc and --dir must be supplied as arguments, "
            "and that exactly one of --enable and --disable must be chosen."
        ),
    )
    add_cmd.add_argument(
        "--loc",
        required=True,
        dest="add_loc",
        help=f"The HOST:PORT setting to use for the new IOC. {port_help_text}",
    )
    add_cmd.add_argument(
        "--dir",
        required=True,
        dest="add_dir",
        help="The new IOC's release or directory.",
    )
    add_enable_group = add_cmd.add_mutually_exclusive_group(required=True)
    add_enable_group.add_argument(
        "--enable",
        action="store_true",
        dest="add_enable",
        help=(
            "Include this argument to add the IOC in an enabled state. "
            "If we add an enabled IOC, we'll also start the new IOC."
        ),
    )
    add_enable_group.add_argument(
        "--disable",
        action="store_true",
        dest="add_disable",
        help=(
            "Include this argument to add the IOC in an disabled state. "
            "This will not start the IOC."
        ),
    )
    list_cmd = subp.add_parser(
        "list",
        help="Show the names of the IOCs in the iocmanager config",
        description=(
            "Show the names of the IOCs in the iocmanager config. "
            "The names will be printed to stdout, one per line. "
            "Use the optional arguments to filter the output."
        ),
    )
    list_cmd.add_argument(
        "--host",
        default="",
        dest="list_host",
        help="Limit the --list output to only IOCs configured for a specific host.",
    )
    list_enable_group = list_cmd.add_mutually_exclusive_group()
    list_enable_group.add_argument(
        "--enabled_only",
        "--enabled-only",
        action="store_true",
        dest="list_enabled",
        help="Limit the --list output to only IOCs that are enabled.",
    )
    list_enable_group.add_argument(
        "--disabled_only",
        "--disabled-only",
        action="store_true",
        dest="list_disabled",
        help="Limit the --list output to only IOCs that are disabled.",
    )
    return parser, set(subp.choices)


def parse_args(args: list[str]) -> ImgrArgs:
    """
    Translate the cli args into our dataclass representation.

    Warning: this can raise SystemExit from argparse!

    Parameters
    ----------
    args : list[str]
        The cli args, aside from the program name.

    Returns
    -------
    imgr_args : ImgrArgs
        The interpreted, structured user arguments.
    """
    parser, commands = get_parser()
    imgr_args = ImgrArgs()
    args = args_backcompat(args, commands)
    parser.parse_args(args, namespace=imgr_args)
    return imgr_args


def args_backcompat(args: list[str], commands: set[str]) -> list[str]:
    """
    Preprocess the args to support old variants that are otherwise parser errors.

    I couldn't support the old behavior 1:1 while leveraging argparse checking,
    because you're normally not allowed to use -- to prepend subcommand names
    and because a nargs="?" positional argument like ioc_name are hard for the
    parser to tell apart from the subcommands if they are allowed to be passed
    in arbitrary orders.

    This difficulty only applies in the general case, and we have a specific case here.
    So, we do some light preprocessing of the input given our specific knowledge
    about what the user and the parser expects.

    Old behavior to support here:
    - Passing ioc_name prior to --hutch HUTCH
    - Prepending any command name with --

    Parameters
    ----------
    args : list[str]
        The cli args, aside from the program name.
    commands : set[str]
        The valid commands, e.g. those returned from get_parser().

    Returns
    -------
    new_args : list[str]
        A modified copy of args with backwards compatibility tweaks.
    """
    new_args = []
    prev_arg = ""
    has_chosen_cmd = False
    for user_arg in args:
        # Send --hutch HUTCH to the front
        if user_arg == "--hutch":
            new_args.insert(0, "--hutch")
        elif prev_arg == "--hutch":
            new_args.insert(1, user_arg)
        # Once we've processed a command, just include the rest
        elif has_chosen_cmd:
            new_args.append(user_arg)
        # Here we find a properly named command
        elif user_arg in commands:
            new_args.append(user_arg)
            has_chosen_cmd = True
        # Here we find an old-style command, remove the --
        elif user_arg.startswith("--") and user_arg.removeprefix("--") in commands:
            new_args.append(user_arg.removeprefix("--"))
            has_chosen_cmd = True
        # Not a command or post-command, just add it to the args
        else:
            new_args.append(user_arg)
        prev_arg = user_arg
    return new_args


# TODO decide if this should be part of another module, may be useful in GUI
def guess_hutch(host: str, ioc_name: str) -> str:
    """
    In cases where hutch is not provided, guess given the inputs.

    A guess using the hostname takes priority over a guess from the
    ioc name.

    Returns the name of a valid hutch or raises.

    Parameters
    ----------
    host : str
        The name of the host we're on.
    ioc_name : str
        The name of the ioc we're working with.

    Returns
    -------
    hutch : str
        A valid hutch that matches our situation.
    """
    options = set(get_hutch_list())
    for name in (host, ioc_name):
        for part in name.split("-"):
            if part in options:
                return part
    raise RuntimeError(
        f"Cannot guess hutch from host={host}, ioc_name={ioc_name}. "
        f"Available hutches are {options}."
    )


def get_proc(config: Config, ioc_name: str) -> IOCProc:
    """
    Helper function for common handling of the ioc_name argument.

    This ensures we have the same error handling everywhere for
    this standard operation.

    Parameters
    ----------
    config : Config
        The loaded config object.
    ioc_name : str
        The name of the IOC.

    Returns
    -------
    ioc_proc : IOCProc
        The data associated with the given IOC.
    """
    try:
        return config.procs[ioc_name]
    except KeyError as exc:
        raise ValueError(f"IOC {ioc_name} not found in config!") from exc


def ensure_iocname(ioc_name: str):
    """
    Helper function for post-parsing of the ioc_name.

    Raise if the ioc_name is invalid, e.g. if the user did not provide a name.
    Normally you'd solve this in the parser by making ioc_name a positional
    argument to the subcommands, but the original version of the app chose
    not to do this so we'll need to add an extra check ourselves sometimes.

    Parameters
    ----------
    ioc_name : str
        The name of the ioc
    """
    if not ioc_name:
        raise ValueError("Must provide an ioc_name argument, see imgr --help.")


def ensure_auth(hutch: str, ioc_name: str, special_ok: bool, special_version: str = ""):
    """
    Helper function for common handling of authentication.

    This pulls together a few core module functions and wraps them
    with clear errors for the user.

    Returns if auth is ok, raises if not.

    Parameters
    ----------
    hutch : str
        The name of the hutch.
    ioc_name : str
        The name of the IOC.
    special_ok : bool
        True if authentication through the "iocmanger.special" file
        is sufficient, False if full authentication through the
        "iocmanager.auth" file is needed.
    special_version: str, optional
        If looking for special authentication to change to a specific special
        version/release/dir of this ioc, it should be provided here.
    """
    user = getuser()
    if check_auth(user=user, hutch=hutch):
        return
    elif not special_ok:
        ...
    elif special_version:
        if check_special(
            req_ioc=ioc_name, req_hutch=hutch, req_version=special_version
        ):
            return
    elif check_special(req_ioc=ioc_name, req_hutch=hutch):
        return

    msg = (
        f"Action not permitted for {user} in {hutch}. "
        "Request access from the hutch controls system owner"
    )
    if special_ok:
        msg = f"{msg}, or request that {ioc_name} be added to iocmanager.special."
    else:
        msg = f"{msg}."

    raise RuntimeError(msg)


# TODO decide if the open-port-finding code should be in a module
# because it might be used in the GUI too
def parse_host_port(config: Config, host_port: str) -> tuple[str, int]:
    """
    Convert the "host:port" string from the cli to a (str host, int port) tuple.

    The port might literally be an integer, or it might
    be "closed" or "open", in which case we need to pick
    an unsed port in the correct range.

    Always returns a (host, port) tuple or raises.

    Parameters
    ----------
    config : Config
        The active iocmanager configuration.
    host_port : str
        The user's host:port input.

    Returns
    -------
    host, port : str, int
        Tuple of host, port.
    """
    try:
        host, port = host_port.split(":")
    except ValueError as exc:
        raise ValueError(f"Expected host:port format, received {host_port}") from exc
    try:
        return host, int(port)
    except ValueError:
        ...
    if port.lower() == "closed":
        port_options = range(30001, 39000)
    elif port.lower() == "open":
        port_options = range(39100, 39200)
    else:
        raise ValueError(
            f"Invalid port {port}, expected an integer or one of closed, open"
        )
    used_ports = set()
    for ioc_proc in config.procs.values():
        if ioc_proc.host == host:
            used_ports.add(ioc_proc.port)
    for check_port in port_options:
        if check_port not in used_ports:
            return host, check_port

    raise ValueError(f"No available port for {host_port}")


def status_cmd(config: Config, ioc_name: str):
    """
    Implementation of "imgr ioc_name status"

    This prints a one-line status for an IOC matching the options from
    the ProcServStatus enum, for example it might say NO CONNECT or RUNNING.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    """
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    status = check_status(host=ioc_proc.host, port=ioc_proc.port, name=ioc_name)
    print(status.status.name)


def info_cmd(config: Config, ioc_name: str):
    """
    Implementation of "imgr ioc_name info"

    This shows verbose status information about an IOC.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    """
    ensure_iocname(ioc_name)
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    status = check_status(host=ioc_proc.host, port=ioc_proc.port, name=ioc_name)

    status_text = status.status.name
    if ioc_proc.disable:
        if status.status == pt.ProcServStatus.NOCONNECT:
            status_text = "DISABLED"
        elif status.status == pt.ProcServStatus.RUNNING:
            status_text = "DISABLED, BUT RUNNING?!?"

    if ioc_proc.alias:
        print(f"{ioc_name} ({ioc_proc.alias}):")
    else:
        print(f"{ioc_name}:")

    print(f"    host  : {ioc_proc.host}")
    print(f"    port  : {ioc_proc.port}")
    print(f"    dir   : {ioc_proc.path}")
    print(f"    status: {status_text}")


def connect_cmd(config: Config, ioc_name: str):
    """
    Implementation of "imgr ioc_name connect"

    This opens a telnet connection to the IOC.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    """
    ensure_iocname(ioc_name)
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    subpr = subprocess.run(["telnet", ioc_proc.host, str(ioc_proc.port)])
    try:
        subpr.check_returncode()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f'Error running "telnet {ioc_proc.host} {ioc_proc.port}"'
        ) from exc


def reboot_cmd(config: Config, ioc_name: str, reboot_mode: str):
    """
    Implementation of "imgr ioc_name reboot soft/hard".

    These commands restart the IOC process.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    reboot_mode : str
        One of "soft" or "hard"
    """
    ensure_iocname(ioc_name)
    match reboot_mode.lower():
        case "soft":
            base = get_base_name(ioc_name)
            caput(base + ":SYSRESET", 1)
        case "hard":
            ioc_proc = get_proc(config=config, ioc_name=ioc_name)
            restart_proc(ioc_proc.host, ioc_proc.port)
        case other:
            raise ValueError(f"Invalid reboot mode {other}, must be soft or hard.")


def _write_apply(config: Config, ioc_name: str, hutch: str):
    """
    Super common write + apply combination.

    Pulled out for ease of testing.
    """
    write_config(cfgname=hutch, config=config)
    apply_config(cfg=hutch, verify=None, ioc=ioc_name)


def _apply_disable(config: Config, ioc_name: str, hutch: str, disable: bool):
    """Shared routines between enable_cmd and disable_cmd."""
    ensure_iocname(ioc_name)
    ensure_auth(hutch=hutch, ioc_name=ioc_name, special_ok=True)
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    ioc_proc.disable = disable
    _write_apply(config=config, ioc_name=ioc_name, hutch=hutch)


def enable_cmd(config: Config, ioc_name: str, hutch: str):
    """
    Implementation of "imgr ioc_name enable".

    This command enables an IOC in the config and starts it.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    hutch : str
        The name of the hutch this is in, for auth
    """
    _apply_disable(config=config, ioc_name=ioc_name, hutch=hutch, disable=False)


def disable_cmd(config: Config, ioc_name: str, hutch: str):
    """
    Implementation of "imgr ioc_name disable".

    This command disables an IOC in the config and kills it.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    hutch : str
        The name of the hutch this is in, for auth
    """
    _apply_disable(config=config, ioc_name=ioc_name, hutch=hutch, disable=True)


def upgrade_cmd(config: Config, ioc_name: str, hutch: str, upgrade_dir: str):
    """
    Implementation of "imgr ioc_name upgrade --dir directory"

    This command changes the release directory of an IOC,
    e.g. to upgrade to a new version.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    hutch : str
        The name of the hutch this is in, for auth
    upgrade_dir : str
        The new directory for the ioc.
    """
    ensure_iocname(ioc_name)
    ensure_auth(
        hutch=hutch, ioc_name=ioc_name, special_ok=True, special_version=upgrade_dir
    )
    if not has_stcmd(directory=upgrade_dir, ioc_name=ioc_name):
        raise RuntimeError(f"{upgrade_dir} does not have an st.cmd for {ioc_name}!")
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    ioc_proc.path = upgrade_dir
    _write_apply(config=config, ioc_name=ioc_name, hutch=hutch)


def move_cmd(config: Config, ioc_name: str, hutch: str, move_host_port: str):
    """
    Implementation of "imgr ioc_name move host:port".

    This command moves an IOC to a new location, possibly on a different
    host, stopping the old IOC and starting the new one if necessary.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    hutch : str
        The name of the hutch this is in, for auth
    move_host_port : str
        The host:port combination to move the ioc to
    """
    ensure_iocname(ioc_name)
    ensure_auth(hutch=hutch, ioc_name=ioc_name, special_ok=False)
    host, port = parse_host_port(config=config, host_port=move_host_port)
    ioc_proc = get_proc(config=config, ioc_name=ioc_name)
    ioc_proc.host = host
    ioc_proc.port = port
    if not config.validate():
        raise RuntimeError(
            f"Port conflict when moving {ioc_name} to {host}:{port}, not moved."
        )
    _write_apply(config=config, ioc_name=ioc_name, hutch=hutch)


def add_cmd(
    config: Config,
    ioc_name: str,
    hutch: str,
    add_loc: str,
    add_dir: str,
    add_enable: bool,
    add_disable: bool,
):
    """
    Implementation of "imgr ioc_name add --loc host:port --dir dir --enable/disable

    This command adds a new ioc to the config and optionally enables and starts it.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    ioc_name : str
        The name of the ioc to check
    hutch : str
        The name of the hutch this is in, for auth
    add_loc : str
        The host:port combination to use for the ioc
    add_dir : str
        The directory of the ioc's repo
    add_enable : bool
        True if the user passed the --enable arg, which is in a required mutually
        exclusive group with the --disable arg.
    add_disable : bool
        True if the user passed the --disable arg, which is in a required mutually
        exclusive group with the --enable arg.
    """
    ensure_iocname(ioc_name)
    ensure_auth(hutch=hutch, ioc_name=ioc_name, special_ok=False)
    if not has_stcmd(directory=add_dir, ioc_name=ioc_name):
        raise RuntimeError(f"{add_dir} does not have an st.cmd for {ioc_name}!")
    if not add_enable ^ add_disable:
        raise ValueError("Must provide exactly one of --enable or --disable.")
    elif add_enable:
        disable = False
    elif add_disable:
        disable = True
    else:
        raise RuntimeError("Invalid codepath?")

    host, port = parse_host_port(config=config, host_port=add_loc)

    config.add_proc(
        IOCProc(
            name=ioc_name,
            port=port,
            host=host,
            path=add_dir,
            alias="",
            disable=disable,
            cmd="",
            history=[],
        )
    )
    if not config.validate():
        del config.procs[ioc_name]
        raise RuntimeError(
            f"Port conflict when adding {ioc_name} at {host}:{port}, aborting."
        )
    _write_apply(config=config, ioc_name=ioc_name, hutch=hutch)


def list_cmd(config: Config, list_host: str, list_enabled: bool, list_disabled: bool):
    """
    Implementation of "imgr ioc_name list --host host --enabled-only/--disabled-only

    This command shows the names of configured iocs.

    Parameters
    ----------
    config : Config
        The parsed iocmanager configuration
    list_host : str
        If provided, only show iocs running on this host
    list_enabled : bool
        If True, only show enabled IOCs. This is mutually incompatible with
        list_disabled in the parser.
    list_disabled : bool
        If True, only show disabled IOCs. This is mutually incompatible with
        list_disabled in the parser.
    """
    for ioc_proc in config.procs.values():
        # Skip if wrong host
        if list_host and ioc_proc.host != list_host:
            continue
        # Skip if --enabled-only and disabled
        if list_enabled and ioc_proc.disable:
            continue
        # Skip if --disabled-only and enabled
        if list_disabled and not ioc_proc.disable:
            continue
        # We're through the filters, show the name
        if ioc_proc.alias:
            print(f"{ioc_proc.name} ({ioc_proc.alias})")
        else:
            print(ioc_proc.name)


def run_command(imgr_args: ImgrArgs):
    """
    Main work function. Fans out to the various subcommands.

    Subcommands are expected to raise with clear error messages
    if they have any issues.

    Their return values will be unused and could optionally be
    used as unit test aids.

    Parameters
    ----------
    imgr_args : ImgrArgs
        The structured options chosen by the user.
    """
    if imgr_args.hutch:
        hutch = imgr_args.hutch
    else:
        hutch = guess_hutch(
            host=socket.gethostname(),
            ioc_name=imgr_args.ioc_name,
        )
    config = read_config(hutch)
    match imgr_args.command:
        case "status":
            status_cmd(config=config, ioc_name=imgr_args.ioc_name)
        case "info":
            info_cmd(config=config, ioc_name=imgr_args.ioc_name)
        case "connect":
            connect_cmd(config=config, ioc_name=imgr_args.ioc_name)
        case "reboot":
            reboot_cmd(
                config=config,
                ioc_name=imgr_args.ioc_name,
                reboot_mode=imgr_args.reboot_mode,
            )
        case "enable":
            enable_cmd(config=config, ioc_name=imgr_args.ioc_name, hutch=hutch)
        case "disable":
            disable_cmd(config=config, ioc_name=imgr_args.ioc_name, hutch=hutch)
        case "upgrade" | "dir":
            upgrade_cmd(
                config=config,
                ioc_name=imgr_args.ioc_name,
                hutch=hutch,
                upgrade_dir=imgr_args.upgrade_dir,
            )
        case "move" | "loc":
            move_cmd(
                config=config,
                ioc_name=imgr_args.ioc_name,
                hutch=hutch,
                move_host_port=imgr_args.move_host_port,
            )
        case "add":
            add_cmd(
                config=config,
                ioc_name=imgr_args.ioc_name,
                hutch=hutch,
                add_loc=imgr_args.add_loc,
                add_dir=imgr_args.add_dir,
                add_enable=imgr_args.add_enable,
                add_disable=imgr_args.add_disable,
            )
        case "list":
            list_cmd(
                config=config,
                list_host=imgr_args.list_host,
                list_enabled=imgr_args.list_enabled,
                list_disabled=imgr_args.list_disabled,
            )
        case other:
            raise RuntimeError(f"{other} is not a valid imgr command.")


def main() -> int:
    """
    Main cli entrypoint for imgr.

    This function parses the cli args, sets up logging,
    and handles the return codes.

    The fanout is in run_command, the various subcommands are
    implemented in dedicated functions.

    The main outputs of the cli will be in stdout, log messages and
    errors will be in stderr.

    Returns
    -------
    return_code : int
        The shell return code for the cli program.
    """
    imgr_args = parse_args(sys.argv[1:])
    if not imgr_args.verbose:
        logging.basicConfig(level=logging.INFO)
    elif imgr_args.verbose == 1:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=log_setup.SPAM_LEVEL)
    try:
        run_command(imgr_args)
    except Exception as exc:
        if imgr_args.verbose:
            raise
        else:
            print(exc)
            return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
