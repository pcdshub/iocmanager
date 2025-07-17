"""
The cli module contains CLI parsing for the imgr CLI tool.

imgr is a convenience cli script for accessing iocmanager's functions,
for example listing IOCs or moving them between hosts.
"""

import argparse
import logging
import sys

from .log_setup import add_verbose_arg, iocmanager_log_config
from .version import version as version_str

logger = logging.getLogger(__name__)


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
            "and start/stop IOCs without opening the full GUI."
        ),
        epilog=(
            "For backwards compatibility with older versions of imgr, "
            "all commands can be prepended with -- and some liberties are "
            "taken to allow various argument permutations. "
        ),
    )
    parser.add_argument(
        "--version", action="store_true", help="Show the version information and exit."
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
    add_verbose_arg(parser)
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
            "that matches what is in the iocmanager status field."
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


def parse_args(args: list[str]):
    """
    Create and run the parser.

    Warning: this can raise SystemExit from argparse!

    Parameters
    ----------
    args : list[str]
        The cli args, aside from the program name.

    Returns
    -------
    imgr_args : argparse.Namespace
        The interpreted, structured user arguments.
    """
    parser, commands = get_parser()
    args = args_backcompat(args, commands)
    return parser.parse_args(args)


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


def main(args: list[str] | None = None) -> int:
    """
    Main cli entrypoint for imgr.

    This function parses the cli args, sets up logging,
    and handles the return codes.

    The fanout is in run_command, the various subcommands are
    implemented in dedicated functions.

    The main outputs of the cli will be in stdout, log messages and
    errors will be in stderr.

    Parameters
    ----------
    args : list[str], optional
        The arguments to pass to imgr, for testing purposes.

    Returns
    -------
    return_code : int
        The shell return code for the cli program.
    """
    if args is None:
        args = sys.argv[1:]
    imgr_args = parse_args(args)
    if imgr_args.version:
        print(version_str)
        return 0
    iocmanager_log_config(imgr_args)
    from .imgr import _main

    try:
        _main(imgr_args)
    except Exception as exc:
        if imgr_args.verbose:
            raise
        else:
            logger.error(exc)
            return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
