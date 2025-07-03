"""
The log_setup module defines logging setup utilities and constants.
"""

import argparse
import functools
import logging

SPAM_LEVEL = 5


def add_spam_level(lgr: logging.Logger):
    """
    Patch a "spam" function onto a logger instance.

    This function will log a message at the spam level,
    so that it won't appear in normal verbose mode but will appear
    in double verbose mode.
    """
    lgr.spam = functools.partial(lgr.log, SPAM_LEVEL)


def add_verbose_arg(parser: argparse.ArgumentParser):
    """
    Add a standard "verbose" arg to an argument parser.
    """
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


def iocmanager_log_config(args):
    """
    Configure logging with the given cli args.

    It is assumed that add_verbose_arg has been applied to the
    parses before parsing user arguments.
    """
    if not args.verbose:
        logging.basicConfig(level=logging.INFO)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=SPAM_LEVEL)
