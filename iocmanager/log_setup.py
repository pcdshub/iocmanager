"""
The log_setup module defines logging setup utilities and constants.
"""

import argparse
import logging

SPAM_LEVEL = 5


def log_spam(lgr: logging.Logger, *args, **kwargs):
    """
    Helper for logging at the spam level.

    Spam log messages won't appear in normal verbose mode
    but will appear in double verbose mode.
    """
    lgr.log(SPAM_LEVEL, *args, **kwargs)


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
    logging.addLevelName(level=SPAM_LEVEL, levelName="SPAM")
    if not args.verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(levelname)s: %(message)s",
        )
    elif args.verbose == 1:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s:%(name)s %(message)s",
        )
    else:
        logging.basicConfig(
            level=SPAM_LEVEL,
            format="%(asctime)s %(levelname)s:%(name)s:%(lineno)d %(message)s",
        )
