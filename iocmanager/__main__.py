#!/usr/bin/env python
import argparse
import logging
import sys

from qtpy import QtWidgets

from .gui import IOCMainWindow
from .log_setup import SPAM_LEVEL
from .version import version as version_str

parser = argparse.ArgumentParser(
    prog="iocmanager",
    description=(
        "iocmanager is a GUI application for managing IOCs. "
        "It allows you to start, stop, and debug IOC processes "
        "running inside procServ on your servers."
    ),
)
parser.add_argument("--hutch", help="The area whose IOCs you'd like to manage.")
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
parser.add_argument(
    "--version", action="store_true", help="Show the version information and exit."
)

if __name__ == "__main__":
    args = parser.parse_args()
    if args.version:
        print(version_str)
        sys.exit(0)
    if not args.verbose:
        log_level = logging.INFO
    elif args.verbose == 1:
        log_level = logging.DEBUG
    else:
        log_level = SPAM_LEVEL
    logging.basicConfig(level=log_level)
    logger = logging.getLogger(__name__)

    app = QtWidgets.QApplication([""])
    gui = IOCMainWindow(hutch=args.hutch.lower())
    try:
        gui.show()
        retval = app.exec_()
    except KeyboardInterrupt:
        logger.debug("KeyboardInterrupt", exc_info=True)
        retval = 1
        app.exit(retval)
    sys.exit(retval)
