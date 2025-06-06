#!/usr/bin/env python
import argparse
import logging
import sys

from qtpy import QtWidgets

from .ioc_impl import GraphicUserInterface
from .log_setup import SPAM_LEVEL

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

if __name__ == "__main__":
    args = parser.parse_args()
    if not args.verbose:
        log_level = logging.INFO
    elif args.verbose == 1:
        log_level = logging.DEBUG
    else:
        log_level = SPAM_LEVEL
    logging.basicConfig(level=log_level)
    logger = logging.getLogger(__name__)

    app = QtWidgets.QApplication([""])
    gui = GraphicUserInterface(app, args.hutch.lower())
    try:
        gui.show()
        retval = app.exec_()
    except KeyboardInterrupt:
        logger.debug("KeyboardInterrupt", exc_info=True)
        app.exit(1)
    sys.exit(retval)
