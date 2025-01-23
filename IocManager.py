#!/usr/bin/env python
import sys

from psp.options import Options
from PyQt5 import QtWidgets

from .ioc_impl import GraphicUserInterface

if __name__ == "__main__":
    options = Options(["hutch"], [], [])
    try:
        options.parse()
    except Exception as msg:
        options.usage(str(msg))
        sys.exit(1)
    app = QtWidgets.QApplication([""])
    gui = GraphicUserInterface(app, options.hutch.lower())
    try:
        gui.show()
        retval = app.exec_()
    except KeyboardInterrupt:
        app.exit(1)
    sys.exit(0)
