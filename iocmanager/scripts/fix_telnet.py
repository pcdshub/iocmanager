#!/usr/bin/env python
import sys

from ..procserv_tools import fixTelnetShell

if __name__ == "__main__":
    port = sys.argv[1]
    fixTelnetShell("localhost", port)
