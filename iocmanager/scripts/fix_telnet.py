#!/usr/bin/env python
import sys

from ..procserv_tools import fix_telnet_shell

if __name__ == "__main__":
    port = sys.argv[1]
    fix_telnet_shell("localhost", port)
