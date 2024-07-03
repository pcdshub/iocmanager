#!/usr/bin/env python
import sys
from . import utils

if __name__ == '__main__':
  port = sys.argv[1]
  utils.fixTelnetShell('localhost', port)
