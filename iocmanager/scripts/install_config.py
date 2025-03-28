#!/usr/bin/env python
import sys

from .. import utils

if __name__ == "__main__":
    hutch = sys.argv[1]
    cfg = sys.argv[2]
    sys.exit(utils.installConfig(hutch, cfg))
