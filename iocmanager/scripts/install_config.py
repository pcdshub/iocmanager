#!/usr/bin/env python
import sys

from ..config import installConfig

if __name__ == "__main__":
    hutch = sys.argv[1]
    cfg = sys.argv[2]
    sys.exit(installConfig(hutch, cfg))
