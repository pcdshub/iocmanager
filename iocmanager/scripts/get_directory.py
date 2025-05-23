#!/usr/bin/env python
import sys

from ..config import read_config

if __name__ == "__main__":
    ioc = sys.argv[1]
    cfg = sys.argv[2]
    try:
        config = read_config(cfg)
    except Exception:
        print("NO DIRECTORY")
        sys.exit(-1)
    try:
        iocproc = config.procs[ioc]
    except KeyError:
        print("NO_DIRECTORY")
        sys.exit(-1)

    print(iocproc.path)
    sys.exit(0)
