#!/usr/bin/env python
import sys

from ..config import readConfig

if __name__ == "__main__":
    ioc = sys.argv[1]
    cfg = sys.argv[2]
    result = readConfig(cfg)
    if result is None:
        print("NO_DIRECTORY")
        sys.exit(-1)
    (mtime, config, hosts, vdict) = result
    for line in config:
        if line["id"] == ioc:
            print(line["dir"])
            sys.exit(0)
    print("NO_DIRECTORY")
    sys.exit(-1)
