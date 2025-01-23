#!/usr/bin/env python
import sys
from . import utils

if __name__ == "__main__":
    ioc = sys.argv[1]
    cfg = sys.argv[2]
    result = utils.readConfig(cfg, silent=True)
    if result == None:
        print("NO_DIRECTORY")
        sys.exit(-1)
    (mtime, config, hosts, vdict) = result
    for l in config:
        if l["id"] == ioc:
            print(l["dir"])
            sys.exit(0)
    print("NO_DIRECTORY")
    sys.exit(-1)
