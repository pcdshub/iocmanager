#!/usr/bin/env python
import sys
import time

from .. import utils
from ..procserv_tools import startProc

if __name__ == "__main__":
    cfg = sys.argv[1]
    host = sys.argv[2]
    result = utils.readConfig(cfg)
    if result is None:
        print("Cannot read configuration for %s!" % cfg)
        sys.exit(-1)
    (mtime, config, hosts, vdict) = result
    for ioc in config:
        if ioc["host"] == host and not ioc["disable"]:
            startProc(cfg, ioc, True)
            try:
                time.sleep(ioc["delay"])
            except Exception:
                pass
