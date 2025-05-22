#!/usr/bin/env python
import sys
import time

from ..config import read_config
from ..procserv_tools import start_proc

if __name__ == "__main__":
    cfg = sys.argv[1]
    host = sys.argv[2]
    try:
        config = read_config(cfg)
    except Exception:
        print("Cannot read configuration for %s!" % cfg)
        sys.exit(-1)
    for ioc in config.procs:
        if ioc.host == host and not ioc.disable:
            start_proc(cfg, ioc, True)
            try:
                time.sleep(ioc["delay"])
            except Exception:
                pass
