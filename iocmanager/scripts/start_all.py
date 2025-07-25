import argparse
import sys
import time

from ..config import read_config
from ..log_setup import add_verbose_arg, iocmanager_log_config
from ..procserv_tools import start_proc

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="start_all",
        description=(
            "Start all the IOCs in a hutch. "
            "This is meant to be run once per server boot "
            "as part of initIOC."
        ),
    )
    parser.add_argument("hutch", help="The name of the hutch to start all IOCs for.")
    parser.add_argument("host", help="The name of the host to start all IOCs for.")
    add_verbose_arg(parser)
    args = parser.parse_args()
    iocmanager_log_config(args)
    try:
        config = read_config(args.hutch)
    except Exception:
        print("Cannot read configuration for %s!" % args.hutch)
        sys.exit(-1)
    for ioc_proc in config.procs.values():
        if ioc_proc.host == args.host and not ioc_proc.disable:
            start_proc(cfg=args.hutch, ioc_proc=ioc_proc, local=True)
            if ioc_proc.delay:
                time.sleep(ioc_proc.delay)
