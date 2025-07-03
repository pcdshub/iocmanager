import argparse
import sys

from ..config import read_config
from ..log_setup import add_verbose_arg, iocmanager_log_config

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="get_directory",
        description=(
            "Output an IOC's directory to stdout, "
            "or NO_DIRECTORY if it cannot be found."
        ),
    )
    parser.add_argument("ioc_name", help="The name of the IOC to check.")
    parser.add_argument("hutch", help="The name of the hutch to check in.")
    add_verbose_arg(parser)
    args = parser.parse_args()
    iocmanager_log_config(args)
    try:
        config = read_config(args.hutch)
    except Exception:
        print("NO_DIRECTORY")
        sys.exit(-1)
    try:
        iocproc = config.procs[args.ioc_name]
    except KeyError:
        print("NO_DIRECTORY")
        sys.exit(-1)
    print(iocproc.path)
