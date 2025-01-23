#!/usr/bin/env python
import sys
from . import utils

host = None


def verify_host(current, config, kill_list, start_list, restart_list):
    kill_list = [k for k in kill_list if k == host]
    start_list = [k for k in start_list if k == host]
    restart_list = [k for k in restart_list if k == host]
    return (kill_list, start_list, restart_list)


if __name__ == "__main__":
    hutch = sys.argv[1]
    if len(sys.argv) > 1:
        host = sys.argv[2]
        sys.exit(utils.applyConfig(hutch, verify_host))
    else:
        sys.exit(utils.applyConfig(hutch))
