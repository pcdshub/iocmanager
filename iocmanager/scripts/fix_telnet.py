import argparse

from ..log_setup import add_verbose_arg, iocmanager_log_config
from ..procserv_tools import fix_telnet_shell

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="fix_telnet",
        description="Change a localhost procmgr telnet prompt to >. Used in initIOC.",
    )
    parser.add_argument("port", help="The procmgrd port to fix.")
    add_verbose_arg(parser)
    args = parser.parse_args()
    iocmanager_log_config(args)
    fix_telnet_shell("localhost", args.port)
