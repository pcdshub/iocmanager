import argparse

from ..log_setup import add_verbose_arg, iocmanager_log_config
from ..procserv_tools import apply_config

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="apply_config",
        description=(
            "Apply the hutch's current configuration, "
            "starting, stopping and restarting IOCs as necessary."
        ),
    )
    parser.add_argument("hutch", help="The hutch to apply configuration to.")
    parser.add_argument(
        "ioc_name",
        required=False,
        default="",
        help="Optionally pass an IOC name to only apply that IOC.",
    )
    add_verbose_arg(parser)
    args = parser.parse_args()
    iocmanager_log_config(args)
    if args.ioc_name:
        apply_config(cfg=args.hutch, ioc=args.ioc_name)
    else:
        apply_config(cfg=args.hutch)
