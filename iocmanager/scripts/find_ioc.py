import argparse

from ..config import find_iocs
from ..log_setup import add_verbose_arg, iocmanager_log_config

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="find_ioc",
        description=(
            "Find IOCs with the given name in any hutch and show basic information."
        ),
    )
    parser.add_argument("name", help="The IOC name to find.")
    add_verbose_arg(parser)
    args = parser.parse_args()
    iocmanager_log_config(args)
    found_iocs = find_iocs(name=args.name)
    for hutch, ioc_proc in found_iocs:
        print(
            f"\tCONFIG:\t\t{hutch}\n"
            f"\tALIAS:\t\t{ioc_proc.alias}\n"
            f"\tDIR:\t\t{ioc_proc.path}\n"
            f"\tCMD:\t\t{ioc_proc.cmd}\n"
            f"\tHOST:\t\t{ioc_proc.host}\n"
            f"\tPORT:\t\t{ioc_proc.port}\n"
            f"\tENABLED:\t{not ioc_proc.disable}"
        )
