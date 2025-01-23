#!/usr/bin/env python
from . import utils
import sys
from psp.options import Options

if __name__ == "__main__":
    options = Options(["name"], [], [])
    try:
        options.parse()
    except Exception as msg:
        options.usage(str(msg))
        sys.exit(1)
    iocs = utils.find_iocs(id=options.name)
    for ioc in iocs:
        print(
            "\tCONFIG:\t\t%s\n\tALIAS:\t\t%s\n\tDIR:\t\t%s\n\tCMD:\t\t%s\n\tHOST:\t\t%s\n\tPORT:\t\t%s\n\tENABLED:\t%s"
            % (
                ioc[0],
                ioc[1].get("alias"),
                ioc[1].get("dir"),
                ioc[1].get("cmd"),
                ioc[1].get("host"),
                ioc[1].get("port"),
                not ioc[1].get("disable"),
            )
        )
    sys.exit(0)
