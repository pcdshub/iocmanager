"""
The hioc_tools module contains helper functions for managing hard IOCs.

Hard IOCs (hardware IOCs, HIOCs for short) are IOCs that are run
as part of a particular hardware's boot process, as opposed to
soft IOCs (SIOC for short) which run on the OS some time after boot.

HIOCs are nominally run real-time and on specialized hardware.
"""

import copy
import logging
import os
import re
import subprocess
import telnetlib

from . import env_paths
from .server_tools import netconfig

logger = logging.getLogger(__name__)


def getHardIOCDir(host: str) -> str:
    """Return the hard IOC directory for a given hard IOC host."""
    dir = "Unknown"
    try:
        lines = [ln.strip() for ln in open(env_paths.HIOC_STARTUP % host).readlines()]
    except Exception:
        logger.error("Error while trying to read HIOC startup file for %s!" % host)
        return "Unknown"
    for ln in lines:
        if ln[:5] == "chdir":
            try:
                dir = "ioc/" + re.search('"/iocs/(.*)/iocBoot', ln).group(1)
            except Exception:
                pass  # Having dir show "Unknown" should suffice.
    return dir


def restartHIOC(host: str) -> bool:
    """Console into a HIOC and reboot it via the shell, return True if successful."""
    try:
        for line in netconfig(host)["console port dn"].split(","):
            if line[:7] == "cn=port":
                port = 2000 + int(line[7:])
            if line[:7] == "cn=digi":
                host = line[3:]
    except Exception:
        logger.debug("Netconfig error", exc_info=True)
        print("Error parsing netconfig for HIOC %s console info!" % host)
        return False
    try:
        tn = telnetlib.Telnet(host, port, 1)
    except Exception:
        logger.debug("Telnet error", exc_info=True)
        print("Error making telnet connection to HIOC %s!" % host)
        return False
    tn.write(b"\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"exit\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"rtemsReboot()\x0a")
    tn.close()
    return True


def rebootHIOC(host: str) -> bool:
    """Power cycle a HIOC via the PDU entry in netconfig, return True if successful."""
    try:
        env = copy.deepcopy(os.environ)
        del env["LD_LIBRARY_PATH"]
        print(
            subprocess.check_output(
                [env_paths.HIOC_POWER, host, "cycle"],
                env=env,
                universal_newlines=True,
            )
        )
        return True
    except Exception:
        logger.debug("Power cycle error", exc_info=True)
        print("Error while trying to power cycle HIOC %s!" % host)
        return False
