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


def get_hard_ioc_dir(host: str) -> str:
    """
    Return the hard IOC directory for a given hard IOC host.

    May raise if the directory cannot be determined.
    """
    with open(env_paths.HIOC_STARTUP % host, "r") as fd:
        lines = fd.readlines()
    for ln in [ln.strip() for ln in lines]:
        if ln[:5] == "chdir":
            try:
                return "ioc/" + re.search('"/iocs/(.*)/iocBoot', ln).group(1)
            except Exception:
                ...
    raise RuntimeError("Did not find chdir in startup file for {host}")


def get_hard_ioc_dir_for_display(host: str) -> str:
    """
    Return the hard IOC directory, or Unknown for a given hard IOC host.

    For user display purposes, we don't really care why this fails, we just
    want to display a placeholder.
    """
    try:
        return get_hard_ioc_dir(host)
    except OSError:
        logger.error("Error while trying to read HIOC startup file for %s!", host)
    except Exception:
        ...
    return "Unknown"


def restart_hioc(host: str):
    """
    Console into a HIOC and reboot it via the shell.

    May raise if something goes wrong.
    """
    try:
        for line in netconfig(host)["console port dn"].split(","):
            if line[:7] == "cn=port":
                port = 2000 + int(line[7:])
            if line[:7] == "cn=digi":
                host = line[3:]
    except Exception as exc:
        logger.debug("Netconfig error", exc_info=True)
        raise RuntimeError(
            f"Error parsing netconfig for HIOC {host} console info!"
        ) from exc
    try:
        tn = telnetlib.Telnet(host, port, 1)
    except Exception as exc:
        logger.debug("Telnet error", exc_info=True)
        raise RuntimeError(f"Error making telnet connection to HIOC {host}!") from exc
    tn.write(b"\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"exit\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"rtemsReboot()\x0a")
    tn.close()


def reboot_hioc(host: str):
    """
    Power cycle a HIOC via the PDU entry in netconfig.

    May raise if unsuccessful.
    """
    try:
        env = copy.deepcopy(os.environ)
        del env["LD_LIBRARY_PATH"]
        subprocess.run(
            [env_paths.HIOC_POWER, host, "cycle"],
            env=env,
            universal_newlines=True,
        )
    except Exception as exc:
        logger.debug("Power cycle error", exc_info=True)
        raise RuntimeError(f"Error while trying to power cycle HIOC {host}!") from exc
