"""
The hioc_tools module contains helper functions for managing hard IOCs.

Hard IOCs (hardware IOCs, HIOCs for short) are IOCs that are run
as part of a particular hardware's boot process, as opposed to
soft IOCs (SIOC for short) which run on the OS some time after boot.

HIOCs are nominally run real-time and on specialized hardware.

Warning: some of these tools no longer work because netconfig is deprecated
and sdfconfig doesn't have the information required to implement them.

Any function that no longer works will now raise NotImplementedError,
though the original implementation will be preserved here
preceded by a leading underscore.
"""

import copy
import logging
import os
import re
import subprocess
import telnetlib

from .env_paths import env_paths
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
            match = re.search('"/iocs/(.*)/iocBoot', ln)
            if match is not None:
                return "ioc/" + match.group(1)
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
    raise NotImplementedError(
        "restart_hioc cannot be implemented with sdfconfig, and netconfig is disabled."
    )


def _restart_hioc(host: str):
    """
    Console into a HIOC and reboot it via the shell.

    May raise if something goes wrong.
    """
    console_host = ""
    console_port = 0
    try:
        for line in netconfig(host)["console port dn"].split(","):
            if line[:7] == "cn=port":
                console_port = 2000 + int(line[7:])
            if line[:7] == "cn=digi":
                console_host = line[3:]
    except Exception as exc:
        logger.debug("Netconfig error", exc_info=True)
        raise RuntimeError(
            f"Error parsing netconfig for HIOC {host} console info!"
        ) from exc
    if not console_host:
        raise RuntimeError(f"Console host not found in netconfig for {host}.")
    if not console_port:
        raise RuntimeError(f"Console port not found in netconfig for {host}.")
    try:
        tn = telnetlib.Telnet(console_host, console_port, 1)
    except Exception as exc:
        logger.debug("Telnet error", exc_info=True)
        raise RuntimeError(
            f"Error making telnet connection to HIOC {host}'s "
            f"console {console_host}:{console_port}!"
        ) from exc
    tn.write(b"\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"exit\x0a")
    tn.read_until(b"> ", 2)
    tn.write(b"rtemsReboot()\x0a")
    tn.close()


def reboot_hioc(host: str):
    raise NotImplementedError(
        "reboot_hioc cannot be implemented with sdfconfig, and netconfig is disabled."
    )


def _reboot_hioc(host: str):
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
