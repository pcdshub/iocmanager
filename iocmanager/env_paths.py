"""
The env_paths module loads and provides paths to other modules.

Many of the paths are determined by the user's environment variables,
such as:

- CAMRECORD_ROOT
- EPICS_DEV_TOP
- EPICS_SITE_TOP
- IOC_COMMON
- IOC_DATA
- TOOLS_SITE_TOP
- PROCSERV_EXE
- PYPS_ROOT

The module is structured to allow for runtime reloading of environment
variables for testing purposes.

To use this module, import the env_paths object and refer to its
properties as needed.
"""

import os


class EnvPaths:
    """
    Interface to getting the correct setting based on the live environment variable.

    This handles cases where the environment variable changes during execution,
    such as in a unit test or in a downstream library.

    The properties here should be conceptualized as global constants
    and are named as such (pep8).
    """

    # The first few of these come directly from environment variables
    @property
    def CAMRECORD_ROOT(self) -> str:
        return os.getenv(
            "CAMRECORD_ROOT", "/cds/group/pcds/controls/camrecord"
        ).removesuffix(os.sep)

    @property
    def PROCSERV_EXE(self) -> str:
        return os.getenv("PROCSERV_EXE", "procServ").split()[0]

    @property
    def PYPS_ROOT(self) -> str:
        return os.getenv("PYPS_ROOT", "/cds/group/pcds/pyps").removesuffix(os.sep)

    @property
    def IOC_DATA(self) -> str:
        return os.getenv("IOC_DATA", "/cds/data/iocData").removesuffix(os.sep)

    @property
    def IOC_COMMON(self) -> str:
        return os.getenv("IOC_COMMON", "/cds/data/iocCommon").removesuffix(os.sep)

    @property
    def TOOLS_SITE_TOP(self) -> str:
        return os.getenv("TOOLS_SITE_TOP", "/cds/sw/tools").removesuffix(os.sep)

    @property
    def EPICS_SITE_TOP(self) -> str:
        return os.getenv("EPICS_SITE_TOP", "/cds/group/pcds/epics").removesuffix(os.sep)

    @property
    def EPICS_DEV_TOP(self) -> str:
        return os.getenv("EPICS_DEV_TOP", self.EPICS_SITE_TOP + "-dev")

    # The rest of these are derived from the above environment variables
    @property
    def CAMRECORDER(self) -> str:
        return self.CAMRECORD_ROOT

    @property
    def TMP_DIR(self) -> str:
        return f"{self.PYPS_ROOT}/config/.status/tmp"

    @property
    def STARTUP_DIR(self) -> str:
        return f"{self.PYPS_ROOT}/config/%s/iocmanager/"

    @property
    def CONFIG_DIR(self) -> str:
        return f"{self.PYPS_ROOT}/config/"

    @property
    def CONFIG_FILE(self) -> str:
        return f"{self.PYPS_ROOT}/config/%s/iocmanager.cfg"

    @property
    def NOSSH_FILE(self) -> str:
        return f"{self.PYPS_ROOT}/config/%s/iocmanager.nossh"

    @property
    def AUTH_FILE(self) -> str:
        return f"{self.PYPS_ROOT}/config/%s/iocmanager.auth"

    @property
    def SPECIAL_FILE(self) -> str:
        return f"{self.PYPS_ROOT}/config/%s/iocmanager.special"

    @property
    def STATUS_DIR(self) -> str:
        return f"{self.PYPS_ROOT}/config/.status/%s"

    @property
    def HOST_DIR(self) -> str:
        return f"{self.PYPS_ROOT}/config/.host"

    @property
    def LOGBASE(self) -> str:
        return f"{self.IOC_DATA}/%s/iocInfo/ioc.log"

    @property
    def PVFILE(self) -> str:
        return f"{self.IOC_DATA}/%s/iocInfo/IOC.pvlist"

    @property
    def NETCONFIG(self) -> str:
        return f"{self.TOOLS_SITE_TOP}/bin/netconfig"

    @property
    def PSIPMI(self) -> str:
        return f"{self.TOOLS_SITE_TOP}/bin/psipmi"

    @property
    def HIOC_POWER(self) -> str:
        return f"{self.TOOLS_SITE_TOP}/bin/power"

    @property
    def HIOC_CONSOLE(self) -> str:
        return f"{self.TOOLS_SITE_TOP}/bin/console"

    @property
    def HIOC_STARTUP(self) -> str:
        return f"{self.IOC_COMMON}/hioc/%s/startup.cmd"


env_paths = EnvPaths()
