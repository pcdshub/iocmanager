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

To facilitate this, import this module as:
from . import env_paths

Do not use * imports or from imports!
"""

import os

PROCSERV_EXE: str
EPICS_SITE_TOP: str
EPICS_DEV_TOP: str
CAMRECORDER: str
TMP_DIR: str
STARTUP_DIR: str
CONFIG_DIR: str
CONFIG_FILE: str
NOSSH_FILE: str
AUTH_FILE: str
SPECIAL_FILE: str
STATUS_DIR: str
HOST_DIR: str
LOGBASE: str
PVFILE: str
NETCONFIG: str
PSIPMI: str
HIOC_POWER: str
HIOC_CONSOLE: str
HIOC_STARTUP: str


# Environment-variable settings: allow us to reset/reload these
def set_env_var_globals():
    """
    Initialize global variables from the shell environment.

    Can be called multiple times in a session for e.g. testing purposes.
    """
    # If you add a global, add a type hint above too
    global PROCSERV_EXE
    global EPICS_SITE_TOP
    global EPICS_DEV_TOP
    global CAMRECORDER
    global TMP_DIR
    global STARTUP_DIR
    global CONFIG_DIR
    global CONFIG_FILE
    global NOSSH_FILE
    global AUTH_FILE
    global SPECIAL_FILE
    global STATUS_DIR
    global HOST_DIR
    global LOGBASE
    global PVFILE
    global NETCONFIG
    global PSIPMI
    global HIOC_POWER
    global HIOC_CONSOLE
    global HIOC_STARTUP
    # Raw env vars with defaults
    CAMRECORD_ROOT = os.getenv("CAMRECORD_ROOT", "/cds/group/pcds/controls/camrecord")
    PROCSERV_EXE = os.getenv("PROCSERV_EXE", "procServ").split()[0]
    PYPS_ROOT = os.getenv("PYPS_ROOT", "/cds/group/pcds/pyps")
    IOC_DATA = os.getenv("IOC_DATA", "/cds/data/iocData")
    IOC_COMMON = os.getenv("IOC_COMMON", "/cds/data/iocCommon")
    TOOLS_SITE_TOP = os.getenv("TOOLS_SITE_TOP", "/cds/sw/tools")
    EPICS_SITE_TOP = os.getenv("EPICS_SITE_TOP", "/cds/group/pcds/epics")
    EPICS_DEV_TOP = os.getenv("EPICS_DEV_TOP", EPICS_SITE_TOP + "-dev")
    EPICS_SITE_TOP += "/"  # Code somewhere expects the trailing /, TODO clean this up

    # Use env vars to build config strings
    CAMRECORDER = CAMRECORD_ROOT
    # Note: TMP_DIR and CONFIG_FILE should be on the same file system so os.rename works
    TMP_DIR = f"{PYPS_ROOT}/config/.status/tmp"
    STARTUP_DIR = f"{PYPS_ROOT}/config/%s/iocmanager/"
    CONFIG_DIR = f"{PYPS_ROOT}/config/"
    CONFIG_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.cfg"
    NOSSH_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.nossh"
    AUTH_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.auth"
    SPECIAL_FILE = f"{PYPS_ROOT}/config/%s/iocmanager.special"
    STATUS_DIR = f"{PYPS_ROOT}/config/.status/%s"
    HOST_DIR = f"{PYPS_ROOT}/config/.host"
    LOGBASE = f"{IOC_DATA}/%s/iocInfo/ioc.log"
    PVFILE = f"{IOC_DATA}/%s/iocInfo/IOC.pvlist"
    NETCONFIG = f"{TOOLS_SITE_TOP}/bin/netconfig"
    PSIPMI = f"{TOOLS_SITE_TOP}/bin/psipmi"
    HIOC_POWER = f"{TOOLS_SITE_TOP}/bin/power"
    HIOC_CONSOLE = f"{TOOLS_SITE_TOP}/bin/console"
    HIOC_STARTUP = f"{IOC_COMMON}/hioc/%s/startup.cmd"


set_env_var_globals()
