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

>>> from .env_paths import env_paths
>>> env_paths.IOC_DATA
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
    def PROCSERV_EXE(self) -> str:
        """
        Full path to the procServ executable.

        This is derived from the PROCSERVE_EXE environment variable, which includes
        both the executable and the arguments to the executable.

        This defaults to "procServ" which may or may not be on the user's PATH.
        """
        return os.getenv("PROCSERV_EXE", "procServ").split()[0]

    @property
    def PYPS_ROOT(self) -> str:
        """
        The facility's base directory for python application and configuration code.

        This is equivalent to the PYPS_ROOT environment variable, which should contain
        a path.

        This defaults to "/cds/group/pcds/pyps".
        """
        return os.getenv("PYPS_ROOT", "/cds/group/pcds/pyps").removesuffix(os.sep)

    @property
    def IOC_DATA(self) -> str:
        """
        The facility's base directory for logs and log-adjacent ioc data.

        This is equivalent to the IOC_DATA environment variable, which should contain
        a path.

        This defaults to "/cds/data/iocData".
        """
        return os.getenv("IOC_DATA", "/cds/data/iocData").removesuffix(os.sep)

    @property
    def IOC_COMMON(self) -> str:
        """
        The facility's base directory for boot code shared between many IOCs.

        This is equivalent to the IOC_COMMON environment variable, which should contain
        a path.

        This defaults to "/cds/data/iocCommon".
        """
        return os.getenv("IOC_COMMON", "/cds/data/iocCommon").removesuffix(os.sep)

    @property
    def TOOLS_SITE_TOP(self) -> str:
        """
        The facility's base directory for shared tool scripts.

        This is equivalent to the TOOLS_SITE_TOP environment variable, which should
        contain a path.

        This defaults to "/cds/sw/tools".
        """
        return os.getenv("TOOLS_SITE_TOP", "/cds/sw/tools").removesuffix(os.sep)

    @property
    def EPICS_SITE_TOP(self) -> str:
        """
        The facility's base directory for its EPICS installs.

        This is equivalent to the EPICS_SITE_TOP environment variable, which should
        contain a path.

        This defaults to "/cds/group/pcds/epics".
        """
        return os.getenv("EPICS_SITE_TOP", "/cds/group/pcds/epics").removesuffix(os.sep)

    @property
    def EPICS_DEV_TOP(self) -> str:
        """
        The facility's base directory for its dev EPICS work.

        This is equivalent to the EPICS_DEV_TOP environment variable, which should
        contain a path.

        This defaults to "/cds/group/pcds/epics-dev".
        """
        return os.getenv("EPICS_DEV_TOP", self.EPICS_SITE_TOP + "-dev")

    @property
    def CAMRECORD_ROOT(self) -> str:
        """
        The value of the CAMRECORD_ROOT environment variable.

        This is the path to the camrecord utility repo.

        This defaults to /cds/group/pcds/controls/camrecord
        """
        return os.getenv(
            "CAMRECORD_ROOT", "/cds/group/pcds/controls/camrecord"
        ).removesuffix(os.sep)

    @property
    def GNOME_TERMINAL_SERVER(self) -> str:
        """
        The path to the gnome-terminal-server executable.

        This is used by the GUI to launch floating terminals if available.
        """
        return os.getenv("GNOME_TERMINAL_SERVER", "/usr/libexec/gnome-terminal-server")

    # The rest of these are derived from the above environment variables
    # or from each other
    @property
    def CONFIG_DIR(self) -> str:
        """
        The designated directory containing all config information for all hutches.

        Each subfolder in CONFIG_DIR should be the three-letter name of a hutch.
        """
        return f"{self.PYPS_ROOT}/config"

    @property
    def STARTUP_DIR(self) -> str:
        """
        A template for the working directory of the procmgrd instance when we start it.

        To complete this template, the %s must be replaced with the 3-letter hutch name.

        This should contain the scripts that procmgrd needs to call.
        It is used as a backup for SCRIPTROOT if unset or empty.
        """
        # TODO should this be removed in favor of setting SCRIPTROOT directly?
        return f"{self.CONFIG_DIR}/%s/iocmanager/scripts"

    @property
    def CONFIG_FILE(self) -> str:
        """
        A template for the location of the main iocmanager.cfg config file.

        This file contains all main settings and enough information about each
        IOC to boot IOCs, launch the GUI with useful information, etc.

        To complete this template, the %s must be replaced with the 3-letter hutch name.
        """
        return f"{self.CONFIG_DIR}/%s/iocmanager.cfg"

    @property
    def NOSSH_FILE(self) -> str:
        """
        A template for the location of the iocmanager.nossh config file.

        This file contains usernames, one per line, of users who should not
        (cannot) ssh without a password prompt. It is used to skip operations
        that would fail for such a user.

        To complete this template, the %s must be replaced with the 3-letter hutch name.
        """
        return f"{self.CONFIG_DIR}/%s/iocmanager.nossh"

    @property
    def AUTH_FILE(self) -> str:
        """
        A template for the location of the iocmanager.auth config file.

        This file contains usernames, one per line, of users who are authorized
        to make changes to the hutch's main iocmanager.cfg configuration file
        (see attr:`CONFIG_FILE`).

        To complete this template, the %s must be replaced with the 3-letter hutch name.
        """
        return f"{self.CONFIG_DIR}/%s/iocmanager.auth"

    @property
    def SPECIAL_FILE(self) -> str:
        """
        A template for the location of the iocmanager.special config file.

        This file contains ioc specifications, one per line, of IOCs that are
        permitted to be switched between variants for non-authenticated users.

        To complete this template, the %s must be replaced with the 3-letter hutch name.

        See func:`check_special` for more information.
        """
        return f"{self.CONFIG_DIR}/%s/iocmanager.special"

    @property
    def HOST_DIR(self) -> str:
        """
        A directory to check or record the operating system of each server.

        It will contain one file per host, with filename matching that host's hostname,
        that simply contains the target architecture of that host.
        These files are created during initIOC.hutch when we start the procmgrd process.
        """
        return f"{self.CONFIG_DIR}/.host"

    @property
    def STATUS_DIR(self) -> str:
        """
        A template for the location of the ioc status files.

        This directory contains one file per IOC, with filename matching ioc name,
        and containing the pid, hostname, port, and path to IOC startup directory.
        These files are created during the startProc script.

        This directory also contains the func:`TMP_DIR` directory right alongside the
        hutch directories with no discernable separation.

        To complete this template, the %s must be replaced with the 3-letter hutch name.

        See func:`read_status_dir`.
        """
        return f"{self.CONFIG_DIR}/.status/%s"

    @property
    def TMP_DIR(self) -> str:
        """
        A designated location for writing out temporary files.

        Files are written here and then moved to their final location in order
        to ensure atomic updates to live configurations.
        """
        return self.STATUS_DIR % "tmp"

    @property
    def LOGBASE(self) -> str:
        """
        A template for the location of the most recent ioc logfile.

        This file contains a record of the IOC's boot process and runtime,
        including errors and other console output.

        To complete this template, the %s must be replaced with the ioc name.
        """
        return f"{self.IOC_DATA}/%s/iocInfo/ioc.log"

    @property
    def PVFILE(self) -> str:
        """
        A template for the location of the most recent ioc pvlist file.

        This file contains all the EPICS records provided by the IOC,
        one per line, including their pv names and record types.

        To complete this template, the %s must be replaced with the ioc name.
        """
        return f"{self.IOC_DATA}/%s/iocInfo/IOC.pvlist"

    @property
    def NETCONFIG(self) -> str:
        """
        The location of the netconfig executable.

        Netconfig is a convenient way to get information about network
        devices.
        """
        return f"{self.TOOLS_SITE_TOP}/bin/netconfig"

    @property
    def PSIPMI(self) -> str:
        """
        The location of the psipmi executable.

        Psipmi is a convenient way to check the status of and reset/reboot servers.
        """
        return f"{self.TOOLS_SITE_TOP}/bin/psipmi"

    @property
    def HIOC_POWER(self) -> str:
        """
        The location of an exectuable for hard ioc power functions.

        This is a convenient way to restart hard iocs.
        """
        return f"{self.TOOLS_SITE_TOP}/bin/power"

    @property
    def HIOC_STARTUP(self) -> str:
        """
        A template for the location of a hard ioc's startup script.

        To complete the template, the %s must be replaced with the hard ioc name.
        """
        return f"{self.IOC_COMMON}/hioc/%s/startup.cmd"


env_paths = EnvPaths()
