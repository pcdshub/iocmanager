"""
This script uses IOC manager to survey the state of operating system update efforts.
"""

import argparse
import dataclasses
import datetime
import enum
import functools
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import jinja2
from packaging.version import InvalidVersion, Version

from ..config import IOCProc, get_host_os, read_config
from ..env_paths import env_paths
from ..log_setup import add_verbose_arg, iocmanager_log_config

ALL_HUTCHES = [
    "lfe",
    "kfe",
    "tmo",
    "rix",
    "txi",
    "xpp",
    "xrt",
    "xcs",
    "mfx",
    "cxi",
    "mec",
    "las",
    "ued",
    "all",
]
GOAL_OS = "rocky9"
UNKNOWN = "Unknown"
NEEDS_UPGRADE = ("rhel7", "rhel5", UNKNOWN)
ARCH_TO_NAME = {
    "rhel9-x86_64": "rocky9",
    "rhel7-x86_64": "rhel7",
    "linux-x86_64": "rhel5",
    "linux-x86": "rhel5",
    "linux-arm-apalis": "mpod-apalis",
    "RTEMS-beatnik": "rtems",
    UNKNOWN: UNKNOWN,
}
HOST_OS_TO_NAME = {
    "rhel9": "rocky9",
    "rhel7": "rhel7",
    "rhel5": "rhel5",
    "ang_v2017": "mpod-apalis",
    UNKNOWN: UNKNOWN,
}

RENAMES = {
    "leviton": "pdu_snmp",
    "arcus_dmx": "arcus",
}
REG = "/reg/g"
CDS = "/cds/group"
PACKAGE = "package/epics/3.14/ioc"
NOPACK = "epics/ioc"
# Include a comment with each please
HARD_CODE_COMMON_IOCS = {
    # parent is a dev dir called ek9000_tmo
    "ioc-bhc-peppex": "ek9000",
    # common ioc has no releases
    "ioc-qrix-cryo-01": "cryotel",
}

logger = logging.getLogger(__name__)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iocmanager survey-os")
    add_verbose_arg(parser)
    parser.add_argument(
        "--hutch",
        default="all",
        help=(
            "The hutch to generate statistics for. "
            "If omitted, generate for all hutches."
        ),
    )
    parser.add_argument(
        "--include-disabled",
        action="store_true",
        help=(
            "If this argument is passed, disabled IOCs "
            "are included in the output. The default "
            "is to only consider enabled IOCs."
        ),
    )
    parser.add_argument(
        "--confluence-table",
        action="store_true",
        help=(
            "Ignore other arguments and create the confluence table html. "
            "This always includes disabled IOCs."
        ),
    )
    parser.add_argument(
        "--debug-ioc",
        default="",
        help=(
            "Pass an IOC name to check just that IOC and do a debug print "
            "instead of the nice user-facing print. "
            "Requires --hutch to be passed."
        ),
    )
    parser.add_argument(
        "--debug-common",
        default="",
        help=(
            "Show details on all IOCs that use a specific common IOC. "
            "Incompatible with --debug-ioc and always includes disabled "
            "iocs."
        ),
    )
    parser.add_argument(
        "--debug-host",
        default="",
        help=(
            "Pass a host name to check just that host and do a debug print "
            "instead of the nice user-facing print."
        ),
    )
    return parser


@dataclasses.dataclass
class IOCResult:
    name: str
    current_os: str
    common_ioc: str
    supported_os: str
    enabled: bool
    hostname: str
    snowflake: bool
    parent_ioc: str

    @classmethod
    def from_ioc_proc[T: IOCResult](cls: type[T], ioc_proc: IOCProc) -> T:
        current_os = get_one_host_os(ioc_proc.host)
        try:
            hc_ioc = HARD_CODE_COMMON_IOCS[ioc_proc.name]
        except KeyError:
            common_ioc = get_common_ioc(ioc_proc.parent)
        else:
            common_ioc = f"/cds/group/pcds/epics/ioc/common/{hc_ioc}"
        snowflake = False
        if common_ioc == UNKNOWN and ioc_proc.path == ioc_proc.parent:
            common_ioc = ioc_proc.path
            snowflake = True
        if common_ioc.startswith(REG):
            common_ioc = common_ioc.replace(REG, CDS, 1)
        if PACKAGE in common_ioc:
            common_ioc = common_ioc.replace(PACKAGE, NOPACK, 1)
        name = Path(common_ioc).name.lower()
        if name in RENAMES:
            common_ioc = str(Path(common_ioc).parent / RENAMES[name])
        if not common_ioc.startswith("/cds/group/pcds/epics/ioc/common"):
            snowflake = True
        if snowflake and ioc_proc.parent and common_ioc == UNKNOWN:
            common_ioc = ioc_proc.parent
        supported_os = get_supported_os(common_ioc)
        if current_os == UNKNOWN and "rhel" not in supported_os:
            # Hack: just assume the live thing matches
            # I don't care about non-rhel today
            current_os = supported_os
        return cls(
            name=ioc_proc.name,
            current_os=current_os,
            common_ioc=common_ioc,
            supported_os=supported_os,
            enabled=not ioc_proc.disable,
            hostname=ioc_proc.host,
            snowflake=snowflake,
            parent_ioc=ioc_proc.parent,
        )


@dataclasses.dataclass
class SurveyStats:
    raw_results: list[IOCResult]
    ioc_count: int
    ready_count: int
    waiting_for_common_count: int
    remaining_common_by_ioc: dict[str, int]
    live_os_ioc_count: dict[str, int]
    iocs_with_unk_common: list[str]
    common_with_unk_os: list[str]
    hosts_with_unk_os: set[str]
    python_upgrade: list[str]
    snowflakes: list[str]
    no_upgrade_needed: list[str]
    iocs_common_ready: dict[str, list[str]]
    iocs_other_ready: list[str]

    def print_data(self):
        print(f"There are {self.ioc_count} IOCs total.")
        for os_name in list(HOST_OS_TO_NAME.values()):
            count = self.live_os_ioc_count[os_name]
            if not count:
                continue
            print(
                f"{100 * count / self.ioc_count:.2f}% "
                f"({count}/{self.ioc_count}) "
                f"of IOCs run {os_name}."
            )
        print(
            f"{100 * self.ready_count / self.ioc_count:.2f}% "
            f"({self.ready_count}/{self.ioc_count}) "
            "of IOCs are migrated or migration-ready."
        )
        if self.iocs_common_ready:
            print(
                f"The following {GOAL_OS}-ready common IOCs "
                "support the following hutch IOCs:"
            )
            common_with_count = [
                (common, len(hutch)) for common, hutch in self.iocs_common_ready.items()
            ]
            common_with_count.sort(key=lambda x: x[0])
            common_with_count.sort(key=lambda x: x[1], reverse=True)
            for common, count in common_with_count:
                print(f"{common} supports {count} hutch IOCs:")
                for ioc_name in self.iocs_common_ready[common]:
                    print(ioc_name)
        if self.iocs_other_ready:
            print(
                f"The following {len(self.iocs_other_ready)} IOCs "
                "do not use common IOCs but are ready to be migrated:"
            )
            for name in sorted(self.iocs_other_ready):
                print(name)
        print(
            f"{100 * self.waiting_for_common_count / self.ioc_count:.2f}% "
            f"({self.waiting_for_common_count}/{self.ioc_count}) "
            "of IOCs are waiting for common IOC updates:"
        )
        for common_ioc, count in sorted(
            self.remaining_common_by_ioc.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"{count} IOCs waiting on {common_ioc}")
        if self.snowflakes:
            print(
                f"{100 * len(self.snowflakes) / self.ioc_count:.2f}% "
                f"({len(self.snowflakes)}/{self.ioc_count}) "
                "of IOCs are custom one-offs that "
                "will need manual upgrades. "
                "Their names are:"
            )
            for name in self.snowflakes:
                print(name)
        if self.python_upgrade:
            print(
                f"{100 * len(self.python_upgrade) / self.ioc_count:.2f}% "
                f"({len(self.python_upgrade)}/{self.ioc_count}) "
                "of IOCs are python-based IOCs "
                "using outdated versions of Python. "
                "Their names are:"
            )
            for name in self.python_upgrade:
                print(name)
        if (
            self.iocs_with_unk_common
            or self.common_with_unk_os
            or self.hosts_with_unk_os
        ):
            print("The following are errors with the script output:")
        if self.iocs_with_unk_common:
            print(
                "The following IOCs' common IOC could not be found: "
                f"{self.iocs_with_unk_common}"
            )
        if self.common_with_unk_os:
            print(
                "The following common IOC supported OSes could not be found: "
                f"{self.common_with_unk_os}"
            )
        if self.hosts_with_unk_os:
            print(
                "The following hosts' live OSes could not be found: "
                f"{self.hosts_with_unk_os}"
            )
        print(
            "The following is a per-host breakdown of "
            "per-ioc-type migration readiness to paste into the google sheet:"
        )
        host_to_common_progress = {}
        host_snowflakes = set()
        for res in self.raw_results:
            if res.current_os not in NEEDS_UPGRADE:
                continue
            if res.hostname not in host_to_common_progress:
                host_to_common_progress[res.hostname] = {}
            if res.common_ioc not in host_to_common_progress[res.hostname]:
                host_to_common_progress[res.hostname][res.common_ioc] = (
                    res.supported_os == GOAL_OS
                )
            if res.snowflake:
                host_snowflakes.add(res.common_ioc)
        for host in sorted(host_to_common_progress):
            ready = 0
            total = 0
            snowflakes = 0
            for common_ioc, status in host_to_common_progress[host].items():
                if status:
                    ready += 1
                total += 1
                if common_ioc in host_snowflakes:
                    snowflakes += 1
            print(f"{host} {ready} {total} {snowflakes}")

    @classmethod
    def from_results[T: SurveyStats](cls: type[T], results: Iterable[IOCResult]) -> T:
        raw_results = list(results)
        ioc_count = 0
        ready_count = 0
        waiting_for_common_count = 0
        remaining_common_by_ioc = defaultdict(int)
        live_os_ioc_count = dict.fromkeys(list(HOST_OS_TO_NAME.values()), 0)
        iocs_with_unk_common = []
        common_with_unk_os = []
        hosts_with_unk_os = set()
        python_upgrade = []
        snowflakes = []
        no_upgrade_needed = []
        iocs_common_ready = defaultdict(list)
        iocs_other_ready = []
        for res in raw_results:
            ioc_count += 1
            if res.supported_os == GOAL_OS:
                ready_count += 1
                if (
                    res.current_os != GOAL_OS
                    and res.common_ioc != UNKNOWN
                    and not res.snowflake
                ):
                    iocs_common_ready[res.common_ioc].append(res.name)
                elif res.current_os != GOAL_OS:
                    iocs_other_ready.append(res.name)
            elif res.supported_os in NEEDS_UPGRADE:
                if res.common_ioc in ("pspkg", "python"):
                    python_upgrade.append(res.name)
                elif res.snowflake:
                    snowflakes.append(res.name)
                else:
                    remaining_common_by_ioc[res.common_ioc] += 1
                    waiting_for_common_count += 1
            else:
                no_upgrade_needed.append(res.name)
            live_os_ioc_count[HOST_OS_TO_NAME.get(res.current_os, res.current_os)] += 1
            if res.common_ioc == UNKNOWN:
                iocs_with_unk_common.append(res.name)
            elif res.supported_os == UNKNOWN:
                common_with_unk_os.append(res.common_ioc)
            if res.current_os == UNKNOWN:
                hosts_with_unk_os.add(res.hostname)
        if ioc_count == 0:
            raise RuntimeError("No IOCs in results!")
        return cls(
            raw_results=raw_results,
            ioc_count=ioc_count,
            ready_count=ready_count,
            waiting_for_common_count=waiting_for_common_count,
            remaining_common_by_ioc=dict(remaining_common_by_ioc),
            live_os_ioc_count=live_os_ioc_count,
            iocs_with_unk_common=iocs_with_unk_common,
            common_with_unk_os=common_with_unk_os,
            hosts_with_unk_os=hosts_with_unk_os,
            python_upgrade=python_upgrade,
            snowflakes=snowflakes,
            no_upgrade_needed=no_upgrade_needed,
            iocs_common_ready=dict(iocs_common_ready),
            iocs_other_ready=iocs_other_ready,
        )


@dataclasses.dataclass
class HutchResult:
    hutch: str
    ioc_results: list[IOCResult]

    @classmethod
    def from_procs[T: HutchResult](
        cls: type[T], hutch: str, procs: Iterable[IOCProc]
    ) -> T:
        return cls(
            hutch=hutch,
            ioc_results=[IOCResult.from_ioc_proc(ioc_proc) for ioc_proc in procs],
        )


@dataclasses.dataclass
class SurveyResult:
    survey_date: datetime.datetime
    hutch_results: list[HutchResult]

    @classmethod
    def from_hutch_list[T: SurveyResult](cls: type[T], hutch_list: list[str]) -> T:
        hutch_results = []
        for hutch in hutch_list:
            if hutch == "all":
                procs = []
                for hutch_name in ALL_HUTCHES:
                    if hutch_name == "all":
                        continue
                    cfg = read_config(hutch_name)
                    procs.extend(cfg.procs.values())
            else:
                config = read_config(hutch)
                procs = config.procs.values()
            hutch_results.append(HutchResult.from_procs(hutch=hutch, procs=procs))
        return cls(
            survey_date=datetime.datetime.now(),
            hutch_results=hutch_results,
        )


@functools.lru_cache(maxsize=1024)
def get_common_ioc(parent_ioc: str) -> str:
    """
    Given a path to a parent ioc, get the full path to the common IOC.

    This is the path that includes the versioned subdirectories.

    Things to handle here:
    - parent_ioc may be an absolute path, or it may be relative to
      EPICS_SITE_TOP
    - parent_ioc may be a dev IOC
    """
    # Regular case: well-formed parent IOC in normal release area
    if parent_ioc.startswith("ioc/"):
        return str((Path(env_paths.EPICS_SITE_TOP) / parent_ioc).parent)
    parent_path = Path(parent_ioc)
    if parent_ioc.startswith(os.path.join(env_paths.EPICS_SITE_TOP, "ioc")):
        return str(parent_path.parent)
    # Something weird with the paths, but it's a versioned dir
    if parent_path.name.startswith("R"):
        try:
            Version(parent_path.name.removeprefix("R"))
        except InvalidVersion:
            ...
        else:
            return str(parent_path.parent)
    # We have something, but it's not in a normal place.
    # It might not even have a normal name.
    # Do our best.
    # Variant 1: /some/path/to/ioc-common-name
    if parent_path.name.startswith("ioc-"):
        parts = parent_path.name.split("-")
        area = parts[1]
        name = "-".join(parts[2:])
        try:
            return path_from_guess(name=name, area=area)
        except RuntimeError:
            ...
    # Variant 2: /some/path/to/ioc/common/name/something
    match = re.match(r".*/ioc/(.*)/(.*)/.*", parent_ioc)
    if match is not None:
        area = match.group(1)
        name = match.group(2)
        try:
            return path_from_guess(name=name, area=area)
        except RuntimeError:
            ...
    # Variant 3: /some/arbitrary/path/ending/in/name
    try:
        return path_from_guess(name=parent_path.name, area="common")
    except RuntimeError:
        ...
    # Might not even be EPICS, check for python stuff
    for option in ("conda", "pspkg", "python", "queueserver", "redis"):
        if option in parent_ioc:
            return option
    # Fallback, e.g. no parent IOC
    return UNKNOWN


def path_from_guess(name: str, area) -> str:
    ioc_area = Path(env_paths.EPICS_SITE_TOP) / "ioc" / area
    name = RENAMES.get(name.lower(), name)
    for ioc_path in ioc_area.glob("*"):
        if ioc_path.name.lower() == name.lower():
            return str(ioc_path)
    raise RuntimeError(f"Could not find a match for {name} in {area}")


@functools.lru_cache(maxsize=1024)
def get_supported_os(common_ioc: str) -> str:
    """
    Get the latest supported OS for a common ioc.

    The input should be the path that contains the versioned subdirectories.
    """
    if common_ioc in ("conda", "queueserver", "redis"):
        return "rocky9"
    elif common_ioc in ("pspkg", "python"):
        return "rhel7"
    latest_version = None
    for version_dir in Path(common_ioc).glob("R*"):
        this_version = version_dir.name.removeprefix("R")
        version_parts = this_version.split("-")
        try:
            if latest_version is None:
                latest_version = [Version(ver) for ver in version_parts]
            else:
                new_version = [Version(ver) for ver in version_parts]
                for latest_part, new_part in zip(
                    latest_version, new_version, strict=True
                ):
                    if new_part > latest_part:
                        latest_version = new_version
                        break
                    if new_part < latest_part:
                        break
                if new_version > latest_version:
                    latest_version = new_version
        except InvalidVersion:
            ...
    if latest_version is None:
        path_to_try = Path(common_ioc)
    else:
        version_str = "-".join(str(ver) for ver in latest_version)
        path_to_try = Path(common_ioc) / f"R{version_str}"
    for arch in ARCH_TO_NAME:
        binaries = list((path_to_try / "bin").glob(f"{arch}/*"))
        if binaries:
            return ARCH_TO_NAME[arch]
    return UNKNOWN


@functools.lru_cache(maxsize=1024)
def get_one_host_os(hostname: str) -> str:
    """Return the OS that a hostname runs on."""
    try:
        return get_host_os([hostname])[hostname]
    except Exception:
        return UNKNOWN


class CommonStatus(enum.StrEnum):
    DEPLOYED_IN_PROD = "deployed in prod on rocky9"
    BUILT_IN_PROD = "ready for prod testing on rocky9"
    NOT_BUILT = "not built on rocky9"
    NOT_MIGRATING = "not migrating to rocky9"
    NO_COMMON = "no common IOC"


@dataclasses.dataclass
class ConfluenceIOCInfo:
    name: str
    enabled: bool
    host_os: str
    hostname: str
    hutch: str
    common_status: CommonStatus
    common_deployed_in_prod_count: int
    common_deployed_in_hutch_names: list[str]
    common_name: str
    common_full_path: str
    using_release: str
    latest_release: str


@dataclasses.dataclass
class ConfluenceHutchSummaryRow:
    hutch: str
    total_host_count: int = 0
    rocky9_host_count: int = 0
    rhel7_host_count: int = 0
    rhel5_host_count: int = 0
    other_host_count: int = 0
    error_host_count: int = 0
    total_ioc_count: int = 0
    rocky9_ioc_count: int = 0
    rhel7_ioc_count: int = 0
    rhel5_ioc_count: int = 0
    other_ioc_count: int = 0
    error_ioc_count: int = 0
    common_deployed_in_prod_count: int = 0
    common_has_build_count: int = 0
    common_not_built_count: int = 0
    no_common_count: int = 0

    def __post_init__(self):
        self._hosts_added = set()

    def add_ioc(self, info: ConfluenceIOCInfo):
        if info.hostname in self._hosts_added:
            new_host = False
        else:
            new_host = True
            self._hosts_added.add(info.hostname)
        self.total_ioc_count += 1
        if new_host:
            self.total_host_count += 1
        if info.host_os == "rhel9":
            self.rocky9_ioc_count += 1
            if new_host:
                self.rocky9_host_count += 1
        elif info.host_os == "rhel7":
            self.rhel7_ioc_count += 1
            if new_host:
                self.rhel7_host_count += 1
        elif info.host_os == "rhel5":
            self.rhel5_ioc_count += 1
            if new_host:
                self.rhel5_host_count += 1
        elif info.host_os == UNKNOWN:
            self.error_ioc_count += 1
            if new_host:
                self.error_host_count += 1
        else:
            self.other_ioc_count += 1
            if new_host:
                self.other_host_count += 1
        match info.common_status:
            case CommonStatus.DEPLOYED_IN_PROD:
                self.common_deployed_in_prod_count += 1
            case CommonStatus.BUILT_IN_PROD:
                self.common_has_build_count += 1
            case CommonStatus.NOT_BUILT:
                self.common_not_built_count += 1
            case _:
                self.no_common_count += 1


@dataclasses.dataclass
class ConfluenceHostSummaryRow:
    hostname: str
    host_os: str
    hutches: list[str] = dataclasses.field(default_factory=list)
    total_count: int = 0
    common_deployed_in_prod_count: int = 0
    common_has_build_count: int = 0
    common_not_built_count: int = 0
    no_common_count: int = 0

    def add_ioc(self, info: ConfluenceIOCInfo):
        if info.hutch not in self.hutches:
            self.hutches.append(info.hutch)
            self.hutches.sort()
        self.total_count += 1
        match info.common_status:
            case CommonStatus.DEPLOYED_IN_PROD:
                self.common_deployed_in_prod_count += 1
            case CommonStatus.BUILT_IN_PROD:
                self.common_has_build_count += 1
            case CommonStatus.NOT_BUILT:
                self.common_not_built_count += 1
            case _:
                self.no_common_count += 1


@dataclasses.dataclass
class ConfluenceCommonIOCRow:
    name: str
    deploy_path: str
    supported_os: str
    latest_version: str
    any_os_deployed_count: int = 0
    rocky9_deployed_count: int = 0
    rocky9_hutch_names: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def from_pathname[T: ConfluenceCommonIOCRow](cls: type[T], pathname: str) -> T:
        # Real name starts at /ioc/
        name = "ioc-" + pathname.split("/ioc/")[1].replace("/", "-")
        deploy_path = pathname
        supported_os = get_supported_os(pathname)
        latest_version = get_common_latest(pathname)
        return cls(
            name=name,
            deploy_path=deploy_path,
            supported_os=supported_os,
            latest_version=latest_version,
        )


@dataclasses.dataclass
class ConfluenceStatsPage:
    # Key by hutch
    hutch_summary_table: dict[str, ConfluenceHutchSummaryRow]
    # Key by host
    host_summary_table: dict[str, ConfluenceHostSummaryRow]
    # Key by hutch, then by ioc name
    hutch_tables: dict[str, dict[str, ConfluenceIOCInfo]]
    # Key by host, then by ioc name
    host_tables: dict[str, dict[str, ConfluenceIOCInfo]]
    # Key by deploy path
    common_ioc_summary_table: dict[str, ConfluenceCommonIOCRow]

    @classmethod
    def from_hutch_list[T: ConfluenceStatsPage](
        cls: type[T], hutch_list: list[str]
    ) -> T:
        hutch_results = []
        for hutch in hutch_list:
            if hutch == "all":
                procs = []
                for hutch_name in ALL_HUTCHES:
                    if hutch_name == "all":
                        continue
                    cfg = read_config(hutch_name)
                    procs.extend(cfg.procs.values())
            else:
                config = read_config(hutch)
                procs = config.procs.values()
            hutch_results.append(HutchResult.from_procs(hutch=hutch, procs=procs))
        return cls.from_results(hutch_results)

    @classmethod
    def from_results[T: ConfluenceStatsPage](
        cls: type[T], results: Iterable[HutchResult]
    ) -> T:
        stats_page = cls(
            hutch_summary_table={"all": ConfluenceHutchSummaryRow(hutch="all")},
            host_summary_table={},
            hutch_tables={},
            host_tables={},
            common_ioc_summary_table={},
        )
        for res in results:
            stats_page.add_hutch_result(res)
        stats_page.finalize_deployed_in_prod_counts()
        return stats_page

    def add_hutch_result(self, hutch_result: HutchResult):
        for ioc_result in hutch_result.ioc_results:
            self.add_ioc_result(hutch_result.hutch, ioc_result)

    def add_ioc_result(self, hutch: str, ioc_result: IOCResult):
        common_status = get_common_status(ioc_result.common_ioc)
        if common_status == CommonStatus.NO_COMMON:
            common_name = "None"
            using_release = "None"
            latest_release = "None"
        else:
            common_name = ioc_result.common_ioc.removeprefix("/cds/group/pcds/epics/")
            using_release = get_parent_version(ioc_result.parent_ioc)
            latest_release = get_common_latest(ioc_result.common_ioc)
        info = ConfluenceIOCInfo(
            name=ioc_result.name,
            enabled=ioc_result.enabled,
            host_os=get_one_host_os(ioc_result.hostname),
            hostname=ioc_result.hostname,
            hutch=hutch,
            common_status=common_status,
            common_deployed_in_prod_count=0,
            common_deployed_in_hutch_names=[],
            common_name=common_name,
            common_full_path=ioc_result.common_ioc,
            using_release=using_release,
            latest_release=latest_release,
        )
        self.hutch_summary_table["all"].add_ioc(info)
        if hutch not in self.hutch_summary_table:
            self.hutch_summary_table[hutch] = ConfluenceHutchSummaryRow(hutch=hutch)
        self.hutch_summary_table[hutch].add_ioc(info)
        if ioc_result.hostname not in self.host_summary_table:
            self.host_summary_table[ioc_result.hostname] = ConfluenceHostSummaryRow(
                ioc_result.hostname, get_one_host_os(ioc_result.hostname)
            )
        self.host_summary_table[ioc_result.hostname].add_ioc(info)
        if hutch not in self.hutch_tables:
            self.hutch_tables[hutch] = {}
        self.hutch_tables[hutch][ioc_result.name] = info
        if ioc_result.hostname not in self.host_tables:
            self.host_tables[ioc_result.hostname] = {}
        self.host_tables[ioc_result.hostname][ioc_result.name] = info

        # Note that the status can't be DEPLOYED_IN_PROD yet- we need to handle this
        # later because we haven't checked all the IOCs yet
        if common_status in (CommonStatus.BUILT_IN_PROD, CommonStatus.NOT_BUILT):
            if ioc_result.common_ioc not in self.common_ioc_summary_table:
                self.common_ioc_summary_table[ioc_result.common_ioc] = (
                    ConfluenceCommonIOCRow.from_pathname(pathname=ioc_result.common_ioc)
                )
        if common_status == CommonStatus.BUILT_IN_PROD:
            self.common_ioc_summary_table[
                ioc_result.common_ioc
            ].any_os_deployed_count += 1

    def finalize_deployed_in_prod_counts(self):
        """
        After adding every ioc, go back and update the deployment counts and statuses.

        There are some number of common IOCs marked as BUILT_IN_PROD that should be
        promoted to DEPLOYED_IN_PROD

        All of the common_deployed_in_prod_count attributes are zero and need to be
        incremented
        """
        # Iterate through the iocs- these are stored two ways, arbitrarily pick
        # The first time, collect names of common iocs
        # and how many hutch IOCs use them at rocky9
        # and which hutches use them at rocky9
        rocky9_deployed_common_to_hutch_iocs: dict[str, int] = {}
        for hutch_dict in self.hutch_tables.values():
            for ioc_info in hutch_dict.values():
                if (
                    ioc_info.common_status == CommonStatus.BUILT_IN_PROD
                    and ioc_info.host_os == "rhel9"
                ):
                    try:
                        rocky9_deployed_common_to_hutch_iocs[ioc_info.common_name] += 1
                    except KeyError:
                        rocky9_deployed_common_to_hutch_iocs[ioc_info.common_name] = 0
                    # For the common ioc table, get a smaller count
                    # Just the number of real deployments
                    common_ioc = self.common_ioc_summary_table[
                        ioc_info.common_full_path
                    ]
                    common_ioc.rocky9_deployed_count += 1
                    if ioc_info.hutch not in common_ioc.rocky9_hutch_names:
                        common_ioc.rocky9_hutch_names.append(ioc_info.hutch)
                        common_ioc.rocky9_hutch_names.sort()

        # The second time, we're looking to update status and counts
        # If ANY ioc of this type is on rocky9, it's deployed in prod!
        for hutch_dict in self.hutch_tables.values():
            for ioc_info in hutch_dict.values():
                try:
                    ioc_info.common_deployed_in_prod_count = (
                        rocky9_deployed_common_to_hutch_iocs[ioc_info.common_name]
                    )
                except KeyError:
                    continue
                ioc_info.common_status = CommonStatus.DEPLOYED_IN_PROD
                ioc_info.common_deployed_in_hutch_names = self.common_ioc_summary_table[
                    ioc_info.common_full_path
                ].rocky9_hutch_names
                self.hutch_summary_table[
                    ioc_info.hutch
                ].common_deployed_in_prod_count += 1
                self.host_summary_table[
                    ioc_info.hostname
                ].common_deployed_in_prod_count += 1
                self.hutch_summary_table["all"].common_deployed_in_prod_count += 1


@functools.lru_cache(maxsize=1024)
def get_common_status(common_ioc: str) -> CommonStatus:
    if (
        common_ioc == UNKNOWN
        or "/cds/group/pcds/epics/ioc/" not in common_ioc
        or "/common/" not in common_ioc
    ):
        return CommonStatus.NO_COMMON
    supp_os = get_supported_os(common_ioc=common_ioc)
    if supp_os == GOAL_OS:
        # This might not be correct
        # We'll need to promote some of these to DEPLOYED_IN_PROD later when we know
        return CommonStatus.BUILT_IN_PROD
    elif supp_os in NEEDS_UPGRADE:
        return CommonStatus.NOT_BUILT
    else:
        return CommonStatus.NOT_MIGRATING


@functools.lru_cache(maxsize=1024)
def get_parent_version(parent_ioc: str) -> str:
    version_str = Path(parent_ioc).name
    try:
        Version(version_str.removeprefix("R"))
    except InvalidVersion:
        return "dev"
    return version_str


@functools.lru_cache(maxsize=1024)
def get_common_latest(common_ioc: str) -> str:
    highest_ver_str = "R0.0.0"
    highest_version = Version("0.0.0")
    for ver_path in Path(common_ioc).glob("*"):
        ver_str = ver_path.name
        try:
            this_version = Version(ver_str.removeprefix("R"))
        except Exception:
            continue
        if this_version > highest_version:
            highest_version = this_version
            highest_ver_str = ver_str
    return highest_ver_str


@dataclasses.dataclass
class WorkStationStatus:
    hostname: str
    host_os: str


def get_workstation_objs(hutches: list[str]) -> list[WorkStationStatus]:
    objs: list[WorkStationStatus] = []
    suffix = ["-daq*", "-control*", "-monitor*", "-console*", "-hutch*"]
    for hutch in hutches:
        for suff in suffix:
            host_info_json = subprocess.check_output(
                ["sdfconfig", "search", "--json", f"{hutch}{suff}"],
                universal_newlines=True,
            )
            host_info_list = json.loads(host_info_json)
            for info in host_info_list:
                status = WorkStationStatus(
                    hostname=info["Hostname"], host_os=info["OS"]
                )
                objs.append(status)
    objs.sort(key=lambda obj: obj.hostname)
    return objs


@dataclasses.dataclass
class Progress:
    header: str
    pct: int
    color: str


def frac_to_color(frac: float) -> str:
    """
    Convert a fraction from 0.0 to 1.0 to a suitable progress hex color.

    0.0 to 0.33 will be red
    0.33 to 0.66 will be yellow
    0.66 to 1.0 will be green

    Strangely: only a small subset of these are supported for table backgrounds
    in confluence, so these numbers are picked very specifically
    """
    if frac < 0.33:
        return "#ff8f73"
    if frac < 0.66:
        return "#ffc400"
    return "#79f2c0"


def build_rocky9_table(hutches: list[str]) -> str:
    confluence_hutches = [hutch for hutch in hutches if hutch != "all"]
    stats_page = ConfluenceStatsPage.from_hutch_list(hutch_list=confluence_hutches)
    with open(Path(__file__).parent / "rocky9_table.html.j2", "r") as fd:
        template = jinja2.Template(fd.read())
    # Put things into the table orders
    hutch_order = sorted(confluence_hutches)
    summary_objs = [stats_page.hutch_summary_table["all"]]
    hutch_dicts = []
    for hutch in hutch_order:
        summary_objs.append(stats_page.hutch_summary_table[hutch])
        local_ioc_order = sorted(ioc for ioc in stats_page.hutch_tables[hutch])
        local_iocs = [stats_page.hutch_tables[hutch][ioc] for ioc in local_ioc_order]
        hutch_dicts.append({"hutch": hutch, "iocs": local_iocs})
    host_order = sorted(host for host in stats_page.host_summary_table)
    host_objs = []
    host_dicts = []
    for host in host_order:
        host_objs.append(stats_page.host_summary_table[host])
        local_ioc_order = sorted(ioc for ioc in stats_page.host_tables[host])
        local_iocs = [stats_page.host_tables[host][ioc] for ioc in local_ioc_order]
        host_dicts.append({"hostname": host, "iocs": local_iocs})
    common_ioc_objs = list(stats_page.common_ioc_summary_table.values())
    common_ioc_objs.sort(key=lambda obj: obj.name)
    common_ioc_objs.sort(key=lambda obj: obj.any_os_deployed_count, reverse=True)
    workstation_objs = get_workstation_objs(hutches=confluence_hutches)
    progress_bars = []
    host_frac = stats_page.hutch_summary_table["all"].rocky9_host_count / (
        stats_page.hutch_summary_table["all"].rocky9_host_count
        + stats_page.hutch_summary_table["all"].rhel7_host_count
        + stats_page.hutch_summary_table["all"].rhel5_host_count
    )
    ioc_frac = stats_page.hutch_summary_table["all"].rocky9_ioc_count / (
        stats_page.hutch_summary_table["all"].rocky9_ioc_count
        + stats_page.hutch_summary_table["all"].rhel7_ioc_count
        + stats_page.hutch_summary_table["all"].rhel5_ioc_count
    )
    workstation_at_rocky9 = len(
        [st for st in workstation_objs if "rocky" in st.host_os.lower()]
    )
    workstation_frac = workstation_at_rocky9 / len(workstation_objs)
    progress_bars.append(
        Progress(
            header="Host upgrade progress",
            pct=int(100 * host_frac),
            color=frac_to_color(host_frac),
        )
    )
    progress_bars.append(
        Progress(
            header="IOC upgrade progress",
            pct=int(100 * ioc_frac),
            color=frac_to_color(ioc_frac),
        )
    )
    progress_bars.append(
        Progress(
            header="Hutch workstation upgrade progress",
            pct=int(100 * workstation_frac),
            color=frac_to_color(workstation_frac),
        )
    )
    return template.render(
        summary_objs=summary_objs,
        hutch_dicts=hutch_dicts,
        host_objs=host_objs,
        host_dicts=host_dicts,
        common_ioc_objs=common_ioc_objs,
        workstation_objs=workstation_objs,
        progress_bars=progress_bars,
    )


def main(sys_argv: list[str] | None = None) -> int:
    parser = get_parser()
    args = parser.parse_args(sys_argv)
    iocmanager_log_config(args)
    if args.hutch == "all":
        hutches = ALL_HUTCHES
    else:
        hutches = [args.hutch]
    if args.confluence_table:
        print(build_rocky9_table(hutches))
        return 0
    if args.debug_ioc:
        config = read_config(args.hutch)
        ioc_proc = config.procs[args.debug_ioc]
        print(ioc_proc)
        result = IOCResult.from_ioc_proc(ioc_proc=ioc_proc)
        print(result)
        return 0
    if args.debug_host:
        configs = [read_config(hutch) for hutch in hutches if hutch != "all"]
        results = []
        for cfg in configs:
            for proc in cfg.procs.values():
                if proc.host == args.debug_host:
                    results.append(IOCResult.from_ioc_proc(proc))
        for res in results:
            print(res)
        return 0

    results = SurveyResult.from_hutch_list(hutch_list=hutches)
    for hutch_res in results.hutch_results:
        if args.debug_common:
            for res in hutch_res.ioc_results:
                if res.common_ioc == args.debug_common:
                    print(res)
        elif args.include_disabled:
            print(f"{hutch_res.hutch} results: (all iocs)")
            stats = SurveyStats.from_results(hutch_res.ioc_results)
            stats.print_data()
            logger.debug(stats)
        else:
            print(f"{hutch_res.hutch} results: (enabled only)")
            stats = SurveyStats.from_results(
                res for res in hutch_res.ioc_results if res.enabled
            )
            stats.print_data()
            logger.debug(stats)
        logger.debug(hutch_res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
