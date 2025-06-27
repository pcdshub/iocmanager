"""
This script uses IOC manager to survey the state of operating system update efforts.
"""

import argparse
import dataclasses
import datetime
import functools
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version

from .. import log_setup
from ..config import IOCProc, get_host_os, read_config
from ..env_paths import env_paths

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

logger = logging.getLogger(__name__)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iocmanager survey-os")
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help=(
            "Increase debug verbosity. "
            "-v or --verbose shows debug messages, "
            "-vv shows spammy debug messages."
        ),
    )
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
    return parser


@dataclasses.dataclass
class IOCResult:
    name: str
    current_os: str
    common_ioc: str
    supported_os: str
    enabled: bool
    hostname: str

    @classmethod
    def from_ioc_proc[T: IOCResult](cls: type[T], ioc_proc: IOCProc) -> T:
        current_os = get_one_host_os(ioc_proc.host)
        common_ioc = get_common_ioc(ioc_proc.parent)
        if common_ioc.startswith(REG):
            common_ioc = common_ioc.replace(REG, CDS, 1)
        if PACKAGE in common_ioc:
            common_ioc = common_ioc.replace(PACKAGE, NOPACK, 1)
        name = Path(common_ioc).name.lower()
        if name in RENAMES:
            common_ioc = str(Path(common_ioc).parent / RENAMES[name])
        supported_os = get_supported_os(common_ioc)
        if current_os == UNKNOWN and "rhel" not in supported_os:
            # Small hack: assume the weird OSes are as they should be on the host
            current_os = supported_os
        return cls(
            name=ioc_proc.name,
            current_os=current_os,
            common_ioc=common_ioc,
            supported_os=supported_os,
            enabled=not ioc_proc.disable,
            hostname=ioc_proc.host,
        )


@dataclasses.dataclass
class SurveyStats:
    ioc_count: int
    common_ready_count: int
    common_ready_percent: float
    remaining_common_by_ioc: dict[str, int]
    live_os_ioc_count: dict[str, int]
    live_os_percent: dict[str, float]
    iocs_with_unk_common: list[str]
    common_with_unk_os: list[str]
    hosts_with_unk_os: set[str]

    def print_data(self):
        print(
            f"{self.common_ready_percent:.2f}% "
            f"({self.common_ready_count}/{self.ioc_count}) "
            "of IOCs ready to migrate."
        )
        for common_ioc, count in sorted(
            self.remaining_common_by_ioc.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"{count} IOCs waiting on {common_ioc}")
        for os_name in list(HOST_OS_TO_NAME.values()):
            count = self.live_os_ioc_count[os_name]
            if not count:
                continue
            print(
                f"{self.live_os_percent[os_name]:.2f}% "
                f"({count}/{self.ioc_count}) "
                f"of IOCs running {os_name}."
            )
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

    @classmethod
    def from_results[T: SurveyStats](cls: type[T], results: Iterable[IOCResult]) -> T:
        ioc_count = 0
        common_ready_count = 0
        remaining_common_by_ioc = defaultdict(int)
        live_os_ioc_count = dict.fromkeys(list(HOST_OS_TO_NAME.values()), 0)
        iocs_with_unk_common = []
        common_with_unk_os = []
        hosts_with_unk_os = set()
        for res in results:
            ioc_count += 1
            if res.supported_os == GOAL_OS:
                common_ready_count += 1
            elif res.supported_os in NEEDS_UPGRADE:
                remaining_common_by_ioc[res.common_ioc] += 1
            live_os_ioc_count[HOST_OS_TO_NAME.get(res.current_os, res.current_os)] += 1
            if res.common_ioc == UNKNOWN:
                iocs_with_unk_common.append(res.name)
            elif res.supported_os == UNKNOWN:
                common_with_unk_os.append(res.common_ioc)
            if res.current_os == UNKNOWN:
                hosts_with_unk_os.add(res.hostname)
        if ioc_count == 0:
            raise RuntimeError("No IOCs in results!")
        common_ready_percent = 100 * (common_ready_count / ioc_count)
        live_os_percent = {
            os_name: 100 * os_count / ioc_count
            for os_name, os_count in live_os_ioc_count.items()
        }
        return cls(
            ioc_count=ioc_count,
            common_ready_count=common_ready_count,
            common_ready_percent=common_ready_percent,
            remaining_common_by_ioc=dict(remaining_common_by_ioc),
            live_os_ioc_count=live_os_ioc_count,
            live_os_percent=live_os_percent,
            iocs_with_unk_common=iocs_with_unk_common,
            common_with_unk_os=common_with_unk_os,
            hosts_with_unk_os=hosts_with_unk_os,
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
    if parent_ioc.startswith(env_paths.EPICS_SITE_TOP):
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
    if parent_path.name.startswith("ioc-common-"):
        guess = parent_path.name.removeprefix("ioc-common-")
        try:
            return path_from_guess(guess=guess)
        except RuntimeError:
            ...
    # Variant 2: /some/path/to/ioc/common/name/something
    if "/ioc/common/" in parent_ioc:
        guess = parent_ioc.split("/ioc/common/")[-1].split(os.sep)[0]
        try:
            return path_from_guess(guess=guess)
        except RuntimeError:
            ...
    # Might not even be EPICS, check for python stuff
    for option in ("conda", "pspkg", "python"):
        if option in parent_ioc:
            return option
    # Fallback, e.g. no parent IOC
    return UNKNOWN


def path_from_guess(guess: str) -> str:
    ioc_common = Path(env_paths.EPICS_SITE_TOP) / "ioc" / "common"
    guess = RENAMES.get(guess.lower(), guess)
    for ioc_path in ioc_common.glob("*"):
        if ioc_path.name.lower() == guess.lower():
            return str(ioc_path)
    raise RuntimeError(f"Could not find a match for {guess}")


@functools.lru_cache(maxsize=1024)
def get_supported_os(common_ioc: str) -> str:
    """
    Get the latest supported OS for a common ioc.

    The input should be the path that contains the versioned subdirectories.
    """
    if common_ioc == "conda":
        return "rhel9"
    elif common_ioc in ("pspkg", "python"):
        return "rhel7"
    latest_version = None
    for version_dir in Path(common_ioc).glob("R*"):
        this_version = version_dir.name.removeprefix("R")
        try:
            if latest_version is None:
                latest_version = Version(this_version)
            else:
                new_version = Version(this_version)
                if new_version > latest_version:
                    latest_version = new_version
        except InvalidVersion:
            ...
    if latest_version is None:
        return UNKNOWN
    for arch in ARCH_TO_NAME:
        binaries = list(
            (Path(common_ioc) / f"R{latest_version}" / "bin").glob(f"{arch}/*")
        )
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


def main(sys_argv: list[str] | None = None) -> int:
    parser = get_parser()
    args = parser.parse_args(sys_argv)
    if not args.verbose:
        logging.basicConfig(level=logging.INFO)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=log_setup.SPAM_LEVEL)
    if args.hutch == "all":
        hutches = ALL_HUTCHES
    else:
        hutches = [args.hutch]
    results = SurveyResult.from_hutch_list(hutch_list=hutches)
    for hutch_res in results.hutch_results:
        if args.include_disabled:
            print(f"{hutch_res.hutch} results: (all iocs)")
            SurveyStats.from_results(hutch_res.ioc_results).print_data()
        else:
            print(f"{hutch_res.hutch} results: (enabled only)")
            SurveyStats.from_results(
                res for res in hutch_res.ioc_results if res.enabled
            ).print_data()
        logger.debug(hutch_res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
