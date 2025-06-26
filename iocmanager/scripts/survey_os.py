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
OS_PRIORITY = ["rhel9", "rhel7", "rhel5", "rtems", "ang_v2017"]
UNKNOWN = "Unknown"
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
    return parser


@dataclasses.dataclass
class IOCResult:
    name: str
    current_os: str
    common_ioc: str
    supported_os: str
    enabled: bool

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
        return cls(
            name=ioc_proc.name,
            current_os=current_os,
            common_ioc=common_ioc,
            supported_os=supported_os,
            enabled=not ioc_proc.disable,
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
        for os_name in OS_PRIORITY + [UNKNOWN]:
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
                "The following common IOC OSes could not be found: "
                f"{self.common_with_unk_os}"
            )

    @classmethod
    def from_results[T: SurveyStats](cls: type[T], results: Iterable[IOCResult]) -> T:
        ioc_count = 0
        common_ready_count = 0
        remaining_common_by_ioc = defaultdict(int)
        live_os_ioc_count = dict.fromkeys(OS_PRIORITY + [UNKNOWN], 0)
        iocs_with_unk_common = []
        common_with_unk_os = []
        for res in results:
            ioc_count += 1
            if res.supported_os == OS_PRIORITY[0]:
                common_ready_count += 1
            else:
                remaining_common_by_ioc[res.common_ioc] += 1
            live_os_ioc_count[res.current_os] += 1
            if res.common_ioc == UNKNOWN:
                iocs_with_unk_common.append(res.name)
            elif res.supported_os == UNKNOWN:
                common_with_unk_os.append(res.common_ioc)
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
    for os_name in OS_PRIORITY:
        binaries = list(
            (Path(common_ioc) / f"R{latest_version}" / "bin").glob(f"{os_name}*/*")
        )
        if binaries:
            return os_name
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
        print(f"{hutch_res.hutch} results: (enabled only)")
        SurveyStats.from_results(
            res for res in hutch_res.ioc_results if res.enabled
        ).print_data()
        print(f"{hutch_res.hutch} results: (all iocs)")
        SurveyStats.from_results(hutch_res.ioc_results).print_data()
        logger.debug(hutch_res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
