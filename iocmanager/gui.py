"""
The gui module parses user input for the iocmanager gui.

Some imports here are deferred to speed up low-op actions like --help
"""

import argparse
import logging
import time
from importlib import import_module
from importlib.util import find_spec

from .log_setup import add_verbose_arg, iocmanager_log_config
from .version import version as version_str

logger = logging.getLogger(__name__)


def get_parser():
    parser = argparse.ArgumentParser(
        prog="iocmanager",
        description=(
            "iocmanager is a GUI application for managing IOCs. "
            "It allows you to start, stop, and debug IOC processes "
            "running inside procServ on your servers."
        ),
    )
    add_verbose_arg(parser)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "hutch", nargs="?", help="The area whose IOCs you'd like to manage."
    )
    group.add_argument(
        "--version", action="store_true", help="Show the version information and exit."
    )
    try:
        # Fastest way to check for package without importing it
        lp_spec = find_spec("line_profiler")
    except ValueError:
        ...
    else:
        if lp_spec is not None:
            parser.add_argument(
                "--profile",
                action="store_true",
                help="Run line profiling for iocmanager to find performance issues.",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = get_parser()
    args = parser.parse_args(argv)
    if args.profile:
        print("Setting up profiler...")
        start = time.monotonic()
        # Late import: optional dep
        from line_profiler import LineProfiler

        profiler = LineProfiler()
        modules = set()
        for obj in globals().values():
            try:
                module_name = obj.__module__
                if "iocmanager" in module_name:
                    modules.add(module_name)
            except AttributeError:
                ...
        for mod in modules:
            real_module = import_module(mod)
            profiler.add_module(real_module)
        print(f"Importing modules for profiler took {time.monotonic() - start}s")
        profiler.enable_by_count()
    else:
        profiler = None
    rval = _main(args)
    if profiler is not None:
        profiler.disable_by_count()
        profiler.print_stats(stripzeros=True, sort=True)
    return rval


def _main(args) -> int:
    if args.version:
        print(version_str)
        return 0
    iocmanager_log_config(args)
    # Late imports: speed up --help, etc.
    from qtpy.QtWidgets import QApplication

    from .main_window import IOCMainWindow

    app = QApplication([""])
    gui = IOCMainWindow(hutch=args.hutch.lower())
    gui.show()
    return app.exec_()
