"""
Helpers for starting interactive tests using the fake data from the test suite.

Usage:

python -m iocmanager.tests.interactive gui (args)
python -m iocmanager.tests.interactive imgr (args)
python -m iocmanager.tests.interactive add_ioc_dialog
python -m iocmanager.tests.interactive floating_terminal command
python -m iocmanager.tests.interactive gnome_terminal command
python -m iocmanager.tests.interactive xterm_terminal command

More can be easily be added later.
"""

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from pytest import MonkeyPatch
from qtpy.QtWidgets import QApplication, QDialog

from ..config import Config
from ..dialog_add_ioc import AddIOCDialog
from ..env_paths import env_paths
from ..gui import main as gui_main
from ..imgr import main as imgr_main
from ..table_model import IOCTableModel
from ..terminal import run_in_floating_terminal, run_in_gnome_terminal, run_in_xterm
from .conftest import setup_test_env


def add_ioc_dialog() -> int:
    app = QApplication([])  # noqa: F841
    config = Config("")
    model = IOCTableModel(config=config, hutch="pytest")
    dialog = AddIOCDialog(hutch="pytest", model=model, parent=None)
    while dialog.exec_() == QDialog.Accepted:
        print(dialog.get_ioc_proc())
    return 0


def main() -> int:
    # Set environment variables etc. similar to the test suite
    with MonkeyPatch.context() as monkeypatch:
        with TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            print(f"Using temp dir {tmpdir}")
            setup_test_env(tmp_path=Path(tmpdir), monkeypatch=monkeypatch)
            print("Using the following environment overrides:")
            for name in dir(env_paths):
                if name.startswith("_"):
                    continue
                print(f"{name} = {getattr(env_paths, name)}")

            # Process args and pass them on
            command = sys.argv[1]
            args = sys.argv[2:]

            print(f"\nStarting interactive test of {command} {' '.join(args)}\n")

            match command:
                case "gui":
                    return gui_main(args)
                case "imgr":
                    return imgr_main(args)
                case "add_ioc_dialog":
                    return add_ioc_dialog()
                case "floating_terminal":
                    shell_cmd = " ".join(args)
                    proc = run_in_floating_terminal(
                        title="Test run_in_floating_terminal", cmd=shell_cmd, out=None
                    )
                    return proc.wait()
                case "gnome_terminal":
                    proc = run_in_gnome_terminal(
                        title="Test run_in_gnome_terminal", args=args, out=None
                    )
                    return proc.wait()
                case "xterm_terminal":
                    proc = run_in_xterm(title="Test run_in_xterm", args=args, out=None)
                    return proc.wait()
                case other:
                    raise RuntimeError(f"Unhandled command {other}")


if __name__ == "__main__":
    return_code = main()
    print(f"Return code was {return_code}")
    sys.exit(return_code)
