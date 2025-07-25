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

from ..cli import main as cli_main
from ..commit import commit_config
from ..config import Config, IOCProc, IOCStatusFile
from ..dialog_add_ioc import AddIOCDialog
from ..dialog_apply_verify import verify_dialog
from ..env_paths import env_paths
from ..gui import main as gui_main
from ..procserv_tools import ApplyConfigContext, VerifyPlan
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


def apply_verify_dialog() -> int:
    app = QApplication([])  # noqa: F841
    status_files = {}
    proc_config = {}
    kill = []
    start = []
    restart = []
    # Normal kill ioc, but not present in status/config
    kill.append("ioc_to_kill_1")
    # Normal start ioc, has a status file
    start.append("ioc_to_start_1")
    status_files["ioc_to_start_1"] = IOCStatusFile(
        name="ioc_to_start_1",
        port=30001,
        host="host1",
        path="/some/path/1",
        pid=12345,
    )
    # A second start ioc, has a proc config
    start.append("ioc_to_start_2")
    proc_config["ioc_to_start_2"] = IOCProc(
        name="ioc_to_start_2",
        port=30002,
        host="host1",
        path="/some/path/2",
    )
    # Normal restart ioc, has both status file and proc config
    restart.append("ioc_to_restart_1")
    status_files["ioc_to_restart_1"] = IOCStatusFile(
        name="ioc_to_restart_1",
        port=30001,
        host="host2",
        path="/some/path/3",
        pid=12345,
    )
    proc_config["ioc_to_restart_1"] = IOCProc(
        name="ioc_to_restart_1",
        port=30001,
        host="host2",
        path="/some/path/3",
    )
    # Normal kill and start, has a proc config with an alias
    kill.append("ioc_to_kill_and_start_1")
    start.append("ioc_to_kill_and_start_1")
    proc_config["ioc_to_kill_and_start_1"] = IOCProc(
        name="ioc_to_kill_and_start_1",
        port=30001,
        host="host2",
        path="/some/path/4",
        alias="Cool Fourth Category IOC",
    )
    starting_plan = VerifyPlan(kill_list=kill, start_list=start, restart_list=restart)
    print(starting_plan)
    new_plan = verify_dialog(
        context=ApplyConfigContext(
            status_files=status_files,
            proc_config=proc_config,
        ),
        plan=starting_plan,
    )
    print(new_plan)
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
                    return cli_main(args)
                case "add_ioc_dialog":
                    return add_ioc_dialog()
                case "apply_verify_dialog":
                    return apply_verify_dialog()
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
                case "ssh_for_commit":
                    return commit_config(
                        hutch="commit_test",
                        comment="test comment",
                        show_output=True,
                        ssh_verbose=1,
                        script="echo",
                    ).returncode
                case other:
                    raise RuntimeError(f"Unhandled command {other}")


if __name__ == "__main__":
    return_code = main()
    print(f"Return code was {return_code}")
    sys.exit(return_code)
