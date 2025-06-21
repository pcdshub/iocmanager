from functools import partial
from unittest.mock import Mock

import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtCore import Qt
from qtpy.QtGui import QColor
from qtpy.QtWidgets import QMessageBox

from ..dialog_add_ioc import AddIOCDialog
from ..table_model import IOCTableModel
from . import IOC_FOLDER


@pytest.fixture(scope="function")
def add_ioc_dialog(model: IOCTableModel, qtbot: QtBot) -> AddIOCDialog:
    dialog = AddIOCDialog(hutch="pytest", model=model, parent=None)
    qtbot.add_widget(dialog)
    return dialog


def setup_cool_ioc(dialog: AddIOCDialog):
    dialog.name_edit.setText("ioc_name")
    dialog.alias_edit.setText("CoolIOC")
    dialog.host_edit.setText("neat_host")
    dialog.port_spinbox.setValue(31000)
    # A real directory different from the reset default of IOC_FOLDER / "pytest"
    dialog.setDirectory(str(IOC_FOLDER / "hutch_name"))
    # Note: selectFile is used to set the selected directory
    # This is because the dialog is in directory mode
    dialog.selectFile("repo_name")
    # See tests/ioc/hutch_name/repo_name/ioc_name.cfg


def test_get_ioc_proc(add_ioc_dialog: AddIOCDialog):
    """
    add_ioc_dialog.get_ioc_proc should return an IOCProc matching the inputs.
    """
    setup_cool_ioc(dialog=add_ioc_dialog)
    ioc_proc = add_ioc_dialog.get_ioc_proc()
    assert ioc_proc.name == "ioc_name"
    assert ioc_proc.alias == "CoolIOC"
    assert ioc_proc.host == "neat_host"
    assert ioc_proc.port == 31000
    assert ioc_proc.path == str(IOC_FOLDER / "hutch_name" / "repo_name")


def test_reset(add_ioc_dialog: AddIOCDialog):
    """
    add_ioc_dialog.reset should revert an IOCProc back to the defaults.
    """
    setup_cool_ioc(dialog=add_ioc_dialog)
    add_ioc_dialog.reset()
    ioc_proc = add_ioc_dialog.get_ioc_proc()
    assert ioc_proc.name == ""
    assert ioc_proc.alias == ""
    assert ioc_proc.host == ""
    assert ioc_proc.port == 30001
    assert ioc_proc.path == str(IOC_FOLDER / "pytest")


@pytest.mark.parametrize("mode", ("name", "directory", "file"))
def test_parent(mode: str, add_ioc_dialog: AddIOCDialog, qtbot: QtBot):
    """
    If we select a templated IOC, the parent text should be set correctly.

    Test whether modulating the ioc name, directory, or file
    properly triggers the update separately.
    """

    def correct_parent():
        assert add_ioc_dialog.parent_edit.text() == "/test/dialog/add_ioc"

    def no_parent():
        assert add_ioc_dialog.parent_edit.text() == ""

    # I couldn't find a way to trigger these signals in a test suite.
    # Even running interactively they're pretty unreliable.
    # This is a compromise.

    def set_dir_and_emit(target: str):
        add_ioc_dialog.setDirectory(target)
        add_ioc_dialog.directoryEntered.emit(target)

    def sel_file_and_emit(target: str):
        add_ioc_dialog.selectFile(target)
        try:
            emission = add_ioc_dialog.selectedFiles()[0]
        except KeyError:
            emission = target
        add_ioc_dialog.currentChanged.emit(emission)

    setup_cool_ioc(dialog=add_ioc_dialog)

    match mode:
        case "name":
            add_ioc_dialog.name_edit.setText("")
        case "directory":
            set_dir_and_emit(str(IOC_FOLDER))
        case "file":
            sel_file_and_emit("asdf")
        case _:
            raise ValueError("Error writing test")

    qtbot.wait_until(no_parent, timeout=1000)

    match mode:
        case "name":
            add_ioc_dialog.name_edit.setText("ioc_name")
        case "directory":
            set_dir_and_emit(str(IOC_FOLDER / "hutch_name"))
        case "file":
            sel_file_and_emit("repo_name")
        case _:
            raise ValueError("Error writing test")

    qtbot.wait_until(correct_parent, timeout=1000)


def test_port_select(
    add_ioc_dialog: AddIOCDialog, qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
):
    """
    Clicking on the select port push buttons should select an available port.

    There is a warning if you haven't filled in a host, since available port
    ranges are checked per host by comparing against the ports that other
    iocs use on that host.
    """
    warning_mock = Mock()
    monkeypatch.setattr(QMessageBox, "warning", warning_mock)

    def wait_mock_called(num: int):
        assert warning_mock.call_count == num

    add_ioc_dialog.reset()
    qtbot.mouseClick(add_ioc_dialog.auto_closed, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(partial(wait_mock_called, 1), timeout=1000)
    assert add_ioc_dialog.port_spinbox.value() == 30001
    qtbot.mouseClick(add_ioc_dialog.auto_open, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(partial(wait_mock_called, 2), timeout=1000)
    assert add_ioc_dialog.port_spinbox.value() == 30001

    def wait_correct_port(port: int):
        assert add_ioc_dialog.port_spinbox.value() == port

    add_ioc_dialog.host_edit.setText("host")
    qtbot.mouseClick(add_ioc_dialog.auto_closed, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(partial(wait_correct_port, 30011), timeout=1000)
    qtbot.mouseClick(add_ioc_dialog.auto_open, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(partial(wait_correct_port, 39100), timeout=1000)
    assert warning_mock.call_count == 2


@pytest.mark.parametrize(
    "port,color",
    (
        # Spot check a few example values
        (-1, "black"),
        (0, "red"),
        (30000, "red"),
        (30001, "black"),
        (38999, "black"),
        (39000, "red"),
        (39099, "red"),
        (39100, "black"),
        (39199, "black"),
    ),
)
def test_port_color(port: int, color: str, add_ioc_dialog: AddIOCDialog):
    """
    Invalid ports should get red text.
    """
    # Make sure we're testing the full range
    assert add_ioc_dialog.port_spinbox.minimum() == -1
    assert add_ioc_dialog.port_spinbox.maximum() == 39199
    add_ioc_dialog.port_spinbox.setValue(port)
    expected_color = QColor(color)
    actual_color = add_ioc_dialog.port_spinbox.palette().text().color()
    assert actual_color == expected_color
