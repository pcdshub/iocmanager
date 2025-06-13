import time
from typing import Any

import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtCore import QSize
from qtpy.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QLineEdit,
    QSpinBox,
    QStyleOptionViewItem,
    QWidget,
)

from ..table_delegate import IOCTableDelegate
from ..table_model import TableColumn


@pytest.mark.parametrize("column", [col.value for col in TableColumn])
def test_size_hint(column: int, delegate: IOCTableDelegate, qapp: QApplication):
    """
    sizeHint should return QSize for any valid index.

    Don't bother checking specifics, we might want to
    change them later (to taste).
    """
    assert isinstance(
        delegate.sizeHint(
            option=QStyleOptionViewItem(), index=delegate.model.index(0, column)
        ),
        QSize,
    )


@pytest.mark.parametrize(
    "row,column,expected_options,expected_index",
    (
        (0, TableColumn.IOCNAME, (), 0),
        (0, TableColumn.ID, (), 0),
        (0, TableColumn.STATUS, (), 0),
        (0, TableColumn.OSVER, (), 0),
        (0, TableColumn.PORT, (), 0),
        (0, TableColumn.PARENT, (), 0),
        (0, TableColumn.EXTRA, (), 0),
        (1, TableColumn.STATE, ("Off", "Dev/Prod"), 0),
        (2, TableColumn.STATE, ("Off", "Dev/Prod"), 1),
        (1, TableColumn.HOST, ("host", "host2", "New Host"), 0),
        (2, TableColumn.HOST, ("host", "host2", "New Host"), 1),
        (1, TableColumn.VERSION, ("ioc/some/path/1", "New Version"), 0),
        (2, TableColumn.VERSION, ("ioc/some/path/2", "old/version", "New Version"), 0),
    ),
)
def test_create_and_set_editor(
    row: int,
    column: int,
    expected_options: tuple[str, ...],
    expected_index: int,
    delegate: IOCTableDelegate,
    qtbot: QtBot,
):
    """
    This tests both createEditor and setEditorData.

    createEditor can be tested independendently but setEditorData only
    makes sense in the context of na existing editor widget, so it makes
    sense to combine the tests.

    We have non-default behavior for STATE, HOST, and VERSION.

    Each of these should create a suitable combobox with the correct options,
    and when we set the data the starting index should match our data source.

    The others should return a default QWidget, but we won't inspect what it is
    (it might slightly change in a new qt version but we shouldn't care).
    """
    # Set up the scenario
    config = delegate.model.get_next_config()
    # ioc1 is disabled, stays on default host, has no history
    ioc1 = config.procs["ioc1"]
    ioc1.disable = True
    config.update_proc(proc=ioc1)
    # ioc2 is default enabled, is on new host2, has an extra old/version history
    ioc2 = config.procs["ioc2"]
    ioc2.host = "host2"
    ioc2.history.append("old/version")
    config.update_proc(proc=ioc2)
    config.mtime = time.time()
    delegate.model.update_from_config_file(config=config)

    parent = QWidget()
    qtbot.add_widget(parent)
    index = delegate.model.index(row, column)
    widget = delegate.createEditor(
        parent=parent,
        option=QStyleOptionViewItem(),
        index=index,
    )

    match column:
        case TableColumn.STATE | TableColumn.HOST | TableColumn.VERSION:
            assert isinstance(widget, QComboBox)
            for idx, text in enumerate(expected_options):
                assert widget.itemText(idx) == text
        case _:
            assert isinstance(widget, QWidget)

    delegate.setEditorData(editor=widget, index=index)

    match column:
        case TableColumn.STATE | TableColumn.HOST | TableColumn.VERSION:
            assert isinstance(widget, QComboBox)
            assert widget.currentIndex() == expected_index


@pytest.mark.parametrize(
    "column,choice,expected_attr,expected_before,expected_after",
    (
        # Port is the only editable field without a custom editor
        # For the integer we expect a default QSpinBox
        (TableColumn.PORT, 40001, "port", 30001, 40001),
        # Select a combobox option other than the default
        (TableColumn.STATE, 0, "disable", False, True),
        (TableColumn.HOST, 1, "host", "host", "host2"),
        (TableColumn.VERSION, 1, "path", "ioc/some/path/0", "/old/ver"),
        # Select the "new host/version" option
        (TableColumn.HOST, 2, "host", "host", "new_host"),
        (TableColumn.VERSION, 2, "path", "ioc/some/path/0", "/new/ver"),
    ),
)
def test_set_model_data(
    column: int,
    choice: int | str,
    expected_attr: str,
    expected_before: int | str | bool,
    expected_after: int | str | bool,
    delegate: IOCTableDelegate,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    delegate.setModelData should update the model based on the widget value.

    We will check each editable column and pick either a new value or a
    new combobox index, and make sure the data chain goes all the way through.

    We will hard-code user responses to the dialogs as needed via patching.
    The dialog overrides assume the user accepts the dialog.
    Dialog rejections should be tested separately.
    """
    # Check the before case
    # This is a sanity check to make sure we change something
    assert expected_before != expected_after

    def get_config_value(attr=expected_attr) -> Any:
        ioc_proc = delegate.model.get_next_config().procs["ioc0"]
        return getattr(ioc_proc, attr)

    assert get_config_value() == expected_before

    # Make an extra host available (host2)
    delegate.model.config.hosts.append("host2")
    assert "host2" in delegate.model.get_next_config().hosts

    # Make an extra version /old/ver available
    delegate.model.config.procs["ioc0"].history.append("/old/ver")
    delegate.model.config.update_proc(delegate.model.config.procs["ioc0"])
    assert get_config_value(attr="history") == ["/old/ver"]

    # Set up auto fill/returns for the dialogs
    def fake_host_dialog_exec() -> QDialog.DialogCode:
        delegate.hostdialog.ui.hostname.setText("new_host")
        return QDialog.Accepted

    delegate.hostdialog.exec_ = fake_host_dialog_exec

    def fake_file_dialog_exec(self) -> QDialog.DialogCode:
        return QDialog.Accepted

    def fake_file_dialog_files(self) -> list[str]:
        return ["/new/ver"]

    monkeypatch.setattr(QFileDialog, "exec_", fake_file_dialog_exec)
    monkeypatch.setattr(QFileDialog, "selectedFiles", fake_file_dialog_files)

    index = delegate.model.index(0, column)

    # Get an editor
    parent = QWidget()
    qtbot.add_widget(parent)
    editor = delegate.createEditor(
        parent=parent,
        option=QStyleOptionViewItem(),
        index=index,
    )
    # Manipulate the editor as a user would
    if isinstance(editor, QLineEdit):
        editor.setText(str(choice))
    elif isinstance(editor, QSpinBox):
        editor.setValue(int(choice))
    elif isinstance(editor, QComboBox):
        editor.setCurrentIndex(int(choice))
    else:
        raise TypeError(f"Unexpected editor type {type(editor)}")

    # Apply the value using setModelData
    delegate.setModelData(editor=editor, model=delegate.model, index=index)

    # Check the result!
    assert get_config_value() == expected_after
