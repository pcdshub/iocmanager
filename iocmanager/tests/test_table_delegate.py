import time

import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtCore import QSize
from qtpy.QtWidgets import QApplication, QComboBox, QStyleOptionViewItem, QWidget

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
    "row,column,expected_options",
    (
        (0, TableColumn.IOCNAME, ()),
        (0, TableColumn.ID, ()),
        (0, TableColumn.STATUS, ()),
        (0, TableColumn.OSVER, ()),
        (0, TableColumn.PORT, ()),
        (0, TableColumn.PARENT, ()),
        (0, TableColumn.EXTRA, ()),
        (1, TableColumn.STATE, ("Off", "Dev/Prod")),
        (2, TableColumn.STATE, ("Off", "Dev/Prod")),
        (1, TableColumn.HOST, ("host", "host2", "New Host")),
        (2, TableColumn.HOST, ("host", "host2", "New Host")),
        (1, TableColumn.VERSION, ("ioc/some/path/1", "New Version")),
        (2, TableColumn.VERSION, ("ioc/some/path/2", "old/version", "New Version")),
    ),
)
def test_create_editor(
    row: int,
    column: int,
    expected_options: tuple[str, ...],
    delegate: IOCTableDelegate,
    qtbot: QtBot,
):
    """
    createEditor has non-default behavior for STATE, HOST, and VERSION.

    Each of these should create a suitable combobox with the correct options.

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
    widget = delegate.createEditor(
        parent=parent,
        option=QStyleOptionViewItem(),
        index=delegate.model.index(row, column),
    )

    match column:
        case TableColumn.STATE | TableColumn.HOST | TableColumn.VERSION:
            assert isinstance(widget, QComboBox)
            for index, text in enumerate(expected_options):
                assert widget.itemText(index) == text
        case _:
            assert isinstance(widget, QWidget)
