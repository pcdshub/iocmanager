import dataclasses
import time
from copy import deepcopy
from typing import Any

import pytest
from qtpy.QtCore import QModelIndex, Qt, QVariant
from qtpy.QtGui import QBrush
from qtpy.QtWidgets import QApplication, QDialog

from .. import table_model
from ..config import Config, IOCProc
from ..procserv_tools import (
    AutoRestartMode,
    IOCStatusFile,
    IOCStatusLive,
    ProcServStatus,
)
from ..table_model import IOCTableModel, StateOption, TableColumn, table_headers


def test_get_next_config_and_reset_edits(model: IOCTableModel, qapp: QApplication):
    """
    model.get_next_config should return a Config object given the table data.

    This object should be the same as the most recent file config but with
    pending edits from the table applied on top of it.

    model.reset_edits should discard all the pending edits.
    It's convenient to test these together.
    """
    # Add three IOCs to the config
    for num in range(3):
        model.add_ioc(
            IOCProc(
                name=f"added{num}",
                port=40001 + num,
                host="blarg",
                path=f"ioc/some/blarg/{num}",
            )
        )
    # Modify an original config and a new config
    # Row 0 = ioc0
    model.setData(model.index(0, TableColumn.PORT), 31001)
    # Row 11 = added1
    model.setData(model.index(11, TableColumn.PORT), 41002)
    # Delete an original config and a new config
    # Note: pending deletion does not remove the row from the table!
    # Row 1 = ioc1
    model.delete_ioc(row=1)
    # Row 12 = added2
    model.delete_ioc(row=12)
    # Get the next config
    next_config = model.get_next_config()
    # All deleted IOCs should be gone, all non-deleted iocs should stay
    all_iocs = [f"ioc{num}" for num in range(10)] + [f"added{num}" for num in range(3)]
    deleted_iocs = ["ioc1", "added2"]
    for ioc_name in all_iocs:
        if ioc_name in deleted_iocs:
            assert ioc_name not in next_config.procs
        else:
            assert ioc_name in next_config.procs
    # All modified IOCs should be in their final states
    assert next_config.procs["ioc0"].port == 31001
    assert next_config.procs["added1"].port == 41002
    # Drop the modifications
    model.reset_edits()
    reset_config = model.get_next_config()
    # Now, only the based iocn iocs should exist
    for ioc_name in (f"ioc{num}" for num in range(10)):
        assert ioc_name in reset_config.procs
    for ioc_name in (f"added{num}" for num in range(3)):
        assert ioc_name not in reset_config.procs
    # The edit to ioc0 should be reverted
    assert reset_config.procs["ioc0"].port == 30001


def test_get_ioc_proc(model: IOCTableModel, qapp: QApplication):
    """
    model.get_ioc_proc should return the IOCProc a row displays/edits
    """
    # Add an IOC
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added",
            port=40001,
            host="new_host",
            path="ioc/some/other/path",
        )
    )
    # Edit an IOC
    # Simplest entrypoint for this is to pretend we used the delegate
    # to call setData
    # setData will be tested more thoroughly in test_set_data
    assert model.setData(index=model.index(2, TableColumn.PORT), value=50000)

    # Check an unmodified IOC from the starting config
    assert model.get_ioc_proc(row=4).name == "ioc4"
    # Check our modified IOC
    assert model.get_ioc_proc(row=2).port == 50000
    # Check our added IOC
    assert model.get_ioc_proc(row=10).name == "added"


def test_get_ioc_row_map(model: IOCTableModel, qapp: QApplication):
    """
    model.get_ioc_row_map should return a list of each ioc name

    The index of each name is the corresponding table row.
    """
    starting_map = [f"ioc{num}" for num in range(10)]
    assert model.get_ioc_row_map() == starting_map
    for num in range(3):
        model.add_ioc(
            ioc_proc=IOCProc(
                name=f"added{num}",
                port=40001 + num,
                host="host",
                path=f"ioc/some/path/{num}",
            )
        )
    ext_map = [f"added{num}" for num in range(3)]
    assert model.get_ioc_row_map() == starting_map + ext_map


def test_get_live_info(model: IOCTableModel, qapp: QApplication):
    """
    model.get_live_info should return information about the live IOC.

    There should be a priority order where values found via direct
    inspection of the IOC take precedence over values found via
    reading the status files.
    """
    # Currently required to exist in the config (or added)
    ioc_name = "ioc7"

    # Default case, no info at all
    null_info = model.get_live_info(ioc_name=ioc_name)
    assert null_info.name == ioc_name
    assert not null_info.port
    assert not null_info.host
    assert not null_info.path
    assert null_info.status == ProcServStatus.INIT

    # No status, but there's a file
    model.update_from_status_file(
        status_file=IOCStatusFile(
            name=ioc_name,
            port=40001,
            host="file_host",
            path="/ioc/file/path/haha",
            pid=12345,
        )
    )
    file_info = model.get_live_info(ioc_name=ioc_name)
    assert file_info.name == ioc_name
    assert file_info.port == 40001
    assert file_info.host == "file_host"
    assert file_info.path == "/ioc/file/path/haha"
    assert file_info.status == ProcServStatus.INIT

    # Yes status, but it's sparsely populated
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name=ioc_name,
            port=0,
            host="",
            path="",
            pid=0,
            status=ProcServStatus.ERROR,
            autorestart_mode=AutoRestartMode.OFF,
        )
    )
    file_info2 = model.get_live_info(ioc_name=ioc_name)
    assert file_info2.name == ioc_name
    assert file_info2.port == 40001
    assert file_info2.host == "file_host"
    assert file_info2.path == "/ioc/file/path/haha"
    assert file_info2.status == ProcServStatus.ERROR

    # Great status
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name=ioc_name,
            port=50001,
            host="live_host",
            path="/ioc/file/live",
            pid=20000,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    live_info = model.get_live_info(ioc_name=ioc_name)
    assert live_info.name == ioc_name
    assert live_info.port == 50001
    assert live_info.host == "live_host"
    assert live_info.path == "/ioc/file/live"
    assert live_info.status == ProcServStatus.RUNNING


def test_row_count(model: IOCTableModel, qapp: QApplication):
    """
    model.rowCount should return the number of rows in the table.

    For us, this is the number of configured IOCs plus the number
    of added IOCs.
    """
    assert model.rowCount() == 10
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added",
            port=40001,
            host="asdf",
            path="asdf",
        )
    )
    assert model.rowCount() == 11
    model.reset_edits()
    assert model.rowCount() == 10


def test_column_count(model: IOCTableModel, qapp: QApplication):
    """
    model.columnCount should return the number of columns in the table.

    For us, this is currently 10.
    """
    assert model.columnCount() == 10
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added",
            port=40001,
            host="asdf",
            path="asdf",
        )
    )
    assert model.columnCount() == 10


@pytest.mark.parametrize(
    "row,col,role,expected",
    (
        (0, TableColumn.ID, Qt.DisplayRole, "ioc0"),
        (1, TableColumn.PORT, Qt.EditRole, 30002),
        (2, TableColumn.HOST, Qt.ForegroundRole, QBrush(Qt.black)),
        (3, TableColumn.VERSION, Qt.BackgroundRole, QBrush(Qt.white)),
        (4, TableColumn.STATE, Qt.FontRole, QVariant()),
        (5, 100, Qt.DisplayRole, QVariant()),
        (6, -10, Qt.DisplayRole, QVariant()),
        (-10, TableColumn.STATUS, Qt.DisplayRole, QVariant()),
        (100, TableColumn.STATUS, Qt.DisplayRole, QVariant()),
    ),
)
def test_data(
    row: int,
    col: int,
    role: int,
    expected: Any,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.data should return data from the table.

    This may be the raw config data, the edited data,
    or iocs that are pending adds.

    Here, spot check just one data point for each role,
    cover file/edited/added, cover a few columns, cover bad inputs.
    We'll test the subfunctions more thoroughly elsewhere.
    """
    assert model.data(index=model.index(row, col), role=role) == expected


@pytest.mark.parametrize(
    "ioc_name,column,expected",
    (
        # Base cases: what it should for a basic fake ioc
        ("ioc0", TableColumn.IOCNAME, "ioc0"),
        ("ioc0", TableColumn.ID, "ioc0"),
        ("ioc0", TableColumn.STATE, StateOption.PROD),
        ("ioc0", TableColumn.STATUS, ProcServStatus.INIT),
        ("ioc0", TableColumn.HOST, "host"),
        ("ioc0", TableColumn.PORT, 30001),
        ("ioc0", TableColumn.VERSION, "ioc/some/path/0"),
        ("ioc0", TableColumn.PARENT, ""),
        ("ioc0", TableColumn.EXTRA, ""),
        # IOCNAME could also be an alias
        ("alias_ioc", TableColumn.IOCNAME, "BEST IOC EVER"),
        ("alias_ioc", TableColumn.ID, "alias_ioc"),
        # STATE can also be OFF or DEV
        ("disa_ioc", TableColumn.STATE, StateOption.OFF),
        ("dev_ioc", TableColumn.STATE, StateOption.DEV),
        # OSVER could exist if there's an entry for it
        ("os_ioc", TableColumn.OSVER, "local_os"),
        # PARENT can have information in it
        ("child_ioc", TableColumn.PARENT, "parent_ioc"),
        # EXTRA can be HARD IOC or a description of live IOC discrepancies
        ("hard_ioc", TableColumn.EXTRA, "HARD IOC"),
        ("rogue_ioc", TableColumn.EXTRA, "Live: /bad/path on badhost:50000"),
    ),
)
def test_get_display_data(
    ioc_name: str, column: int, expected: str, model: IOCTableModel, qapp: QApplication
):
    """
    model.get_display_data should get the data we want to display for the ioc's column.

    We'll set up a table that should have a variant from each possible code path,
    then we'll use parameterize to switch through them.
    """
    model.add_ioc(
        IOCProc(
            name="alias_ioc",
            port=40001,
            host="host",
            path="/some/path",
            alias="BEST IOC EVER",
        )
    )
    model.add_ioc(
        IOCProc(
            name="disa_ioc",
            port=40002,
            host="host",
            path="/another/path",
            disable=True,
        )
    )
    model.add_ioc(
        IOCProc(
            name="dev_ioc",
            port=40003,
            host="host",
            # Absolute paths outside of ioc dir are dev
            path="/yet/another/path",
        )
    )
    model.add_ioc(
        IOCProc(
            name="os_ioc",
            port=40004,
            host="known_os_host",
            # Absolute paths outside of ioc dir are dev
            path="/operating/systems",
        )
    )
    model.host_os["known_os_host"] = "local_os"
    child_ioc = IOCProc(
        name="child_ioc",
        port=40005,
        host="host",
        path="child/path",
    )
    # Override automatic parent finding
    child_ioc.parent = "parent_ioc"
    model.add_ioc(child_ioc)
    model.add_ioc(
        IOCProc(
            name="hard_ioc",
            port=30001,
            host="hard_ioc",
            path="/such/path/wow",
        )
    )
    model.add_ioc(
        IOCProc(
            name="rogue_ioc",
            port=40006,
            host="host",
            path="ioc/normal/path",
        )
    )
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="rogue_ioc",
            port=50000,
            host="badhost",
            path="/bad/path",
            pid=420,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )

    # Now that we've set up, let's check the case from params
    config = model.get_next_config()
    assert (
        model.get_display_data(ioc_proc=config.procs[ioc_name], column=column)
        == expected
    )


@pytest.mark.parametrize(
    "ioc_name,column,expected",
    (
        # Base cases: black text, except status INIT is blue bg white text
        ("ioc0", TableColumn.IOCNAME, Qt.black),
        ("ioc0", TableColumn.ID, Qt.black),
        ("ioc0", TableColumn.STATE, Qt.black),
        ("ioc0", TableColumn.STATUS, Qt.white),
        ("ioc0", TableColumn.HOST, Qt.black),
        ("ioc0", TableColumn.OSVER, Qt.black),
        ("ioc0", TableColumn.PORT, Qt.black),
        ("ioc0", TableColumn.VERSION, Qt.black),
        ("ioc0", TableColumn.PARENT, Qt.black),
        ("ioc0", TableColumn.EXTRA, Qt.black),
        # Modified fields are blue
        ("ioc1", TableColumn.IOCNAME, Qt.blue),
        ("ioc1", TableColumn.ID, Qt.black),
        ("ioc1", TableColumn.STATE, Qt.blue),
        ("ioc1", TableColumn.STATUS, Qt.white),
        ("ioc1", TableColumn.HOST, Qt.blue),
        ("ioc1", TableColumn.OSVER, Qt.black),
        ("ioc1", TableColumn.PORT, Qt.blue),
        ("ioc1", TableColumn.VERSION, Qt.blue),
        ("ioc1", TableColumn.PARENT, Qt.black),
        ("ioc1", TableColumn.EXTRA, Qt.black),
        # Deleted IOC is red
        ("ioc2", TableColumn.IOCNAME, Qt.red),
        ("ioc2", TableColumn.ID, Qt.red),
        ("ioc2", TableColumn.STATE, Qt.red),
        ("ioc2", TableColumn.STATUS, Qt.red),
        ("ioc2", TableColumn.HOST, Qt.red),
        ("ioc2", TableColumn.OSVER, Qt.red),
        ("ioc2", TableColumn.PORT, Qt.red),
        ("ioc2", TableColumn.VERSION, Qt.red),
        ("ioc2", TableColumn.PARENT, Qt.red),
        ("ioc2", TableColumn.EXTRA, Qt.red),
        # Added IOC is all blue
        ("added", TableColumn.IOCNAME, Qt.blue),
        ("added", TableColumn.ID, Qt.blue),
        ("added", TableColumn.STATE, Qt.blue),
        ("added", TableColumn.STATUS, Qt.blue),
        ("added", TableColumn.HOST, Qt.blue),
        ("added", TableColumn.OSVER, Qt.blue),
        ("added", TableColumn.PORT, Qt.blue),
        ("added", TableColumn.VERSION, Qt.blue),
        ("added", TableColumn.PARENT, Qt.blue),
        ("added", TableColumn.EXTRA, Qt.blue),
        # Port conflict -> red BG = white text (or blue if modified)
        ("ioc3", TableColumn.PORT, Qt.white),
        ("ioc4", TableColumn.PORT, Qt.blue),
        # Edited to dev mode -> black in state
        ("ioc5", TableColumn.STATE, Qt.black),
        # Yellow status bg -> black text
        ("ioc6", TableColumn.STATUS, Qt.black),
        # Green status bg -> black text
        ("ioc7", TableColumn.STATUS, Qt.black),
        # Red status bg -> white text
        ("ioc8", TableColumn.STATUS, Qt.white),
    ),
)
def test_get_foreground_color(
    ioc_name: str,
    column: int,
    expected: Qt.GlobalColor,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.get_foreground_color should get the text color of a cell.

    This is almost always black for black text, except:
    - Modified editable fields should be blue
    - Added IOCs should have all their text blue
    - Deleted IOCs should have all their text red

    In addition, we'll change black text to white on colored
    backgrounds such as blue or red.
    """
    # Modify one of each modifiable field
    model.setData(model.index(1, TableColumn.IOCNAME), "IOC ALIAS")
    model.setData(model.index(1, TableColumn.STATE), False)
    model.setData(model.index(1, TableColumn.HOST), "newhost")
    model.setData(model.index(1, TableColumn.PORT), 40001)
    model.setData(model.index(1, TableColumn.VERSION), "/new/version")
    # Delete an IOC
    model.delete_ioc(2)
    # Add an IOC
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added",
            port=40001,
            host="asdf",
            path="asdf",
        )
    )
    # Create a port conflict
    model.setData(model.index(4, TableColumn.PORT), 30004)
    # Edit dev variant
    model.setData(model.index(5, TableColumn.VERSION), "/epics-dev/stuff")
    # Set one of each status bg color variant
    # Yellow bg -> host, port, or path changed
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc6",
            port=30007,
            host="different_host",
            path="/some/other/path",
            pid=0,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Green bg -> running, consistent values
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc7",
            port=30008,
            host="host",
            path="ioc/some/path/7",
            pid=0,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Red bg -> Error, etc.
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc8",
            port=30009,
            host="host",
            path="ioc/some/path/8",
            pid=0,
            status=ProcServStatus.ERROR,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Check this test case
    config = model.get_next_config()
    try:
        ioc_proc = config.procs[ioc_name]
    except KeyError:
        ioc_proc = model.config.procs[ioc_name]
    assert model.get_foreground_color(ioc_proc=ioc_proc, column=column) == expected


@pytest.mark.parametrize(
    "ioc_name,column,expected",
    (
        # Base cases: white bg, except blue status
        ("ioc0", TableColumn.IOCNAME, Qt.white),
        ("ioc0", TableColumn.ID, Qt.white),
        ("ioc0", TableColumn.STATE, Qt.white),
        ("ioc0", TableColumn.STATUS, Qt.blue),
        ("ioc0", TableColumn.HOST, Qt.white),
        ("ioc0", TableColumn.OSVER, Qt.white),
        ("ioc0", TableColumn.PORT, Qt.white),
        ("ioc0", TableColumn.VERSION, Qt.white),
        ("ioc0", TableColumn.PARENT, Qt.white),
        ("ioc0", TableColumn.EXTRA, Qt.white),
        # Dev mode state is yellow
        ("ioc1", TableColumn.STATE, Qt.yellow),
        # Status green if running and enabled
        ("ioc2", TableColumn.STATUS, Qt.green),
        # Status green if shutdown and disabled
        ("ioc3", TableColumn.STATUS, Qt.green),
        # Status red if running and disabled
        ("ioc4", TableColumn.STATUS, Qt.red),
        # Status red if shutdown and enabled
        ("ioc5", TableColumn.STATUS, Qt.red),
        # Status yellow with some conflict
        ("ioc6", TableColumn.STATUS, Qt.yellow),
        # Status red with some other error
        ("ioc7", TableColumn.STATUS, Qt.red),
        # Port conflict -> red BG
        ("ioc8", TableColumn.PORT, Qt.red),
    ),
)
def test_get_background_color(
    ioc_name: str,
    column: int,
    expected: Qt.GlobalColor,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.get_background_color should get the background color for a cell.

    Most of these are white, except for a few situations to highlight:
    - STATE column can be yellow if we're in DEV mode
    - STATUS can be blue, yellow, green, or red depending on the live IOC's status
    - PORT can be highlighted red if it conflicts with another host/port combination
    """
    # Put one IOC in dev mode for STATE -> yellow
    model.setData(index=model.index(1, TableColumn.VERSION), value="/some/dev/folder")
    # Status starts at blue
    # Set up green, yellow, and red status examples
    # Green: running and enabled
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc2",
            port=30003,
            host="host",
            path="ioc/some/path/2",
            pid=0,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Green: shutdown and disabled
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc3",
            port=30004,
            host="host",
            path="ioc/some/path/3",
            pid=0,
            status=ProcServStatus.SHUTDOWN,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    model.setData(index=model.index(3, TableColumn.STATE), value=False)
    # Red: running and disabled
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc4",
            port=30005,
            host="host",
            path="ioc/some/path/4",
            pid=0,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    model.setData(index=model.index(4, TableColumn.STATE), value=False)
    # Red: shutdown and enabled
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc5",
            port=30006,
            host="host",
            path="ioc/some/path/5",
            pid=0,
            status=ProcServStatus.SHUTDOWN,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Yellow: info conflict
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc6",
            port=40007,
            host="host",
            path="ioc/some/path/6",
            pid=0,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Red: errors
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name="ioc7",
            port=30008,
            host="host",
            path="ioc/some/path/7",
            pid=0,
            status=ProcServStatus.ERROR,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    # Create a port conflict
    model.setData(index=model.index(9, TableColumn.PORT), value=30009)
    # Check this test case
    config = model.get_next_config()
    assert (
        model.get_background_color(ioc_proc=config.procs[ioc_name], column=column)
        == expected
    )


@pytest.mark.parametrize(
    "column,orientation,expected",
    (
        (
            TableColumn.IOCNAME,
            Qt.Horizontal,
            table_headers[TableColumn.IOCNAME],
        ),
        (TableColumn.ID, Qt.Horizontal, table_headers[TableColumn.ID]),
        (TableColumn.STATE, Qt.Horizontal, table_headers[TableColumn.STATE]),
        (
            TableColumn.STATUS,
            Qt.Horizontal,
            table_headers[TableColumn.STATUS],
        ),
        (TableColumn.HOST, Qt.Horizontal, table_headers[TableColumn.HOST]),
        (TableColumn.OSVER, Qt.Horizontal, table_headers[TableColumn.OSVER]),
        (TableColumn.PORT, Qt.Horizontal, table_headers[TableColumn.PORT]),
        (
            TableColumn.VERSION,
            Qt.Horizontal,
            table_headers[TableColumn.VERSION],
        ),
        (
            TableColumn.PARENT,
            Qt.Horizontal,
            table_headers[TableColumn.PARENT],
        ),
        (TableColumn.EXTRA, Qt.Horizontal, table_headers[TableColumn.EXTRA]),
        (TableColumn.IOCNAME, Qt.Vertical, QVariant()),
        (-1, Qt.Horizontal, QVariant()),
        (100, Qt.Horizontal, QVariant()),
    ),
)
def test_header_data(
    column: int,
    orientation: Qt.Orientation,
    expected: Any,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.headerData should return the text in a column.

    For the horizontal header within our range it should return text.

    For invalid values or values outside the table it should
    return an empty QVariant()
    """
    assert model.headerData(section=column, orientation=orientation) == expected


@pytest.mark.parametrize(
    "column,value,exp_attr,exp_value",
    (
        (TableColumn.IOCNAME, "Cool Alias", "alias", "Cool Alias"),
        (TableColumn.ID, "new_name", "", ""),
        (TableColumn.STATE, False, "disable", True),
        (TableColumn.STATUS, "SHUTDOWN", "", ""),
        (TableColumn.HOST, "new_host", "host", "new_host"),
        (TableColumn.OSVER, "rocky9", "", ""),
        (TableColumn.PORT, "40001", "port", 40001),
        (TableColumn.VERSION, "new_version", "path", "new_version"),
        (TableColumn.PARENT, "new_parent", "", ""),
        (TableColumn.EXTRA, "new_extra", "", ""),
        (-1, "asdf", "", ""),
        (100, "asdf", "", ""),
    ),
)
def test_set_data(
    column: int,
    value: Any,
    exp_attr: str,
    exp_value: Any,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.setData should stage an edit to the configuration.

    Any value sent to this function should have an expected attribute change
    on the underlying configuration.

    Returns `True` when write succeeded, and `False` otherwise.
    Needs to emit `dataChanged` when the write succeeds.

    For parameterization, exp_attr = "" signifies an expected failed set_data
    (which should not change anything about the config!)
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)
    old_config = model.get_next_config()
    old_proc = old_config.procs["ioc0"]
    success = model.setData(index=model.index(0, column), value=value)
    if exp_attr:
        # Return value
        assert success
        # dataChanged emits
        assert len(data_emits) == 1
        assert data_emits[0][0].row() == 0
        assert data_emits[0][1].row() == 0
        assert data_emits[0][0].column() == column
        assert data_emits[0][1].column() == column
    else:
        assert not success
        assert not data_emits
    # effects on the config
    new_config = model.get_next_config()
    new_proc = new_config.procs["ioc0"]
    has_checked_attr = False
    for attr in dataclasses.asdict(new_proc):
        if attr == exp_attr:
            assert getattr(new_proc, attr) == exp_value
            has_checked_attr = True
        else:
            assert getattr(new_proc, attr) == getattr(old_proc, attr)
    if exp_attr:
        assert has_checked_attr
    else:
        assert not has_checked_attr


@pytest.mark.parametrize(
    "row,column,expected",
    (
        (0, TableColumn.IOCNAME, Qt.ItemIsEnabled | Qt.ItemIsSelectable),
        (0, TableColumn.ID, Qt.ItemIsEnabled | Qt.ItemIsSelectable),
        (
            0,
            TableColumn.STATE,
            Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable,
        ),
        (0, TableColumn.STATUS, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (0, TableColumn.HOST, Qt.ItemIsEnabled | Qt.ItemIsEditable),
        (0, TableColumn.OSVER, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (0, TableColumn.PORT, Qt.ItemIsEnabled | Qt.ItemIsEditable),
        (0, TableColumn.VERSION, Qt.ItemIsEnabled | Qt.ItemIsEditable),
        (0, TableColumn.PARENT, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (0, TableColumn.EXTRA, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.IOCNAME, Qt.ItemIsEnabled | Qt.ItemIsSelectable),
        (10, TableColumn.ID, Qt.ItemIsEnabled | Qt.ItemIsSelectable),
        (10, TableColumn.STATE, Qt.ItemIsEnabled | Qt.ItemIsSelectable),
        (10, TableColumn.STATUS, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.HOST, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.OSVER, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.PORT, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.VERSION, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.PARENT, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (10, TableColumn.EXTRA, Qt.ItemIsEnabled | Qt.NoItemFlags),
        (-1, TableColumn.IOCNAME, Qt.NoItemFlags | Qt.NoItemFlags),
        (100, TableColumn.IOCNAME, Qt.NoItemFlags | Qt.NoItemFlags),
        (0, -1, Qt.NoItemFlags | Qt.NoItemFlags),
        (0, 100, Qt.NoItemFlags | Qt.NoItemFlags),
    ),
)
def test_flags(
    row: int,
    column: int,
    expected: Qt.ItemFlags,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.flags should return the intended click behavior of the cell.

    This will be an integer whose bits represent which behavior options
    are on or off.
    """
    # Row 10
    model.add_ioc(
        ioc_proc=IOCProc(
            name="some_hioc",
            port=40001,
            host="some_hioc",
            path="ioc/some/path",
        )
    )
    assert model.flags(index=model.index(row, column)) == expected


def test_poll(
    model: IOCTableModel, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
):
    """
    The model's polling loop should get updated information.

    We'll monkeypatch a few things to keep this manageable:
    - read_config to return a local config object we manage
    - get_host_os to return a fake host/os mapping
    - check_status to return some canned fake live statuses
    - read_status_dir to return some canned fake status files
    """
    fake_config = deepcopy(model.config)
    fake_config.commithost = "psbuild-lmao"
    fake_config.mtime = time.time()
    fake_host_os = "rocky9"
    fake_live_status = ProcServStatus.RUNNING

    def read_config_patch(*args, **kwargs) -> Config:
        return fake_config

    def get_host_os_patch(hosts_list: list[str]) -> dict[str, str]:
        return dict.fromkeys(hosts_list, fake_host_os)

    def check_status_patch(host: str, port: int, name: str) -> IOCStatusLive:
        return IOCStatusLive(
            name=name,
            port=port,
            host=host,
            path="ioc/path",
            pid=0,
            status=fake_live_status,
            autorestart_mode=AutoRestartMode.ON,
        )

    def read_status_dir_patch(cfg: str) -> list[IOCStatusFile]:
        return [
            IOCStatusFile(
                name=proc.name, port=proc.port, host=proc.host, path=proc.path, pid=0
            )
            for proc in fake_config.procs.values()
        ]

    monkeypatch.setattr(table_model, "read_config", read_config_patch)
    monkeypatch.setattr(table_model, "get_host_os", get_host_os_patch)
    monkeypatch.setattr(table_model, "check_status", check_status_patch)
    monkeypatch.setattr(table_model, "read_status_dir", read_status_dir_patch)

    assert model.config.commithost != "psbuild-lmao"
    assert not model.host_os
    assert not model.status_files
    assert not model.status_live

    def assert_poll_works():
        assert model.config.commithost == "psbuild-lmao"
        for val in model.host_os.values():
            assert val == fake_host_os
        for name, status_file in model.status_files.items():
            assert name == status_file.name
        for name, live_status in model.status_live.items():
            assert name == live_status.name
            assert live_status.status == fake_live_status
        assert model.poll_thread.is_alive()

    model.poll_interval = 0.1
    model.start_poll_thread()
    time.sleep(0.2)
    try:
        assert_poll_works()
        fake_host_os = "rhel7"
        fake_live_status = ProcServStatus.SHUTDOWN
        time.sleep(0.2)
        assert_poll_works()
    finally:
        model.stop_poll_thread()
        model.poll_thread.join(timeout=1.0)
    assert not model.poll_thread.is_alive()


def test_update_from_config_file(model: IOCTableModel, qapp: QApplication):
    """
    model.update_from_config_file should introduce a new config file to the model.

    If the new config file is newer than the most recently read config file,
    we'll use it as our new base truth config.

    If we store a new config, we'll emit dataChanged across the entire valid
    range of the table.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)

    original_config = model.config

    # Update using our exact existing config. Nothing should happen!
    model.update_from_config_file(config=model.config)
    assert not data_emits
    assert model.config == original_config
    # Update using some bogus config from the past. Nothing should happen!
    model.update_from_config_file(config=Config(path="bogus!", mtime=0))
    assert not data_emits
    assert model.config == original_config
    # Update using a newer config. It should be accepted!
    new_config = deepcopy(model.config)
    new_config.commithost = "psbuild-lmao"
    new_config.mtime = time.time()
    model.update_from_config_file(config=new_config)
    assert model.config == new_config
    assert data_emits
    assert data_emits[0][0].row() == 0
    assert data_emits[0][0].column() == 0
    assert data_emits[0][1].row() == model.rowCount() - 1
    assert data_emits[0][1].column() == model.columnCount() - 1


def test_update_from_status_file(model: IOCTableModel, qapp: QApplication):
    """
    model.update_from_status_file should introduce a new status file to the model.

    The corresponding extras column should get a dataChanged emit just in case
    the status file introduces a host/port discrepency.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)
    dummy_status_file = IOCStatusFile(
        name="ioc0",
        port=30001,
        host="host",
        path="ioc/some/path/0",
        pid=0,
    )

    model.update_from_status_file(status_file=dummy_status_file)
    assert model.status_files["ioc0"] == dummy_status_file
    assert len(data_emits) == 1

    # Same file again = no change
    model.update_from_status_file(status_file=dummy_status_file)
    assert model.status_files["ioc0"] == dummy_status_file
    assert len(data_emits) == 1

    # Should emit ioc0's extra's column
    assert data_emits[0][0].row() == 0
    assert data_emits[0][0].column() == TableColumn.EXTRA
    assert data_emits[0][1].row() == 0
    assert data_emits[0][1].column() == TableColumn.EXTRA


def test_update_from_live_ioc(model: IOCTableModel, qapp: QApplication):
    """
    model.update_from_live_ioc should introduce a new IOC live status to the model.

    This is expected to impact the "status" and "extra" columns.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)
    dummy_status_live = IOCStatusLive(
        name="ioc0",
        port=30001,
        host="host",
        path="ioc/some/path/0",
        pid=0,
        status=ProcServStatus.RUNNING,
        autorestart_mode=AutoRestartMode.ON,
    )

    model.update_from_live_ioc(status_live=dummy_status_live)
    assert model.status_live["ioc0"] == dummy_status_live
    assert len(data_emits) == 2

    # Same file again = no change
    model.update_from_live_ioc(status_live=dummy_status_live)
    assert model.status_live["ioc0"] == dummy_status_live
    assert len(data_emits) == 2

    # Should emit ioc0's extra's status and extra columns
    assert data_emits[0][0].row() == 0
    assert data_emits[0][0].column() == TableColumn.STATUS
    assert data_emits[0][1].row() == 0
    assert data_emits[0][1].column() == TableColumn.STATUS
    assert data_emits[1][0].row() == 0
    assert data_emits[1][0].column() == TableColumn.EXTRA
    assert data_emits[1][1].row() == 0
    assert data_emits[1][1].column() == TableColumn.EXTRA


@pytest.mark.parametrize("user_accept", (True, False))
def test_edit_details(
    user_accept: bool,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.edit_details opens the details dialog.

    This dialog has widgets for changing the alias, cmd, and delay parameters.
    If the user sets values in those widgets and accepts the gui, then
    the IOC should get the corresponding pending edit.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)

    def fake_exec() -> QDialog.DialogCode:
        """Replace exec_ to simulate user edits."""
        model.details_dialog.ui.aliasEdit.setText("New Alias")
        model.details_dialog.ui.cmdEdit.setText("new_cmd.sh")
        model.details_dialog.ui.delayEdit.setValue(10)
        if user_accept:
            return QDialog.Accepted
        else:
            return QDialog.Rejected

    # Instance override doesn't need monkeypatch fixture
    model.details_dialog.exec_ = fake_exec

    # Edited from row 0, column 0 (ioc0)
    model.edit_details(index=model.index(0, 0))
    new_config = model.get_next_config()
    ioc_proc = new_config.procs["ioc0"]

    if user_accept:
        assert ioc_proc.alias == "New Alias"
        assert ioc_proc.cmd == "new_cmd.sh"
        assert ioc_proc.delay == 10
        assert len(data_emits) == 1
        assert data_emits[0][0].row() == 0
        assert data_emits[0][0].column() == TableColumn.IOCNAME
    else:
        assert ioc_proc.alias == ""
        assert ioc_proc.cmd == ""
        assert ioc_proc.delay == 0
        assert not data_emits


def test_add_ioc(model: IOCTableModel, qapp: QApplication):
    """
    model.add_ioc should add a pending IOC, adding a new row to the table.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)

    assert model.rowCount() == 10
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added1",
            port=40001,
            host="host",
            path="/some/other/path",
        )
    )
    assert model.rowCount() == 11
    assert len(data_emits) == 1
    assert data_emits[0][0].row() == 10
    assert data_emits[0][0].column() == 0
    assert data_emits[0][1].row() == 10
    assert data_emits[0][1].column() == model.columnCount() - 1
    model.add_ioc(
        ioc_proc=IOCProc(
            name="added2",
            port=40002,
            host="host",
            path="/some/other/path",
        )
    )
    assert model.rowCount() == 12
    assert len(data_emits) == 2
    assert data_emits[1][0].row() == 10
    assert data_emits[1][0].column() == 0
    assert data_emits[1][1].row() == 11
    assert data_emits[1][1].column() == model.columnCount() - 1

    new_config = model.get_next_config()
    assert "added1" in new_config.procs
    assert "added2" in new_config.procs


def test_delete_ioc(model: IOCTableModel, qapp: QApplication):
    """
    model.delete_ioc should pend an IOC for deletion.

    The row should update so we know to change its color in the table.
    """
    data_emits: list[tuple[QModelIndex, QModelIndex]] = []

    def save_data_emit(index1: QModelIndex, index2: QModelIndex):
        data_emits.append((index1, index2))

    model.dataChanged.connect(save_data_emit)

    model.delete_ioc(0)

    assert "ioc0" in model.delete_iocs
    assert "ioc0" not in model.get_next_config().procs

    assert len(data_emits) == 1
    assert data_emits[0][0].row() == 0
    assert data_emits[0][0].column() == 0
    assert data_emits[0][1].row() == 0
    assert data_emits[0][1].column() == model.columnCount() - 1


def test_revert_ioc(model: IOCTableModel, qapp: QApplication):
    """
    model.revert_ioc should undo all pending changes.

    No matter what we do, revert_ioc should bring us back to the
    original config.
    """
    original_config = model.get_next_config()

    def assert_not_changed():
        assert model.get_next_config() == original_config
        assert not model.add_iocs
        assert not model.edit_iocs
        assert not model.delete_iocs
        assert model.rowCount() == 10

    assert_not_changed()
    model.add_ioc(
        ioc_proc=IOCProc(name="added", port=40001, host="host", path="some/path")
    )
    model.revert_ioc(10)
    assert_not_changed()
    model.delete_ioc(0)
    model.revert_ioc(0)
    assert_not_changed()
    assert model.setData(index=model.index(1, TableColumn.IOCNAME), value="Alias")
    model.revert_ioc(1)
    assert_not_changed()
