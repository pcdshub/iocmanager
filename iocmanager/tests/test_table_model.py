import concurrent.futures
import dataclasses
import time
from copy import deepcopy
from typing import Any
from unittest.mock import Mock

import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtCore import QModelIndex, Qt, QVariant
from qtpy.QtGui import QBrush
from qtpy.QtWidgets import QDialog, QMessageBox

from .. import table_model
from ..config import Config, IOCProc
from ..procserv_tools import (
    AutoRestartMode,
    IOCStatusFile,
    IOCStatusLive,
    ProcServStatus,
)
from ..table_model import (
    DesyncInfo,
    IOCTableModel,
    StateOption,
    TableColumn,
    table_headers,
)


@pytest.mark.parametrize(
    "cfg_disable,live_port,live_host,live_path,status,expected_port,expected_host,expected_path,expected_disable,expected_has_diff",
    # Use a mostly fixed config, modulate the live parameters
    (
        # No diff case
        (
            False,
            30001,
            "host",
            "/correct/path",
            ProcServStatus.RUNNING,
            None,
            None,
            None,
            None,
            False,
        ),
        # Invalid status
        (False, 0, "", "", ProcServStatus.INIT, None, None, None, None, False),
        # Different port
        (
            False,
            39000,
            "host",
            "/correct/path",
            ProcServStatus.RUNNING,
            39000,
            None,
            None,
            None,
            True,
        ),
        # Different host
        (
            False,
            30001,
            "roast",
            "/correct/path",
            ProcServStatus.RUNNING,
            None,
            "roast",
            None,
            None,
            True,
        ),
        # Different path
        (
            False,
            30001,
            "host",
            "/wrong/path",
            ProcServStatus.RUNNING,
            None,
            None,
            "/wrong/path",
            None,
            True,
        ),
        # Noconnect when should be enabled
        (
            False,
            30001,
            "host",
            "/correct/path",
            ProcServStatus.NOCONNECT,
            None,
            None,
            None,
            True,
            True,
        ),
        # Running when should be disabled
        (
            True,
            30001,
            "host",
            "/correct/path",
            ProcServStatus.RUNNING,
            None,
            None,
            None,
            False,
            True,
        ),
        # Shutdown when should be enabled
        (
            False,
            30001,
            "host",
            "/correct/path",
            ProcServStatus.SHUTDOWN,
            None,
            None,
            None,
            True,
            True,
        ),
        # Shutdown when should be disabled
        (
            True,
            30001,
            "host",
            "/correct/path",
            ProcServStatus.SHUTDOWN,
            None,
            None,
            None,
            False,
            True,
        ),
    ),
)
def test_desync_info(
    cfg_disable: bool,
    live_port: int,
    live_host: str,
    live_path: str,
    status: ProcServStatus,
    expected_port: int | None,
    expected_host: str | None,
    expected_path: str | None,
    expected_disable: bool | None,
    expected_has_diff: bool,
):
    """
    DesyncInfo should compare a saved IOC config with the live status.

    If there are any differences, has_diff should be True and the specific
    conflicting live value should be non-None.
    """
    ioc_proc = IOCProc(
        name="ioc",
        port=30001,
        host="host",
        path="/correct/path",
        disable=cfg_disable,
    )
    status_live = IOCStatusLive(
        name="ioc",
        port=live_port,
        host=live_host,
        path=live_path,
        pid=None,
        status=status,
        autorestart_mode=AutoRestartMode.ON,
    )
    desync_info = DesyncInfo.from_info(
        ioc_proc=ioc_proc,
        status_live=status_live,
    )
    assert desync_info.port == expected_port
    assert desync_info.host == expected_host
    assert desync_info.path == expected_path
    assert desync_info.disable == expected_disable
    assert desync_info.has_diff == expected_has_diff


def test_get_next_config_and_reset_edits(model: IOCTableModel):
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
    model.delete_ioc(ioc=1)
    # Row 12 = added2
    model.delete_ioc(ioc=12)
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


def test_get_ioc_proc(model: IOCTableModel):
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
    assert model.get_ioc_proc(ioc=4).name == "ioc4"
    # Check our modified IOC
    assert model.get_ioc_proc(ioc=2).port == 50000
    # Check our added IOC
    assert model.get_ioc_proc(ioc=10).name == "added"


def test_get_ioc_row_map(model: IOCTableModel):
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


def test_get_live_info(model: IOCTableModel):
    """
    model.get_live_info should return information about the live IOC.

    There should be a priority order where values found via direct
    inspection of the IOC take precedence over values found via
    reading the status files.
    """
    # Currently required to exist in the config (or added)
    ioc_name = "ioc7"

    # Default case, no info at all
    null_info = model.get_live_info(ioc=ioc_name)
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
            path="/ioc/file/live",
            pid=12345,
        )
    )
    file_info = model.get_live_info(ioc=ioc_name)
    assert file_info.name == ioc_name
    assert file_info.port == 40001
    assert file_info.host == "file_host"
    assert file_info.path == "/ioc/file/live"
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
    file_info2 = model.get_live_info(ioc=ioc_name)
    assert file_info2.name == ioc_name
    assert file_info2.port == 40001
    assert file_info2.host == "file_host"
    assert file_info2.path == "/ioc/file/live"
    assert file_info2.status == ProcServStatus.ERROR

    # Great status
    model.update_from_live_ioc(
        status_live=IOCStatusLive(
            name=ioc_name,
            port=50001,
            host="live_host",
            path="/tmp",
            pid=20000,
            status=ProcServStatus.RUNNING,
            autorestart_mode=AutoRestartMode.ON,
        )
    )
    live_info = model.get_live_info(ioc=ioc_name)
    assert live_info.name == ioc_name
    assert live_info.port == 50001
    assert live_info.host == "live_host"
    assert live_info.path == "/ioc/file/live"
    assert live_info.status == ProcServStatus.RUNNING


def test_row_count(model: IOCTableModel):
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


def test_column_count(model: IOCTableModel):
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
    ioc_name: str, column: int, expected: str, model: IOCTableModel
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
            hard=True,
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
    assert model.get_display_data(ioc=ioc_name, column=column) == expected


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
        # Added IOC is all blue (except to avoid blue on blue)
        ("added", TableColumn.IOCNAME, Qt.blue),
        ("added", TableColumn.ID, Qt.blue),
        ("added", TableColumn.STATE, Qt.blue),
        ("added", TableColumn.STATUS, Qt.white),
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
    assert model.get_foreground_color(ioc=ioc_name, column=column) == expected


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
    assert model.get_background_color(ioc=ioc_name, column=column) == expected


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
        if column == TableColumn.HOST:
            # Might update port too (color)
            assert len(data_emits) == 2
        else:
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
            hard=True,
        )
    )
    assert model.flags(index=model.index(row, column)) == expected


def test_poll(model: IOCTableModel, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot):
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
    try:
        qtbot.wait_until(assert_poll_works)
        fake_host_os = "rhel7"
        fake_live_status = ProcServStatus.SHUTDOWN
        qtbot.wait_until(assert_poll_works)
    finally:
        model.stop_poll_thread()
        model.poll_thread.join(timeout=1.0)
    assert not model.poll_thread.is_alive()


def test_update_from_config_file(model: IOCTableModel):
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


def test_update_from_status_file(model: IOCTableModel):
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


def test_update_from_live_ioc(model: IOCTableModel):
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


def test_live_only_iocs(
    model: IOCTableModel, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot
):
    """
    This is a general integration test for iocs that are live but not in the config.

    The following behavior is expected:
    - During a poll, status files will be used to identify out-of-config iocs to check.
    - If we check for an out-of-config ioc and it exists, that's a live-only ioc.
    - These live-only iocs will be added to the model at the bottom of the table
      (order is: configured iocs, added iocs, live-only iocs)
    - The live-only iocs will be given provisional IOCProc structs and will be
      queriable/findable as if they are a normal IOC.
    - The live-only iocs will not be saved in the config unless the user requests it.
    - When an ioc is added to the config with a name that matches a live-only ioc it
      will no longer be considered a live-only ioc.
    """
    # We'll monkeypatch here to avoid fiddling with files and processes
    fake_config = model.config
    fake_status_files = []
    fake_status_enums = {}

    def read_config_patch(cfgname: str) -> Config:
        return fake_config

    def get_host_os_patch(hosts_list: list[str]) -> dict[str, str]:
        return dict.fromkeys(hosts_list, "linux")

    def read_status_dir_patch(cfg: str) -> list[IOCStatusFile]:
        return fake_status_files

    def check_status_patch(host: str, port: int, name: str) -> IOCStatusLive:
        try:
            status = fake_status_enums[(host, port)]
        except KeyError:
            status = ProcServStatus.DOWN
        return IOCStatusLive(
            name=name,
            port=port,
            host=host,
            path="",
            pid=None,
            status=status,
            autorestart_mode=AutoRestartMode.ON,
        )

    monkeypatch.setattr(table_model, "read_config", read_config_patch)
    monkeypatch.setattr(table_model, "get_host_os", get_host_os_patch)
    monkeypatch.setattr(table_model, "read_status_dir", read_status_dir_patch)
    monkeypatch.setattr(table_model, "check_status", check_status_patch)

    # One status file for each possible status
    base_port = 40001
    for num, status in enumerate(ProcServStatus):
        name = status.name.lower()
        fake_status_files.append(
            IOCStatusFile(name=name, port=base_port + num, host="host", path="", pid=0)
        )
        fake_status_enums[("host", base_port + num)] = status

    # Define which iocs should be live-only and which should not be
    live_only_yes = ["running", "shutdown"]
    live_only_no = [
        status.name.lower()
        for status in ProcServStatus
        if status.name.lower() not in live_only_yes
    ]

    # Poll once
    with concurrent.futures.ThreadPoolExecutor() as executor:
        model._inner_poll(executor=executor)
    qtbot.wait_signal(model.signal_poll_done, timeout=1000)

    # Check that the correct iocs are or are not queryable
    for name in live_only_yes:
        assert model.get_ioc_info(ioc=name).ioc_live.status.name.lower() == name
    for name in live_only_no:
        with pytest.raises(RuntimeError):
            model.get_ioc_info(ioc=name)

    # Check the table rows for live-only ioc info
    for num in range(len(live_only_yes)):
        assert model.data(model.index(10 + num, TableColumn.IOCNAME)) in live_only_yes
    for row in range(model.rowCount()):
        assert model.data(model.index(row, TableColumn.IOCNAME)) not in live_only_no

    # Check that the live-only iocs are not included in the next config
    next_config = model.get_next_config()
    for name in live_only_yes + live_only_no:
        assert name not in next_config.procs

    # Add a live-only ioc to the config, check that it changes category and index
    include_ioc_name = model.data(model.index(11, TableColumn.IOCNAME))
    include_ioc_proc = model.get_ioc_proc(ioc=include_ioc_name)
    assert include_ioc_name in model.live_only_iocs
    assert include_ioc_name not in model.add_iocs
    model.add_ioc(ioc_proc=include_ioc_proc)
    assert include_ioc_name not in model.live_only_iocs
    assert include_ioc_name in model.add_iocs
    assert model.data(model.index(10, TableColumn.IOCNAME)) == include_ioc_name

    # Once added, verify that it is included in the next config
    assert include_ioc_name in model.get_next_config().procs


def test_add_ioc_dialog(model: IOCTableModel, monkeypatch: pytest.MonkeyPatch):
    """
    model.add_ioc_dialog opens a dialog to add an IOC.

    The specifics of this dialog should be tested in test_dialog_add_ioc.py
    Here, we'll test the behavior defined in IOCTableModel:
    - Clear the dialog before starting
    - If the user picks an invalid port, show an error pop-up and re-open
    - If the user omits a required field, show an error pop-up and re-open
    - If the ioc name already exists, show an error pop-up and re-open
    - If everything was ok, call add_ioc

    We'll need to monkeypatch away the actual dialog opens since we can't
    easily interact with the dialogs

    QMessageBox.critical opens the error dialogs, here we just need to count
    the calls and return QMessageBox.Ok. We'll use monkeypatch because this
    is a class method that would otherwise bleed into other tests.

    model.dialog_add.exec_() is how we open the dialog for the user,
    we'll hard-patch this with the series of inputs we want the user
    to take and then return QDialog.Accepted or QDialog.Rejected.
    We don't need to use monkeypatch since the dialog object is transient.
    """
    error_message_mock = Mock()
    monkeypatch.setattr(QMessageBox, "critical", error_message_mock)

    # Set a starting name on the dialog, should be cleared
    model.dialog_add.name_edit.setText("turkey")

    # First call: make sure it's cleared, reject the dialog
    def exec1() -> QDialog.DialogCode:
        assert not model.dialog_add.name_edit.text()
        return QDialog.Rejected

    # Second call: user picks an invalid port, should error and go to third call
    def exec2() -> QDialog.DialogCode:
        # check from last exec
        assert error_message_mock.call_count == 0
        model.dialog_add.name_edit.setText("some_name")
        model.dialog_add.host_edit.setText("some_host")
        model.dialog_add.port_spinbox.setValue(42)
        return QDialog.Accepted

    # Third call: user forgot to pick a name, should error and go to fourth call
    def exec3() -> QDialog.DialogCode:
        # check from last exec
        assert error_message_mock.call_count == 1
        model.dialog_add.name_edit.setText("")
        model.dialog_add.host_edit.setText("some_host")
        model.dialog_add.port_spinbox.setValue(40001)
        return QDialog.Accepted

    # Fourth call: user picked a name that already exists, error and fifth
    def exec4() -> QDialog.DialogCode:
        # check from last exec
        assert error_message_mock.call_count == 2
        model.dialog_add.name_edit.setText("ioc1")
        model.dialog_add.host_edit.setText("some_host")
        model.dialog_add.port_spinbox.setValue(40001)
        return QDialog.Accepted

    # Fifth call: user did it right
    def exec5() -> QDialog.DialogCode:
        # check from last exec
        assert error_message_mock.call_count == 3
        model.dialog_add.name_edit.setText("some_name")
        model.dialog_add.host_edit.setText("some_host")
        model.dialog_add.port_spinbox.setValue(40001)
        return QDialog.Accepted

    n_exec_calls = 0

    def exec_patch() -> QDialog.DialogCode:
        nonlocal n_exec_calls
        n_exec_calls += 1
        match n_exec_calls:
            case 1:
                return exec1()
            case 2:
                return exec2()
            case 3:
                return exec3()
            case 4:
                return exec4()
            case 5:
                return exec5()
            case num:
                raise RuntimeError(f"Test error: no patch for call number {num}")

    model.dialog_add.exec_ = exec_patch

    # First try at the dialog: only exec1
    model.add_ioc_dialog()
    assert n_exec_calls == 1

    # The first call was the assert-and-reject check
    # IOC should not have been added!
    assert "some_name" not in model.add_iocs

    # Second try at the dialog: exec2+
    model.add_ioc_dialog()
    assert n_exec_calls == 5
    # e.g. no error after exec5
    assert error_message_mock.call_count == 3

    # IOC should have been added!
    assert "some_name" in model.add_iocs


@pytest.mark.parametrize("user_accept", (True, False))
def test_edit_details_dialog(
    user_accept: bool,
    model: IOCTableModel,
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
        model.dialog_details.ui.aliasEdit.setText("New Alias")
        model.dialog_details.ui.cmdEdit.setText("new_cmd.sh")
        model.dialog_details.ui.delayEdit.setValue(10)
        if user_accept:
            return QDialog.Accepted
        else:
            return QDialog.Rejected

    # Instance override doesn't need monkeypatch fixture
    model.dialog_details.exec_ = fake_exec

    # Edited from row 0, column 0 (ioc0)
    model.edit_details_dialog(ioc=model.index(0, 0))
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


def test_add_ioc(model: IOCTableModel):
    """
    model.add_ioc should add a pending IOC, adding a new row to the table.
    """
    data_emits: list[tuple[QModelIndex, int, int]] = []

    def save_data_emit(index: QModelIndex, start: int, end: int):
        data_emits.append((index, start, end))

    model.rowsAboutToBeInserted.connect(save_data_emit)

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
    # You must pass an invalid index or it doesn't work
    assert not data_emits[0][0].isValid()
    assert data_emits[0][1] == 10
    assert data_emits[0][2] == 10
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
    assert not data_emits[1][0].isValid()
    assert data_emits[1][1] == 11
    assert data_emits[1][2] == 11

    new_config = model.get_next_config()
    assert "added1" in new_config.procs
    assert "added2" in new_config.procs


def test_delete_ioc(model: IOCTableModel):
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


def test_revert_ioc(model: IOCTableModel):
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


def test_save_version(model: IOCTableModel):
    """
    model.save_version should pend saving a new history entry for the given row.
    """
    assert not model.get_next_config().procs["ioc0"].history
    model.save_version(0)
    ioc_proc = model.get_next_config().procs["ioc0"]
    assert ioc_proc.path in ioc_proc.history


def test_save_all_versions(model: IOCTableModel):
    """
    model.save_all_versions should pend saving a new history entry for all rows.
    """
    for ioc_name in (f"ioc{num}" for num in range(10)):
        assert not model.get_next_config().procs[ioc_name].history
    model.save_all_versions()
    for ioc_name in (f"ioc{num}" for num in range(10)):
        ioc_proc = model.get_next_config().procs[ioc_name]
        assert ioc_proc.path in ioc_proc.history


def test_pending_edits(model: IOCTableModel):
    """
    model.pending_edits should return True if we have unsaved changes for an ioc.
    """
    # Start without any pending edits on any IOC
    for ioc in model.config.procs:
        assert not model.pending_edits(ioc=ioc)

    # Try some of the valid APIs for making an edit
    # setData is typically called via QTableView when the user edits a cell
    model.setData(model.index(0, TableColumn.PORT), 40001)
    # delete_ioc is typically called via the QTableView context menu
    model.delete_ioc(ioc=1)
    # save_version is typically called via the QTableView context menu
    model.save_version(ioc=2)
    # add_ioc is typically called via the QTableView context menu
    model.add_ioc(ioc_proc=IOCProc(name="added", port=50001, host="host", path=""))

    # Each of the above should count as edited!
    assert model.pending_edits(ioc="ioc0")
    assert model.pending_edits(ioc="ioc1")
    assert model.pending_edits(ioc="ioc2")
    assert model.pending_edits(ioc="added")

    # The rest should still not be pending edits!
    for ioc_name in (f"ioc{num}" for num in range(3, 10)):
        assert not model.pending_edits(ioc=ioc_name)


def test_set_from_running(model: IOCTableModel):
    """
    model.set_from_running should edit the IOC to match the live status.
    """
    # Arbitrary example: live IOC has a different path/version
    old = IOCProc(name="added", port=40001, host="host", path="old/path")
    new = IOCProc(name="added", port=40001, host="host", path="new/path")
    status_live = IOCStatusLive(
        name="added",
        port=40001,
        host="host",
        path="new/path",
        pid=None,
        status=ProcServStatus.RUNNING,
        autorestart_mode=AutoRestartMode.ON,
    )

    model.add_ioc(ioc_proc=old)
    assert model.get_next_config().procs["added"] == old
    model.update_from_live_ioc(status_live=status_live)
    model.set_from_running(ioc="added")
    assert model.get_next_config().procs["added"] == new


def test_get_unused_port(model: IOCTableModel):
    """
    model.get_unused_port should return the smallest valid unused port.

    The port should be in the context of the next saved config.
    For example, if an IOC gets deleted, its port is fair game.
    """
    assert model.get_unused_port(host="new_host", closed=True) == 30001
    assert model.get_unused_port(host="host", closed=True) == 30011
    model.add_ioc(ioc_proc=IOCProc(name="added", port=30011, host="host", path=""))
    assert model.get_unused_port(host="host", closed=True) == 30012
    model.delete_ioc(ioc=5)
    assert model.get_unused_port(host="host", closed=True) == 30006
