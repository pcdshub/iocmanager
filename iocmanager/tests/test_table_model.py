import pytest
from qtpy.QtCore import Qt, QVariant
from qtpy.QtGui import QBrush
from qtpy.QtWidgets import QApplication

from ..config import Config, IOCProc
from ..procserv_tools import (
    AutoRestartMode,
    IOCStatusFile,
    IOCStatusLive,
    ProcServStatus,
)
from ..table_model import IOCTableModel, StateOption, TableColumn, table_headers


@pytest.fixture(scope="function")
def model() -> IOCTableModel:
    """Basic re-usable model with starting data for use in test suite."""
    config = Config(path="")
    for num in range(10):
        config.add_proc(
            IOCProc(
                name=f"ioc{num}",
                port=30001 + num,
                host="host",
                path=f"ioc/some/path/{num}",
            )
        )
    return IOCTableModel(config=config, hutch="pytest")


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
    model.setData(model.index(0, TableColumn.PORT), QVariant(31001))
    # Row 11 = added1
    model.setData(model.index(11, TableColumn.PORT), QVariant(41002))
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
    assert model.setData(index=model.index(2, TableColumn.PORT), value=QVariant(50000))

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
        (0, TableColumn.ID, Qt.DisplayRole, QVariant("ioc0")),
        (1, TableColumn.PORT, Qt.EditRole, QVariant(30002)),
        (2, TableColumn.HOST, Qt.ForegroundRole, QVariant(QBrush(Qt.black))),
        (3, TableColumn.VERSION, Qt.BackgroundRole, QVariant(QBrush(Qt.white))),
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
    expected: QVariant,
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
        ("ioc0", TableColumn.PORT, "30001"),
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
def test_get_display_text(
    ioc_name: str, column: int, expected: str, model: IOCTableModel, qapp: QApplication
):
    """
    model.get_display_text should get the str we want to display for the ioc's column.

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
        model.get_display_text(ioc_proc=config.procs[ioc_name], column=column)
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
    model.setData(model.index(1, TableColumn.IOCNAME), QVariant("IOC ALIAS"))
    model.setData(model.index(1, TableColumn.STATE), QVariant(False))
    model.setData(model.index(1, TableColumn.HOST), QVariant("newhost"))
    model.setData(model.index(1, TableColumn.PORT), QVariant(40001))
    model.setData(model.index(1, TableColumn.VERSION), QVariant("/new/version"))
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
    model.setData(model.index(4, TableColumn.PORT), QVariant(30004))
    # Edit dev variant
    model.setData(model.index(5, TableColumn.VERSION), QVariant("/epics-dev/stuff"))
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
    model.setData(
        index=model.index(1, TableColumn.VERSION), value=QVariant("/some/dev/folder")
    )
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
    model.setData(index=model.index(3, TableColumn.STATE), value=QVariant(False))
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
    model.setData(index=model.index(4, TableColumn.STATE), value=QVariant(False))
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
    model.setData(index=model.index(9, TableColumn.PORT), value=QVariant(30009))
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
            QVariant(table_headers[TableColumn.IOCNAME]),
        ),
        (TableColumn.ID, Qt.Horizontal, QVariant(table_headers[TableColumn.ID])),
        (TableColumn.STATE, Qt.Horizontal, QVariant(table_headers[TableColumn.STATE])),
        (
            TableColumn.STATUS,
            Qt.Horizontal,
            QVariant(table_headers[TableColumn.STATUS]),
        ),
        (TableColumn.HOST, Qt.Horizontal, QVariant(table_headers[TableColumn.HOST])),
        (TableColumn.OSVER, Qt.Horizontal, QVariant(table_headers[TableColumn.OSVER])),
        (TableColumn.PORT, Qt.Horizontal, QVariant(table_headers[TableColumn.PORT])),
        (
            TableColumn.VERSION,
            Qt.Horizontal,
            QVariant(table_headers[TableColumn.VERSION]),
        ),
        (
            TableColumn.PARENT,
            Qt.Horizontal,
            QVariant(table_headers[TableColumn.PARENT]),
        ),
        (TableColumn.EXTRA, Qt.Horizontal, QVariant(table_headers[TableColumn.EXTRA])),
        (TableColumn.IOCNAME, Qt.Vertical, QVariant()),
        (-1, Qt.Horizontal, QVariant()),
        (100, Qt.Horizontal, QVariant()),
    ),
)
def test_header_data(
    column: int,
    orientation: Qt.Orientation,
    expected: QVariant,
    model: IOCTableModel,
    qapp: QApplication,
):
    """
    model.headerData should return the text in a column.

    For the horizontal header within our range it should return
    QVariants that contain text.

    For invalid values or values outside the table it should
    return an empty QVariant()
    """
    assert model.headerData(section=column, orientation=orientation) == expected
