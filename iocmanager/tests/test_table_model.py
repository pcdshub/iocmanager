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
from ..table_model import IOCTableModel, TableColumn


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
