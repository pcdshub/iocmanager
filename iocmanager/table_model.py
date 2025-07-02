"""
The table_model module defines a data model for the main GUI table.

This implements a QAbstractTableModel which manages reading and writing data
for the central QTableView in the main GUI.

The data in the table represents:

- The contents of the IOC manager config file's IOC data
- Any pending edits of the config file IOCs (to include at next save)
- Helpful status and context information for each IOC

See https://doc.qt.io/qt-5/qabstracttablemodel.html#details
"""

import concurrent.futures
import logging
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any

from qtpy.QtCore import QAbstractTableModel, QModelIndex, Qt, QVariant
from qtpy.QtGui import QBrush
from qtpy.QtWidgets import QDialog, QMessageBox

from .config import (
    Config,
    IOCProc,
    IOCStatusFile,
    get_host_os,
    read_config,
    read_status_dir,
)
from .dialog_add_ioc import AddIOCDialog
from .dialog_edit_details import DetailsDialog
from .epics_paths import normalize_path
from .procserv_tools import (
    AutoRestartMode,
    IOCStatusLive,
    ProcServStatus,
    check_status,
)
from .type_hints import ParentWidget

logger = logging.getLogger(__name__)


@dataclass
class IOCModelInfo:
    """
    Disambiguated information about an IOC in context of the model.

    Attributes
    ----------
    ioc_proc : IOCProc
        The ioc's config information including all pending edits.
    ioc_live : IOCStatusLive
        The ioc's actual live status based on our polling loop.
    name : str
        The name of the ioc (not the alias).
    row : int
        The row in the table associated with the ioc.
    deleted : bool
        True if the ioc is pending deletion, False otherwise.
    file_proc : IOCProc | None
        The ioc's config information without any pending edits.
    """

    ioc_proc: IOCProc
    ioc_live: IOCStatusLive
    name: str
    row: int
    deleted: bool
    file_proc: IOCProc | None


# Alias for type union that lets us uniquely identify an IOC in the table
# Can use the full dataclass, the name, the row, or the index
IOCModelIdentifier = IOCModelInfo | IOCProc | IOCStatusLive | str | int | QModelIndex


class TableColumn(IntEnum):
    """
    Options and indices for table columns
    """

    IOCNAME = 0
    ID = 1
    STATE = 2
    STATUS = 3
    HOST = 4
    OSVER = 5
    PORT = 6
    VERSION = 7
    PARENT = 8
    EXTRA = 9


# Map TableColumn to the desired table header
table_headers = {
    TableColumn.IOCNAME: "IOC Name",
    TableColumn.ID: "IOC ID",
    TableColumn.STATE: "State",
    TableColumn.STATUS: "Status",
    TableColumn.HOST: "Host",
    TableColumn.OSVER: "OS",
    TableColumn.PORT: "PORT",
    TableColumn.VERSION: "Version",
    TableColumn.PARENT: "Parent",
    TableColumn.EXTRA: "Information",
}


class StateOption(StrEnum):
    """
    Possible display values for an IOC's "state" column.
    """

    OFF = "Off"
    PROD = "Prod"
    DEV = "Dev"


@dataclass(frozen=True)
class DesyncInfo:
    """
    Used in IOCTableModel.get_desync to summarize IOC desync.

    IOC desync is when the live IOC and the configured IOC do not match.
    Any non-None value here represents a live value that is different
    than the configured value.

    The has_diff parameter will be set to True if there is a desync
    and False if the live IOC matches the configured IOC.
    """

    port: int | None = None
    host: str | None = None
    path: str | None = None
    has_diff: bool = False

    @classmethod
    def from_info[T: DesyncInfo](
        cls: type[T], ioc_proc: IOCProc, status_live: IOCStatusLive
    ) -> T:
        if not all((status_live.path, status_live.host, status_live.port)):
            # Exit now if any of the status info is e.g. 0, empty str
            # This means we don't know where the IOC is running
            return cls()
        has_diff = False
        if ioc_proc.port != status_live.port:
            port = status_live.port
            has_diff = True
        else:
            port = None
        if ioc_proc.host != status_live.host:
            host = status_live.host
            has_diff = True
        else:
            host = None
        if ioc_proc.path != status_live.path:
            path = status_live.path
            has_diff = True
        else:
            path = None
        return cls(port=port, host=host, path=path, has_diff=has_diff)


class IOCTableModel(QAbstractTableModel):
    """
    The data model for the contents of the big IOC table in the GUI.

    This has two purposes:
    1. Allow the user to see data from and related to the config in a table format
    2. Allow the user to modify data in the config using the table

    This reads to and writes from the hosts and procs parts of the
    configuration. It also inspects the statuses of running processes
    to show them to the user.

    Notes on QAbstractTableModel
    (https://doc.qt.io/archives/qt-5.15/qabstracttablemodel.html#subclassing)

    Always required:
    - rowCount(self, parent: QModelIndex) -> int
    - columnCount(self, parent: QModelIndex) -> int
    - data(self, index: QModelIndex, role: int) -> QVariant

    Recommended:
    - headerData(self, section: int, orientation: Orientation, role: int) -> QVariant

    Editable required:
    - setData(self, index: QModelIndex, value: QVariant, role: int) -> bool
    - flags(self, index: QModelIndex) -> ItemFlags

    The optional insertRows, etc. are not required here because we don't care to
    insert additional empty rows or columns.

    Parameters
    ----------
    config : Config
        The config object that represents the hutch's iocmanager config.
    parent : QWidget or None
        The parent qt widget if any (standard qt argument).
    """

    config: Config

    def __init__(self, config: Config, hutch: str, parent: ParentWidget = None):
        super().__init__(parent)
        self.config = config
        self.hutch = hutch
        self.dialog_add = AddIOCDialog(hutch=hutch, model=self, parent=parent)
        self.dialog_details = DetailsDialog(parent=parent)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        # Local changes (not applied yet)
        self.add_iocs: dict[str, IOCProc] = {}
        self.edit_iocs: dict[str, IOCProc] = {}
        self.delete_iocs: set[str] = set()
        # Live info, collected in poll_thread
        self.live_only_iocs: dict[str, IOCProc] = {}
        self.status_live: dict[str, IOCStatusLive] = {}
        self.status_files: dict[str, IOCStatusFile] = {}
        self.host_os: dict[str, str] = {}
        self.poll_interval = 10.0
        self.poll_stop_ev = threading.Event()

    # Main external business logic
    def get_next_config(self) -> Config:
        """
        Creates a new config including the edits made by the user.

        This should be used when the user asks to save and apply config to decide
        which config to apply.

        Note: the order is important: add first, then edit, then delete.
        This creates a priority for IOCs that are included in multiple local change
        categories.
        For example, if the user added the IOC to the table but then edited it,
        or edited an IOC and then deleted it, we always end in the desired final
        state.
        """
        config = deepcopy(self.config)
        for ioc_proc in self.add_iocs.values():
            config.add_proc(proc=ioc_proc)
        for ioc_proc in self.edit_iocs.values():
            config.update_proc(proc=ioc_proc)
        for ioc_name in self.delete_iocs:
            config.delete_proc(ioc_name=ioc_name)
        return config

    def reset_edits(self):
        """
        Removes pending configuration edits.
        """
        # Removes rows equal to the len of self.add_iocs
        # Order is config, added, live
        if self.add_iocs:
            self.beginRemoveRows(
                QModelIndex(),
                len(self.config.procs),
                len(self.config.procs) + len(self.add_iocs) - 1,
            )
            finish_remove = True
        else:
            finish_remove = False
        self.add_iocs.clear()
        self.edit_iocs.clear()
        self.delete_iocs.clear()
        if finish_remove:
            self.endRemoveRows()
        self.refresh_all()

    # Basic helpers
    def get_ioc_info(self, ioc: IOCModelIdentifier) -> IOCModelInfo:
        """
        Given one of a variety of input types, disambiguate to get all the info.

        This is used throughout the model to remove the need to keep track of
        which functions need rows, which need QModelIndex, which need ioc names, etc.
        """
        match ioc:
            case IOCModelInfo():
                return ioc
            case IOCProc():
                return IOCModelInfo(
                    ioc_proc=ioc,
                    ioc_live=self.get_live_info(ioc=ioc),
                    name=ioc.name,
                    row=self.get_ioc_row(ioc=ioc),
                    deleted=ioc.name in self.delete_iocs,
                    file_proc=self.config.procs.get(ioc.name),
                )
            case IOCStatusLive():
                return IOCModelInfo(
                    ioc_proc=self.get_ioc_proc(ioc=ioc),
                    ioc_live=ioc,
                    name=ioc.name,
                    row=self.get_ioc_row(ioc=ioc),
                    deleted=ioc.name in self.delete_iocs,
                    file_proc=self.config.procs.get(ioc.name),
                )
            case int():
                ioc_proc = self.get_ioc_proc(ioc=ioc)
                return IOCModelInfo(
                    ioc_proc=ioc_proc,
                    ioc_live=self.get_live_info(ioc=ioc),
                    name=ioc_proc.name,
                    row=ioc,
                    deleted=ioc_proc.name in self.delete_iocs,
                    file_proc=self.config.procs.get(ioc_proc.name),
                )
            case str() | QModelIndex():
                ioc_proc = self.get_ioc_proc(ioc=ioc)
                return IOCModelInfo(
                    ioc_proc=self.get_ioc_proc(ioc=ioc),
                    ioc_live=self.get_live_info(ioc=ioc),
                    name=ioc_proc.name,
                    row=self.get_ioc_row(ioc=ioc),
                    deleted=ioc_proc.name in self.delete_iocs,
                    file_proc=self.config.procs.get(ioc_proc.name),
                )
            case _:
                raise TypeError(f"Invalid ioc identifier type {type(ioc)}")

    def get_ioc_row_map(self) -> list[str]:
        """
        Define the row -> name mapping for the table.

        We'll define the rows in the apparent dictionary order:
        - First, the config file contents
        - Second, any IOCs that are being added
        - Third, any discovered IOCs that are not in the config

        See get_ioc_proc.
        """
        return list(self.config.procs) + list(self.add_iocs) + list(self.live_only_iocs)

    def get_ioc_name(self, ioc: IOCModelIdentifier) -> str:
        """For any valid ioc identifier, get the name."""
        if isinstance(ioc, QModelIndex):
            ioc = ioc.row()
        match ioc:
            case IOCModelInfo():
                return ioc.name
            case IOCProc() | IOCStatusLive():
                return ioc.name
            case str():
                return ioc
            case int():
                return self.get_ioc_row_map()[ioc]
            case _:
                raise TypeError(f"Invalid ioc identifier type {type(ioc)}")

    def get_ioc_proc(self, ioc: IOCModelIdentifier) -> IOCProc:
        """
        For any valid ioc identifier, get the correct IOCProc instance.

        When picking an IOCProc instance to return, one from the edit_iocs dict
        will be chosen first, to make sure we display and edit the values that
        include the user's edits.
        """
        ioc_name = self.get_ioc_name(ioc=ioc)
        for source in (
            self.edit_iocs,
            self.add_iocs,
            self.config.procs,
            self.live_only_iocs,
        ):
            try:
                return source[ioc_name]
            except KeyError:
                ...
        raise RuntimeError(f"No data associated with {ioc_name}!")

    def get_live_info(self, ioc: IOCModelIdentifier) -> IOCStatusLive:
        """
        Return the information about a live ioc.

        This uses the cached IOCStatusLive if it is fully populated,
        but auguments it with values from the IOCStatusFile if not.
        """
        ioc_name = self.get_ioc_name(ioc=ioc)
        try:
            live_info = deepcopy(self.status_live[ioc_name])
        except KeyError:
            # This might get called too early,
            # use some default values for display purposes
            live_info = IOCStatusLive(
                name=ioc_name,
                port=0,
                host="",
                path="",
                pid=None,
                status=ProcServStatus.INIT,
                autorestart_mode=AutoRestartMode.OFF,
            )
        if ioc_name in self.status_files:
            for attr in ("port", "host", "path", "pid"):
                if not getattr(live_info, attr):
                    setattr(live_info, attr, getattr(self.status_files[ioc_name], attr))
        return live_info

    def get_ioc_row(self, ioc: IOCModelIdentifier) -> int:
        """
        Get the row in the table we expect to find ioc at.
        """
        if isinstance(ioc, int):
            return ioc
        ioc_name = self.get_ioc_name(ioc=ioc)
        return self.get_ioc_row_map().index(ioc_name)

    # Implement QAbstractTableModel API
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """
        Returns the number of rows in the table.

        Note that for table models, it is typical for parent to be unused.
        It's included for compatibility with the base class.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#rowCount
        """
        return len(self.get_ioc_row_map())

    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """
        Returns the number of columns in the table.

        Note that for table models, it is typical for parent to be unused.
        It's included for compatibility with the base class.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#columnCount
        """
        return len(TableColumn)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        """
        Returns one element of stored data corresponding to one table cell.

        Fans out to a number of helper functions depending on which column and role
        we're getting data for.

        Note: must return an empty/invalid QVariant if there is not a valid value
        to return.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#data
        """
        if not index.isValid() or index.row() >= self.rowCount():
            # Invalid or off the table
            return QVariant()
        column = index.column()
        match role:
            case Qt.DisplayRole | Qt.EditRole:
                try:
                    return self.get_display_data(ioc=index, column=column)
                except (KeyError, ValueError):
                    return QVariant()
            case Qt.ForegroundRole:
                return QBrush(self.get_foreground_color(ioc=index, column=column))
            case Qt.BackgroundRole:
                return QBrush(self.get_background_color(ioc=index, column=column))
            case _:
                # Unsupported role
                return QVariant()

    def get_display_data(self, ioc: IOCModelIdentifier, column: int) -> str | int:
        """Get data for displaying and editing in the table."""
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_proc = ioc_info.ioc_proc
        ioc_live = ioc_info.ioc_live
        norm_path = normalize_path(directory=ioc_proc.path, ioc_name=ioc_proc.name)
        match column:
            case TableColumn.IOCNAME:
                return ioc_proc.alias or ioc_proc.name
            case TableColumn.ID:
                return ioc_proc.name
            case TableColumn.STATE:
                if ioc_proc.disable:
                    return StateOption.OFF.value
                elif norm_path.startswith("ioc/") or norm_path.endswith("/camrecord"):
                    return StateOption.PROD.value
                else:
                    return StateOption.DEV.value
            case TableColumn.STATUS:
                return ioc_live.status.value
            case TableColumn.HOST:
                return ioc_proc.host
            case TableColumn.OSVER:
                return self.host_os[ioc_proc.host]
            case TableColumn.PORT:
                return ioc_proc.port
            case TableColumn.VERSION:
                return norm_path
            case TableColumn.PARENT:
                return ioc_proc.parent
            case TableColumn.EXTRA:
                if ioc_proc.hard:
                    return "HARD IOC"
                # Goal: summarize differences between configured and running
                if ioc_live.status not in (
                    ProcServStatus.RUNNING,
                    ProcServStatus.SHUTDOWN,
                    ProcServStatus.ERROR,
                ):
                    # There isn't a meaningful comparison to check
                    return ""
                desync_info = self.get_desync_info(ioc=ioc_info)
                if not desync_info.has_diff:
                    # There's nothing different
                    return ""
                text_parts = []
                if desync_info.path is not None:
                    text_parts.append(desync_info.path)
                if desync_info.host is not None or desync_info.port is not None:
                    host = desync_info.host or ioc_proc.host
                    port = desync_info.port or ioc_proc.port
                    text_parts.append(f"on {host}:{port}")
                if text_parts:
                    text_parts.insert(0, "Live:")
                    return " ".join(text_parts)
                return ""
            case _:
                raise ValueError(f"Invalid column {column}")

    def get_foreground_color(
        self, ioc: IOCModelIdentifier, column: int
    ) -> Qt.GlobalColor:
        """Get the text color for a cell in the table"""
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_proc = ioc_info.ioc_proc
        file_proc = ioc_info.file_proc

        # Default, contrast with background
        bg_color = self.get_background_color(ioc=ioc_info, column=column)
        if bg_color in (Qt.blue, Qt.red):
            default = Qt.white
        else:
            default = Qt.black

        # Universal handling for pending deletion
        if ioc_proc.name in self.delete_iocs:
            return Qt.red
        # Universal handling for new ioc row
        if file_proc is None:
            # Note: avoid blue on blue
            if bg_color == Qt.blue:
                return default
            return Qt.blue

        # Specific handling for modified (blue) and other
        match column:
            case TableColumn.IOCNAME:
                # Check modified
                if ioc_proc.alias != file_proc.alias:
                    return Qt.blue
            case TableColumn.ID:
                # User can't modify this, keep as default
                ...
            case TableColumn.STATE:
                # Check modified
                if ioc_proc.disable != file_proc.disable:
                    return Qt.blue
            case TableColumn.STATUS:
                # Read-only field, can have different backgrounds
                ...
            case TableColumn.HOST:
                # Check modified
                if ioc_proc.host != file_proc.host:
                    return Qt.blue
            case TableColumn.OSVER:
                # User can't modify this, keep as default
                ...
            case TableColumn.PORT:
                # Check modified (note the background could be red here)
                if ioc_proc.port != file_proc.port:
                    return Qt.blue
            case TableColumn.VERSION:
                # Check modified
                if ioc_proc.path != file_proc.path:
                    return Qt.blue
            case TableColumn.PARENT:
                # User can't modify this, keep as default
                ...
            case TableColumn.EXTRA:
                # User can't modify this, keep as default
                ...
            case _:
                raise ValueError(f"Invalid column {column}")
        return default

    def get_background_color(
        self, ioc: IOCModelIdentifier, column: int
    ) -> Qt.GlobalColor:
        """Get the background color for a cell in the table."""
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_proc = ioc_info.ioc_proc
        ioc_live = ioc_info.ioc_live

        # In general, stay default
        # In a few specific cases put special colors up
        match column:
            case TableColumn.IOCNAME:
                ...
            case TableColumn.ID:
                ...
            case TableColumn.STATE:
                # Be annoying with yellow if the IOC is in dev mode
                if (
                    self.get_display_data(ioc=ioc_info, column=column)
                    == StateOption.DEV
                ):
                    return Qt.yellow
            case TableColumn.STATUS:
                # Blue is init, or host down while being enabled
                # Would otherwise be yellow or red
                if ioc_live.status == ProcServStatus.INIT or (
                    ioc_live.status == ProcServStatus.DOWN and not ioc_proc.disable
                ):
                    return Qt.blue
                # Yellow has priority and means reality != configured (host, port, path)
                if (
                    ioc_proc.host != ioc_live.host
                    or ioc_proc.port != ioc_live.port
                    or ioc_proc.path != ioc_live.path
                ):
                    return Qt.yellow
                # Green is what we want to see (reality matches config)
                if (ioc_live.status == ProcServStatus.RUNNING) ^ ioc_proc.disable:
                    return Qt.green
                # Red is the other bad cases
                return Qt.red
            case TableColumn.HOST:
                ...
            case TableColumn.OSVER:
                ...
            case TableColumn.PORT:
                # Port conflicts are bad! Red bad!
                for other_proc in self.get_next_config().procs.values():
                    if ioc_proc.name == other_proc.name:
                        continue
                    if (
                        ioc_proc.host == other_proc.host
                        and ioc_proc.port == other_proc.port
                    ):
                        return Qt.red
            case TableColumn.VERSION:
                ...
            case TableColumn.PARENT:
                ...
            case TableColumn.EXTRA:
                ...
            case _:
                raise ValueError(f"Invalid column {column}")
        # Default
        return Qt.white

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole
    ) -> QVariant:
        """
        Returns data for the header contents.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#headerData
        """
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            try:
                return QVariant(table_headers[TableColumn(section)])
            except (KeyError, ValueError):
                logger.debug(f"Invalid table section {section}")
        # We only have text and only on the horizontal headers,
        # the rest should be invalid
        return QVariant()

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.EditRole) -> bool:
        """
        Sets the role data for the item at index to value.

        Returns true if successful; otherwise returns false.

        The dataChanged() signal should be emitted if the data was successfully set.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#setData
        """
        if role != Qt.EditRole or not index.isValid() or index.row() >= self.rowCount():
            return False

        ioc_proc = self.get_ioc_proc(ioc=index)
        new_proc = deepcopy(ioc_proc)

        # We mostly need to do type handling based on the column
        # Some columns could never be meaningfully written to
        # Others could be written to even though they are technically read-only
        # in the context of the gui application.
        match index.column():
            case TableColumn.IOCNAME:
                new_proc.alias = str(value)
            case TableColumn.ID:
                return False
            case TableColumn.STATE:
                new_proc.disable = not bool(value)
            case TableColumn.STATUS:
                return False
            case TableColumn.HOST:
                new_proc.host = str(value)
            case TableColumn.OSVER:
                return False
            case TableColumn.PORT:
                new_proc.port = int(value)
            case TableColumn.VERSION:
                new_proc.path = str(value)
            case TableColumn.PARENT:
                return False
            case TableColumn.EXTRA:
                return False
            case _:
                logger.debug(f"Invalid column {index.column()}")
                return False
        # Write succeeded!
        self.edit_iocs[new_proc.name] = new_proc
        self.dataChanged.emit(index, index)
        return True

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        """
        Returns the item flags for the given index.

        This tells qt whether a cell is selectable, editable, etc.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#flags
        https://doc.qt.io/archives/qt-5.15/qt.html#ItemFlag-enum
        """
        if not index.isValid() or index.row() >= self.rowCount():
            logger.debug("Invalid index")
            return Qt.NoItemFlags | Qt.NoItemFlags
        ioc_proc = self.get_ioc_proc(ioc=index)

        if ioc_proc.hard:
            # Hard IOCs are never editable
            edit_flag = Qt.NoItemFlags
        else:
            edit_flag = Qt.ItemIsEditable

        match index.column():
            case TableColumn.IOCNAME:
                return Qt.ItemIsEnabled | Qt.ItemIsSelectable
            case TableColumn.ID:
                return Qt.ItemIsEnabled | Qt.ItemIsSelectable
            case TableColumn.STATE:
                return Qt.ItemIsEnabled | Qt.ItemIsSelectable | edit_flag
            case TableColumn.STATUS:
                # Implementation note: type checker upset if I don't use an or here
                return Qt.ItemIsEnabled | Qt.NoItemFlags
            case TableColumn.HOST:
                return Qt.ItemIsEnabled | edit_flag
            case TableColumn.OSVER:
                return Qt.ItemIsEnabled | Qt.NoItemFlags
            case TableColumn.PORT:
                return Qt.ItemIsEnabled | edit_flag
            case TableColumn.VERSION:
                return Qt.ItemIsEnabled | edit_flag
            case TableColumn.PARENT:
                return Qt.ItemIsEnabled | Qt.NoItemFlags
            case TableColumn.EXTRA:
                return Qt.ItemIsEnabled | Qt.NoItemFlags
            case _:
                logger.debug(f"Invalid column {index.column()}")
                return Qt.NoItemFlags | Qt.NoItemFlags

    # Methods for updating the data using our dataclasses
    def start_poll_thread(self):
        """Public API to start checking IOC statuses in the background."""
        self.poll_stop_ev.clear()
        self.poll_thread.start()

    def stop_poll_thread(self):
        self.poll_stop_ev.set()

    def _poll_loop(self):
        """
        Continually check the status of configured IOCs.

        Uses the following sources to update the table:
        - iocmanager.cfg config file
        - status directory
        - check ioc statuses e.g. via ping, telnet from info in the above
        """
        with concurrent.futures.ThreadPoolExecutor() as executor:
            stopped = False
            while not stopped:
                start_time = time.monotonic()
                self._inner_poll(executor=executor)
                duration = time.monotonic() - start_time
                if duration < self.poll_interval:
                    stopped = self.poll_stop_ev.wait(self.poll_interval - duration)
                else:
                    stopped = self.poll_stop_ev.is_set()

    def _inner_poll(self, executor: concurrent.futures.ThreadPoolExecutor):
        """
        One poll for updates to the IOC.

        This function exists to avoid deep nesting.
        See _poll_loop
        """
        # Ensure an up-to-date config
        try:
            config = read_config(self.hutch)
        except Exception:
            ...
        else:
            self.host_os = get_host_os(config.hosts)
            self.update_from_config_file(config)

        for status_file in read_status_dir(self.hutch):
            self.update_from_status_file(status_file=status_file)

        # IO-bound task, use threads
        futures: list[concurrent.futures.Future[IOCStatusLive]] = []
        next_config = self.get_next_config()
        for ioc_proc in next_config.procs.values():
            futures.append(
                executor.submit(
                    check_status,
                    host=ioc_proc.host,
                    port=ioc_proc.port,
                    name=ioc_proc.name,
                )
            )
        for ioc_name, ioc_file in self.status_files.items():
            if ioc_name not in next_config.procs:
                futures.append(
                    executor.submit(
                        check_status,
                        host=ioc_file.host,
                        port=ioc_file.port,
                        name=ioc_file.name,
                    )
                )

        # Collect the thread results and apply them
        for fut in futures:
            self.update_from_live_ioc(fut.result())

    def update_from_config_file(self, config: Config):
        """
        Update the GUI when the config file changes, e.g. from other users.

        The config file contains information about:
        - Each IOC's intended launch host, port, and other settings
        - The configured hosts

        The StatusPollThread calls this function cyclically with an up-to-date Config.

        Parameters
        ----------
        config : Config
            The config object that represents the hutch's iocmanager config.
        """
        if config.mtime <= self.config.mtime:
            return
        # This might add or remove rows in the config section
        # Order is config, added, live
        old_size = len(self.config.procs)
        new_size = len(config.procs)
        delta = new_size - old_size
        if delta > 0:
            self.beginInsertRows(
                QModelIndex(),
                old_size,
                new_size - 1,
            )
        elif delta < 0:
            self.beginRemoveRows(
                QModelIndex(),
                new_size,
                old_size - 1,
            )
        self.config = config
        if delta > 0:
            self.endInsertRows()
        elif delta < 0:
            self.endRemoveRows()
        # It should be faster to tell most everything to update than to pick cells
        # Technically we could skip the status columns but it's ok
        self._emit_config_changed()

    def update_from_status_file(self, status_file: IOCStatusFile):
        """
        Update the GUI from information in a status file.

        Status files are generated on IOC boot and contain information about
        the IOC's pid, host, port, and version at the time of last boot.

        The StatusPollThread calls this function cyclically with up-to-date
        status files.

        This is primarily used to find candidates for IOCs that are live but
        not in the configuration.

        This also impacts the contents of the "extra" column in the table,
        which can help us identify what the real running
        IOC is when different from the configuration.

        Parameters
        ----------
        status_file : IOCStatusFile
            Boot-time information about an IOC
        """
        if status_file != self.status_files.get(status_file.name):
            self.status_files[status_file.name] = status_file
            # Update extra cell if IOC exists
            try:
                row = self.get_ioc_row(ioc=status_file.name)
            except Exception:
                return
            idx = self.index(row, TableColumn.EXTRA)
            self.dataChanged.emit(idx, idx)

    def update_from_live_ioc(self, status_live: IOCStatusLive):
        """
        Update the GUI from information inspected from a live IOC.

        This is typically gathered by using diagnostic tools like
        ping and telnet and contains information like whether or not
        the IOC is running, in addition to the same boot-time information
        found in the status files.

        Functionally, this can impact the "status" and "extra" information.
        It has priority over the status file when their shared information
        is in conflict.

        Parameters
        ----------
        status_live : IOCStatusLive
            Live-inspected information about an IOC
        """
        if status_live != self.status_live.get(status_live.name):
            self.status_live[status_live.name] = status_live
            self.refresh_live_only_iocs()
            # Update status, extra cells if IOC exists
            try:
                row = self.get_ioc_row(ioc=status_live)
            except Exception:
                return
            idx1 = self.index(row, TableColumn.STATUS)
            idx2 = self.index(row, TableColumn.EXTRA)
            self.dataChanged.emit(idx1, idx1)
            self.dataChanged.emit(idx2, idx2)

    def refresh_live_only_iocs(self):
        """
        Update our cache of IOCs that are only live (and not in the config).

        An IOC is live if it has a non-erroring entry in self.status_live.
        An IOC is in the config if it is present in any of:
        - self.config.procs
        - self.add_iocs
        - self.edit_iocs
        """
        old_live_only = self.live_only_iocs
        new_live_only = {}
        for ioc_name, ioc_live in self.status_live.items():
            if ioc_name in self.config.procs:
                continue
            if ioc_name in self.add_iocs:
                continue
            if ioc_name in self.edit_iocs:
                continue
            # We were able to connect to it and get a status
            if ioc_live.status in ("RUNNING", "SHUTDOWN"):
                new_live_only[ioc_name] = IOCProc(
                    name=ioc_name,
                    port=ioc_live.port,
                    host=ioc_live.host,
                    path=ioc_live.path,
                )
        # This might add or remove rows
        old_size = len(old_live_only)
        new_size = len(new_live_only)
        delta = new_size - old_size
        if delta > 0:
            self.beginInsertRows(
                QModelIndex(),
                self.rowCount(),
                self.rowCount() + delta - 1,
            )
        elif delta < 0:
            self.beginRemoveRows(
                QModelIndex(),
                self.rowCount() - delta,
                self.rowCount() - 1,
            )
        self.live_only_iocs = new_live_only
        if delta > 0:
            self.endInsertRows()
        elif delta < 0:
            self.endRemoveRows()
        if self.live_only_iocs:
            self._emit_live_only_changed()

    def refresh_all(self):
        """
        Refresh all information in the table.

        This includes:
        - The config file information
        - The live IOC information

        Note: added IOCs only exist as items
        in this application and do not need to
        be refreshed.
        """
        try:
            config = read_config(self.hutch)
        except Exception:
            ...
        else:
            self.update_from_config_file(config)
        self.refresh_live_only_iocs()

    # User Dialogs
    def add_ioc_dialog(self):
        """
        Open the add ioc dialog to create a new IOC and add it to the table
        """
        self.dialog_add.reset()

        while self._add_ioc_dialog_again():
            ...

    def _add_ioc_dialog_again(self) -> bool:
        """
        Subloop of add_ioc_dialog, return True if we should try again.
        """
        if self.dialog_add.exec_() != QDialog.Accepted:
            return False
        if not self.dialog_add.port_is_valid:
            QMessageBox.critical(
                None,
                "Error",
                (
                    "Invalid port selected! "
                    "Expected port ranges are 30001-38999 for closed ports, "
                    "39100-39199 for open ports, "
                    "and -1 to signify a hard ioc."
                ),
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return True
        ioc_proc = self.dialog_add.get_ioc_proc()
        if not ioc_proc.name or (
            not ioc_proc.hard
            and (not ioc_proc.host or not ioc_proc.port or not ioc_proc.path)
        ):
            QMessageBox.critical(
                None,
                "Error",
                "Failed to set required parameters for new IOC!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return True
        if ioc_proc.name in self.get_next_config().procs:
            QMessageBox.critical(
                None,
                "Error",
                f"IOC {ioc_proc.name} already exists!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return True
        self.add_ioc(ioc_proc=ioc_proc)
        return False

    def edit_details_dialog(self, ioc: IOCModelIdentifier):
        """
        Open the details dialog to edit settings not directly displayed in the table.
        """
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_proc = ioc_info.ioc_proc
        self.dialog_details.set_ioc_proc(ioc_proc=ioc_proc)

        if self.dialog_details.exec_() != QDialog.Accepted:
            return

        new_proc = self.dialog_details.get_ioc_proc()

        if new_proc != ioc_proc:
            self.edit_iocs[new_proc.name] = new_proc
        if new_proc.alias != ioc_proc.alias:
            index = self.index(ioc_info.row, TableColumn.IOCNAME)
            self.dataChanged.emit(index, index)

    # Basic utility helpers
    def add_ioc(self, ioc_proc: IOCProc):
        """
        Add a completely new IOC to the config.
        """
        add_row = len(self.config.procs) + len(self.add_iocs)
        self.beginInsertRows(
            QModelIndex(),
            add_row,
            add_row,
        )
        self.add_iocs[ioc_proc.name] = ioc_proc
        self.endInsertRows()
        self.refresh_live_only_iocs()

    def delete_ioc(self, ioc: IOCModelIdentifier):
        """
        Mark the IOC as pending deletion.

        Refreshes that row to pick up the color updates.
        """
        ioc_info = self.get_ioc_info(ioc=ioc)
        self.delete_iocs.add(ioc_info.name)
        self._emit_row_changed(ioc_info.row)

    def revert_ioc(self, ioc: IOCModelIdentifier):
        """
        Revert all pending adds, edits, and deletes for an IOC.

        Refreshes the row in the case of reverting edits and deletes,
        or the added rows section in the case of reverting an add.
        """
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_name = ioc_info.name
        row = ioc_info.row
        if ioc_name in self.add_iocs:
            self.beginRemoveRows(
                QModelIndex(),
                row,
                row,
            )
        undo_add = self.add_iocs.pop(ioc_name, None)
        undo_edit = self.edit_iocs.pop(ioc_name, None)
        try:
            undo_delete = self.delete_iocs.remove(ioc_name)
        except KeyError:
            undo_delete = None
        if undo_add is not None:
            self.endRemoveRows()
        elif undo_edit is not None or undo_delete is not None:
            self._emit_row_changed(row=row)
        self.refresh_live_only_iocs()

    def _emit_all_changed(self):
        """Helper for causing a full table update."""
        self.dataChanged.emit(
            self.index(0, 0), self.index(self.rowCount() - 1, self.columnCount() - 1)
        )

    def _emit_config_changed(self):
        """Helper for causing an update of only the config file IOCs."""
        self.dataChanged.emit(
            self.index(0, 0),
            self.index(len(self.config.procs) - 1, self.columnCount() - 1),
        )

    def _emit_added_changed(self):
        """Helper for causing an update of only the added IOCs."""
        added_iocs_row = len(self.config.procs)
        added_iocs_count = len(self.add_iocs)
        idx1 = self.index(added_iocs_row, 0)
        idx2 = self.index(added_iocs_row + added_iocs_count - 1, self.columnCount() - 1)
        self.dataChanged.emit(idx1, idx2)

    def _emit_live_only_changed(self):
        """Helper for causing an update of only the live-only IOCs."""
        live_only_row = len(self.config.procs) + len(self.add_iocs)
        idx1 = self.index(live_only_row, 0)
        idx2 = self.index(self.rowCount() - 1, self.columnCount() - 1)
        self.dataChanged.emit(idx1, idx2)

    def _emit_row_changed(self, row: int):
        """Helper for updating a single row."""
        idx1 = self.index(row, 0)
        idx2 = self.index(row, self.columnCount() - 1)
        self.dataChanged.emit(idx1, idx2)

    # Helper functions that are simpler to maintain here than in IOCMainWindow
    # due to proximity to related code
    def save_version(self, ioc: IOCModelIdentifier):
        """
        For the IOC at row, add the current version to the history.

        This is treated as a pending edit.
        """
        ioc_proc = deepcopy(self.get_ioc_proc(ioc=ioc))
        if ioc_proc.path not in ioc_proc.history:
            ioc_proc.history.insert(0, ioc_proc.path)
            self.edit_iocs[ioc_proc.name] = ioc_proc

    def save_all_versions(self):
        """For all IOCs in the table, call save_version."""
        for row in range(self.rowCount()):
            self.save_version(ioc=row)

    def get_desync_info(self, ioc: IOCModelIdentifier) -> DesyncInfo:
        """
        Return info about the differences between an IOC's config and live settings.

        See DesyncInfo.
        """
        ioc_info = self.get_ioc_info(ioc=ioc)
        return DesyncInfo.from_info(
            ioc_proc=ioc_info.ioc_proc, status_live=ioc_info.ioc_live
        )

    def pending_edits(self, ioc: IOCModelIdentifier) -> bool:
        """Return True if the ioc has pending edits."""
        ioc_info = self.get_ioc_info(ioc=ioc)
        # Deleted is a pending edit regardless of the fields
        if ioc_info.deleted and ioc_info.name not in self.add_iocs:
            return True
        # Covers any normal add, edit scenario via comparing fields or to None
        if ioc_info.ioc_proc != ioc_info.file_proc:
            return True
        return False

    def set_from_running(self, ioc: IOCModelIdentifier) -> None:
        """
        Edit the IOC's config such that it matches the values found in the live status.

        The IOC might be in any state: newly added, edited, deleted, or unchanged.
        Check edited first, then added, then base config for IOCProc.
        """
        ioc_info = self.get_ioc_info(ioc=ioc)
        ioc_proc = ioc_info.ioc_proc
        ioc_live = ioc_info.ioc_live
        edit_proc = deepcopy(ioc_proc)
        # Check port, host, and path
        if ioc_live.port:
            edit_proc.port = ioc_live.port
        if ioc_live.host:
            edit_proc.host = ioc_live.host
        if ioc_live.path:
            edit_proc.path = ioc_live.path
        self.edit_iocs[ioc_info.name] = edit_proc
        self.refresh_live_only_iocs()

    def get_unused_port(self, host: str, closed: bool) -> int:
        """
        Return the smallest valid unused port for the host.

        Works in the context of the current config including
        pending edits.
        """
        return self.get_next_config().get_unused_port(host=host, closed=closed)
