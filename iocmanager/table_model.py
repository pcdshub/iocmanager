"""
The table_model module defines a data model for the main GUI table.

This implements a QAbstractTableModel which manages reading and writing data
for the central QTableView in the main GUI.

The data in the table represents:

- The contents of the IOC manager config file's IOC data
- Any pending edits of the config file IOCs (to include at next save)
- Helpful status and context information for each IOC

See https://doc.qt.io/qt-5/qabstracttablemodel.html#details

TODO: handle IOCs that are running, but not in the config at all
TODO: e.g. IOCs that have status files but are not in config
TODO: clean up input args. Some functions take ints, others take str etc.
TODO: allow all functions to take any of int, str, IOCProc, QModelIndex
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
from .procserv_tools import (
    AutoRestartMode,
    IOCStatusLive,
    ProcServStatus,
    check_status,
)
from .type_hints import ParentWidget

logger = logging.getLogger(__name__)


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
        self.dialog_add = AddIOCDialog(hutch=hutch, parent=parent)
        self.dialog_details = DetailsDialog(parent=parent)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        # Track last sort to reapply sorting after changing the IOC list
        self.last_sort: tuple[int, Qt.SortOrder] = (0, Qt.DescendingOrder)
        # Local changes (not applied yet)
        self.add_iocs: dict[str, IOCProc] = {}
        self.edit_iocs: dict[str, IOCProc] = {}
        self.delete_iocs: set[str] = set()
        # Live info, collected in poll_thread
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

    def reset_edits(self, needs_refresh: bool = False):
        """
        Removes pending configuration edits.

        Call this after saving the config file, without refreshing.
        Note that this doesn't ask for a model update, intentionally,
        since that would cause the pending changes to disappear.
        We'll update on the next poll, including the now-saved changes.

        Call this with a refresh if the user specifically asked to
        undo all of their changes.
        """
        self.add_iocs.clear()
        self.edit_iocs.clear()
        self.delete_iocs.clear()
        if needs_refresh:
            self._emit_all_changed()

    # Basic helpers
    def get_ioc_proc(self, row: int) -> IOCProc:
        """
        Define the row -> proc mapping for the table.

        This does not need maintain stable row indices, nor does it need to consider
        the timing of data updates.

        We'll define the rows in the apparent dictionary order:
        - First, the config file contents
        - Second, any IOCs that are being added

        When picking an IOCProc instance to return, one from the edit_iocs dict
        will be chosen first, to make sure we display and edit the values that
        include the user's edits.
        """
        ioc_name = self.get_ioc_row_map()[row]
        for source in (self.edit_iocs, self.add_iocs, self.config.procs):
            try:
                return source[ioc_name]
            except KeyError:
                ...
        # This is not a valid codepath, but let's be paranoid
        raise RuntimeError(
            f"Found {ioc_name} at row {row} but no data associated with it."
        )

    def get_ioc_row_map(self) -> list[str]:
        """
        Define the row -> name mapping for the table.

        See get_ioc_proc.
        """
        return list(self.config.procs) + list(self.add_iocs)

    def get_live_info(self, ioc_name: str) -> IOCStatusLive:
        """
        Return the information about a live IOC.

        This uses the cached IOCStatusLive if it is fully populated,
        but auguments it with values from the IOCStatusFile if not.
        """
        try:
            live_info = self.status_live[ioc_name]
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

    # Implement QAbstractTableModel API
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """
        Returns the number of rows in the table.

        Note that for table models, it is typical for parent to be unused.
        It's included for compatibility with the base class.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#rowCount
        """
        return len(self.config.procs) + len(self.add_iocs)

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
        ioc_proc = self.get_ioc_proc(index.row())
        column = index.column()
        match role:
            case Qt.DisplayRole | Qt.EditRole:
                try:
                    return self.get_display_data(ioc_proc=ioc_proc, column=column)
                except (KeyError, ValueError):
                    return QVariant()
            case Qt.ForegroundRole:
                return QBrush(
                    self.get_foreground_color(ioc_proc=ioc_proc, column=column)
                )
            case Qt.BackgroundRole:
                return QBrush(
                    self.get_background_color(ioc_proc=ioc_proc, column=column)
                )
            case _:
                # Unsupported role
                return QVariant()

    def get_display_data(self, ioc_proc: IOCProc, column: int) -> str | int:
        """Get data for displaying and editing in the table."""
        match column:
            case TableColumn.IOCNAME:
                return ioc_proc.alias or ioc_proc.name
            case TableColumn.ID:
                return ioc_proc.name
            case TableColumn.STATE:
                if ioc_proc.disable:
                    return StateOption.OFF
                elif ioc_proc.path.startswith("ioc/") or ioc_proc.path.endswith(
                    "/camrecord"
                ):
                    return StateOption.PROD
                else:
                    return StateOption.DEV
            case TableColumn.STATUS:
                return self.get_live_info(ioc_name=ioc_proc.name).status
            case TableColumn.HOST:
                return ioc_proc.host
            case TableColumn.OSVER:
                return self.host_os[ioc_proc.host]
            case TableColumn.PORT:
                return ioc_proc.port
            case TableColumn.VERSION:
                return ioc_proc.path
            case TableColumn.PARENT:
                return ioc_proc.parent
            case TableColumn.EXTRA:
                if ioc_proc.hard:
                    return "HARD IOC"
                # Goal: summarize differences between configured and running
                desync_info = self.get_desync_info(ioc_proc=ioc_proc)
                if not desync_info.has_diff:
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

    def get_foreground_color(self, ioc_proc: IOCProc, column: int) -> Qt.GlobalColor:
        """Get the text color for a cell in the table"""
        # Universal handling for pending deletion
        if ioc_proc.name in self.delete_iocs:
            return Qt.red
        # Universal handling for new ioc row
        if ioc_proc.name not in self.config.procs:
            return Qt.blue
        file_proc = self.config.procs[ioc_proc.name]
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
        # Default, contrast with background
        bg_color = self.get_background_color(ioc_proc=ioc_proc, column=column)
        if bg_color in (Qt.blue, Qt.red):
            return Qt.white
        return Qt.black

    def get_background_color(self, ioc_proc: IOCProc, column: int) -> Qt.GlobalColor:
        """Get the background color for a cell in the table."""
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
                    self.get_display_data(ioc_proc=ioc_proc, column=column)
                    == StateOption.DEV
                ):
                    return Qt.yellow
            case TableColumn.STATUS:
                status = self.get_live_info(ioc_name=ioc_proc.name)
                # Blue is init, or host down while being enabled
                # Would otherwise be yellow or red
                if status.status == ProcServStatus.INIT or (
                    status.status == ProcServStatus.DOWN and not ioc_proc.disable
                ):
                    return Qt.blue
                # Yellow has priority and means reality != configured (host, port, path)
                if (
                    ioc_proc.host != status.host
                    or ioc_proc.port != status.port
                    or ioc_proc.path != status.path
                ):
                    return Qt.yellow
                # Green is what we want to see (reality matches config)
                if (status.status == ProcServStatus.RUNNING) ^ ioc_proc.disable:
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
                    if ioc_proc == other_proc:
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

        ioc_proc = self.get_ioc_proc(index.row())
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
        ioc_proc = self.get_ioc_proc(row=index.row())

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

        # IO-bound task, use threads
        futures: list[concurrent.futures.Future[IOCStatusLive]] = []
        for ioc_proc in self.config.procs.values():
            futures.append(
                executor.submit(
                    check_status,
                    host=ioc_proc.host,
                    port=ioc_proc.port,
                    name=ioc_proc.name,
                )
            )

        # TODO consider reordering, might be correct to check status files first
        # TODO so we can include running-but-not-in-config IOC candidates
        # TODO when we extend this to support these dark IOCs
        # Check the status files while thread IO finishes
        for status_file in read_status_dir(self.hutch):
            self.update_from_status_file(status_file=status_file)

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
        self.config = config
        # It should be faster to tell most everything to update than to pick cells
        # Technically we could skip the status columns but it's ok
        self._emit_all_changed()

    def update_from_status_file(self, status_file: IOCStatusFile):
        """
        Update the GUI from information in a status file.

        Status files are generated on IOC boot and contain information about
        the IOC's pid, host, port, and version at the time of last boot.

        The StatusPollThread calls this function cyclically with up-to-date
        status files.

        Functionally, this can only impact the contents of the "extra"
        information, which can help us identify what the real running
        IOC is when different from the configuration.

        Parameters
        ----------
        status_file : IOCStatusFile
            Boot-time information about an IOC
        """
        if status_file != self.status_files.get(status_file.name):
            self.status_files[status_file.name] = status_file
            # Update extra cell
            row_map = self.get_ioc_row_map()
            row = row_map.index(status_file.name)
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
            # Update status, extra cells
            row_map = self.get_ioc_row_map()
            row = row_map.index(status_live.name)
            idx1 = self.index(row, TableColumn.STATUS)
            idx2 = self.index(row, TableColumn.EXTRA)
            self.dataChanged.emit(idx1, idx1)
            self.dataChanged.emit(idx2, idx2)

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

    def edit_details_dialog(self, index: QModelIndex):
        """
        Open the details dialog to edit settings not directly displayed in the table.
        """
        ioc_proc = self.get_ioc_proc(row=index.row())
        self.dialog_details.set_ioc_proc(ioc_proc=ioc_proc)

        if self.dialog_details.exec_() != QDialog.Accepted:
            return

        new_proc = self.dialog_details.get_ioc_proc()

        if new_proc != ioc_proc:
            self.edit_iocs[new_proc.name] = new_proc
        if new_proc.alias != ioc_proc.alias:
            self.dataChanged.emit(self.index(index.row(), TableColumn.IOCNAME))

    # Basic utility helpers
    def add_ioc(self, ioc_proc: IOCProc):
        """
        Add a completely new IOC to the config.

        Refreshes the bottom few rows of the table (the added IOCs section)
        """
        self.add_iocs[ioc_proc.name] = ioc_proc
        self._emit_added_changed()

    def delete_ioc(self, row: int):
        """
        Mark the IOC at row as pending deletion.

        Refreshes that row to pick up the color updates.
        """
        ioc_name = self.get_ioc_row_map()[row]
        self.delete_iocs.add(ioc_name)
        self._emit_row_changed(row=row)

    def revert_ioc(self, row: int):
        """
        Revert all pending adds, edits, and deletes for an IOC.

        Refreshes the row in the case of reverting edits and deletes,
        or the added rows section in the case of reverting an add.
        """
        ioc_name = self.get_ioc_row_map()[row]
        undo_add = self.add_iocs.pop(ioc_name, None)
        undo_edit = self.edit_iocs.pop(ioc_name, None)
        try:
            undo_delete = self.delete_iocs.remove(ioc_name)
        except KeyError:
            undo_delete = None
        if undo_add is not None:
            self._emit_added_changed()
        elif undo_edit is not None or undo_delete is not None:
            self._emit_row_changed(row=row)

    def _emit_all_changed(self):
        """Helper for causing a full table update."""
        self.dataChanged.emit(
            self.index(0, 0), self.index(self.rowCount() - 1, self.columnCount() - 1)
        )

    def _emit_added_changed(self):
        """Helper for causing an update of only the added IOCs."""
        added_iocs_row = len(self.config.procs)
        idx1 = self.index(added_iocs_row, 0)
        idx2 = self.index(self.rowCount() - 1, self.columnCount() - 1)
        self.dataChanged.emit(idx1, idx2)

    def _emit_row_changed(self, row: int):
        """Helper for updating a single row."""
        idx1 = self.index(row, 0)
        idx2 = self.index(row, self.columnCount() - 1)
        self.dataChanged.emit(idx1, idx2)

    # Helper functions that are easier to implement here than in IOCMainWindow
    def save_version(self, row: int):
        """
        For the IOC at row, add the current version to the history.

        This is treated as a pending edit.
        """
        ioc_proc = self.get_ioc_proc(row)
        if ioc_proc.path not in ioc_proc.history:
            ioc_proc.history.insert(0, ioc_proc.path)
            self.edit_iocs[ioc_proc.name] = ioc_proc

    def save_all_versions(self):
        """For all IOCs in the table, call save_version."""
        for row in range(self.rowCount()):
            self.save_version(row=row)

    def get_desync_info(self, ioc_proc: IOCProc) -> DesyncInfo:
        """
        Return info about the differences between an IOC's config and live settings.

        See DesyncInfo.
        """
        status_live = self.get_live_info(ioc_name=ioc_proc.name)
        return DesyncInfo.from_info(ioc_proc=ioc_proc, status_live=status_live)

    def pending_edits(self, ioc_name: str) -> bool:
        """Return True if the ioc has pending edits."""
        return self.config.procs.get(ioc_name) != self.get_next_config().procs.get(
            ioc_name
        )

    def set_from_running(self, ioc_name: str) -> None:
        """
        Edit the IOC's config such that it matches the values found in the live status.

        The IOC might be in any state: newly added, edited, deleted, or unchanged.
        Check edited first, then added, then base config for IOCProc.
        """
        status_live = self.get_live_info(ioc_name=ioc_name)
        try:
            ioc_proc = self.edit_iocs[ioc_name]
        except KeyError:
            try:
                ioc_proc = self.add_iocs[ioc_name]
            except KeyError:
                ioc_proc = self.config.procs[ioc_name]
        edit_proc = deepcopy(ioc_proc)
        # Check port, host, and path
        if status_live.port:
            edit_proc.port = status_live.port
        if status_live.host:
            edit_proc.host = status_live.host
        if status_live.path:
            edit_proc.path = status_live.path
        self.edit_iocs[ioc_name] = edit_proc
