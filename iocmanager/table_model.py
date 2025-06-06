"""
The table_model module defines a data model for the main GUI table.

This implements a QAbstractTableModel which manages reading and writing data
for the central QTableView in the main GUI.

See https://doc.qt.io/qt-5/qabstracttablemodel.html#details
"""

import concurrent.futures
import itertools
import logging
import os
import re
import tempfile
import threading
import time
from enum import IntEnum, StrEnum

import psp
from qtpy.QtCore import QAbstractTableModel, QEvent, QModelIndex, Qt, QVariant
from qtpy.QtGui import QBrush
from qtpy.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from . import commit_ui, details_ui
from .config import (
    Config,
    IOCProc,
    IOCStatusFile,
    get_host_os,
    read_config,
    read_status_dir,
    write_config,
)
from .epics_paths import get_parent, normalize_path
from .hioc_tools import get_hard_ioc_dir_for_display, reboot_hioc, restart_hioc
from .ioc_info import find_pv, get_base_name
from .procserv_tools import (
    IOCStatusLive,
    ProcServStatus,
    apply_config,
    check_status,
    restart_proc,
)
from .server_tools import netconfig, reboot_server
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
    OFF = "Off"
    PROD = "Prod"
    DEV = "Dev"


class CommitOption(IntEnum):
    """
    Integer codes for the three results from the CommitDialog.
    """

    SAVE_AND_COMMIT = 0
    SAVE_ONLY = 1
    CANCEL = 2


class DetailsDialog(QDialog):
    """
    Load the pyuic-compiled ui/details.ui into a QDialog.

    This dialog contains edit widgets for some of the less common IOC settings,
    namely, the ones that are not editable in the table using the table delegate.
    This dialog is launched when someone right-clicks on a table row and clicks
    on "Edit Details".
    """

    def __init__(self, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = details_ui.Ui_Dialog()
        self.ui.setupUi(self)


class CommitDialog(QDialog):
    """
    Load the pyuic-compiled ui/commit.ui into a QDialog.

    This dialog contains a large QTextEdit that can be used to enter a
    commit message.
    It is opened right after a user asks to apply the configuration,
    and right before we save the file.
    """

    def __init__(self, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = commit_ui.Ui_Dialog()
        self.ui.setupUi(self)
        self.setResult(CommitOption.CANCEL)
        self.ui.buttonBox.button(QDialogButtonBox.Yes).clicked.connect(self.yes_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.No).clicked.connect(self.no_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(
            self.cancel_clicked
        )

    def yes_clicked(self):
        self.setResult(CommitOption.SAVE_AND_COMMIT)

    def no_clicked(self):
        self.setResult(CommitOption.SAVE_ONLY)

    def cancel_clicked(self):
        # Technically this is always already set, but it's good to be paranoid
        self.setResult(CommitOption.CANCEL)


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

    def __init__(self, config: Config, parent: ParentWidget = None):
        super().__init__(parent)
        self.details_dialog = DetailsDialog(parent)
        self.commit_dialog = CommitDialog(parent)
        self.poll_thread = StatusPollThread(
            model=self, interval=5.0, config=self.config
        )
        # Track last sort to reapply sorting after changing the IOC list
        self.last_sort: tuple[int, Qt.SortOrder] = (0, Qt.DescendingOrder)
        # Note: this sets self.config
        self.update_from_config_file(config)
        # Local changes (not applied yet)
        self.add_iocs: dict[str, IOCProc] = {}
        self.edit_iocs: dict[str, IOCProc] = {}
        self.delete_iocs: list[str] = []
        # Live info
        self.status_live: dict[str, IOCStatusLive] = {}
        self.status_files: dict[str, IOCStatusLive] = {}
        self.host_os: dict[str, str] = {}

    # Basic helpers for implementing the QAbstractTableModel API
    def get_ioc_proc(self, row: int) -> IOCProc:
        """Define the row -> proc mapping for the table."""
        return (list(self.config.procs.values()) + list(self.add_iocs.values()))[row]

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

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> QVariant:
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
                    return QVariant(
                        self.get_display_text(ioc_proc=ioc_proc, column=column)
                    )
                except (KeyError, ValueError):
                    return QVariant()
            case Qt.ForegroundRole:
                return QVariant(
                    QBrush(self.get_foreground_color(ioc_proc=ioc_proc, column=column))
                )
            case Qt.BackgroundRole:
                return QVariant(
                    QBrush(self.get_background_color(ioc_proc=ioc_proc, column=column))
                )
            case _:
                # Unsupported role
                return QVariant()

    def get_display_text(self, ioc_proc: IOCProc, column: int) -> str:
        """Get text data for displaying and editing in the table."""
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
                return self.status_live[ioc_proc.name].status
            case TableColumn.HOST:
                return ioc_proc.host
            case TableColumn.OSVER:
                return self.host_os[ioc_proc.host]
            case TableColumn.PORT:
                return str(ioc_proc.port)
            case TableColumn.VERSION:
                return ioc_proc.path
            case TableColumn.PARENT:
                return ioc_proc.parent
            case TableColumn.EXTRA:
                if ioc_proc.hard:
                    return "HARD IOC"
                # Goal: summarize differences between configured and running
                status_file = self.status_files[ioc_proc.name]
                text_parts = []
                if ioc_proc.path != status_file.path:
                    text_parts.append(f"{status_file.path}")
                if (
                    ioc_proc.host != status_file.host
                    or ioc_proc.port != status_file.port
                ):
                    text_parts.append(f"on {status_file.host}:{status_file.port}")
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
        # Specific handling for modified (blue) and other
        match column:
            case TableColumn.IOCNAME:
                # Check modified
                try:
                    if self.edit_iocs[ioc_proc.name].alias != ioc_proc.alias:
                        return Qt.blue
                except KeyError:
                    ...
            case TableColumn.ID:
                # User can't modify this, keep as default
                ...
            case TableColumn.STATE:
                # Check modified
                try:
                    if self.edit_iocs[ioc_proc.name].disable != ioc_proc.disable:
                        return Qt.blue
                except KeyError:
                    ...
            case TableColumn.STATUS:
                # Read-only field, pick black or white for contrast with background
                bg_color = self.get_background_color(ioc_proc=ioc_proc, column=column)
                if bg_color in (Qt.blue, Qt.red):
                    return Qt.white
            case TableColumn.HOST:
                # Check modified
                try:
                    if self.edit_iocs[ioc_proc.name].host != ioc_proc.host:
                        return Qt.blue
                except KeyError:
                    ...
            case TableColumn.OSVER:
                # User can't modify this, keep as default
                ...
            case TableColumn.PORT:
                # Check modified
                try:
                    if self.edit_iocs[ioc_proc.name].port != ioc_proc.port:
                        return Qt.blue
                except KeyError:
                    ...
            case TableColumn.VERSION:
                # Check modified
                try:
                    if self.edit_iocs[ioc_proc.name].path != ioc_proc.path:
                        return Qt.blue
                except KeyError:
                    ...
            case TableColumn.PARENT:
                # User can't modify this, keep as default
                ...
            case TableColumn.EXTRA:
                # User can't modify this, keep as default
                ...
            case _:
                raise ValueError(f"Invalid column {column}")
        # Default
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
                    self.get_display_text(ioc_proc=ioc_proc, column=column)
                    == StateOption.DEV
                ):
                    return Qt.yellow
            case TableColumn.STATUS:
                status = self.status_live[ioc_proc.name]
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
                # Blue is host down while being enabled, would otherwise be red
                if status.status == ProcServStatus.DOWN and not ioc_proc.disable:
                    return Qt.blue
                # Red is the other bad cases
                return Qt.red
            case TableColumn.HOST:
                ...
            case TableColumn.OSVER:
                ...
            case TableColumn.PORT:
                # Port conflicts are bad! Red bad!
                for other_proc in itertools.chain(
                    self.config.procs.values(), self.add_iocs.values()
                ):
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
            return QVariant(table_headers[TableColumn(section)])
        # We only have text and only on the horizontal headers, the rest should be invalid
        return QVariant()

    def setData(
        self, index: QModelIndex, value: QVariant, role: int = Qt.EditRole
    ) -> bool:
        """
        Sets the role data for the item at index to value.

        Returns true if successful; otherwise returns false.

        The dataChanged() signal should be emitted if the data was successfully set.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#setData
        """
        if role != Qt.EditRole or not index.isValid() or index.row() >= self.rowCount():
            return False

        raw_value = value.value()
        ioc_proc = self.get_ioc_proc(index.row())

        # We mostly need to do type handling based on the column
        # Some columns could never be meaningfully written to
        # Others could be written to even though they are technically read-only
        # in the context of the gui application.
        match index.column():
            case TableColumn.IOCNAME:
                ioc_proc.alias = str(raw_value)
            case TableColumn.ID:
                ioc_proc.name = str(raw_value)
            case TableColumn.STATE:
                ioc_proc.disable = not bool(raw_value)
            case TableColumn.STATUS:
                return False
            case TableColumn.HOST:
                ioc_proc.host = str(raw_value)
            case TableColumn.OSVER:
                return False
            case TableColumn.PORT:
                ioc_proc.port = int(raw_value)
            case TableColumn.VERSION:
                ioc_proc.path = str(raw_value)
            case TableColumn.PARENT:
                return False
            case TableColumn.EXTRA:
                return False
            case _:
                raise ValueError(f"Invalid column {index.column()}")
        # Write succeeded!
        self.dataChanged.emit(index, index)
        return True

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        """
        Returns the item flags for the given index.

        This tells qt whether a cell is selectable, editable, etc.

        https://doc.qt.io/archives/qt-5.15/qabstractitemmodel.html#flags
        https://doc.qt.io/archives/qt-5.15/qt.html#ItemFlag-enum
        """
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
                raise ValueError(f"Invalid column {index.column()}")

    # Methods for updating the data using our dataclasses
    def start_poll_thread(self):
        """Public API to start checking IOC statuses in the background."""
        self.poll_thread.start()

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
        self.config = config
        # todo emit which fields have changed for the model
        self.sort(self.last_sort[0], self.last_sort[1])

    def update_from_status_file(self, status_file: IOCStatusFile):
        """
        Update the GUI from information in a status file.

        Status files are generated on IOC boot and contain information about
        the IOC's pid, host, port, and version at the time of last boot.

        The StatusPollThread calls this function cyclically with up-to-date
        status files.

        Parameters
        ----------
        status_file : IOCStatusFile
            Boot-time information about an IOC
        """
        ...

    def update_from_live_ioc(self, status_live: IOCStatusLive):
        """
        Update the GUI from information inspected from a live IOC.

        This is typically gathered by using diagnostic tools like
        ping and telnet and contains information like whether or not
        the IOC is running, in addition to the same boot-time information
        found in the status files.

        Parameters
        ----------
        status_live : IOCStatusLive
            Live-inspected information about an IOC
        """
        ...

    def running(self, d):
        # Process a new status dictionary!
        i = self.findid(d["rid"], self.cfglist)
        if i is None:
            i = self.findhostport(d["rhost"], d["rport"], self.cfglist)
        if i is not None:
            if self.cfglist[i]["dir"] == utils.CAMRECORDER:
                d["rdir"] = utils.CAMRECORDER
            if (
                d["status"] == utils.STATUS_RUNNING
                or self.cfglist[i]["cfgstat"] != utils.CONFIG_DELETED
            ):
                # Sigh.  If we just emit dataChanged for the row, editing the port
                # number becomes nearly impossible, because we keep writing it over.
                # Therefore, we need to avoid it... except, of course, sometimes it
                # *does* change!
                oldport = self.cfglist[i]["rport"]
                self.cfglist[i].update(d)
                if oldport != self.cfglist[i]["rport"]:
                    self.dataChanged.emit(
                        self.index(i, 0), self.index(i, len(self.headerdata) - 1)
                    )
                else:
                    if PORT > 0:
                        self.dataChanged.emit(self.index(i, 0), self.index(i, PORT - 1))
                    if PORT < len(self.headerdata) - 1:
                        self.dataChanged.emit(
                            self.index(i, PORT + 1),
                            self.index(i, len(self.headerdata) - 1),
                        )
            else:
                self.cfglist = self.cfglist[0:i] + self.cfglist[i + 1 :]
                self.sort(self.last_sort[0], self.last_sort[1])
            return
        elif d["status"] == utils.STATUS_RUNNING:
            d["id"] = d["rid"]
            d["host"] = d["rhost"]
            d["port"] = d["rport"]
            d["dir"] = d["rdir"]
            d["pdir"] = ""
            d["disable"] = False
            d["cfgstat"] = utils.CONFIG_DELETED
            d["alias"] = ""
            self.cfglist.append(d)
            self.sort(self.last_sort[0], self.last_sort[1])

    def value(self, entry, c, display=True):
        if c == STATUS:
            return entry["status"]
        if c == OSVER:
            try:
                return self.poll_thread.host_os[entry["host"]]
            except Exception:
                return ""
        elif c == EXTRA:
            if entry["hard"]:
                return "HARD IOC"
            v = ""
            if entry["dir"] != entry["rdir"] and entry["rdir"] != "/tmp":
                v = entry["rdir"] + " "
            if entry["host"] != entry["rhost"] or entry["port"] != entry["rport"]:
                v += "on " + entry["rhost"] + ":" + str(entry["rport"])
            if entry["id"] != entry["rid"]:
                v += "as " + entry["rid"]
            return v
        elif c == STATE:
            try:
                v = entry["newdisable"]
            except Exception:
                v = entry["disable"]
            if v:
                return "Off"
            try:
                v = entry["newdir"]
            except Exception:
                v = entry["dir"]
            if v[:4] == "ioc/" or v == "/reg/g/pcds/controls/camrecord":
                return "Prod"
            else:
                return "Dev"
        if c == IOCNAME and display:
            # First try to find an alias!
            try:
                if entry["newalias"] != "":
                    return entry["newalias"]
            except Exception:
                if entry["alias"] != "":
                    return entry["alias"]
        if c == PORT and entry["hard"]:
            return ""
        try:
            return entry[self.newfield[c]]
        except Exception:
            try:
                return entry[self.field[c]]
            except Exception:
                print("No %s in entry:" % self.field[c])
                print(entry)
                return ""

    def _portkey(self, d, Ncol):
        v = self.value(d, Ncol)
        if v == "":
            return -1
        else:
            return int(v)

    def sort(self, Ncol, order):
        self.last_sort = (Ncol, order)
        self.layoutAboutToBeChanged.emit()
        if Ncol == PORT:
            self.cfglist = sorted(self.cfglist, key=lambda d: self._portkey(d, Ncol))
        else:
            self.cfglist = sorted(self.cfglist, key=lambda d: self.value(d, Ncol))
        if order == Qt.DescendingOrder:
            self.cfglist.reverse()
        self.layoutChanged.emit()

    def applyAddList(self, i, config, current, pfix, d, lst, verb):
        for ls in lst:
            if ls in list(config.keys()):
                try:
                    a = config[ls]["alias"]
                    if a == "":
                        a = config[ls]["id"]
                    else:
                        a += " (%s)" % config[ls]["id"]
                except Exception:
                    a = config[ls]["id"]
            else:
                a = current[ls]["rid"]
            check = QCheckBox(d)
            check.setChecked(False)
            #
            # We are presenting dead things as options to kill.
            # Make sure we can have something there!
            #
            try:
                h = current[ls][pfix + "host"]
            except Exception:
                h = config[ls]["host"]
            try:
                p = current[ls][pfix + "port"]
            except Exception:
                p = config[ls]["port"]
            check.setText("%s %s on %s:%d" % (verb, a, h, p))
            d.clayout.addWidget(check)
            i = i + 1
            d.checks.append(check)
        return i

    def setDialogState(self, d, v):
        for c in d.checks:
            c.setChecked(v)

    # This is called when we are acting as an eventFilter for a dialog from applyVerify.
    def eventFilter(self, o, e):
        if (
            self.dialog is not None
            and o == self.dialog.sw
            and e.type() == QEvent.Resize
        ):
            self.dialog.setMinimumWidth(
                self.dialog.sw.minimumSizeHint().width()
                + self.dialog.sa.verticalScrollBar().width()
            )
        return False

    def applyVerify(self, current, config, kill, start, restart):
        if kill == [] and start == [] and restart == []:
            QMessageBox.critical(
                None, "Warning", "Nothing to apply!", QMessageBox.Ok, QMessageBox.Ok
            )
            return ([], [], [])
        d = QDialog()
        self.dialog = d
        d.setWindowTitle("Apply Confirmation")
        d.layout = QVBoxLayout(d)
        d.mlabel = QLabel(d)
        d.mlabel.setText("Apply will take the following actions:")
        d.layout.addWidget(d.mlabel)

        # Create a scroll area with no frame and no horizontal scrollbar
        d.sa = QScrollArea(d)
        d.sa.setFrameStyle(QFrame.NoFrame)
        d.sa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        d.sa.setWidgetResizable(True)

        # Create a widget for the scroll area and limit its size.
        # Resize events for this widget will be sent to us.
        d.sw = QWidget(d.sa)
        d.sw.setMaximumHeight(5000)
        d.sw.installEventFilter(self)
        d.sa.setWidget(d.sw)

        # Create a layout for the widget in the scroll area.
        d.clayout = QVBoxLayout(d.sw)

        d.layout.addWidget(d.sa)

        d.checks = []
        kill_only = [k for k in kill if k not in start]
        kill_restart = [k for k in kill if k in start]
        start_only = [s for s in start if s not in kill]
        k = self.applyAddList(0, config, current, "r", d, kill_only, "KILL")
        k2 = self.applyAddList(
            k, config, current, "r", d, kill_restart, "KILL and RESTART"
        )
        s = self.applyAddList(k2, config, config, "", d, start_only, "START")
        r = self.applyAddList(s, config, current, "r", d, restart, "RESTART")

        d.buttonBox = QDialogButtonBox(d)
        d.buttonBox.setOrientation(Qt.Horizontal)
        d.buttonBox.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        clear_button = d.buttonBox.addButton("Clear All", QDialogButtonBox.ActionRole)
        set_button = d.buttonBox.addButton("Set All", QDialogButtonBox.ActionRole)
        d.layout.addWidget(d.buttonBox)
        d.buttonBox.accepted.connect(d.accept)
        d.buttonBox.rejected.connect(d.reject)
        clear_button.clicked.connect(lambda: self.setDialogState(d, False))
        set_button.clicked.connect(lambda: self.setDialogState(d, True))

        if d.exec_() == QDialog.Accepted:
            checks = [c.isChecked() for c in d.checks]
            kill_only = [kill_only[i] for i in range(len(kill_only)) if checks[i]]
            kill_restart = [
                kill_restart[i] for i in range(len(kill_restart)) if checks[k + i]
            ]
            start_only = [
                start_only[i] for i in range(len(start_only)) if checks[k2 + i]
            ]
            restart = [restart[i] for i in range(len(restart)) if checks[s + i]]
            kill = kill_only + kill_restart
            start = start_only + kill_restart
            r = (kill, start, restart)
        else:
            r = ([], [], [])
        d.sw.removeEventFilter(self)
        self.dialog = None
        return r

    def applyOne(self, index):
        id = self.cfglist[index.row()]["id"]
        if not self.validateConfig():
            QMessageBox.critical(
                None,
                "Error",
                "Configuration has errors, not applied!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return
        if self.doSave():
            apply_config(self.hutch, self.applyVerify, id)

    def doApply(self):
        if not self.validateConfig():
            QMessageBox.critical(
                None,
                "Error",
                "Configuration has errors, not applied!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return
        if self.doSave():
            apply_config(self.hutch, self.applyVerify)

    def doSave(self):
        if not self.validateConfig():
            QMessageBox.critical(
                None,
                "Error",
                "Configuration has errors, not saved!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return False
        # Do we want to check it in!?
        d = self.commit_dialog
        d.setWindowTitle("Commit %s" % self.hutch)
        d.ui.commentEdit.setPlainText("")
        while True:
            d.exec_()
            if d.result == QDialogButtonBox.Cancel:
                return False
            if d.result == QDialogButtonBox.No:
                comment = None
                break
            comment = str(d.ui.commentEdit.toPlainText())
            if comment != "":
                break
            QMessageBox.critical(
                None,
                "Error",
                "Must have a comment for commit for %s" % self.hutch,
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
        try:
            file = tempfile.NamedTemporaryFile(
                mode="w", dir=utils.TMP_DIR, delete=False
            )
            write_config(self.hutch, self.hosts, self.cfglist, self.vdict, file)
        except Exception as exc:
            logger.error(f"Error writing config: {exc}")
            logger.debug("Error writing config", exc_info=True)
            QMessageBox.critical(
                None,
                "Error",
                "Failed to write configuration for %s" % self.hutch,
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            try:
                os.unlink(file.name)  # Clean up!
            except Exception:
                pass
            return False
        for entry in self.cfglist:
            #
            # IOC names are special.  If we just reprocess the file, we will have both
            # the old *and* the new names!  So we have to change the names here.
            #
            try:
                entry["id"] = entry["newid"].strip()
                del entry["newid"]
            except Exception:
                pass
            try:
                del entry["details"]
            except Exception:
                pass
        if comment is not None:
            try:
                utils.commit_config(self.hutch, comment, self.userIO)
            except Exception as exc:
                logger.info(f"Error committing config file: {exc}")
                logger.debug("Error committing config file", exc_info=True)

        return True

    def doRevert(self):
        for entry in self.cfglist:
            for f in self.newfield:
                try:
                    if f is not None:
                        del entry[f]
                except Exception:
                    pass
        self.poll_thread.mtime = None  # Force a re-read!
        self.dataChanged.emit(
            self.index(0, 0), self.index(len(self.cfglist), len(self.headerdata) - 1)
        )

    def inConfig(self, index):
        entry = self.cfglist[index.row()]
        return entry["cfgstat"] != utils.CONFIG_DELETED

    def notSynched(self, index):
        entry = self.cfglist[index.row()]
        return (
            entry["dir"] != entry["rdir"]
            or entry["host"] != entry["rhost"]
            or entry["port"] != entry["rport"]
            or entry["id"] != entry["rid"]
        )

    def isChanged(self, index):
        entry = self.cfglist[index.row()]
        keys = list(entry.keys())
        try:
            if entry["cfgstat"] == utils.CONFIG_DELETED:
                return True
        except Exception:
            pass
        return (
            "newhost" in keys
            or "newport" in keys
            or "newdir" in keys
            or "newid" in keys
            or "newdisable" in keys
        )

    def isHard(self, index):
        entry = self.cfglist[index.row()]
        return entry["hard"]

    def needsApply(self, index):
        entry = self.cfglist[index.row()]
        try:
            if entry["disable"] != entry["newdisable"]:
                return True
        except Exception:
            pass
        if entry["disable"]:
            return entry["status"] == utils.STATUS_RUNNING
        else:
            if entry["status"] != utils.STATUS_RUNNING:
                return True
            try:
                if entry["newhost"] != entry["rhost"]:
                    return True
            except Exception:
                if entry["host"] != entry["rhost"]:
                    return True
            try:
                if entry["newport"] != entry["rport"]:
                    return True
            except Exception:
                if entry["port"] != entry["rport"]:
                    return True
            try:
                if entry["newdir"] != entry["rdir"]:
                    return True
            except Exception:
                if entry["dir"] != entry["rdir"]:
                    return True
            try:
                if entry["newid"] != entry["rid"]:
                    return True
            except Exception:
                if entry["id"] != entry["rid"]:
                    return True
            return False

    def revertIOC(self, index):
        entry = self.cfglist[index.row()]
        if entry["cfgstat"] == utils.CONFIG_DELETED:
            entry["cfgstat"] = utils.CONFIG_NORMAL
        for f in self.newfield:
            try:
                if f is not None:
                    del entry[f]
            except Exception:
                pass
        self.dataChanged.emit(
            self.index(index.row(), 0),
            self.index(index.row(), len(self.headerdata) - 1),
        )

    def deleteIOC(self, index):
        entry = self.cfglist[index.row()]
        entry["cfgstat"] = utils.CONFIG_DELETED
        if entry["status"] == utils.STATUS_RUNNING:
            self.dataChanged.emit(
                self.index(index.row(), 0),
                self.index(index.row(), len(self.headerdata) - 1),
            )
        else:
            self.cfglist = (
                self.cfglist[0 : index.row()] + self.cfglist[index.row() + 1 :]
            )
            self.sort(self.last_sort[0], self.last_sort[1])

    def setFromRunning(self, index):
        entry = self.cfglist[index.row()]
        for f in ["id", "dir", "host", "port"]:
            if entry[f] != entry["r" + f]:
                entry["new" + f] = entry["r" + f]
        entry["cfgstat"] = utils.CONFIG_ADDED
        self.dataChanged.emit(
            self.index(index.row(), 0),
            self.index(index.row(), len(self.headerdata) - 1),
        )

    def addExisting(self, index):
        entry = self.cfglist[index.row()]
        entry["cfgstat"] = utils.CONFIG_ADDED
        self.dataChanged.emit(
            self.index(index.row(), 0),
            self.index(index.row(), len(self.headerdata) - 1),
        )

    def editDetails(self, index):
        entry = self.cfglist[index.row()]
        try:
            details = entry["details"]
        except Exception:
            # Remember what was in the configuration file!
            details = ["", 0, ""]
            try:
                details[0] = entry["cmd"]
            except Exception:
                pass
            try:
                details[1] = entry["delay"]
            except Exception:
                pass
            try:
                details[2] = entry["flags"]
            except Exception:
                pass
            entry["details"] = details
        self.details_dialog.setWindowTitle("Edit Details - %s" % entry["id"])
        try:
            self.details_dialog.ui.aliasEdit.setText(entry["newalias"])
        except Exception:
            self.details_dialog.ui.aliasEdit.setText(entry["alias"])
        try:
            self.details_dialog.ui.cmdEdit.setText(entry["cmd"])
        except Exception:
            self.details_dialog.ui.cmdEdit.setText("")
        try:
            self.details_dialog.ui.delayEdit.setText(str(entry["delay"]))
        except Exception:
            self.details_dialog.ui.delayEdit.setText("")
        try:
            self.details_dialog.ui.flagCheckBox.setChecked("u" in entry["flags"])
        except Exception:
            self.details_dialog.ui.flagCheckBox.setChecked(False)
        if self.details_dialog.exec_() == QDialog.Accepted:
            if entry["hard"]:
                newcmd = ""
                newdelay = 0
                newflags = ""
            else:
                newcmd = str(self.details_dialog.ui.cmdEdit.text())
                if newcmd == "":
                    try:
                        del entry["cmd"]
                    except Exception:
                        pass
                else:
                    entry["cmd"] = newcmd

                if (
                    "cmd" in list(entry.keys())
                    and self.details_dialog.ui.flagCheckBox.isChecked()
                ):
                    newflags = "u"
                    entry["flags"] = "u"
                else:
                    newflags = ""
                    try:
                        del entry["flags"]
                    except Exception:
                        pass

                try:
                    newdelay = int(self.details_dialog.ui.delayEdit.text())
                except Exception:
                    newdelay = 0
                if newdelay == 0:
                    try:
                        del entry["delay"]
                    except Exception:
                        pass
                else:
                    entry["delay"] = newdelay

            alias = str(self.details_dialog.ui.aliasEdit.text())
            if alias != entry["alias"]:
                entry["newalias"] = alias
            else:
                try:
                    del entry["newalias"]
                except Exception:
                    pass

            if details != [newcmd, newdelay, newflags]:
                # We're changed, so flag this with a fake ID change!
                if "newid" not in list(entry.keys()):
                    entry["newid"] = entry["id"] + " "
            else:
                # We're not changed, so remove any fake ID change!
                if (
                    "newid" in list(entry.keys())
                    and entry["newid"] == entry["id"] + " "
                ):
                    del entry["newid"]

    def addIOC(self, id, alias, host, port, dir):
        if int(port) == -1:
            dir = get_hard_ioc_dir_for_display(id)
            host = id
            try:
                base = get_base_name(id)
            except Exception:
                base = ""
            cfg = {
                "id": id,
                "host": id,
                "port": -1,
                "dir": dir,
                "status": utils.STATUS_INIT,
                "base": base,
                "stattime": 0,
                "cfgstat": utils.CONFIG_ADDED,
                "disable": False,
                "history": [],
                "rid": id,
                "rhost": id,
                "rport": -1,
                "rdir": dir,
                "pdir": "",
                "newstyle": False,
                "alias": alias,
                "hard": True,
            }
        else:
            dir = normalize_path(dir, id)
            try:
                pname = get_parent(dir, id)
            except Exception:
                pname = ""
            cfg = {
                "id": id,
                "host": host,
                "port": int(port),
                "dir": dir,
                "status": utils.STATUS_INIT,
                "stattime": 0,
                "cfgstat": utils.CONFIG_ADDED,
                "disable": False,
                "history": [],
                "rid": id,
                "rhost": host,
                "rport": int(port),
                "rdir": dir,
                "pdir": pname,
                "newstyle": True,
                "alias": alias,
                "hard": False,
            }
        if host not in self.hosts:
            self.hosts.append(host)
            self.hosts.sort()
        self.cfglist.append(cfg)
        self.sort(self.last_sort[0], self.last_sort[1])

    # index is either an IOC name or an index!
    def connectIOC(self, index):
        if isinstance(index, QModelIndex):
            entry = self.cfglist[index.row()]
        else:
            entry = None
            for line in self.cfglist:
                if line["id"] == index:
                    entry = line
                    break
            if entry is not None:
                return
        #
        # Sigh.  Because we want to do authentication, we have a version of kerberos on
        # our path, but unfortunately it doesn't play nice with the library that telnet
        # uses!  Therefore, we have to get rid of LD_LIBRARY_PATH here.
        #
        try:
            if entry["hard"]:
                for line in netconfig(entry["id"])["console port dn"].split(","):
                    if line[:7] == "cn=port":
                        port = 2000 + int(line[7:])
                    if line[:7] == "cn=digi":
                        host = line[3:]
                    if line[:5] == "cn=ts":
                        host = line[3:]
            else:
                host = entry["host"]
                port = entry["port"]
            self.runCommand(
                None,
                entry["id"],
                "unsetenv LD_LIBRARY_PATH ; telnet %s %s" % (host, port),
            )
        except KeyError:
            logger.error(
                "Dict key error while setting up telnet interface for: %s", entry
            )
        except Exception:
            logger.error("Unspecified error while setting up telnet interface")
            logger.debug("Telnet setup error", exc_info=True)

    def viewlogIOC(self, index):
        if isinstance(index, QModelIndex):
            id = self.cfglist[index.row()]["id"]
        else:
            id = str(index)
        try:
            self.runCommand(
                "128x30",
                id,
                "tail -1000lf `ls -t " + (utils.LOGBASE % id) + "* |head -1`",
            )
        except Exception as exc:
            logger.error(f"Error while trying to view log file: {exc}")
            logger.debug("Error while trying to view log file", exc_info=True)

    # index is either an IOC name or an index!
    def rebootIOC(self, index):
        if isinstance(index, QModelIndex):
            entry = self.cfglist[index.row()]
        else:
            entry = None
            for line in self.cfglist:
                if line["id"] == index:
                    entry = line
                    break
            if entry is None:
                return
        if entry["hard"]:
            try:
                restart_hioc(entry["id"])
            except Exception:
                QMessageBox.critical(
                    None,
                    "Error",
                    "Failed to restart hard IOC %s!" % entry["id"],
                    QMessageBox.Ok,
                    QMessageBox.Ok,
                )
        else:
            if not restart_proc(entry["host"], entry["port"]):
                QMessageBox.critical(
                    None,
                    "Error",
                    "Failed to restart IOC %s!" % entry["id"],
                    QMessageBox.Ok,
                    QMessageBox.Ok,
                )

    def rebootServer(self, index):
        if isinstance(index, QModelIndex):
            entry = self.cfglist[index.row()]
        else:
            entry = None
            for line in self.cfglist:
                if line["id"] == index:
                    entry = line
                    break
            if entry is None:
                return
        if entry["hard"]:
            try:
                reboot_hioc(entry["id"])
            except Exception:
                QMessageBox.critical(
                    None,
                    "Error",
                    "Failed to reboot hard IOC %s!" % entry["id"],
                    QMessageBox.Ok,
                    QMessageBox.Ok,
                )
            return
        host = entry["host"]
        d = QDialog()
        d.setWindowTitle("Reboot Server " + host)
        d.layout = QVBoxLayout(d)
        ihost = host + "-ipmi"
        nc = netconfig(ihost)
        try:
            nc["name"]
        except Exception:
            label = QLabel(d)
            label.setText("Cannot find IPMI address for host %s!" % host)
            d.layout.addWidget(label)
            d.buttonBox = QDialogButtonBox(d)
            d.buttonBox.setOrientation(Qt.Horizontal)
            d.buttonBox.setStandardButtons(QDialogButtonBox.Ok)
            d.layout.addWidget(d.buttonBox)
            d.buttonBox.accepted.connect(d.accept)
            d.exec_()
            return
        llist = []
        label = QLabel(d)
        label.setText(
            "Rebooting " + host + " will temporarily stop the following IOCs:"
        )
        d.layout.addWidget(label)
        llist.append(label)
        for line in self.cfglist:
            if line["host"] == host:
                label = QLabel(d)
                if line["alias"] != "":
                    label.setText("        " + line["alias"] + " (" + line["id"] + ")")
                else:
                    label.setText("        " + line["id"])
                d.layout.addWidget(label)
                llist.append(label)
        label = QLabel(d)
        label.setText("Proceed?")
        d.layout.addWidget(label)
        llist.append(label)
        d.buttonBox = QDialogButtonBox(d)
        d.buttonBox.setOrientation(Qt.Horizontal)
        d.buttonBox.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        d.layout.addWidget(d.buttonBox)
        d.buttonBox.accepted.connect(d.accept)
        d.buttonBox.rejected.connect(d.reject)
        if d.exec_() == QDialog.Accepted:
            if not reboot_server(ihost):
                QMessageBox.critical(
                    None,
                    "Error",
                    "Failed to reboot host %s!" % ihost,
                    QMessageBox.Ok,
                    QMessageBox.Ok,
                )

    def cleanupChildren(self):
        for p in self.children:
            try:
                p.kill()
            except Exception:
                pass

    def doSaveVersions(self):
        for i in range(len(self.cfglist)):
            self.saveVersion(i)

    # index is either an integer or an index!
    def saveVersion(self, index):
        if isinstance(index, QModelIndex):
            entry = self.cfglist[index.row()]
        else:
            entry = self.cfglist[index]
        try:
            dir = entry[self.newfield[VERSION]]
        except Exception:
            dir = entry[self.field[VERSION]]
        try:
            h = entry["history"]
            if dir in h:
                h.remove(dir)
            h[:0] = [dir]
            if len(h) > 5:
                h = h[0:5]
        except Exception:
            h = [dir]
        entry["history"] = h

    #
    # Generate a history list.  In order:
    #    New configuration setting
    #    Current configuration setting
    #    Current running setting
    #    Others in the history list.
    #
    def history(self, row):
        entry = self.cfglist[row]
        x = [entry["dir"]]
        try:
            x[:0] = [entry["newdir"]]
        except Exception:
            pass
        try:
            i = entry["rdir"]
            if i not in x:
                x[len(x) :] = [i]
        except Exception:
            pass
        try:
            h = entry["history"]
            for i in h:
                if i not in x:
                    x[len(x) :] = [i]
        except Exception:
            pass
        return x

    def getID(self, row):
        return self.cfglist[row]["id"]

    def validateConfig(self):
        for i in range(len(self.cfglist)):
            h = self.value(self.cfglist[i], HOST)
            p = self.value(self.cfglist[i], PORT)
            for j in range(i + 1, len(self.cfglist)):
                h2 = self.value(self.cfglist[j], HOST)
                p2 = self.value(self.cfglist[j], PORT)
                if h == h2 and p == p2:
                    return False
        #
        # Anything else we want to check here?!?
        #
        return True

    def getVar(self, v):
        try:
            return self.vdict[v]
        except Exception:
            return None

    def findPV(self, name):
        line = []
        try:
            regexp = re.compile(name)
        except Exception:
            return "Bad regular expression!"
        for entry in self.cfglist:
            try:
                ll = find_pv(regexp, entry["id"])
            except Exception:
                continue
            for r in ll:
                if r == name:  # One exact match, forget the rest!
                    return [(r, entry["id"], entry["alias"])]
                else:
                    line.append((r, entry["id"], entry["alias"]))
        return line

    def selectPort(self, host, lowport, highport):
        for port in range(lowport, highport):
            hit = False
            for entry in self.cfglist:
                if self.value(entry, HOST) == host and self.value(entry, PORT) == port:
                    hit = True
                    break
            if not hit:
                return port
        return None


class StatusPollThread(threading.Thread):
    """
    A thread running a loop to continually check the status of configured IOCs.

    This updates data in the model that is used for the "Status" column.

    Parameters
    ----------
    model : IOCTableModel
        The model we need to update.
    config : Config
        The config object that represents the hutch's iocmanager config.
    interval : float
        How often to check the status in seconds.
    """

    def __init__(self, model: IOCTableModel, interval: float, config: Config):
        threading.Thread.__init__(self)
        self.model = model
        self.hutch = model.hutch
        self.mtime = None
        self.interval = interval
        self.rmtime = {}
        self.daemon = True
        self.dialog = None
        self.host_os = host_os

    def run(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            while True:
                start_time = time.monotonic()
                futures = []

                try:
                    config = read_config(self.hutch)
                except Exception:
                    ...
                else:
                    self.host_os = get_host_os(config.hosts)
                    self.rmtime = {}  # Force a re-read!
                    self.model.configuration(config)

                result = read_status_dir(self.hutch)
                for line in result:
                    futures.append(executor.submit(self.check_one_file_status, line))

                for line in self.model.cfglist:
                    futures.append(executor.submit(self.check_one_config_status, line))

                for p in self.model.children:
                    futures.append(executor.submit(self.poll_one_child, p))

                for fut in futures:
                    fut.result()
                duration = time.monotonic() - start_time
                if duration < self.interval:
                    time.sleep(self.interval + 1 - duration)

    def check_one_file_status(self, line):
        rdir = line["rdir"]
        line.update(check_status(line["rhost"], line["rport"], line["rid"]))
        line["stattime"] = time.time()
        if line["rdir"] == "/tmp":
            line["rdir"] = rdir
        else:
            line["newstyle"] = False
        self.model.running(line)

    def check_one_config_status(self, line):
        if line["stattime"] + self.interval > time.time():
            return
        if line["hard"]:
            s = {"pid": -1, "autorestart": False}
            try:
                pv = psp.Pv.Pv(line["base"] + ":HEARTBEAT")
                pv.connect(1.0)
                pv.disconnect()
                s["status"] = utils.STATUS_RUNNING
            except Exception:
                s["status"] = utils.STATUS_SHUTDOWN
            s["rid"] = line["id"]
            s["rdir"] = line["dir"]
        else:
            s = check_status(line["host"], line["port"], line["id"])
        s["stattime"] = time.time()
        s["rhost"] = line["host"]
        s["rport"] = line["port"]
        if line["newstyle"]:
            if s["rdir"] == "/tmp":
                del s["rdir"]
            else:
                s["newstyle"] = False  # We've switched from new to old?!?
        self.model.running(s)

    def poll_one_child(self, p):
        if p.poll() is not None:
            self.model.children.remove(p)
