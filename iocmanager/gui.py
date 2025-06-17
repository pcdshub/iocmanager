"""
The gui module impelements the main window of the iocmanager GUI.
"""

import logging
import os
import re
from enum import IntEnum

from pydm.exception import raise_to_operator
from qtpy.QtCore import (
    QItemSelection,
    QItemSelectionModel,
    QPoint,
    QSortFilterProxyModel,
    Qt,
    pyqtSignal,
)
from qtpy.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTableView,
)

from . import commit_ui, find_pv_ui, utils
from .commit import commit_config
from .config import read_config, write_config
from .env_paths import env_paths
from .epics_paths import get_parent
from .hioc_tools import reboot_hioc
from .imgr import ensure_auth, reboot_cmd
from .ioc_info import find_pv, get_base_name
from .ioc_ui import Ui_MainWindow
from .procserv_tools import apply_config
from .server_tools import netconfig, reboot_server
from .table_delegate import IOCTableDelegate
from .table_model import IOCTableModel, TableColumn
from .terminal import run_in_floating_terminal
from .type_hints import ParentWidget
from .version import version as version_str

logger = logging.getLogger(__name__)


class CommitOption(IntEnum):
    """
    Integer codes for the three results from the CommitDialog.
    """

    SAVE_AND_COMMIT = 0
    SAVE_ONLY = 1
    CANCEL = 2


class CommitDialog(QDialog):
    """
    Load the pyuic-compiled ui/commit.ui into a QDialog.

    This dialog contains a large QTextEdit that can be used to enter a
    commit message.
    It is opened right after a user asks to apply the configuration,
    and right before we save the file.
    """

    def __init__(self, hutch: str, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = commit_ui.Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle(f"Commit {hutch}")
        self.setResult(CommitOption.CANCEL)
        self.ui.buttonBox.button(QDialogButtonBox.Yes).clicked.connect(self.yes_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.No).clicked.connect(self.no_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(
            self.cancel_clicked
        )

    def get_comment(self) -> str:
        return self.ui.commentEdit.toPlainText()

    def reset(self):
        self.ui.commentEdit.setPlainText("")

    def yes_clicked(self):
        self.setResult(CommitOption.SAVE_AND_COMMIT)

    def no_clicked(self):
        self.setResult(CommitOption.SAVE_ONLY)

    def cancel_clicked(self):
        # Technically this is always already set, but it's good to be paranoid
        self.setResult(CommitOption.CANCEL)


class FindPVDialog(QDialog):
    """
    Load the pyuic-compiled ui/find_pv.ui into a QDialog.

    This dialog contains space to place to results from a find_pv operation.
    """

    process_next = pyqtSignal(int)

    def __init__(
        self, model: IOCTableModel, view: QTableView, parent: ParentWidget = None
    ):
        super().__init__(parent)
        self.ui = find_pv_ui.Ui_Dialog()
        self.ui.setupUi(self)
        self.model = model
        self.view = view
        self.config = model.config
        self.ioc_names = []
        self.regex_text = ""
        self.regexp = re.compile("")
        self.last_ioc_found = ""
        self.found_count = 0
        self.process_next.connect(self._process_next_ioc)

    def find_pv_and_exec(self, regex_text: str):
        """
        Call this with the user's input to get a result and show it to the user.

        The dialog should open, then find with all the PVs in the config that match
        the regular expression, then stay open until the user closes it.
        """
        self.setWindowTitle(f"Find PV: {regex_text}")
        self.ui.progress_label.setText("Initializing find_pv...")
        self.ui.found_pvs.setPlainText("")
        self.show()
        self.config = self.model.get_next_config()
        self.ioc_names = list(self.config.procs)
        self.regex_text = regex_text
        self.regexp = re.compile(regex_text)
        self.last_ioc_found = ""
        self.found_count = 0
        self.process_next.emit(0)
        self.exec_()

    def _process_next_ioc(self, index: int):
        """Process IOCs one at a time to get an updating display."""
        try:
            ioc_name = self.ioc_names[index]
        except IndexError:
            self._finish_find_pv()
            return
        self.ui.progress_label.setText(
            f"Checking IOC {index + 1}/{len(self.ioc_names)} ({ioc_name})"
        )
        results = []
        try:
            results = find_pv(regexp=self.regexp, ioc=ioc_name)
        except Exception:
            ...
        ioc_proc = self.config.procs[ioc_name]
        for res in results:
            if ioc_proc.alias:
                text = f"{res} --> {ioc_name} ({ioc_proc.alias})"
            else:
                text = f"{res} --> {ioc_name}"
            self.ui.found_pvs.appendPlainText(text)
        if results:
            self.last_ioc_found = ioc_name
            self.found_count += len(results)
        self.process_next.emit(index + 1)

    def _finish_find_pv(self):
        """Clean up and finalize at the end of find_pv"""
        self.ui.progress_label.setText("Find PV Results:")
        if self.found_count == 0:
            self.ui.found_pvs.setPlainText(
                f"Searching for '{self.regex_text}' produced no matches."
            )
        elif self.found_count == 1:
            # We can jump to the IOC with that PV
            selection_model = self.view.selectionModel()
            idx = self.model.index(
                self.model.get_ioc_row_map().index(self.last_ioc_found), 0
            )
            selection_model.select(idx, QItemSelectionModel.SelectCurrent)
            self.view.scrollTo(idx, QAbstractItemView.PositionAtCenter)


class IOCMainWindow(QMainWindow):
    """
    The main window of the iocmanager gui.

    This contains a view of the table model and has utilities
    for e.g. saving and comitting configs.

    It loads from the pyuic-compiled ui/ioc.ui file.
    """

    def __init__(self, hutch: str):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # Not sure how to do this in designer, so we put it randomly and move it now.
        self.ui.statusbar.addWidget(self.ui.userLabel)

        # Data interfaces
        self.hutch = hutch
        config = read_config(hutch)
        self.model = IOCTableModel(config=config, hutch=hutch)
        self.sort_model = QSortFilterProxyModel()
        self.sort_model.setSourceModel(self.model)
        self.delegate = IOCTableDelegate(hutch=hutch, model=self.model)

        # User state
        self.current_ioc = ""

        # Set up all the qt objects we'll need
        # Helpful title: which hutch and iocmanager version we're using
        self.setWindowTitle(f"{hutch.upper()} iocmanager {version_str}")
        # Re-usable dialogs
        self.commit_dialog = CommitDialog(hutch=hutch, parent=self)
        self.find_pv_dialog = FindPVDialog(
            model=self.model, view=self.ui.tableView, parent=self
        )
        # Configuration menu
        self.ui.actionApply.triggered.connect(self.action_write_and_apply_config)
        self.ui.actionSave.triggered.connect(self.action_write_config)
        self.ui.actionRevert.triggered.connect(self.action_revert)
        # IOC Control menu
        self.ui.actionReboot.triggered.connect(self.action_soft_reboot)
        self.ui.actionHard_Reboot.triggered.connect(self.action_hard_reboot)
        self.ui.actionReboot_Server.triggered.connect(self.action_server_reboot)
        self.ui.actionLog.triggered.connect(self.action_view_log)
        self.ui.actionConsole.triggered.connect(self.action_show_console)
        # Utilities menu
        self.ui.actionHelp.triggered.connect(self.action_help)
        self.ui.actionRemember.triggered.connect(self.action_remember_versions)
        self.ui.actionQuit.triggered.connect(self.action_quit)
        # At the very bottom of the window
        self.ui.findpv.returnPressed.connect(self.on_find_pv)
        # Set up the table view properly
        self.ui.tableView.setModel(self.sort_model)
        self.ui.tableView.setItemDelegate(self.delegate)
        self.ui.tableView.verticalHeader().setVisible(False)
        self.ui.tableView.horizontalHeader().setStretchLastSection(True)
        self.ui.tableView.resizeColumnsToContents()
        self.ui.tableView.resizeRowsToContents()
        self.ui.tableView.setSortingEnabled(True)
        self.ui.tableView.sortByColumn(0, Qt.AscendingOrder)
        self.ui.tableView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tableView.setSelectionMode(QAbstractItemView.SingleSelection)
        self.ui.tableView.selectionModel().selectionChanged.connect(
            self.on_table_select
        )
        self.ui.tableView.customContextMenuRequested.connect(self.show_context_menu)

        # Ready to go! Start checking ioc status!
        self.model.start_poll_thread()

    def action_write_and_apply_config(self):
        """
        Action when the user clicks "Apply".

        Runs through the same steps as action_write_config,
        and then starts, stops, restarts IOCs as needed to make the new
        configuration reality.
        """
        try:
            if not self.action_write_config():
                return
            apply_config(cfg=self.hutch)
        except Exception as exc:
            raise_to_operator(exc)

    def action_write_config(self) -> bool:
        """
        Action when the user clicks "Save".

        Checks auth, then prompts the user with a save/commit dialog.

        Returns True if the save was successfull and False otherwise, e.g.
        if the user cancelled the save or if something went wrong.
        """
        try:
            ensure_auth(hutch=self.hutch, ioc_name="", special_ok=False)
            self.commit_dialog.reset()
            comment = ""
            while not comment:
                self.commit_dialog.exec_()
                match self.commit_dialog.result():
                    case CommitOption.SAVE_AND_COMMIT:
                        comment = self.commit_dialog.get_comment()
                    case CommitOption.SAVE_ONLY:
                        break
                    case CommitOption.CANCEL:
                        return False
                    case other:
                        raise RuntimeError(f"Invalid commit option {other}")
                if not comment:
                    QMessageBox.critical(
                        None,
                        "Error",
                        "Must have a comment to commit",
                        QMessageBox.Ok,
                        QMessageBox.Ok,
                    )
            write_config(cfgname=self.hutch, config=self.model.get_next_config())
            self.model.reset_edits(needs_refresh=False)
            if comment:
                commit_config(hutch=self.hutch, comment=comment)
            return True
        except Exception as exc:
            raise_to_operator(exc)
            return False

    def action_revert(self):
        """
        Action when the user clicks "Revert".

        Unconditionally discards all pending edits.
        """
        self.model.reset_edits(needs_refresh=True)

    def action_soft_reboot(self):
        """
        Action when the user clicks "Soft IOC Reboot".

        This reboots the IOC via using the SYSRESET PV.
        """
        self._ioc_process_reboot(reboot_mode="soft")

    def action_hard_reboot(self):
        """
        Action when the user clicks "Hard IOC Reboot".

        This reboots the IOC via procServ telnet controls.
        """
        self._ioc_process_reboot(reboot_mode="hard")

    def _ioc_process_reboot(self, reboot_mode: str):
        """
        Shared functionality between soft and hard reboot actions.

        Imports the implementation from imgr.
        """
        if not self._check_selected():
            return
        try:
            reboot_cmd(
                config=self.model.get_next_config(),
                ioc_name=self.current_ioc,
                reboot_mode=reboot_mode,
            )
        except Exception as exc:
            raise_to_operator(exc)

    def _check_selected(self) -> bool:
        """
        Shared check and message box when no IOC has been selected yet.

        Some actions need a specific IOC to be selected in order to run.

        Shows a warning and returns False if no IOC is selected.
        """
        if self.current_ioc is None:
            QMessageBox.warning(
                None,
                "Error",
                "No IOC selected to reboot.",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return False
        return True

    def action_server_reboot(self):
        """
        Action when the user clicks "Reboot Server".

        For SIOCs, this uses ipmi to turn power off, then back on again.
        For HIOCs, this finds a PDU in netconfig to turn off and back on.
        This action requires full authorization and confirmation.
        """
        if not self._check_selected():
            return
        try:
            ensure_auth(hutch=self.hutch, ioc_name="", special_ok=False)
            # Need to figure out which IOCs are on this host
            config = self.model.get_next_config()
            this_proc = config.procs[self.current_ioc]
            if this_proc.hard:
                self._hioc_server_reboot(host=this_proc.host)
            else:
                all_names = []
                for ioc_name, ioc_proc in config.procs.items():
                    if ioc_proc.host == this_proc.host:
                        all_names.append(ioc_name)
                self._sioc_server_reboot(host=this_proc.host, ioc_names=all_names)
        except Exception as exc:
            raise_to_operator(exc)

    def _hioc_server_reboot(self, host: str):
        """
        Subfunction of action_server_reboot to reboot a hard ioc.

        This includes a special confirm dialog for the hard ioc.
        """
        user_choice = QMessageBox.question(
            None,
            f"Reboot Hard IOC {host}",
            f"Confirm: reboot hard IOC {host}?",
            QMessageBox.Cancel | QMessageBox.Ok,
            QMessageBox.Cancel,
        )
        if user_choice != QMessageBox.Ok:
            return
        reboot_hioc(host=host)

    def _sioc_server_reboot(self, host: str, ioc_names: list[str]):
        """
        Subfunction of action_server_reboot to reboot a soft ioc.

        This includes a special confirm dialog for the soft ioc.
        """
        msg = f"Confirm: reboot ioc server {host}?"
        if ioc_names:
            msg += f"Rebooting {host} will temporarily stop the following IOCs:"
            for name in ioc_names:
                ioc_proc = self.model.get_next_config().procs[name]
                if ioc_proc.alias:
                    msg += f"\n- {ioc_proc.alias} ({name})"
                else:
                    msg += f"\n- {name}"
        else:
            msg += f" There are no IOCs running on {host}."
        user_choice = QMessageBox.question(
            None,
            f"Reboot IOC Server {host}",
            msg,
            QMessageBox.Cancel | QMessageBox.Ok,
            QMessageBox.Cancel,
        )
        if user_choice != QMessageBox.Ok:
            return
        if not reboot_server(host=host):
            QMessageBox.critical(
                None,
                "Error",
                f"Failed to reboot host {host}!",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )

    def action_view_log(self):
        """
        Action when the user clicks "Show Log".

        This opens a floating terminal that tails the IOC's logfile.
        """
        if not self._check_selected():
            return
        try:
            run_in_floating_terminal(
                title=f"{self.current_ioc} logfile",
                cmd=f"tail -1000lf {env_paths.LOGBASE % self.current_ioc}",
            )
        except Exception as exc:
            raise_to_operator(exc)

    def action_show_console(self):
        """
        Action when the user clicks "Show Console".

        This opens a floating terminal that telnets to the IOC's host and port.
        """
        if not self._check_selected():
            return
        try:
            ioc_proc = self.model.get_next_config().procs[self.current_ioc]
            run_in_floating_terminal(
                title=f"{self.current_ioc} telnet session",
                cmd=f"telnet {ioc_proc.host} {ioc_proc.port}",
            )
        except Exception as exc:
            raise_to_operator(exc)

    def action_help(self):
        """
        Action when the user clicks "Help".

        This opens a small dialog with a link to the confluence page.
        """
        QMessageBox.information(
            None,
            "IOC Manager Help",
            (
                "Documentation for the iocmanager can be found on confluence:\n"
                "https://confluence.slac.stanford.edu/x/WYCPCg"
            ),
            QMessageBox.Ok,
            QMessageBox.Ok,
        )

    def action_remember_versions(self):
        """
        Action when the user clicks "Remember Versions"

        For every IOC in the configuration, add the current version to the history.
        """
        try:
            self.model.save_all_versions()
        except Exception as exc:
            raise_to_operator(exc)

    def action_quit(self):
        """
        Action when the user clicks "Quit"
        """
        self.close()

    def on_find_pv(self):
        """
        Callback when the user types a regex into the "Find PV" field and presses enter.

        This searches through all IOCs in the config for PV names that match the regex.
        """
        try:
            self.find_pv_dialog.find_pv_and_exec(self.ui.findpv.text())
        except Exception as exc:
            raise_to_operator(exc)

    def on_table_select(self, selected: QItemSelection, deselected: QItemSelection):
        """
        Callback when the user selects any cell in the gsrid.

        We need to update the widget displays and instance variables to reflect which
        IOC we've selected.
        """
        try:
            row = selected.indexes()[0].row()
            ioc_name = self.model.data(self.model.index(row, TableColumn.IOCNAME))
            host = self.model.data(self.model.index(row, TableColumn.HOST))
            if ioc_name == self.current_ioc:
                return
            self.current_ioc = ioc_name
            self.ui.IOCname.setText(ioc_name)
            try:
                base = get_base_name(ioc=ioc_name)
            except Exception:
                self.ui.heartbeat.set_channel("")
                self.ui.tod.set_channel("")
                self.ui.boottime.set_channel("")
            else:
                self.ui.heartbeat.set_channel(f"ca://{base}:HEARTBEAT")
                self.ui.tod.set_channel(f"ca://{base}:TOD")
                self.ui.boottime.set_channel(f"ca://{base}:STARTTOD")
            try:
                host_info = netconfig(host)
            except Exception:
                host_info = {}
            try:
                self.ui.location.setText(host_info["location"])
            except KeyError:
                self.ui.location.setText("")
            try:
                self.ui.description.setText(host_info["description"])
            except KeyError:
                self.ui.description.setText("")
        except Exception as exc:
            raise_to_operator(exc)

    def show_context_menu(self, pos: QPoint):
        """
        When the user right-clicks the table, generate a proper menu.

        This has the following features:
        - Add New IOC
          - Opens a dialog to add a new IOC to the config
        - Delete IOC
          - Schedule this right-clicked row for deletion
          - Only appears if we right-clicked on a row
        - Add Running to Config
          - Add this untracked row to the config
          - Only appears if we right-clicked on a row
          - Only appears if the row isn't in the config (but is live)
          - Invalid for HIOCs
        - Set from Running
          - Update the config to have the parameters of the running IOC
          - Only appears if we right-clicked on a row
          - Only appears if the row's live status doesn't match the config
          - Invalid for HIOCs
        - Apply Configuration
          - Save the config with all of our pending changes
          - Apply the config to reality for the right-clicked IOC
          - Only appears if we right-clicked a row with changes to apply
          - Invalid for HIOCs
        - Remember Version
          - Add the IOC's current version to the history, if not present
          - Only appears if we right-clicked on a row
          - Invalid for HIOCs
        - Revert IOC
          - Undo all pending changes for an IOC row
          - Only appears if we right-clicked on a row with pending changes
        - Edit Details
          - Opens up a dialog for editing some of the items not in the table.
          - Only appears if we right-clicked on a row
        """
        index = self.ui.tableView.indexAt(pos)
        menu = QMenu()
        menu.addAction("Add New IOC")
        if index.row() != -1:
            menu.addAction("Delete IOC")
            if not self.model.isHard(index):
                if not self.model.inConfig(index):
                    menu.addAction("Add Running to Config")
                if self.model.notSynched(index):
                    menu.addAction("Set from Running")
                if self.model.needsApply(index):
                    menu.addAction("Apply Configuration")
                menu.addAction("Remember Version")
            if self.model.isChanged(index):
                menu.addAction("Revert IOC")
            menu.addAction("Edit Details")
        gpos = self.ui.tableView.viewport().mapToGlobal(pos)
        selectedItem = menu.exec_(gpos)
        if selectedItem is not None:
            txt = selectedItem.text()
            if txt == "Revert IOC":
                self.model.revertIOC(index)
            elif txt == "Delete IOC":
                self.model.deleteIOC(index)
            elif txt == "Add New IOC":
                self.addIOC(index)
            elif txt == "Set from Running":
                self.model.setFromRunning(index)
            elif txt == "Add Running to Config":
                self.model.addExisting(index)
            elif txt == "Remember Version":
                self.model.saveVersion(index)
            elif txt == "Edit Details":
                self.model.editDetails(index)
            elif txt == "Apply Configuration":
                self.model.applyOne(index)

    def setParent(self, gui, iocfn, dir):
        if dir != "":
            try:
                pname = get_parent(dir, iocfn())
            except Exception:
                pname = ""
            gui.setText(pname)

    def selectPort(self, hostgui, portgui, lowport, highport):
        host = hostgui.text()
        if host == "":
            QtWidgets.QMessageBox.critical(
                None,
                "Error",
                "Need to select a host before automatic port selection!",
                QtWidgets.QMessageBox.Ok,
                QtWidgets.QMessageBox.Ok,
            )
            return
        port = self.model.selectPort(host, lowport, highport)
        if port is None:
            QtWidgets.QMessageBox.critical(
                None,
                "Error",
                "No port available in range!",
                QtWidgets.QMessageBox.Ok,
                QtWidgets.QMessageBox.Ok,
            )
            return
        portgui.setText(str(port))

    def addIOC(self, index):
        d = QtWidgets.QFileDialog(
            self, "Add New IOC", utils.EPICS_SITE_TOP + "ioc/" + self.hutch
        )
        d.setFileMode(Qt.QFileDialog.Directory)
        d.setOptions(Qt.QFileDialog.ShowDirsOnly | Qt.QFileDialog.DontUseNativeDialog)
        d.setSidebarUrls(
            [
                QtCore.QUrl("file://" + os.getenv("HOME")),
                QtCore.QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/" + self.hutch),
                QtCore.QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/common"),
                QtCore.QUrl("file://" + utils.EPICS_DEV_TOP),
            ]
        )
        dialog_layout = d.layout()

        tmp = QtWidgets.QLabel()
        tmp.setText("IOC Name *+")
        dialog_layout.addWidget(tmp, 4, 0)
        namegui = QtWidgets.QLineEdit()
        dialog_layout.addWidget(namegui, 4, 1)

        tmp = QtWidgets.QLabel()
        tmp.setText("Alias")
        dialog_layout.addWidget(tmp, 5, 0)
        aliasgui = QtWidgets.QLineEdit()
        dialog_layout.addWidget(aliasgui, 5, 1)

        tmp = QtWidgets.QLabel()
        tmp.setText("Host *")
        dialog_layout.addWidget(tmp, 6, 0)
        hostgui = QtWidgets.QLineEdit()
        dialog_layout.addWidget(hostgui, 6, 1)

        tmp = QtWidgets.QLabel()
        tmp.setText("Port (-1 = HARD IOC) *+")
        dialog_layout.addWidget(tmp, 7, 0)
        layout = QtWidgets.QHBoxLayout()
        portgui = QtWidgets.QLineEdit()
        layout.addWidget(portgui)
        autoClosed = QtWidgets.QPushButton()
        autoClosed.setText("Select CLOSED")
        autoClosed.clicked.connect(
            lambda: self.selectPort(hostgui, portgui, 30001, 39000)
        )
        layout.addWidget(autoClosed)
        autoOpen = QtWidgets.QPushButton()
        autoOpen.setText("Select OPEN")
        autoOpen.clicked.connect(
            lambda: self.selectPort(hostgui, portgui, 39100, 39200)
        )
        layout.addWidget(autoOpen)
        dialog_layout.addLayout(layout, 7, 1)

        tmp = QtWidgets.QLabel()
        tmp.setText("Parent")
        dialog_layout.addWidget(tmp, 8, 0)
        parentgui = QtWidgets.QLineEdit()
        parentgui.setReadOnly(True)
        dialog_layout.addWidget(parentgui, 8, 1)

        tmp = QtWidgets.QLabel()
        tmp.setText("* = Required Fields for Soft IOCs.")
        dialog_layout.addWidget(tmp, 9, 0)

        tmp = QtWidgets.QLabel()
        tmp.setText("+ = Required Fields for Hard IOCs.")
        dialog_layout.addWidget(tmp, 10, 0)

        def fn(dir):
            self.setParent(parentgui, namegui.text, dir)

        d.directoryEntered.connect(fn)
        d.currentChanged.connect(fn)

        while True:
            if d.exec_() == Qt.QDialog.Rejected:
                return
            name = str(namegui.text()).strip()
            alias = str(aliasgui.text()).strip()
            host = str(hostgui.text()).strip()
            port = str(portgui.text()).strip()
            try:
                dir = str(d.selectedFiles()[0]).strip()
            except Exception:
                dir = ""
            try:
                n = int(port)
            except Exception:
                QtWidgets.QMessageBox.critical(
                    None,
                    "Error",
                    "Port is not an integer!",
                    QtWidgets.QMessageBox.Ok,
                    QtWidgets.QMessageBox.Ok,
                )
                continue
            if name == "" or (n != -1 and (host == "" or port == "" or dir == "")):
                QtWidgets.QMessageBox.critical(
                    None,
                    "Error",
                    "Failed to set required parameters for new IOC!",
                    QtWidgets.QMessageBox.Ok,
                    QtWidgets.QMessageBox.Ok,
                )
                continue
            if self.model.findid(name) is not None:
                QtWidgets.QMessageBox.critical(
                    None,
                    "Error",
                    "IOC %s already exists!" % name,
                    QtWidgets.QMessageBox.Ok,
                    QtWidgets.QMessageBox.Ok,
                )
                continue
            self.model.addIOC(name, alias, host, port, dir)
            return
