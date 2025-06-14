"""
The gui module impelements the main window of the iocmanager GUI.
"""

import io
import logging
import os
import pty
import socket
import sys
import traceback
from enum import IntEnum

from qtpy.QtCore import QSortFilterProxyModel, Qt
from qtpy.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QMainWindow,
    QMessageBox,
)

from . import commit_ui, utils
from .commit import commit_config
from .config import check_auth, check_ssh, read_config, write_config
from .epics_paths import get_parent
from .imgr import ensure_auth, reboot_cmd
from .ioc_info import get_base_name
from .ioc_ui import Ui_MainWindow
from .procserv_tools import apply_config
from .server_tools import netconfig
from .table_delegate import IOCTableDelegate
from .table_model import IOCTableModel
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


def raise_to_operator(exc: Exception) -> QMessageBox:
    """
    Utility function to show an Exception to a user.

    Vendored from typhos/pydm, can unvendor if we add either
    as a dependency later.
    """
    logger.error("Reporting error %r to user ...", exc)
    err_msg = QMessageBox()
    err_msg.setText(f"{exc.__class__.__name__}: {exc}")
    err_msg.setWindowTitle(type(exc).__name__)
    err_msg.setIcon(QMessageBox.Critical)
    handle = io.StringIO()
    traceback.print_tb(exc.__traceback__, file=handle)
    handle.seek(0)
    err_msg.setDetailedText(handle.read())
    err_msg.exec_()
    return err_msg


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
        self.current_base = ""

        # Set up all the qt objects we'll need
        # Helpful title: which hutch and iocmanager version we're using
        self.setWindowTitle(f"{hutch.upper()} iocmanager {version_str}")
        # Re-usable dialogs
        self.commit_dialog = CommitDialog(hutch=hutch, parent=self)
        # Configuration menu
        self.ui.actionApply.triggered.connect(self.action_write_and_apply_config)
        self.ui.actionSave.triggered.connect(self.action_write_config)
        self.ui.actionRevert.triggered.connect(self.action_revert)
        # IOC Control menu
        self.ui.actionReboot.triggered.connect(self.action_soft_reboot)
        self.ui.actionHard_Reboot.triggered.connect(self.action_hard_reboot)
        self.ui.actionReboot_Server.triggered.connect(self.action_server_reboot)
        self.ui.actionLog.triggered.connect(self.doLog)
        self.ui.actionConsole.triggered.connect(self.doConsole)
        # Utilities menu
        self.ui.actionHelp.triggered.connect(self.doHelp)
        self.ui.actionRemember.triggered.connect(self.doSaveVersions)
        self.ui.actionAuth.triggered.connect(self.doAuthenticate)
        self.ui.actionQuit.triggered.connect(self.doQuit)
        # At the very bottom of the window
        self.ui.findpv.returnPressed.connect(self.doFindPV)
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
        self.ui.tableView.selectionModel().selectionChanged.connect(self.getSelection)
        self.ui.tableView.customContextMenuRequested.connect(self.showContextMenu)

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
        self._reboot(reboot_mode="soft")

    def action_hard_reboot(self):
        """
        Action when the user clicks "Hard IOC Reboot".

        This reboots the IOC via procServ telnet controls.
        """
        self._reboot(reboot_mode="hard")

    def _reboot(self, reboot_mode: str):
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
        ...

    def _sioc_server_reboot(self, host: str, ioc_names: list[str]):
        """
        Subfunction of action_server_reboot to reboot a soft ioc.

        This includes a special confirm dialog for the soft ioc.
        """
        ...

    def doHelp(self):
        d = QtWidgets.QDialog()
        d.setWindowTitle("IocManager Help")
        d.layout = QtWidgets.QVBoxLayout(d)
        d.label1 = QtWidgets.QLabel(d)
        d.label1.setText("Documentation for the IocManager can be found on confluence:")
        d.layout.addWidget(d.label1)
        d.label2 = QtWidgets.QLabel(d)
        d.label2.setText(
            "https://confluence.slac.stanford.edu/display/PCDS/IOC+Manager+User+Guide"
        )
        d.layout.addWidget(d.label2)
        d.buttonBox = QtWidgets.QDialogButtonBox(d)
        d.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        d.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        d.layout.addWidget(d.buttonBox)
        d.buttonBox.accepted.connect(d.accept)
        d.exec_()

    def doFindPV(self):
        d = QtWidgets.QDialog()
        d.setWindowTitle("Find PV: %s" % self.ui.findpv.text())
        d.layout = QtWidgets.QVBoxLayout(d)
        te = QtWidgets.QPlainTextEdit(d)
        te.setMinimumSize(QtCore.QSize(600, 200))
        font = QtGui.QFont()
        font.setFamily("Monospace")
        font.setPointSize(10)
        te.setFont(font)
        te.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByKeyboard | QtCore.Qt.TextSelectableByMouse
        )
        te.setMaximumBlockCount(500)
        te.setPlainText("")
        result = self.model.findPV(
            str(self.ui.findpv.text())
        )  # Return list of (pv, ioc, alias)
        if isinstance(result, list):
            for res in result:
                if res[2] != "":
                    te.appendPlainText("%s --> %s (%s)" % res)
                else:
                    te.appendPlainText("%s --> %s%s" % res)  # Since l[2] is empty!
            if len(result) == 1:
                sm = self.ui.tableView.selectionModel()
                idx = self.model.createIndex(self.model.findid(res[1]), 0)
                sm.select(idx, Qt.QItemSelectionModel.SelectCurrent)
                self.ui.tableView.scrollTo(idx, Qt.QAbstractItemView.PositionAtCenter)
            elif len(result) == 0:
                te.appendPlainText(
                    "Searching for '%s' produced no matches!\n" % self.ui.findpv.text()
                )
        else:
            te.appendPlainText(result)
        d.layout.addWidget(te)
        d.buttonBox = QtWidgets.QDialogButtonBox(d)
        d.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        d.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        d.layout.addWidget(d.buttonBox)
        d.buttonBox.accepted.connect(d.accept)
        d.exec_()

    def doQuit(self):
        self.close()

    def doLog(self):
        if self.current_ioc:
            self.model.viewlogIOC(self.current_ioc)

    def doConsole(self):
        if self.current_ioc and (
            self.model.getVar("allow_console") or self.authorize_action(False)
        ):
            self.model.connectIOC(self.current_ioc)

    def dopv(self, name, gui, format):
        pv = Pv(name, initialize=True)
        if pv is not None:
            gui.setText("")
            pv.gui = gui
            pv.format = format
            self.pvlist.append(pv)
            pv.add_monitor_callback(lambda e: self.displayPV(pv, e))
            try:
                pv.wait_ready(0.5)
                pv.monitor()
            except Exception:
                logger.debug(f"Error setting up {pv} in dopv", exc_info=True)

    def getSelection(self, selected, deselected):
        try:
            row = selected.indexes()[0].row()
            ioc = self.model.data(
                self.model.index(row, table_model.IOCNAME), QtCore.Qt.EditRole
            ).value()
            host = self.model.data(
                self.model.index(row, table_model.HOST), QtCore.Qt.EditRole
            ).value()
            if ioc == self.current_ioc:
                return
            self.disconnectPVs()
            self.current_ioc = ioc
            self.ui.IOCname.setText(ioc)
            try:
                base = get_base_name(ioc)
            except Exception:
                self.current_base = None
            else:
                self.current_base = base
                self.dopv(base + ":HEARTBEAT", self.ui.heartbeat, "%d")
                self.dopv(base + ":TOD", self.ui.tod, "%s")
                self.dopv(base + ":STARTTOD", self.ui.boottime, "%s")
                pyca.flush_io()
            d = netconfig(host)
            try:
                self.ui.location.setText(d["location"])
            except Exception:
                self.ui.location.setText("")
            try:
                self.ui.description.setText(d["description"])
            except Exception:
                self.ui.description.setText("")
        except Exception:
            pass

    def showContextMenu(self, pos):
        index = self.ui.tableView.indexAt(pos)
        menu = QtWidgets.QMenu()
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

    def authenticate_user(self, user):
        if user == "":
            user = self.myuid
        need_su = self.myuid != user
        if not check_ssh(user, self.hutch):
            if self.model.userIO is not None:
                try:
                    os.close(self.model.userIO)
                except Exception:
                    logger.debug(
                        f"Error closing {self.model.userIO} in authenticate_user",
                        exc_info=True,
                    )
            self.model.userIO = None
            self.ui.userLabel.setText("User: " + self.myuid)
            self.model.user = self.myuid
            return self.myuid == user
        #
        # Try to use su to become the user.  If this fails, one of the
        # I/O operations below will raise an exception, because the su
        # will exit.
        #
        (pid, fd) = pty.fork()
        if pid == 0:
            try:
                if need_su:
                    if utils.COMMITHOST == socket.gethostname().split(".")[0]:
                        os.execv("/usr/bin/su", ["su", user, "-c", "/bin/tcsh -if"])
                    else:
                        os.execv(
                            "/usr/bin/ssh",
                            ["ssh", user + "@" + utils.COMMITHOST, "/bin/tcsh", "-if"],
                        )
                else:
                    if utils.COMMITHOST == socket.gethostname().split(".")[0]:
                        os.execv("/bin/tcsh", ["tcsh", "-if"])
                    else:
                        os.execv(
                            "/usr/bin/ssh",
                            ["ssh", utils.COMMITHOST, "/bin/tcsh", "-if"],
                        )
            except Exception:
                pass
            print("Say what?  execv failed?")
            sys.exit(0)
        tty_text = utils.read_until(
            fd, "(assphrase for key '[a-zA-Z0-9._/]*':|assword:|> )"
        ).group(1)
        password = None
        if tty_text[:5] == "assph":
            passphrase = self.getAuthField("Key for '%s':" % tty_text[19:-2], True)
            if passphrase is None:
                return
            os.write(fd, passphrase + "\n")
            #
            # We have entered a passphrase for an ssh key.  Maybe it was wrong,
            # maybe it was empty (and now we're being asked for a password) or
            # maybe it worked.
            #
            tty_text = utils.read_until(fd, "(> |assword:|assphrase)").group(1)
            if tty_text == "assphrase":
                raise Exception("Passphrase not accepted")  # Life is cruel.
        if tty_text == "assword:":
            password = self.getAuthField("Password:", True)
            if password is None:
                return
            os.write(fd, password + "\n")
            #
            # I don't *think* we can get a passphrase prompt.  But let's not
            # hang around here if we do...
            #
            tty_text = utils.read_until(fd, "(> |assword:|assphrase)").group(1)
            if tty_text != "> ":
                raise Exception("Password not accepted")
        #
        # Sigh.  Someone once had a file named time.py in their home
        # directory.  So let's go somewhere where we know the files.
        #
        os.write(fd, ("cd %s\n" % utils.TMP_DIR).encode("utf-8"))
        tty_text = utils.read_until(fd, "> ")
        self.model.user = user
        if self.model.userIO is not None:
            try:
                os.close(self.model.userIO)
            except Exception:
                logger.debug(
                    f"Error closing {self.model.userIO} in authenticate_user",
                    exc_info=True,
                )
        self.model.userIO = fd
        if need_su:
            self.utimer.start(10 * 60000)  # Let's go for 10 minutes.
        self.ui.userLabel.setText("User: " + user)

    def getAuthField(self, prompt, password):
        self.auth_dialog.ui.label.setText(prompt)
        self.auth_dialog.ui.nameEdit.setText("")
        self.auth_dialog.ui.nameEdit.setEchoMode(
            QtWidgets.QLineEdit.Password if password else QtWidgets.QLineEdit.Normal
        )
        result = self.auth_dialog.exec_()
        if result == QtWidgets.QDialog.Accepted:
            return self.auth_dialog.ui.nameEdit.text()
        else:
            return None

    def doAuthenticate(self):
        user = self.getAuthField("User:", False)
        if user is not None:
            try:
                self.authenticate_user(user)
            except Exception:
                logger.info("Authentication as %s failed!", user)
                logger.debug("", exc_info=True)
                self.unauthenticate()

    def unauthenticate(self):
        self.utimer.stop()
        try:
            self.authenticate_user(self.myuid)
        except Exception:
            logger.error("Authentication as self failed?!?")
            logger.debug("", exc_info=True)

    def authorize_action(self, file_action):
        # The user might be OK.
        if check_auth(self.model.user, self.hutch) and (
            not file_action or check_ssh(self.model.user, self.hutch) == file_action
        ):
            return True
        # If the user isn't OK, give him or her a chance to authenticate.
        if self.model.user == self.myuid:
            self.doAuthenticate()
        if check_auth(self.model.user, self.hutch) and (
            not file_action or check_ssh(self.model.user, self.hutch) == file_action
        ):
            return True
        QtWidgets.QMessageBox.critical(
            None,
            "Error",
            "Action not authorized for user %s" % self.model.user,
            QtWidgets.QMessageBox.Ok,
            QtWidgets.QMessageBox.Ok,
        )
        return False
