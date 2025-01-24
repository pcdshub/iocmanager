import logging
import os
import pty
import pwd
import socket
import sys

import pyca
from psp.Pv import Pv
from qtpy import QtCore, QtGui, QtWidgets
from qtpy.QtCore import Qt

from . import auth_ui, my_model, utils
from .ioc_ui import Ui_MainWindow
from .my_delegate import MyDelegate

logger = logging.getLogger(__name__)


class authdialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.ui = auth_ui.Ui_Dialog()
        self.ui.setupUi(self)


def caput(pvname, value, timeout=1.0):
    try:
        pv = Pv(pvname)
        pv.connect(timeout)
        pv.get(ctrl=False, timeout=timeout)
        pv.put(value, timeout)
        pv.disconnect()
    except pyca.pyexc as e:
        logger.warning("pyca exception: %s", e)
    except pyca.caexc as e:
        logger.warning("channel access exception: %s", e)


######################################################################


class GraphicUserInterface(QtWidgets.QMainWindow):
    def __init__(self, app, hutch):
        QtWidgets.QMainWindow.__init__(self)
        self.__app = app
        self.myuid = pwd.getpwuid(os.getuid())[0]
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Not sure how to do this in designer, so we put it randomly and move it now.
        self.ui.statusbar.addWidget(self.ui.userLabel)

        d = sys.path[0]
        while os.path.islink(d):
            real_path = os.readlink(d)
            if real_path[0] != "/":
                real_path = os.path.join(os.path.dirname(d), real_path)
            d = real_path
        version = os.path.basename(d)
        if len(version) > 1 and version[0] == "R":
            version = " %s" % version
        else:
            version = ""
        self.setWindowTitle("%s IocManager%s" % (hutch.upper(), version))
        self.hutch = hutch
        self.authdialog = authdialog(self)
        self.model = my_model.MyModel(hutch)
        self.utimer = QtCore.QTimer()
        self.delegate = MyDelegate(None, hutch)
        self.ui.actionApply.triggered.connect(self.doApply)
        self.ui.actionSave.triggered.connect(self.doSave)
        self.ui.actionRevert.triggered.connect(self.model.doRevert)
        self.ui.actionReboot.triggered.connect(self.doReboot)
        self.ui.actionHard_Reboot.triggered.connect(self.doHardReboot)
        self.ui.actionReboot_Server.triggered.connect(self.doServerReboot)
        self.ui.actionLog.triggered.connect(self.doLog)
        self.ui.actionConsole.triggered.connect(self.doConsole)
        self.ui.actionRemember.triggered.connect(self.model.doSaveVersions)
        self.ui.actionAuth.triggered.connect(self.doAuthenticate)
        self.ui.actionQuit.triggered.connect(self.doQuit)
        self.ui.actionHelp.triggered.connect(self.doHelp)
        self.ui.findpv.returnPressed.connect(self.doFindPV)
        self.utimer.timeout.connect(self.unauthenticate)
        self.ui.tableView.setModel(self.model)
        self.ui.tableView.setItemDelegate(self.delegate)
        self.ui.tableView.verticalHeader().setVisible(False)
        self.ui.tableView.horizontalHeader().setStretchLastSection(True)
        self.ui.tableView.resizeColumnsToContents()
        self.ui.tableView.resizeRowsToContents()
        self.ui.tableView.setSortingEnabled(True)
        self.ui.tableView.sortByColumn(0, QtCore.Qt.AscendingOrder)
        self.ui.tableView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.ui.tableView.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.ui.tableView.selectionModel().selectionChanged.connect(self.getSelection)
        self.ui.tableView.customContextMenuRequested.connect(self.showContextMenu)
        self.currentIOC = None
        self.currentBase = None
        self.pvlist = []
        self.model.startPoll()
        self.unauthenticate()

    def closeEvent(self, event):
        self.disconnectPVs()
        self.model.cleanupChildren()
        QtWidgets.QMainWindow.closeEvent(self, event)

    def disconnectPVs(self):
        for pv in self.pvlist:
            try:
                pv.disconnect()
            except Exception:
                logger.debug(f"Error disconnecting {pv}", exc_info=True)
                pass
        self.pvlist = []

    def displayPV(self, pv, e=None):
        try:
            if e is None:
                pv.gui.setText(pv.format % pv.value)
        except Exception:
            logger.debug(f"Error displaying {pv}", exc_info=True)

    def doApply(self):
        if not self.authorize_action(True):
            return
        self.model.doApply()

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

    def doSave(self):
        if not self.authorize_action(True):
            return
        self.model.doSave()

    def doReboot(self):
        if self.currentBase:
            caput(self.currentBase + ":SYSRESET", 1)

    def doHardReboot(self):
        if self.currentIOC:
            self.model.rebootIOC(self.currentIOC)

    def doServerReboot(self):
        if self.currentIOC:
            if not self.authorize_action(False):
                return
            self.model.rebootServer(self.currentIOC)

    def doLog(self):
        if self.currentIOC:
            self.model.viewlogIOC(self.currentIOC)

    def doConsole(self):
        if self.currentIOC and (
            self.model.getVar("allow_console") or self.authorize_action(False)
        ):
            self.model.connectIOC(self.currentIOC)

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
                self.model.index(row, my_model.IOCNAME), QtCore.Qt.EditRole
            ).value()
            host = self.model.data(
                self.model.index(row, my_model.HOST), QtCore.Qt.EditRole
            ).value()
            if ioc == self.currentIOC:
                return
            self.disconnectPVs()
            self.currentIOC = ioc
            self.ui.IOCname.setText(ioc)
            base = utils.getBaseName(ioc)
            self.currentBase = base
            if base is not None:
                self.dopv(base + ":HEARTBEAT", self.ui.heartbeat, "%d")
                self.dopv(base + ":TOD", self.ui.tod, "%s")
                self.dopv(base + ":STARTTOD", self.ui.boottime, "%s")
                pyca.flush_io()
            d = utils.netconfig(host)
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
            gui.setText(utils.findParent(iocfn(), dir))

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
        if not utils.check_ssh(user, self.hutch):
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
        os.write(fd, "cd %s\n" % utils.TMP_DIR)
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
        self.authdialog.ui.label.setText(prompt)
        self.authdialog.ui.nameEdit.setText("")
        self.authdialog.ui.nameEdit.setEchoMode(
            QtWidgets.QLineEdit.Password if password else QtWidgets.QLineEdit.Normal
        )
        result = self.authdialog.exec_()
        if result == QtWidgets.QDialog.Accepted:
            return self.authdialog.ui.nameEdit.text()
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
        if utils.check_auth(self.model.user, self.hutch) and (
            not file_action
            or utils.check_ssh(self.model.user, self.hutch) == file_action
        ):
            return True
        # If the user isn't OK, give him or her a chance to authenticate.
        if self.model.user == self.myuid:
            self.doAuthenticate()
        if utils.check_auth(self.model.user, self.hutch) and (
            not file_action
            or utils.check_ssh(self.model.user, self.hutch) == file_action
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
