"""
The table_model module defines a data model for the main GUI table.

This implements a QAbstractTableModel which manages reading and writing data
for the central QTableView in the main GUI.

See https://doc.qt.io/qt-5/qabstracttablemodel.html#details
"""

# TODO: big fix
# self.cfglist, self.hosts, self.vdict must be replaced with self.config
import concurrent.futures
import logging
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import psp
from qtpy.QtCore import QAbstractTableModel, QEvent, QModelIndex, Qt, QVariant
from qtpy.QtGui import QBrush, QColor
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

from . import commit_ui, details_ui, utils
from .config import get_host_os, read_config, read_status_dir, write_config
from .epics_paths import get_parent, normalize_path
from .hioc_tools import get_hard_ioc_dir_for_display, reboot_hioc, restart_hioc
from .ioc_info import find_pv, get_base_name
from .procserv_tools import apply_config, check_status, restart_proc
from .server_tools import netconfig, rebootServer

logger = logging.getLogger(__name__)

#
# Column definitions.
#
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
statelist = ["Off", "Dev", "Prod"]
statecombolist = ["Off", "Dev/Prod"]


class StatusPoll(threading.Thread):
    def __init__(self, model, interval, hosttype):
        threading.Thread.__init__(self)
        self.model = model
        self.hutch = model.hutch
        self.mtime = None
        self.interval = interval
        self.rmtime = {}
        self.daemon = True
        self.dialog = None
        self.hosttype = hosttype

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
                    self.hosttype = get_host_os(config.hosts)
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


class detailsdialog(QDialog):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.ui = details_ui.Ui_Dialog()
        self.ui.setupUi(self)


class commitdialog(QDialog):
    def doYes(self):
        self.result = QDialogButtonBox.Yes

    def doNo(self):
        self.result = QDialogButtonBox.No

    def doCancel(self):
        self.result = QDialogButtonBox.Cancel

    def __init__(self, parent=None):
        self.result = QDialogButtonBox.Cancel
        QWidget.__init__(self, parent)
        self.ui = commit_ui.Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.buttonBox.button(QDialogButtonBox.Yes).clicked.connect(self.doYes)
        self.ui.buttonBox.button(QDialogButtonBox.No).clicked.connect(self.doNo)
        self.ui.buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(self.doCancel)


class TableModel(QAbstractTableModel):
    def __init__(self, hutch, parent=None):
        QAbstractTableModel.__init__(self, parent)
        self.myuid = "%s.x%d.x%%d" % (pwd.getpwuid(os.getuid())[0], os.getpid())
        self.nextid = 0
        self.detailsdialog = detailsdialog(parent)
        self.commitdialog = commitdialog(parent)
        self.hutch = hutch
        self.user = ""
        self.userIO = None
        self.children = []
        try:
            self.config = read_config(hutch)
        except Exception:
            print("Cannot read configuration for %s!" % hutch)
            sys.exit(-1)
        self.poll = StatusPoll(self, 5, get_host_os(self.config.hosts))
        self.poll.mtime = self.config.mtime
        try:
            utils.COMMITHOST = self.config.commithost
        except Exception:
            pass
        self.addUsedHosts()

        for line in self.cfglist:
            line["status"] = utils.STATUS_INIT
            line["stattime"] = 0
        self.headerdata = [
            "IOC Name",
            "IOC ID",
            "State",
            "Status",
            "Host",
            "OS",
            "Port",
            "Version",
            "Parent",
            "Information",
        ]
        self.field = [
            "id",
            "id",
            "disable",
            None,
            "host",
            None,
            "port",
            "dir",
            "pdir",
            None,
        ]
        self.newfield = [
            "newid",
            "newid",
            "newdisable",
            None,
            "newhost",
            None,
            "newport",
            "newdir",
            None,
            None,
        ]
        self.lastsort = (0, Qt.DescendingOrder)

    def runCommand(self, geo, id, cmd):
        if os.path.exists("/usr/libexec/gnome-terminal-server"):
            appid = self.myuid % self.nextid
            self.nextid += 1
            x = subprocess.Popen(
                ["/usr/libexec/gnome-terminal-server", "--app-id", appid]
            )
            time.sleep(1)
            self.children.append(x)
            cmdlist = ["gnome-terminal", "--app-id", appid]
        else:
            cmdlist = ["gnome-terminal", "--disable-factory"]

        if shutil.which("gnome-terminal") is None:
            # For non-gnome os like rocky9
            cmdlist = ["xterm", "-bg", "black", "-fg", "white", "--hold"]
            if geo is not None:
                cmdlist += ["-geometry", geo]
            cmdlist += ["-title", id, "-e", "/bin/csh", "-c", cmd]
        else:
            if geo is not None:
                cmdlist.append("--geometry=%s" % geo)
            cmdlist += ["-t", id, "--", "/bin/csh", "-c", cmd]
        x = subprocess.Popen(cmdlist)
        self.children.append(x)

    def addUsedHosts(self):
        hosts = [line["host"] for line in self.cfglist]
        hosts[-1:] = self.hosts
        hosts = list(set(hosts))
        hosts.sort()
        self.hosts = hosts

    def startPoll(self):
        self.poll.start()

    def findid(self, id, line=None):
        if line is None:
            line = self.cfglist
        for i in range(len(line)):
            if id == line[i]["id"]:
                return i
        return None

    def findhostport(self, h, p, ln):
        for i in range(len(ln)):
            if h == ln[i]["host"] and p == ln[i]["port"]:
                return i
        return None

    def configuration(self, cfglist, hostlist, vdict):
        # Process a new configuration file!
        self.vdict = vdict
        try:
            utils.COMMITHOST = self.vdict["COMMITHOST"]
        except Exception:
            pass
        cfgonly = []
        ouronly = []
        both = []
        for i in range(len(cfglist)):
            j = self.findid(cfglist[i]["id"], self.cfglist)
            if j is not None:
                both.append((i, j))
            else:
                cfgonly.append(i)
        for i in range(len(self.cfglist)):
            j = self.findid(self.cfglist[i]["id"], cfglist)
            if j is None:
                ouronly[:0] = [i]

        for i, j in both:
            del cfglist[i]["newstyle"]
            self.cfglist[j].update(cfglist[i])

        for i in cfgonly:
            cfglist[i]["status"] = utils.STATUS_INIT
            cfglist[i]["stattime"] = 0
            self.cfglist.append(cfglist[i])

        # Note: this list is reverse sorted by construction!
        for i in ouronly:
            if self.cfglist[i]["cfgstat"] != utils.CONFIG_ADDED:
                self.cfglist = self.cfglist[0:i] + self.cfglist[i + 1 :]

        self.sort(self.lastsort[0], self.lastsort[1])

        # Just append the new hostlist, duplicates and all, then go fix it up!
        self.hosts[-1:] = hostlist
        self.addUsedHosts()

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
                self.sort(self.lastsort[0], self.lastsort[1])
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
            self.sort(self.lastsort[0], self.lastsort[1])

    #
    # IOCNAME can be selected.
    # STATE can be selected.  If not hard, it can also be checked.
    # HOST, PORT, and VERSION can be edited if not hard.
    # STATUS, OSVER, and EXTRA are only enabled.
    #
    def flags(self, index):
        c = index.column()
        try:
            if self.cfglist[index.row()]["hard"]:
                editable = Qt.NoItemFlags
            else:
                editable = Qt.ItemIsEditable
        except Exception:
            return Qt.NoItemFlags
        if c == IOCNAME or c == ID:
            return Qt.ItemIsEnabled | Qt.ItemIsSelectable
        elif c == STATE:
            return Qt.ItemIsEnabled | Qt.ItemIsSelectable | editable
        elif c == STATUS or c == EXTRA or c == OSVER:
            return Qt.ItemIsEnabled
        else:
            return Qt.ItemIsEnabled | editable

    def setData(self, index, val, role=Qt.EditRole):
        if isinstance(val, QVariant):
            val = val.value()
        try:
            entry = self.cfglist[index.row()]
        except Exception:
            return False
        c = index.column()
        if c == STATE:
            entry["newdisable"] = val == 0
            if entry["newdisable"] == entry["disable"]:
                del entry["newdisable"]
            self.dataChanged.emit(index, index)
            return True
        elif c == PORT:
            entry["newport"] = val
            if entry["newport"] == entry["port"]:
                del entry["newport"]
            self.dataChanged.emit(index, index)
            return True
        else:
            entry[self.newfield[c]] = val
            if entry[self.newfield[c]] == entry[self.field[c]]:
                del entry[self.newfield[c]]
            self.dataChanged.emit(index, index)
            if c == IOCNAME or c == ID:
                # Two columns might have the same information!
                self.dataChanged.emit(index, index)
            return True

    def rowCount(self, parent):
        return len(self.cfglist)

    def columnCount(self, parent):
        return len(self.headerdata)

    def value(self, entry, c, display=True):
        if c == STATUS:
            return entry["status"]
        if c == OSVER:
            try:
                return self.poll.hosttype[entry["host"]]
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

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.cfglist):
            return QVariant()
        elif role == Qt.DisplayRole or role == Qt.EditRole:
            return QVariant(
                self.value(
                    self.cfglist[index.row()], index.column(), role == Qt.DisplayRole
                )
            )
        elif role == Qt.ForegroundRole:
            c = index.column()
            entry = self.cfglist[index.row()]
            if c == STATUS:
                entry = self.cfglist[index.row()]
                if entry["disable"]:
                    if (
                        entry["status"] != utils.STATUS_RUNNING
                        or entry["host"] != entry["rhost"]
                        or entry["port"] != entry["rport"]
                        or entry["dir"] != entry["rdir"]
                        or entry["id"] != entry["rid"]
                    ):
                        return QVariant(QBrush(Qt.black))
                    else:
                        return QVariant(QBrush(Qt.white))
                else:
                    if entry["status"] != utils.STATUS_RUNNING:
                        return QVariant(QBrush(Qt.white))
                    else:
                        return QVariant(QBrush(Qt.black))
            if entry["cfgstat"] == utils.CONFIG_DELETED:
                return QVariant(QBrush(Qt.red))
            try:
                if c == IOCNAME and entry["newalias"] != entry["alias"]:
                    return QVariant(QBrush(Qt.blue))
            except Exception:
                pass
            try:
                if c == STATE and entry["newdisable"] != entry["disable"]:
                    return QVariant(QBrush(Qt.blue))
            except Exception:
                pass
            try:
                if entry[self.newfield[c]] != entry[self.field[c]]:
                    return QVariant(QBrush(Qt.blue))
                else:
                    del entry[self.newfield[c]]
                    return QVariant()
            except Exception:
                return QVariant()
        elif role == Qt.BackgroundRole:
            c = index.column()
            if c == STATUS:
                entry = self.cfglist[index.row()]
                if entry["disable"]:
                    if entry["status"] == utils.STATUS_RUNNING:
                        if (
                            entry["host"] != entry["rhost"]
                            or entry["port"] != entry["rport"]
                            or entry["dir"] != entry["rdir"]
                            or entry["id"] != entry["rid"]
                        ):
                            return QVariant(QBrush(Qt.yellow))
                        else:
                            return QVariant(QBrush(Qt.red))
                    else:
                        return QVariant(QBrush(Qt.green))
                else:
                    if entry["status"] != utils.STATUS_RUNNING:
                        if entry["status"] == utils.STATUS_DOWN:
                            return QVariant(QBrush(Qt.blue))
                        else:
                            return QVariant(QBrush(Qt.red))
                    if (
                        entry["host"] != entry["rhost"]
                        or entry["port"] != entry["rport"]
                        or entry["dir"] != entry["rdir"]
                        or entry["id"] != entry["rid"]
                    ):
                        return QVariant(QBrush(Qt.yellow))
                    else:
                        return QVariant(QBrush(Qt.green))
            elif c == PORT:
                r = index.row()
                if self.cfglist[r]["hard"]:
                    return QVariant(QBrush(QColor(224, 224, 224)))  # Light gray
                h = self.value(self.cfglist[r], HOST)
                p = self.value(self.cfglist[r], PORT)
                for i in range(len(self.cfglist)):
                    if i == r:
                        continue
                    h2 = self.value(self.cfglist[i], HOST)
                    p2 = self.value(self.cfglist[i], PORT)
                    if h == h2 and p == p2:
                        return QVariant(QBrush(Qt.red))
                return QVariant()
            elif c == STATE:
                v = self.value(
                    self.cfglist[index.row()], index.column(), role == Qt.DisplayRole
                )
                if v == "Dev":
                    # MCB - Add a check and make this red if a hutch is in production!
                    return QVariant(QBrush(Qt.yellow))
                else:
                    return QVariant()
            else:
                return QVariant()
        elif role == Qt.CheckStateRole:
            return QVariant()
        else:
            return QVariant()

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return QVariant(self.headerdata[col])
        return QVariant()

    def _portkey(self, d, Ncol):
        v = self.value(d, Ncol)
        if v == "":
            return -1
        else:
            return int(v)

    def sort(self, Ncol, order):
        self.lastsort = (Ncol, order)
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
        d = self.commitdialog
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
        self.poll.mtime = None  # Force a re-read!
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
            self.sort(self.lastsort[0], self.lastsort[1])

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
        self.detailsdialog.setWindowTitle("Edit Details - %s" % entry["id"])
        try:
            self.detailsdialog.ui.aliasEdit.setText(entry["newalias"])
        except Exception:
            self.detailsdialog.ui.aliasEdit.setText(entry["alias"])
        try:
            self.detailsdialog.ui.cmdEdit.setText(entry["cmd"])
        except Exception:
            self.detailsdialog.ui.cmdEdit.setText("")
        try:
            self.detailsdialog.ui.delayEdit.setText(str(entry["delay"]))
        except Exception:
            self.detailsdialog.ui.delayEdit.setText("")
        try:
            self.detailsdialog.ui.flagCheckBox.setChecked("u" in entry["flags"])
        except Exception:
            self.detailsdialog.ui.flagCheckBox.setChecked(False)
        if self.detailsdialog.exec_() == QDialog.Accepted:
            if entry["hard"]:
                newcmd = ""
                newdelay = 0
                newflags = ""
            else:
                newcmd = str(self.detailsdialog.ui.cmdEdit.text())
                if newcmd == "":
                    try:
                        del entry["cmd"]
                    except Exception:
                        pass
                else:
                    entry["cmd"] = newcmd

                if (
                    "cmd" in list(entry.keys())
                    and self.detailsdialog.ui.flagCheckBox.isChecked()
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
                    newdelay = int(self.detailsdialog.ui.delayEdit.text())
                except Exception:
                    newdelay = 0
                if newdelay == 0:
                    try:
                        del entry["delay"]
                    except Exception:
                        pass
                else:
                    entry["delay"] = newdelay

            alias = str(self.detailsdialog.ui.aliasEdit.text())
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
        self.sort(self.lastsort[0], self.lastsort[1])

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
            if not rebootServer(ihost):
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
