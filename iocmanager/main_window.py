"""
The main_window module impelements the main window of the iocmanager GUI.

It will be launched via the cli parser in gui.py.
"""

import getpass
import io
import logging
import threading
import traceback
from enum import Enum
from functools import partial

import pydm.config
import pydm.data_plugins
from pydm.exception import ExceptionDispatcher
from pydm.exception import install as install_pydm_excepthook
from qtpy.QtCore import (
    QItemSelection,
    QItemSelectionModel,
    QPoint,
    QSortFilterProxyModel,
    Qt,
)
from qtpy.QtGui import QCloseEvent
from qtpy.QtWidgets import (
    QAbstractItemView,
    QMainWindow,
    QMenu,
    QMessageBox,
    QWidget,
)

from .commit import check_commit_possible, commit_config
from .config import check_auth, check_ssh, read_config, write_config
from .dialog_apply_verify import verify_dialog
from .dialog_commit import CommitDialog, CommitOption
from .dialog_find_pv import FindPVDialog
from .env_paths import env_paths
from .hioc_tools import reboot_hioc
from .imgr import ensure_auth, reboot_cmd
from .ioc_info import get_base_name
from .procserv_tools import apply_config
from .server_tools import reboot_server, sdfconfig
from .table_delegate import IOCTableDelegate
from .table_model import IOCModelIdentifier, IOCTableModel
from .terminal import run_in_floating_terminal
from .ui_ioc import Ui_MainWindow
from .version import version as version_str

logger = logging.getLogger(__name__)


class IOCMainWindow(QMainWindow):
    """
    The main window of the iocmanager gui.

    This contains a view of the table model and has utilities
    for e.g. saving and comitting configs.

    It loads from the pyuic-compiled ui/ioc.ui file.
    """

    def __init__(self, hutch: str, verbose: int = 0):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Not sure how to do this in designer, so we put it randomly and move it now.
        self.ui.statusbar.addWidget(self.ui.userLabel)

        # Init args
        self.hutch = hutch
        self.verbose = verbose

        # Data interfaces
        config = read_config(hutch)
        self.model = IOCTableModel(config=config, hutch=hutch, parent=self)
        self.sort_model = QSortFilterProxyModel()
        self.sort_model.setSourceModel(self.model)
        self.delegate = IOCTableDelegate(
            hutch=hutch,
            model=self.model,
            proxy_model=self.sort_model,
            parent=self,
        )

        # User state
        self.current_ioc = ""
        self.user = getpass.getuser()
        self.auth = check_auth(user=self.user, hutch=self.hutch)
        self.commit_host_status = CommitHostStatus.UNKNOWN
        self.update_user_label()

        # Set up all the qt objects we'll need
        # Helpful title: which hutch and iocmanager version we're using
        self.setWindowTitle(f"{hutch.upper()} iocmanager R{version_str}")
        # Re-usable dialogs
        self.commit_dialog = CommitDialog(hutch=hutch, parent=self)
        self.find_pv_dialog = FindPVDialog(
            model=self.model,
            parent=self,
        )
        self.find_pv_dialog.request_scroll.connect(self.scroll_to_ioc)
        # Configuration menu
        self.ui.actionApply.triggered.connect(self.action_write_and_apply_config)
        self.ui.actionSave.triggered.connect(self.action_write_config)
        self.ui.actionRevert.triggered.connect(self.action_revert_all)
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

        # Performance quibbles
        # Doing this in a thread saves a startup second
        self.pydm_ready = threading.Event()
        self.pydm_prep_thread = threading.Thread(target=self.prepare_pydm, daemon=True)
        self.pydm_prep_thread.start()
        # Pre-loading the sdfconfig info makes the table snappier
        self.sdfconfig_cache = {}
        self.sdfconfig_prep_thread = threading.Thread(
            target=self.prepare_sdfconfig, daemon=True
        )
        self.sdfconfig_prep_thread.start()
        # Checking if we can ssh can take a few seconds for kerberos
        self.commit_check_thread = threading.Thread(
            target=self.prepare_commit_host_status, daemon=True
        )
        self.commit_check_thread.start()

        # Exception Handling: show a dialog if anything in the qt main thread errors out
        install_pydm_excepthook(use_default_handler=False)
        self.exception_notifier = IOCExceptionNotifier(self)

    def update_user_label(self):
        text = f"User: {self.user}"
        if self.auth:
            text += " (full auth)"
        else:
            text += " (limited auth)"
        match self.commit_host_status:
            case CommitHostStatus.UNKNOWN:
                text += " (ssh/git checking...)"
            case CommitHostStatus.READY:
                text += " (ssh/git ready)"
            case CommitHostStatus.ERROR:
                text += " (ssh/git error)"
            case CommitHostStatus.DISABLED:
                text += " (ssh/git disabled)"
        self.ui.userLabel.setText(text)

    def prepare_pydm(self):
        """
        Skip some pydm startup we don't care for, do the rest early and in a thread.

        Saves 3-7s to do this at all (takes about 1s no matter what)
        The final 1s is sort of saved by doing it in a thread because it can
        start while the user is thinking about what to do without slowing down
        the ui load.
        """
        # Don't load typhos, etc. plugins, wastes time
        pydm.config.ENTRYPOINT_DATA_PLUGIN += "_disable"
        # Force early load of the plugins
        pydm.data_plugins.initialize_plugins_if_needed()
        self.pydm_ready.set()

    def prepare_sdfconfig(self):
        """
        Load sdfconfig info in the background to make the table feel snappier
        """
        for host in self.model.config.hosts:
            self._get_sdfconfig(host)

    def _get_sdfconfig(self, host: str) -> dict[str, str]:
        """
        Return the cached sdfconfig information if available, otherwise get it.
        """
        if host not in self.sdfconfig_cache:
            try:
                self.sdfconfig_cache[host] = sdfconfig(host=host)
            except Exception:
                self.sdfconfig_cache[host] = {
                    "foreman_location": "Please configure sdfconfig"
                }
            if not self.sdfconfig_cache[host]:
                # Invalid hostname
                self.sdfconfig_cache[host] = {
                    "foreman_location": "Server not in sdfconfig"
                }
        return self.sdfconfig_cache[host]

    def prepare_commit_host_status(self):
        """
        Check if we can ssh for a commit or not.

        Update the cached value for this and the user label.
        Note that this can take several seconds in the worst case.
        """
        if check_ssh(user=self.user, hutch=self.hutch):
            if check_commit_possible(self.hutch):
                self.commit_host_status = CommitHostStatus.READY
            else:
                self.commit_host_status = CommitHostStatus.ERROR
        else:
            self.commit_host_status = CommitHostStatus.DISABLED
        self.update_user_label()

    def closeEvent(self, a0: QCloseEvent):
        """
        Override base closeEvent to also stop polling.

        This avoids shutdown exceptions.
        The strange signature makes pylance happy because it matches the base class 1:1.
        """
        self.model.stop_poll_thread()
        self.model.poll_thread.join(timeout=1.0)
        return super().closeEvent(a0)

    def action_write_and_apply_config(
        self, checked: bool, ioc: IOCModelIdentifier | None = None
    ):
        """
        Action when the user clicks "Apply".

        Runs through the same steps as action_write_config,
        and then starts, stops, restarts IOCs as needed to make the new
        configuration reality.

        This may also be called from the context menu "Apply Configuration"
        action, which will pass an ioc to use (so we only apply to one ioc).
        Note that this will still save all pending edits.

        There is a dummy unused "checked" parameter because QAction provides it.
        """
        if ioc is None:
            ioc_name = None
        else:
            ioc_name = self.model.get_ioc_name(ioc=ioc)
        if not self.action_write_config():
            return
        apply_config(
            cfg=self.hutch, verify=partial(verify_dialog, parent=self), ioc=ioc_name
        )

    def action_write_config(self) -> bool:
        """
        Action when the user clicks "Save".

        Checks auth, then prompts the user with a save/commit dialog.

        Raises if unsuccessful.
        Returns True if successful.
        Returns False if cancelled by the user.
        """
        ensure_auth(hutch=self.hutch, ioc_name="", special_ok=False)
        comment = ""
        match self.commit_host_status:
            case CommitHostStatus.UNKNOWN | CommitHostStatus.ERROR:
                if (
                    QMessageBox.warning(
                        self,
                        "Commits broken for user",
                        "You will not be able to commit in this session.\n\n"
                        "In order to commit, you must be able to ssh to "
                        f"{self.model.config.commithost} without a password.\n\n"
                        "This may require you to kinit and/or aklog for kerberos auth "
                        "or source ssh-agent-helper for key-based auth."
                        "\n\nContinue anyway?",
                        QMessageBox.Yes | QMessageBox.Cancel,
                        QMessageBox.Yes,
                    )
                    != QMessageBox.Yes
                ):
                    return False
            case CommitHostStatus.DISABLED:
                if (
                    QMessageBox.information(
                        self,
                        "Commits disabled for user",
                        f"Commits are disabled for {self.user}.\n\nContinue anyway?",
                        QMessageBox.Yes | QMessageBox.Cancel,
                        QMessageBox.Yes,
                    )
                    != QMessageBox.Yes
                ):
                    return False
            case CommitHostStatus.READY:
                self.commit_dialog.reset()
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
                        QMessageBox.warning(
                            self,
                            "Error",
                            "Must have a comment to commit",
                            QMessageBox.Ok,
                            QMessageBox.Ok,
                        )
        write_config(cfgname=self.hutch, config=self.model.get_next_config())
        self.model.reset_edits()
        if comment:
            try:
                commit_config(
                    hutch=self.hutch,
                    comment=comment,
                    show_output=bool(self.verbose),
                    ssh_verbose=max(0, self.verbose - 1),
                )
            except Exception:
                # Likely a git error since we ruled out ssh config issue
                if (
                    QMessageBox.warning(
                        self,
                        "Commit Failed",
                        "Git commit failed (after successfully saving file).\n\n"
                        "Possibly the new file was the same as the old file, "
                        "or maybe there was a network hiccup.\n\n"
                        "Would you like to continue?",
                        QMessageBox.Yes | QMessageBox.Cancel,
                        QMessageBox.Yes,
                    )
                    != QMessageBox.Yes
                ):
                    return False
        return True

    def action_revert_all(self):
        """
        Action when the user clicks "Revert".

        Unconditionally discards all pending edits.
        """
        self.model.reset_edits()

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
        reboot_cmd(
            config=self.model.get_next_config(),
            ioc_name=self.current_ioc,
            reboot_mode=reboot_mode,
        )

    def _check_selected(self) -> bool:
        """
        Shared check and message box when no IOC has been selected yet.

        Some actions need a specific IOC to be selected in order to run.

        Shows a warning and returns False if no IOC is selected.
        """
        if not self.current_ioc:
            QMessageBox.warning(
                self,
                "Error",
                "No IOC selected.",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return False
        return True

    def action_server_reboot(self):
        """
        Action when the user clicks "Reboot Server".

        For SIOCs, this uses ipmi to turn power off, then back on again.
        For HIOCs, this fails because the legacy behavior cannot be
        implemented with sdfconfig.
        """
        if not self._check_selected():
            return
        ensure_auth(hutch=self.hutch, ioc_name="", special_ok=False)
        # Need to figure out which IOCs are on this host
        config = self.model.get_next_config()
        this_proc = config.procs[self.current_ioc]
        if this_proc.hard:
            self._hioc_server_reboot(host=this_proc.host)
        else:
            all_names = []
            for ioc_name, ioc_proc in config.procs.items():
                if ioc_proc.host == this_proc.host and not ioc_proc.disable:
                    all_names.append(ioc_name)
            self._sioc_server_reboot(host=this_proc.host, ioc_names=all_names)

    def _hioc_server_reboot(self, host: str):
        """
        Subfunction of action_server_reboot to reboot a hard ioc.

        This includes a special confirm dialog for the hard ioc.
        """
        user_choice = QMessageBox.question(
            self,
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
            msg += f"\nRebooting {host} will temporarily stop the following IOCs:"
            for name in ioc_names:
                ioc_proc = self.model.get_next_config().procs[name]
                if ioc_proc.alias:
                    msg += f"\n- {ioc_proc.alias} ({name})"
                else:
                    msg += f"\n- {name}"
        else:
            msg += f" There are no IOCs running on {host}."
        user_choice = QMessageBox.question(
            self,
            f"Reboot IOC Server {host}",
            msg,
            QMessageBox.Cancel | QMessageBox.Ok,
            QMessageBox.Cancel,
        )
        if user_choice != QMessageBox.Ok:
            return
        if not reboot_server(host=host):
            QMessageBox.critical(
                self,
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
        pos = self.ui.menuIOC_Control.pos()
        run_in_floating_terminal(
            title=f"{self.current_ioc} logfile",
            cmd=f"tail -1000lf {env_paths.LOGBASE % self.current_ioc}",
            xpos=pos.x(),
            ypos=pos.y(),
        )

    def action_show_console(self):
        """
        Action when the user clicks "Show Console".

        This opens a floating terminal that telnets to the IOC's host and port.
        """
        if not self._check_selected():
            return
        ioc_proc = self.model.get_ioc_proc(ioc=self.current_ioc)
        pos = self.ui.menuIOC_Control.pos()
        run_in_floating_terminal(
            title=f"{self.current_ioc} telnet session",
            cmd=f"telnet {ioc_proc.host} {ioc_proc.port}",
            xpos=pos.x(),
            ypos=pos.y(),
        )

    def action_help(self):
        """
        Action when the user clicks "Help".

        This opens a small dialog with a link to the confluence page.
        """
        QMessageBox.information(
            self,
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
        self.model.save_all_versions()

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
        self.find_pv_dialog.find_pv_and_exec(self.ui.findpv.text())

    def on_table_select(self, selected: QItemSelection, deselected: QItemSelection):
        """
        Callback when the user selects any cell in the grid.

        We need to update the widget displays and instance variables to reflect which
        IOC we've selected.

        Note: these indices are in the context of the proxy model,
        so we want to convert them to the base model indices to use the
        dataclass getters.
        """
        try:
            proxy_index = selected.indexes()[0]
        except IndexError:
            # Nothing selected
            return
        source_index = self.sort_model.mapToSource(proxy_index)
        ioc_proc = self.model.get_ioc_proc(ioc=source_index)
        ioc_name = ioc_proc.name
        host = ioc_proc.host
        if ioc_name == self.current_ioc:
            return
        self.current_ioc = ioc_name
        self.ui.iocname.setText(ioc_name)
        try:
            base = get_base_name(ioc=ioc_name)
        except Exception:
            self.ui.heartbeat.set_channel("")
            self.ui.tod.set_channel("")
            self.ui.boottime.set_channel("")
            self.ui.heartbeat.setText("")
            self.ui.tod.setText("")
            self.ui.boottime.setText("")
        else:
            self.ui.heartbeat.setText("")
            self.ui.tod.setText("")
            self.ui.boottime.setText("")
            self.pydm_ready.wait(timeout=1.0)
            self.ui.heartbeat.set_channel(f"ca://{base}:HEARTBEAT")
            self.ui.tod.set_channel(f"ca://{base}:TOD")
            self.ui.boottime.set_channel(f"ca://{base}:STARTTOD")
        try:
            host_info = self._get_sdfconfig(host)
        except Exception:
            host_info = {}
        try:
            self.ui.location.setText(host_info["foreman_location"])
        except KeyError:
            self.ui.location.setText("")
        try:
            self.ui.description.setText(host_info["description"])
        except KeyError:
            self.ui.description.setText("")

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

        Note: these indices are in the context of the proxy model,
        so we want to convert them to the base model indices to use the
        dataclass getters.
        """
        proxy_index = self.ui.tableView.indexAt(pos)
        source_index = self.sort_model.mapToSource(proxy_index)
        menu = QMenu()
        add_ioc = menu.addAction("Add New IOC")
        add_ioc.triggered.connect(self.action_add_ioc)
        if source_index.row() != -1:
            ioc_proc = self.model.get_ioc_proc(ioc=source_index)
            del_ioc = menu.addAction("Delete IOC")
            del_ioc.triggered.connect(partial(self.model.delete_ioc, ioc=ioc_proc))
            if not ioc_proc.hard:
                desync_info = self.model.get_desync_info(ioc=ioc_proc)
                if ioc_proc.name in self.model.live_only_iocs:
                    add_running = menu.addAction("Add Running to Config")
                    add_running.triggered.connect(
                        partial(self.action_add_running, ioc=ioc_proc)
                    )
                elif desync_info.has_diff:
                    set_running = menu.addAction("Set from Running")
                    set_running.triggered.connect(
                        partial(self.action_set_from_running, ioc=ioc_proc)
                    )
                if desync_info.has_diff or self.model.pending_edits(ioc_proc.name):
                    apply_config = menu.addAction("Apply Configuration")
                    apply_config.triggered.connect(
                        partial(self.action_write_and_apply_config, ioc=ioc_proc)
                    )
                rem_ver = menu.addAction("Remember Version")
                rem_ver.triggered.connect(
                    partial(self.action_remember_one_version, ioc=ioc_proc)
                )
            if self.model.pending_edits(ioc=ioc_proc):
                rev_ioc = menu.addAction("Revert IOC")
                rev_ioc.triggered.connect(partial(self.action_revert_one, ioc=ioc_proc))
            edit_detail = menu.addAction("Edit Details")
            edit_detail.triggered.connect(
                partial(self.model.edit_details_dialog, ioc=ioc_proc)
            )
        gpos = self.ui.tableView.viewport().mapToGlobal(pos)
        menu.exec_(gpos)

    def action_add_ioc(self):
        """
        Context menu action when the user clicks "Add IOC".

        This will open a dialog that will prompt the user for all the required
        fields and all of the commonly used normal fields needed for an IOC.
        """
        ioc_name = self.model.add_ioc_dialog()
        if ioc_name:
            self.scroll_to_ioc(ioc=ioc_name)

    def action_add_running(self, ioc: IOCModelIdentifier):
        """
        Context menu action when the user clicks "Add Running to Config".

        This takes an IOC that is running without being tracked by IOC manager
        and adds it to IOC manager.
        """
        self.model.add_ioc(ioc_proc=self.model.get_ioc_proc(ioc=ioc))

    def action_set_from_running(self, ioc: IOCModelIdentifier):
        """
        Context menu action when the user clicks "Set from Running".

        This will make pending edits to the selected IOC config such that the
        selected IOC config matches the live IOC status.
        """
        self.model.set_from_running(ioc=ioc)

    def action_remember_one_version(self, ioc: IOCModelIdentifier):
        """
        Context menu action when the user clicks "Remember Version".

        This will make a pending history edit where the IOC's current version
        will be added to the history.
        """
        self.model.save_version(ioc=ioc)

    def action_revert_one(self, ioc: IOCModelIdentifier):
        """
        Context menu action when the user clicks "Revert IOC".

        This will undo all pending edits for the selected IOC, e.g.
        pending deletions, additions, and changes will be removed.
        """
        self.model.revert_ioc(ioc=ioc)

    def scroll_to_ioc(self, ioc: IOCModelIdentifier):
        """
        Helper to scroll the view to an IOC.
        """
        row = self.model.get_ioc_row(ioc=ioc)
        selection_model = self.ui.tableView.selectionModel()
        idx = self.sort_model.mapFromSource(self.model.index(row, 0))
        selection_model.select(idx, QItemSelectionModel.SelectCurrent)
        self.ui.tableView.scrollTo(idx, QAbstractItemView.PositionAtCenter)


class IOCExceptionNotifier:
    """
    Similar to the default PyDM exception handler, but with a parent.

    This can't subclass the default exception handler because that
    does some hard-coding of the class singleton.
    """

    def __init__(self, main_window: IOCMainWindow):
        self.main_window = main_window
        ExceptionDispatcher().newException.connect(self.recieve_new_exception)

    def recieve_new_exception(
        self, exc_info: tuple[type[BaseException], BaseException, tuple]
    ):
        raise_to_operator(exc_info[1], self.main_window)


def raise_to_operator(
    exc: BaseException,
    parent: QWidget,
) -> QMessageBox:
    """
    Utility function to show an Exception to the operator.

    Vendored from pydm and modified:
    - Allow us to pass a parent widget so that the message box
    appears in the bounds of the parent instead of possibly
    elsewhere on the screen.
    """
    err_msg = QMessageBox(parent)
    err_msg.setText("{}: {}".format(exc.__class__.__name__, exc))
    err_msg.setWindowTitle(type(exc).__name__)
    err_msg.setIcon(QMessageBox.Critical)
    handle = io.StringIO()
    traceback.print_tb(exc.__traceback__, file=handle)
    handle.seek(0)
    err_msg.setDetailedText(handle.read())
    err_msg.exec_()
    return err_msg


class CommitHostStatus(Enum):
    """
    Enum to express how the GUI should interact with the commit host.

    The commit host is a host we ssh to for commits in order to
    avoid issues associated with NFS git repo file synchronization.

    The possible values are:
    - UNKNOWN: we haven't checked yet
    - READY: last time we checked, we could ssh to the commit host
    - ERROR: last time we checked, we could not ssh to the commit host
    - DISABLED: this user is not allowed to ssh to the commit host
        (usually, this is for opr users that can't ssh without password)
    """

    UNKNOWN = 0
    READY = 1
    ERROR = 2
    DISABLED = 3
