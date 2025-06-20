"""
The dialog_find_pv module defines logic for the FindPVDialog.

The FindPVDialog is shown when the user asks to find a PV in the GUI.
It should show the user all PVs that match their regex and which
IOC serves them.

The layout is defined in ui/find_pv.ui
"""

import logging
import re

from qtpy.QtCore import QItemSelectionModel
from qtpy.QtWidgets import QAbstractItemView, QDialog, QTableView

from . import ui_find_pv
from .ioc_info import find_pv
from .table_model import IOCTableModel
from .type_hints import ParentWidget

# Depends on the version, even pylance gets confused
try:
    from qtpy.QtCore import pyqtSignal as Signal
except ImportError:
    from qtpy.QtCore import Signal  # type: ignore


logger = logging.getLogger(__name__)


class FindPVDialog(QDialog):
    """
    Load the pyuic-compiled ui/find_pv.ui into a QDialog.

    This dialog contains space to place to results from a find_pv operation.
    """

    process_next = Signal(int)

    def __init__(
        self, model: IOCTableModel, view: QTableView, parent: ParentWidget = None
    ):
        super().__init__(parent)
        self.ui = ui_find_pv.Ui_Dialog()
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
