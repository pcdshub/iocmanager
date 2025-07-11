"""
The dialog_edit_details module defines the DetailsDialog's logic.

The DetailsDialog is used to edit details about an IOC that
are otherwise not shown in the table.

The DetailsDialog's layout is defined in ui/details.ui
"""

from copy import deepcopy

from qtpy.QtWidgets import QDialog, QWidget

from . import ui_details
from .config import IOCProc


class DetailsDialog(QDialog):
    """
    Load the pyuic-compiled ui/details.ui into a QDialog.

    This dialog contains edit widgets for some of the less common IOC settings,
    namely, the ones that are not editable in the table using the table delegate.
    This dialog is launched when someone right-clicks on a table row and clicks
    on "Edit Details".
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.ui = ui_details.Ui_Dialog()
        self.ui.setupUi(self)
        self.ioc_proc = IOCProc(name="", port=0, host="", path="")

    def set_ioc_proc(self, ioc_proc: IOCProc):
        """
        Set the contents of this dialog to match ioc_proc and cache it.
        """
        self.ioc_proc = deepcopy(ioc_proc)
        self.setWindowTitle(f"Edit Details - {ioc_proc.name}")
        self.ui.aliasEdit.setText(ioc_proc.alias)
        self.ui.cmdEdit.setText(ioc_proc.cmd)
        self.ui.delayEdit.setValue(ioc_proc.delay)

        # Hard IOCs cannot edit cmd or delay
        self.ui.cmdEdit.setDisabled(ioc_proc.hard)
        self.ui.delayEdit.setDisabled(ioc_proc.hard)

    def get_ioc_proc(self) -> IOCProc:
        """
        Return a modified copy of the last given ioc_proc using the widget data.
        """
        new_proc = deepcopy(self.ioc_proc)
        new_proc.alias = self.ui.aliasEdit.text()
        new_proc.cmd = self.ui.cmdEdit.text()
        new_proc.delay = self.ui.delayEdit.value()
        return new_proc
