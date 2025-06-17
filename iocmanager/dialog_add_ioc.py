"""
The dialog_add_ioc module defines the AddIOCDialog.

This dialog helps the user add an IOC to the GUI table.
"""

from qtpy.QtCore import QUrl
from qtpy.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QWidget,
)

from .config import IOCProc
from .epics_paths import standard_ioc_paths
from .type_hints import ParentWidget


class AddIOCDialog(QFileDialog):
    """
    Modify the built-in QFileDialog.

    - Extend the grid layout with new widgets
    - Helpers for port selection
    """

    def __init__(self, hutch: str, parent: ParentWidget):
        standard_paths = standard_ioc_paths(hutch=hutch)
        default_dir = standard_paths[0]
        for pth in standard_paths:
            if pth.endswith(hutch):
                default_dir = pth
                break
        super().__init__(parent, "Add New IOC", default_dir)
        self.setFileMode(QFileDialog.Directory)
        self.setOptions(QFileDialog.ShowDirsOnly | QFileDialog.DontUseNativeDialog)
        self.setSidebarUrls(QUrl("file://" + pth) for pth in standard_paths)

        self.name_edit = self._add_row("IOC Name *+", QLineEdit())
        self.alias_edit = self._add_row("Alias", QLineEdit())
        self.host_edit = self._add_row("Host *", QLineEdit())
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setMinimum(-1)
        self.port_spinbox.setMaximum(39199)
        # TODO data validation for port edit
        self.auto_closed = QPushButton("Select CLOSED")
        # TODO implement select closed
        self.auto_open = QPushButton("Select OPEN")
        # TODO implement select open
        port_layout = QHBoxLayout()
        port_layout.addWidget(self.port_spinbox)
        port_layout.addWidget(self.auto_closed)
        port_layout.addWidget(self.auto_open)
        self._add_row("Port (-1 = HARD IOC)", port_layout)
        self.parent_edit = self._add_row("Parent", QLineEdit())
        self.parent_edit.setReadOnly(True)
        self._add_row("* = Required Fields for Soft IOCs.")
        self._add_row("+ = Required fields for Hard IOCs.")
        # TODO implement parent edit updating on directoryEnterered, currentChanged

    def _add_row[T](self, text: str, widget: T = None) -> T:
        """Helper for adding a widget to the grid, similar to a form layout."""
        layout = self.layout()
        if not isinstance(layout, QGridLayout):
            raise RuntimeError("QFileDialog changed in qt update: not QGridLayout")
        if layout.columnCount() != 3:
            raise RuntimeError("QFileDialog changed in qt update: not 3 columns")

        row = layout.rowCount()
        layout.addWidget(QLabel(text), row, 0)
        if isinstance(widget, QWidget):
            layout.addWidget(widget, row, 1)
        elif isinstance(widget, QLayout):
            layout.addLayout(widget, row, 1)
        return widget

    def reset(self):
        """
        Set the widgets back to their default values.
        """
        self.name_edit.setText("")
        self.alias_edit.setText("")
        self.host_edit.setText("")
        # TODO initialize port_edit to an available closed port
        self.port_spinbox.setValue(30001)
        self.parent_edit.setText("")

    def get_ioc_proc(self) -> IOCProc:
        """
        Get the IOCProc instance that represents the widget data.
        """
        name = self.name_edit.text().strip()
        port = self.port_spinbox.value()
        if port == -1:
            host = name
        else:
            host = self.host_edit.text().strip()
        return IOCProc(
            name=name,
            port=port,
            host=host,
            path=self.selectedFiles()[0].strip(),
            alias=self.alias_edit.text().strip(),
        )
