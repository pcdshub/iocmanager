"""
The dialog_add_ioc module defines the AddIOCDialog.

This dialog helps the user add an IOC to the GUI table.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from qtpy.QtCore import QUrl
from qtpy.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QWidget,
)

from .config import IOCProc
from .epics_paths import get_parent, standard_ioc_paths
from .type_hints import ParentWidget

if TYPE_CHECKING:
    from .table_model import IOCTableModel


class AddIOCDialog(QFileDialog):
    """
    Modify the built-in QFileDialog.

    - Extend the grid layout with new widgets
    - Helpers for port selection
    """

    def __init__(self, hutch: str, model: IOCTableModel, parent: ParentWidget):
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

        self.model = model

        self.name_edit = self._add_row("IOC Name *+", QLineEdit())
        self.alias_edit = self._add_row("Alias", QLineEdit())
        self.host_edit = self._add_row("Host *", QLineEdit())
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setMinimum(-1)
        self.port_spinbox.setMaximum(39199)
        self.port_spinbox.valueChanged.connect(self._validate_port_spinbox)
        self.port_is_valid = False
        self.auto_closed = QPushButton("Select CLOSED")
        self.auto_closed.clicked.connect(self._select_closed_port)
        self.auto_open = QPushButton("Select OPEN")
        self.auto_open.clicked.connect(self._select_open_port)
        port_layout = QHBoxLayout()
        port_layout.addWidget(self.port_spinbox)
        port_layout.addWidget(self.auto_closed)
        port_layout.addWidget(self.auto_open)
        self._add_row("Port (-1 = HARD IOC)", port_layout)
        self.parent_edit = self._add_row("Parent", QLineEdit())
        self.parent_edit.setReadOnly(True)
        self._add_row("* = Required Fields for Soft IOCs.")
        self._add_row("+ = Required fields for Hard IOCs.")
        self.directoryEntered.connect(self._update_parent)
        self.currentChanged.connect(self._update_parent)
        self.reset()

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

    def _validate_port_spinbox(self, value: int):
        """
        Turn the text in the spinbox black/red depending on if the port is valid or not.
        """
        if value == -1 or (30000 < value < 39000) or (39100 <= value < 39200):
            self.port_spinbox.setStyleSheet("QSpinBox { color: black; }")
            self.port_is_valid = True
        else:
            self.port_spinbox.setStyleSheet("QSpinBox { color: red; }")
            self.port_is_valid = False

    def _select_closed_port(self):
        """
        Slot when the user clicks on "Select CLOSED".

        Puts an available closed port in the port spinbox.
        Host must already be selected.
        """
        self._select_port(closed=True)

    def _select_open_port(self):
        """
        Slot when the user clicks on "Select OPEN".

        Puts an available open port in the port spinbox.
        Host must already be selected.
        """
        self._select_port(closed=False)

    def _select_port(self, closed: bool):
        """Shared implementation for automatically selecting ports."""
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(
                None,
                "Host not selected!",
                "Selecting a port requires the host field to be populated.",
                QMessageBox.Ok,
                QMessageBox.Ok,
            )
            return
        unused_port = self.model.get_unused_port(host=host, closed=closed)
        self.port_spinbox.setValue(unused_port)

    def _update_parent(self, selected_path: str):
        """Set the parent widget to the IOC parent (for templated IOCs)"""
        ioc_name = self.name_edit.text().strip()
        parent_path = self._get_parent(selected_path=selected_path, ioc_name=ioc_name)
        self.parent_edit.setText(parent_path)

    def _get_parent(self, selected_path: str, ioc_name: str) -> str:
        """Inner wrapper for _update_parent that returns the str to use."""
        if not ioc_name or not selected_path:
            return ""
        try:
            return get_parent(directory=selected_path, ioc_name=ioc_name)
        except Exception:
            return ""

    def reset(self):
        """
        Set the widgets back to their default values.
        """
        self.name_edit.setText("")
        self.alias_edit.setText("")
        self.host_edit.setText("")
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
