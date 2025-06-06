"""
The table_delegate module defines editing behavior for the main GUI table.

This implements a QStyledItemDelegate with different editors for each of the
columns in the central QTableView of the GUI.

See https://doc.qt.io/qt-5/qstyleditemdelegate.html#details
"""

import os

from qtpy.QtCore import QModelIndex, QSize, Qt, QUrl, QVariant
from qtpy.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QWidget,
)

from . import hostname_ui, table_model, utils
from .epics_paths import get_parent, normalize_path
from .table_model import IOCTableModel
from .type_hints import ParentWidget

STATELIST = ["Off", "Dev", "Prod"]
STATECOMBOLIST = ["Off", "Dev/Prod"]


class HostnameDialog(QDialog):
    """
    Load the pyuic-compiled ui/hostname.ui into a QDialog.

    This is a simple dialog that allows the user to input a
    hostname into a QLineEdit. It pops up when the user selects
    the "New Host" option when editing IOC hosts in the table.
    """

    def __init__(self, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = hostname_ui.Ui_Dialog()
        self.ui.setupUi(self)


class IOCTableDelegate(QStyledItemDelegate):
    def __init__(self, hutch: str, parent: ParentWidget = None):
        super().__init__(parent)
        self.hutch = hutch
        self.boxsize = None
        self.hostdialog = HostnameDialog(parent)

    def createEditor(
        self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex
    ):
        """https://doc.qt.io/qt-5/qstyleditemdelegate.html#createEditor"""
        col = index.column()
        if (
            col == table_model.HOST
            or col == table_model.VERSION
            or col == table_model.STATE
        ):
            editor = QComboBox(parent)
            editor.setAutoFillBackground(True)
            editor.currentIndexChanged.connect(lambda n: self.do_commit(n, editor))
            if col == table_model.HOST:
                items = index.model().hosts
            elif col == table_model.VERSION:
                items = index.model().history(index.row())
            else:
                items = STATECOMBOLIST
            for item in items:
                editor.addItem(item)
            editor.lastitem = editor.count()
            if col == table_model.HOST:
                editor.addItem("New Host")
                if self.boxsize is None:
                    self.boxsize = QSize(150, 25)
            elif col == table_model.VERSION:
                editor.addItem("New Version")
            # STATE doesn't need another entry!
            return editor
        else:
            return QStyledItemDelegate.createEditor(self, parent, option, index)

    def setEditorData(self, editor: QWidget | QComboBox, index: QModelIndex):
        """https://doc.qt.io/qt-5/qstyleditemdelegate.html#setEditorData"""
        col = index.column()
        if col == table_model.HOST:
            value = index.model().data(index, Qt.EditRole).value()
            try:
                idx = index.model().hosts.index(value)
                editor.setCurrentIndex(idx)
            except Exception:
                editor.setCurrentIndex(editor.lastitem)
        elif col == table_model.VERSION:
            # We don't have anything to do here.  It is created pointing to 0
            # (the newest setting)
            # And after setModelData, it is pointing to what we just added.
            pass
        elif col == table_model.STATE:
            value = index.model().data(index, Qt.EditRole).value()
            try:
                idx = STATELIST.index(value)
                if idx >= len(STATECOMBOLIST):
                    idx = len(STATECOMBOLIST) - 1
                editor.setCurrentIndex(idx)
            except Exception:
                editor.setCurrentIndex(editor.lastitem)
        else:
            QStyledItemDelegate.setEditorData(self, editor, index)

    def setModelData(
        self, editor: QWidget | QComboBox, model: IOCTableModel, index: QModelIndex
    ):
        """https://doc.qt.io/qt-5/qstyleditemdelegate.html#setModelData"""
        col = index.column()
        if col == table_model.HOST:
            idx = editor.currentIndex()
            if idx == editor.lastitem:
                # Pick a new hostname!
                if self.hostdialog.exec_() == QDialog.Accepted:
                    value = self.hostdialog.ui.hostname.text()
                    if value not in model.hosts:
                        model.hosts.append(value)
                        model.hosts.sort()
                        for i in range(len(model.hosts)):
                            editor.setItemText(i, model.hosts[i])
                        editor.lastitem = editor.count()
                        editor.addItem("New Host")
                    editor.setCurrentIndex(model.hosts.index(value))
                    model.setData(index, QVariant(value), Qt.EditRole)
                else:
                    self.setEditorData(editor, index)  # Restore the original value!
            else:
                model.setData(index, QVariant(str(editor.currentText())), Qt.EditRole)
        elif col == table_model.VERSION:
            idx = editor.currentIndex()
            if idx == editor.lastitem:
                # Pick a new directory!
                r = str(editor.itemText(0))
                if r[0] != "/" and r[0:3] != "../":
                    try:
                        r = utils.EPICS_SITE_TOP + r[: r.rindex("/")]
                    except Exception:
                        print("Error picking new directory!")
                row = index.row()
                idm = model.getID(row)
                dlg = QFileDialog(self.parent(), "New Version for %s" % idm, r)
                dlg.setFileMode(QFileDialog.Directory)
                dlg.setOptions(
                    QFileDialog.ShowDirsOnly | QFileDialog.DontUseNativeDialog
                )
                dlg.setSidebarUrls(
                    [
                        QUrl("file://" + r),
                        QUrl("file://" + os.getenv("HOME")),
                        QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/" + self.hutch),
                        QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/common"),
                        QUrl("file://" + utils.EPICS_DEV_TOP),
                    ]
                )
                dialog_layout = dlg.layout()
                tmp = QLabel()
                tmp.setText("Parent")
                dialog_layout.addWidget(tmp, 4, 0)
                parentgui = QLineEdit()
                parentgui.setReadOnly(True)
                dialog_layout.addWidget(parentgui, 4, 1)

                def fn(dirname):
                    self.set_ioc_parent(parentgui, idm, dirname)

                dlg.directoryEntered.connect(fn)
                dlg.currentChanged.connect(fn)

                if dlg.exec_() == QDialog.Rejected:
                    editor.setCurrentIndex(0)
                    return
                try:
                    directory = str(dlg.selectedFiles()[0])
                    directory = normalize_path(directory, idm)
                except Exception:
                    return
                editor.setItemText(editor.lastitem, directory)
                editor.addItem("New Version")
                editor.lastitem += 1
                model.setData(index, QVariant(directory), Qt.EditRole)
            else:
                model.setData(index, QVariant(str(editor.currentText())), Qt.EditRole)
        elif col == table_model.STATE:
            idx = editor.currentIndex()
            model.setData(index, QVariant(idx), Qt.EditRole)
        else:
            QStyledItemDelegate.setModelData(self, editor, model, index)

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex):
        """https://doc.qt.io/qt-5/qstyleditemdelegate.html#sizeHint"""
        col = index.column()
        if col == table_model.HOST:
            if self.boxsize is None:
                result = QSize(150, 25)
            else:
                result = self.boxsize
        else:
            result = QStyledItemDelegate.sizeHint(self, option, index)
        return result

    def do_commit(self, _, editor: QComboBox):
        """https://doc.qt.io/qt-5/qabstractitemdelegate.html#commitData"""
        self.commitData.emit(editor)

    def set_ioc_parent(self, gui: QLineEdit, ioc: str, directory: str):
        if directory != "":
            try:
                pname = get_parent(directory, ioc)
            except Exception:
                pname = ""
            gui.setText(pname)
