"""
The table_delegate module defines editing behavior for the main GUI table.

This implements a QStyledItemDelegate with different editors for each of the
columns in the central QTableView of the GUI.

See https://doc.qt.io/qt-5/qstyleditemdelegate.html#details
"""

import logging
import os

from qtpy.QtCore import (
    QAbstractItemModel,
    QModelIndex,
    QSize,
    QSortFilterProxyModel,
    QUrl,
)
from qtpy.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QWidget,
)

from . import ui_hostname
from .env_paths import env_paths
from .epics_paths import get_parent, normalize_path, standard_ioc_paths
from .table_model import IOCTableModel, TableColumn
from .type_hints import ParentWidget

STATECOMBOLIST = ["Off", "Dev/Prod"]
logger = logging.getLogger(__name__)


class HostnameDialog(QDialog):
    """
    Load the pyuic-compiled ui/hostname.ui into a QDialog.

    This is a simple dialog that allows the user to input a
    hostname into a QLineEdit. It pops up when the user selects
    the "New Host" option when editing IOC hosts in the table.
    """

    def __init__(self, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = ui_hostname.Ui_Dialog()
        self.ui.setupUi(self)


class IOCTableDelegate(QStyledItemDelegate):
    """
    QStyledItemDelegate that helps us show and edit the IOCTableModel.

    Does not reimplement paint (we only use text data), but we do need to implement
    many of the other functions.

    Also skips updateEditorGeometry (the default is fine)

    Notes on QStyledItemDelegate
    (https://doc.qt.io/archives/qt-5.15/qstyleditemdelegate.html#subclassing-qstyleditemdelegate)

    - sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize
    - createEditor(
          self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex
      ) -> QWidget
    - setEditorData(self, editor: QWidget, index: QModelIndex) -> None
    - setModelData(
          self, editor: QWidget, model: QAbstractItemModel, index: QModelIndex
      ) -> None
    """

    def __init__(
        self,
        hutch: str,
        model: IOCTableModel,
        proxy_model: QSortFilterProxyModel | None = None,
        parent: ParentWidget = None,
    ):
        super().__init__(parent)
        self.hutch = hutch
        self.model = model
        self.proxy_model = proxy_model
        self.hostdialog = HostnameDialog(parent)

    def _source_index(self, index: QModelIndex) -> QModelIndex:
        """If we have a proxy model, convert to source model."""
        if self.proxy_model is None:
            return index
        sauce = self.proxy_model.mapToSource(index)
        return sauce

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        """
        Returns the size needed by the delegate to display the item.

        This is used when the table first renders to set the initial row/column sizes.
        The default default without this function is to have exactly enough space
        to fix the text. This works OK sometimes but other times we don't have a
        value filled in on first render, and cells get generated much too small.

        This function sets some minimums for cell height and width (column-specific)

        https://doc.qt.io/qt-5/qstyleditemdelegate.html#sizeHint
        """
        index = self._source_index(index)
        size = super().sizeHint(option, index)

        # Makes the table feel less cramped!
        if size.height() < 25:
            size.setHeight(25)

        # Make sure there's enough room for incoming data/edits
        match index.column():
            case TableColumn.HOST | TableColumn.VERSION | TableColumn.PARENT:
                min_width = 150
            case TableColumn.IOCNAME | TableColumn.ID:
                min_width = 110
            case TableColumn.STATUS:
                min_width = 80
            case _:
                min_width = 50

        if size.width() < min_width:
            size.setWidth(min_width)

        return size

    def createEditor(
        self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex
    ) -> QWidget:
        """
        Returns the widget used to edit the item specified by index for editing.

        For some columns we'll edit via combobox, for others we'll fallback to the
        default in-line text edit behavior.

        https://doc.qt.io/qt-5/qstyleditemdelegate.html#createEditor
        """
        index = self._source_index(index)
        col = index.column()
        if col in (TableColumn.STATE, TableColumn.HOST, TableColumn.VERSION):
            editor = QComboBox(parent)
            editor.setAutoFillBackground(True)
            editor.activated.connect(lambda _: self.commitData.emit(editor))
            if col == TableColumn.STATE:
                items = STATECOMBOLIST
            elif col == TableColumn.HOST:
                items = self.model.get_next_config().hosts
            elif col == TableColumn.VERSION:
                ioc_proc = self.model.get_ioc_proc(ioc=index)
                items = [ioc_proc.path]
                items.extend(path for path in ioc_proc.history if path != ioc_proc.path)
            else:
                raise RuntimeError("Invalid codepath")
            for item in items:
                editor.addItem(item)
            if col == TableColumn.HOST:
                editor.addItem("New Host")
            elif col == TableColumn.VERSION:
                editor.addItem("New Version")
            # STATE doesn't need another entry!
            return editor
        else:
            return super().createEditor(parent, option, index)

    def setEditorData(self, editor: QWidget | QComboBox, index: QModelIndex):
        """
        Sets the data to be displayed and edited by the editor.

        For the comboboxes, this will set the starting index to match
        the stored value.
        For others this will use the default behavior.

        https://doc.qt.io/qt-5/qstyleditemdelegate.html#setEditorData
        """
        index = self._source_index(index)
        if not isinstance(editor, QComboBox):
            return super().setEditorData(editor, index)

        match index.column():
            case TableColumn.STATE:
                # Coerce off -> off and both dev and prod to dev/prod
                if self.model.data(index) == "Off":
                    editor.setCurrentIndex(0)
                else:
                    editor.setCurrentIndex(1)
            case TableColumn.HOST:
                # Default last item (New Host)
                editor.setCurrentIndex(editor.count() - 1)
                # If there's a match, match it (otherwise this is a no-op)
                editor.setCurrentText(str(self.model.data(index)))
            case TableColumn.VERSION:
                # We don't have anything to do here.  It is created pointing to 0
                # (the newest setting)
                # And after setModelData, it is pointing to what we just added.
                ...

    def setModelData(
        self, editor: QWidget, model: QAbstractItemModel, index: QModelIndex
    ):
        """
        Gets data from the editor widget and stores in the model.

        https://doc.qt.io/qt-5/qstyleditemdelegate.html#setModelData

        For whatever reason, this is the only function that doesn't need
        to be converted from proxy coordinates to standard coordinates.
        """
        if not isinstance(editor, QComboBox):
            return super().setModelData(editor, model, index)

        idx = editor.currentIndex()

        match index.column():
            case TableColumn.STATE:
                model.setData(index, idx)
            case TableColumn.HOST:
                if idx == editor.count() - 1:
                    # Pick a new hostname!
                    if self.hostdialog.exec_() == QDialog.Accepted:
                        value = self.hostdialog.ui.hostname.text()
                        model.setData(index, value)
                    else:
                        # Revert the widget, else it stays on "new"
                        self.setEditorData(editor, index)
                else:
                    model.setData(index, editor.currentText())
            case TableColumn.VERSION:
                if idx == editor.count() - 1:
                    # Pick a new directory!
                    current_version = editor.itemText(0)
                    full_path_candidate = os.path.join(
                        env_paths.EPICS_SITE_TOP, current_version
                    )
                    if os.path.exists(full_path_candidate):
                        current_version = full_path_candidate

                    ioc_name = str(model.data(model.index(index.row(), TableColumn.ID)))
                    parent = self.parent()
                    if not isinstance(parent, QWidget):
                        parent = None
                    dlg = QFileDialog(
                        parent, f"New Version for {ioc_name}", current_version
                    )
                    dlg.setFileMode(QFileDialog.Directory)
                    dlg.setOptions(
                        QFileDialog.ShowDirsOnly | QFileDialog.DontUseNativeDialog
                    )

                    sidebar_urls = [current_version] + standard_ioc_paths(
                        hutch=self.hutch
                    )
                    dlg.setSidebarUrls([QUrl("file://" + url) for url in sidebar_urls])

                    dialog_layout = dlg.layout()
                    if isinstance(dialog_layout, QGridLayout):
                        # Guard against breaking changes upstream
                        tmp = QLabel()
                        tmp.setText("Parent")
                        dialog_layout.addWidget(tmp, 4, 0)
                        parentgui = QLineEdit()
                        parentgui.setReadOnly(True)
                        dialog_layout.addWidget(parentgui, 4, 1)

                        def fn(dirname):
                            self.set_ioc_parent(parentgui, ioc_name, dirname)

                        dlg.directoryEntered.connect(fn)
                        dlg.currentChanged.connect(fn)
                    else:
                        logger.error("Qt API changed, QFileDialog not QGridLayout")

                    if dlg.exec_() == QDialog.Rejected:
                        editor.setCurrentIndex(0)
                        return
                    try:
                        directory = str(dlg.selectedFiles()[0])
                        directory = normalize_path(directory, ioc_name)
                    except Exception:
                        return
                    model.setData(index, directory)
                else:
                    model.setData(index, editor.currentText())

    def set_ioc_parent(self, gui: QLineEdit, ioc: str, directory: str):
        """Slot to update the "parent" value in the new version selection dialog."""
        if directory != "":
            try:
                pname = get_parent(directory, ioc)
            except Exception:
                pname = ""
            gui.setText(pname)
