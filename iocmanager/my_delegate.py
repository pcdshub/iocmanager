import os

from qtpy.QtCore import QSize, Qt, QUrl, QVariant
from qtpy.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QStyledItemDelegate,
    QWidget,
)

from . import hostname_ui, my_model, utils


class hostnamedialog(QDialog):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.ui = hostname_ui.Ui_Dialog()
        self.ui.setupUi(self)


class MyDelegate(QStyledItemDelegate):
    def __init__(self, parent, hutch):
        QStyledItemDelegate.__init__(self, parent)
        self.parent = parent
        self.hutch = hutch
        self.boxsize = None
        self.hostdialog = hostnamedialog(parent)

    def createEditor(self, parent, option, index):
        col = index.column()
        if col == my_model.HOST or col == my_model.VERSION or col == my_model.STATE:
            editor = QComboBox(parent)
            editor.setAutoFillBackground(True)
            editor.currentIndexChanged.connect(lambda n: self.do_commit(n, editor))
            if col == my_model.HOST:
                items = index.model().hosts
            elif col == my_model.VERSION:
                items = index.model().history(index.row())
            else:
                items = my_model.statecombolist
            for item in items:
                editor.addItem(item)
            editor.lastitem = editor.count()
            if col == my_model.HOST:
                editor.addItem("New Host")
                if self.boxsize is None:
                    self.boxsize = QSize(150, 25)
            elif col == my_model.VERSION:
                editor.addItem("New Version")
            # STATE doesn't need another entry!
            return editor
        else:
            return QStyledItemDelegate.createEditor(self, parent, option, index)

    def setEditorData(self, editor, index):
        col = index.column()
        if col == my_model.HOST:
            value = index.model().data(index, Qt.EditRole).value()
            try:
                idx = index.model().hosts.index(value)
                editor.setCurrentIndex(idx)
            except Exception:
                editor.setCurrentIndex(editor.lastitem)
        elif col == my_model.VERSION:
            # We don't have anything to do here.  It is created pointing to 0
            # (the newest setting)
            # And after setModelData, it is pointing to what we just added.
            pass
        elif col == my_model.STATE:
            value = index.model().data(index, Qt.EditRole).value()
            try:
                idx = my_model.statelist.index(value)
                if idx >= len(my_model.statecombolist):
                    idx = len(my_model.statecombolist) - 1
                editor.setCurrentIndex(idx)
            except Exception:
                editor.setCurrentIndex(editor.lastitem)
        else:
            QStyledItemDelegate.setEditorData(self, editor, index)

    def setParent(self, gui, ioc, dir):
        if dir != "":
            gui.setText(utils.findParent(ioc, dir))

    def setModelData(self, editor, model, index):
        col = index.column()
        if col == my_model.HOST:
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
        elif col == my_model.VERSION:
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
                id = model.getID(row)
                d = QFileDialog(self.parent, "New Version for %s" % id, r)
                d.setFileMode(QFileDialog.Directory)
                d.setOptions(QFileDialog.ShowDirsOnly | QFileDialog.DontUseNativeDialog)
                d.setSidebarUrls(
                    [
                        QUrl("file://" + r),
                        QUrl("file://" + os.getenv("HOME")),
                        QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/" + self.hutch),
                        QUrl("file://" + utils.EPICS_SITE_TOP + "ioc/common"),
                        QUrl("file://" + utils.EPICS_DEV_TOP),
                    ]
                )
                dialog_layout = d.layout()
                tmp = QLabel()
                tmp.setText("Parent")
                dialog_layout.addWidget(tmp, 4, 0)
                parentgui = QLineEdit()
                parentgui.setReadOnly(True)
                dialog_layout.addWidget(parentgui, 4, 1)

                def fn(dir):
                    self.setParent(parentgui, id, dir)

                d.directoryEntered.connect(fn)
                d.currentChanged.connect(fn)

                if d.exec_() == QDialog.Rejected:
                    editor.setCurrentIndex(0)
                    return
                try:
                    dir = str(d.selectedFiles()[0])
                    dir = utils.fixdir(dir, id)
                except Exception:
                    return
                editor.setItemText(editor.lastitem, dir)
                editor.addItem("New Version")
                editor.lastitem += 1
                model.setData(index, QVariant(dir), Qt.EditRole)
            else:
                model.setData(index, QVariant(str(editor.currentText())), Qt.EditRole)
        elif col == my_model.STATE:
            idx = editor.currentIndex()
            model.setData(index, QVariant(idx), Qt.EditRole)
        else:
            QStyledItemDelegate.setModelData(self, editor, model, index)

    def sizeHint(self, option, index):
        col = index.column()
        if col == my_model.HOST:
            if self.boxsize is None:
                result = QSize(150, 25)
            else:
                result = self.boxsize
        else:
            result = QStyledItemDelegate.sizeHint(self, option, index)
        return result

    def do_commit(self, n, editor):
        self.commitData.emit(editor)
