# Form implementation generated from reading ui file 'details.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog:
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(417, 171)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 0, 0, 1, 1)
        self.aliasEdit = QtWidgets.QLineEdit(Dialog)
        self.aliasEdit.setObjectName("aliasEdit")
        self.gridLayout.addWidget(self.aliasEdit, 0, 1, 1, 1)
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 1, 0, 1, 1)
        self.cmdEdit = QtWidgets.QLineEdit(Dialog)
        self.cmdEdit.setObjectName("cmdEdit")
        self.gridLayout.addWidget(self.cmdEdit, 1, 1, 1, 1)
        self.flagCheckBox = QtWidgets.QCheckBox(Dialog)
        self.flagCheckBox.setObjectName("flagCheckBox")
        self.gridLayout.addWidget(self.flagCheckBox, 2, 0, 1, 2)
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 3, 0, 1, 1)
        self.delayEdit = QtWidgets.QLineEdit(Dialog)
        self.delayEdit.setObjectName("delayEdit")
        self.gridLayout.addWidget(self.delayEdit, 3, 1, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Ok
        )
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 4, 0, 1, 2)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label_3.setText(_translate("Dialog", "IOC Alias:"))
        self.label.setText(_translate("Dialog", "Command:"))
        self.flagCheckBox.setText(_translate("Dialog", "Append IOC Name to Command"))
        self.label_2.setText(_translate("Dialog", "Delay after Start (sec):"))
