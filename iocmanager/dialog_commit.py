"""
The dialog_commit module defines the CommitDialog's logic.

The CommitDialog is used to prompt the user to enter a commit
message.

The CommitDialog's layout is defined in ui/commit.ui
"""

from enum import IntEnum

from qtpy.QtWidgets import QDialog, QDialogButtonBox

from . import ui_commit
from .type_hints import ParentWidget


class CommitOption(IntEnum):
    """
    Integer codes for the three results from the CommitDialog.
    """

    SAVE_AND_COMMIT = 0
    SAVE_ONLY = 1
    CANCEL = 2


class CommitDialog(QDialog):
    """
    Load the pyuic-compiled ui/commit.ui into a QDialog.

    This dialog contains a large QTextEdit that can be used to enter a
    commit message.
    It is opened right after a user asks to apply the configuration,
    and right before we save the file.
    """

    def __init__(self, hutch: str, parent: ParentWidget = None):
        super().__init__(parent)
        self.ui = ui_commit.Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle(f"Commit {hutch}")
        self.setResult(CommitOption.CANCEL)
        self.ui.buttonBox.button(QDialogButtonBox.Yes).clicked.connect(self.yes_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.No).clicked.connect(self.no_clicked)
        self.ui.buttonBox.button(QDialogButtonBox.Cancel).clicked.connect(
            self.cancel_clicked
        )

    def get_comment(self) -> str:
        return self.ui.commentEdit.toPlainText()

    def reset(self):
        self.ui.commentEdit.setPlainText("")

    def yes_clicked(self):
        self.setResult(CommitOption.SAVE_AND_COMMIT)

    def no_clicked(self):
        self.setResult(CommitOption.SAVE_ONLY)

    def cancel_clicked(self):
        # Technically this is always already set, but it's good to be paranoid
        self.setResult(CommitOption.CANCEL)
