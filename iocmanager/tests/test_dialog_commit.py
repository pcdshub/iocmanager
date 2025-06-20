import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtCore import Qt
from qtpy.QtWidgets import QDialogButtonBox

from ..dialog_commit import CommitDialog, CommitOption


@pytest.fixture(scope="function")
def commit_dialog(qtbot: QtBot) -> CommitDialog:
    dialog = CommitDialog(hutch="pytest")
    qtbot.add_widget(dialog)
    return dialog


def test_get_comment(commit_dialog: CommitDialog):
    commit_dialog.ui.commentEdit.setPlainText("Some text")
    assert commit_dialog.get_comment() == "Some text"


def test_reset(commit_dialog: CommitDialog):
    commit_dialog.ui.commentEdit.setPlainText("Some text")
    commit_dialog.reset()
    assert not commit_dialog.get_comment()


def test_yes(commit_dialog: CommitDialog, qtbot: QtBot):
    def result_is_yes():
        assert commit_dialog.result() == CommitOption.SAVE_AND_COMMIT

    qtbot.mouseClick(
        commit_dialog.ui.buttonBox.button(QDialogButtonBox.Yes),
        Qt.MouseButton.LeftButton,
    )
    qtbot.waitUntil(result_is_yes, timeout=1000)


def test_no(commit_dialog: CommitDialog, qtbot: QtBot):
    def result_is_no():
        assert commit_dialog.result() == CommitOption.SAVE_ONLY

    qtbot.mouseClick(
        commit_dialog.ui.buttonBox.button(QDialogButtonBox.No),
        Qt.MouseButton.LeftButton,
    )
    qtbot.waitUntil(result_is_no, timeout=1000)


def test_cancel(commit_dialog: CommitDialog, qtbot: QtBot):
    def result_is_cancel():
        assert commit_dialog.result() == CommitOption.CANCEL

    qtbot.mouseClick(
        commit_dialog.ui.buttonBox.button(QDialogButtonBox.Cancel),
        Qt.MouseButton.LeftButton,
    )
    qtbot.waitUntil(result_is_cancel, timeout=1000)
