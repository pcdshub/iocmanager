from unittest.mock import Mock

import pytest
from pytestqt.qtbot import QtBot
from qtpy.QtWidgets import QTableView

from ..config import IOCProc
from ..dialog_find_pv import FindPVDialog
from ..table_model import IOCTableModel


@pytest.fixture(scope="function")
def find_pv_dialog(model: IOCTableModel, qtbot: QtBot):
    table_view = QTableView()
    table_view.setModel(model)
    dialog = FindPVDialog(model=model, view=table_view)
    qtbot.add_widget(dialog)
    return dialog


def test_find_pv(find_pv_dialog: FindPVDialog, model: IOCTableModel, qtbot: QtBot):
    """
    There's a lot of moving parts here, just set up a real test and check text
    """
    # Patch over exec_ so we don't show the dialog and wait forever
    exec_mock = Mock()
    find_pv_dialog.exec_ = exec_mock

    # Add missing ioc to the config to make sure we search in it
    # We also need ioc1 but this name is used in the model fixture setup too
    model.add_ioc(
        ioc_proc=IOCProc(name="iocbad", port=40002, host="host", path="", alias="Bad!")
    )

    # See tests/ioc_data/ioc1/iocInfo/IOC.pvlist
    # and tests/ioc_data/iocbad/iocInfo/IOC.pvlist
    # for match sources

    # No matches -> expect the text to say no matches
    def no_matches():
        assert "produced no matches" in find_pv_dialog.ui.found_pvs.toPlainText()

    find_pv_dialog.find_pv_and_exec("definitely_not_a_match")
    qtbot.wait_until(no_matches, timeout=1000)
    assert exec_mock.call_count == 1

    # A few matches -> should all be in the text
    def a_few_matches():
        for text in ("TST:FLOAT", "TST:INT", "TST:STRING"):
            assert text in find_pv_dialog.ui.found_pvs.toPlainText()
        assert "ioc1" in find_pv_dialog.ui.found_pvs.toPlainText()
        assert "iocbad" not in find_pv_dialog.ui.found_pvs.toPlainText()

    find_pv_dialog.find_pv_and_exec("TST:.*")
    qtbot.wait_until(a_few_matches, timeout=1000)
    assert exec_mock.call_count == 2

    # One match -> the view stuff shouldn't error out, this one has an alias too
    def one_match():
        assert "What:An:IOC" in find_pv_dialog.ui.found_pvs.toPlainText()
        assert "ioc1" not in find_pv_dialog.ui.found_pvs.toPlainText()
        assert "iocbad" in find_pv_dialog.ui.found_pvs.toPlainText()
        assert "Bad!" in find_pv_dialog.ui.found_pvs.toPlainText()

    find_pv_dialog.find_pv_and_exec("What:An:IOC")
    qtbot.wait_until(one_match, timeout=1000)
    assert exec_mock.call_count == 3
