import pytest
from pytestqt.qtbot import QtBot

from ..config import IOCProc
from ..dialog_edit_details import DetailsDialog


@pytest.fixture(scope="function")
def details_dialog(qtbot: QtBot):
    dialog = DetailsDialog()
    qtbot.add_widget(dialog)
    return dialog


def get_cool_ioc() -> IOCProc:
    return IOCProc(
        name="cool_name",
        port=30001,
        host="host",
        path="path",
        alias="Cool Beans",
        cmd="better_st.cmd",
        delay=20,
    )


def test_set_ioc_proc(details_dialog: DetailsDialog):
    details_dialog.set_ioc_proc(ioc_proc=get_cool_ioc())
    assert details_dialog.ui.aliasEdit.text() == "Cool Beans"
    assert details_dialog.ui.cmdEdit.text() == "better_st.cmd"
    assert details_dialog.ui.delayEdit.value() == 20


def test_get_ioc_proc(details_dialog: DetailsDialog):
    ioc_proc = details_dialog.get_ioc_proc()
    assert not ioc_proc.alias
    assert not ioc_proc.cmd
    assert not ioc_proc.delay


def test_ioc_proc_round_trip(details_dialog: DetailsDialog):
    old_proc = get_cool_ioc()
    details_dialog.set_ioc_proc(ioc_proc=old_proc)
    new_proc = details_dialog.get_ioc_proc()
    assert new_proc == old_proc
    assert new_proc is not old_proc
