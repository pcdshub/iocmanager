"""
The dialog_apply_verify module implements a dialog to approve an apply_config.

This takes the form of a verify callable that can be passed to apply_config,
allowing the user to check which IOCs they'd like to apply changes to.
"""

from functools import partial

from qtpy.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QMessageBox, QWidget

from . import ui_apply_verify
from .procserv_tools import ApplyConfigContext, VerifyPlan


def verify_dialog(context: ApplyConfigContext, plan: VerifyPlan) -> VerifyPlan:
    """
    Allow the user to select which IOCs to apply config to.

    This will split the IOCs into four distinct groups:
    - "KILL"
    - "KILL and RESTART"
    - "START"
    - "RESTRT"

    All IOCs will begin unchecked and the user must opt-in by checking them.
    """
    if not any((plan.kill_list, plan.restart_list, plan.start_list)):
        QMessageBox.critical(
            None, "Warning", "Nothing to apply!", QMessageBox.Ok, QMessageBox.Ok
        )
        return VerifyPlan(kill_list=[], start_list=[], restart_list=[])
    dialog = ApplyVerifyDialog(context=context, plan=plan)
    if dialog.exec_() == QDialog.Accepted:
        return dialog.get_verify_result()
    else:
        return VerifyPlan(kill_list=[], start_list=[], restart_list=[])


class ApplyVerifyDialog(QDialog):
    """
    Load the pyuic-compiled ui/apply_verify.ui into a QDialog.

    This dialog is meant to be used via the verify_dialog function above.
    """

    def __init__(
        self,
        context: ApplyConfigContext,
        plan: VerifyPlan,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.ui = ui_apply_verify.Ui_Dialog()
        self.ui.setupUi(self)

        self.context = context
        self.plan = plan

        clear_button = self.ui.buttonBox.addButton(
            "Clear All", QDialogButtonBox.ActionRole
        )
        set_button = self.ui.buttonBox.addButton("Set All", QDialogButtonBox.ActionRole)
        clear_button.clicked.connect(partial(self.set_state_all, False))
        set_button.clicked.connect(partial(self.set_state_all, True))

        self.checkboxes: list[QCheckBox] = []
        self.checkbox_ioc_names: list[str] = []
        kill = [name for name in plan.kill_list if name not in plan.start_list]
        kill_start = [name for name in plan.kill_list if name in plan.start_list]
        start = [name for name in plan.start_list if name not in plan.kill_list]

        self._add_checkbox_section(action="KILL", ioc_names=kill)
        self._add_checkbox_section(action="KILL and RESTART", ioc_names=kill_start)
        self._add_checkbox_section(action="START", ioc_names=start)
        self._add_checkbox_section(action="RESTART", ioc_names=plan.restart_list)

    def _add_checkbox_section(self, action: str, ioc_names: list[str]):
        for ioc in ioc_names:
            # Alias is only in the desired ioc config
            # For host and port, the status file needs priority
            # Defaults
            name = ioc
            alias = ""
            host = "no_host"
            port = 0
            # Override with the desired config if present
            try:
                ioc_proc = self.context.proc_config[ioc]
            except KeyError:
                ...
            else:
                name = ioc_proc.name
                alias = ioc_proc.alias
                host = ioc_proc.host
                port = ioc_proc.port
            # Override with the live values if present
            try:
                ioc_file = self.context.status_files[ioc]
            except KeyError:
                ...
            else:
                name = ioc_file.name
                host = ioc_file.host
                port = ioc_file.port
            # Whatever values we ended up with, we're using
            checkbox = QCheckBox(self)
            checkbox.setChecked(False)
            if alias:
                checkbox.setText(f"{action} {alias} ({name}) on {host}:{port}")
            else:
                checkbox.setText(f"{action} {name} on {host}:{port}")
            self.checkboxes.append(checkbox)
            self.checkbox_ioc_names.append(name)
            self.ui.scroll_contents.layout().addWidget(checkbox)

    def set_state_all(self, checked: bool):
        """Slot to check or uncheck all the checkboxes."""
        for box in self.checkboxes:
            box.setChecked(checked)

    def get_verify_result(self) -> VerifyPlan:
        """After the user has made their choice, call this to get the result."""
        verified_iocs = set()
        for ioc_name, checkbox in zip(
            self.checkbox_ioc_names, self.checkboxes, strict=True
        ):
            if checkbox.isChecked():
                verified_iocs.add(ioc_name)
        return VerifyPlan(
            kill_list=[name for name in self.plan.kill_list if name in verified_iocs],
            start_list=[name for name in self.plan.start_list if name in verified_iocs],
            restart_list=[
                name for name in self.plan.restart_list if name in verified_iocs
            ],
        )
