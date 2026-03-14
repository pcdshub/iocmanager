"""
Functions for validating pending IOC configuration edits.
"""

from dataclasses import fields
from .config import Config, IOCProc, check_special


def changed_iocproc_fields(
    new_proc: IOCProc,
    old_proc: IOCProc,
    ignore_fields: set[str] | None = None,
) -> set[str]:
    """
    Return the names of the IOC settings that are different.

    Parameters
    ----------
    new_proc : IOCProc
        The pending IOC configuration
    old_proc : IOCProc
        The saved IOC configuration
    ignore_fields : set[str], optional 
        Field names to skip while comparing

    Returns
    -------
    set[str]
        The set of field names whose values differ.
    """
    ignore_fields = ignore_fields or set()
    changed_fields = set()
    for field_info in fields(IOCProc):
        field_name = field_info.name
        if field_name in ignore_fields:
            continue
        if getattr(new_proc, field_name) != getattr(old_proc, field_name):
            changed_fields.add(field_name)
    return changed_fields


def has_non_state_changes(new_proc: IOCProc, old_proc: IOCProc) -> bool:
    """
    If something else other than the IOC's on/off state has changed, return True.

    The 'disable' field tracks whether the IOC is off. The 'parent' field is
    computed automatically and is not considered a user edit.
    """
    return bool(
        changed_iocproc_fields(
            new_proc,
            old_proc,
            ignore_fields={"disable", "parent"},
        )
    )


def state_changed(new_proc: IOCProc, old_proc: IOCProc) -> bool:
    """
    Return True if the IOC on/off state has changed.
    """
    return new_proc.disable != old_proc.disable


def is_special_ioc(ioc_name: str, hutch: str) -> bool:
    """
    Return True if the IOC is listed in `iocmanager.special` for this hutch.
    """
    return check_special(req_ioc=ioc_name, req_hutch=hutch)


def special_edits_ok(
    *,
    config: Config,
    add_iocs: dict,
    edit_iocs: dict[str, IOCProc],
    delete_iocs,
    hutch: str,
) -> tuple[bool, str]:
    """
    Return whether the pending edits are limited to allowed state changes.

    Limited-access users may only toggle the on/off state of IOCs listed in
    `iocmanager.special`.
    """
    if add_iocs or delete_iocs:
        return False, "Limited-access users cannot add or delete IOCs."
    if not edit_iocs:
        return False, "No configuration changes to save."

    for ioc_name, new_proc in edit_iocs.items():
        try:
            old_proc = config.procs[ioc_name]
        except KeyError:
            return (
                False,
                f"Unable to validate pending changes for {ioc_name} against the saved configuration.",
            )

        if has_non_state_changes(new_proc, old_proc):
            return (
                False,
                f"Limited-access users can only change IOC state (Off/Dev) for {ioc_name}.",
            )
        if not state_changed(new_proc, old_proc):
            return (
                False,
                f"{ioc_name} is unchanged. Nothing to save for this IOC.",
            )
        if not is_special_ioc(ioc_name=ioc_name, hutch=hutch):
            return (
                False,
                f"{ioc_name} is not listed in iocmanager.special for {hutch}.",
            )

    return True, ""
