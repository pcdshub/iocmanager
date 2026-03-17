"""
Functions for validating pending IOC configuration edits.
"""

from dataclasses import dataclass, fields
from enum import Enum

from .config import Config, IOCProc, check_special


class SpecialEditDecision(Enum):
    """
    Possible outcomes when validating pending special IOC edits.
    """

    ALLOW = "allow"
    INFO = "info"
    DENY = "deny"


@dataclass(frozen=True)
class SpecialEditResponse:
    """
    Structured result returned from special IOC edit validation.
    """

    decision: SpecialEditDecision
    message: str = ""


def _changed_iocproc_fields(
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


def _has_non_state_changes(new_proc: IOCProc, old_proc: IOCProc) -> bool:
    """
    If something else other than the IOC's on/off state has changed, return True.

    The 'disable' field tracks whether the IOC is off. The 'parent' field is
    computed automatically and is not considered a user edit.
    """
    return bool(
        _changed_iocproc_fields(
            new_proc,
            old_proc,
            ignore_fields={"disable", "parent"},
        )
    )


def _state_changed(new_proc: IOCProc, old_proc: IOCProc) -> bool:
    """
    Return True if the IOC on/off state has changed.
    """
    return new_proc.disable != old_proc.disable


def _is_special_ioc(ioc_name: str, hutch: str) -> bool:
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
) -> SpecialEditResponse:
    """
    Return whether the pending edits are limited to allowed state changes.

    Non-authorized users may only toggle the on/off state of IOCs listed in
    `iocmanager.special`.
    """
    if add_iocs or delete_iocs:
        return SpecialEditResponse(
            decision=SpecialEditDecision.DENY,
            message="Non-authorized users cannot add or delete IOCs.",
        )
    if not edit_iocs:
        return SpecialEditResponse(
            decision=SpecialEditDecision.INFO,
            message="No configuration changes to save or apply.",
        )

    for ioc_name, new_proc in edit_iocs.items():
        try:
            old_proc = config.procs[ioc_name]
        except KeyError:
            return SpecialEditResponse(
                decision=SpecialEditDecision.DENY,
                message=(
                    f"Unable to validate pending changes for {ioc_name} "
                    "against the saved configuration."
                ),
            )

        if not _is_special_ioc(ioc_name=ioc_name, hutch=hutch):
            return SpecialEditResponse(
                decision=SpecialEditDecision.DENY,
                message=(
                    f"You do not have permission to modify {ioc_name}. "
                    f"Contact the {hutch} controls administrator if you "
                    "need access to this IOC."
                ),
            )

        if _has_non_state_changes(new_proc, old_proc):
            return SpecialEditResponse(
                decision=SpecialEditDecision.DENY,
                message=(
                    "Non-authorized users can only change IOC state "
                    f"(Off or Dev/Prod) for {ioc_name}."
                ),
            )
        if not _state_changed(new_proc, old_proc):
            return SpecialEditResponse(
                decision=SpecialEditDecision.INFO,
                message=f"{ioc_name} is unchanged. Nothing to save or apply for this IOC.",
            )

    return SpecialEditResponse(decision=SpecialEditDecision.ALLOW)
