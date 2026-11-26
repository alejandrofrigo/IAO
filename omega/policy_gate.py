"""Deterministic authorization gate for IAO autonomous operations.

The language model is never an authority source. Every action is evaluated
against explicit runtime state and evidence supplied by the control plane.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class RuntimeState(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    RESTRICTED = "RESTRICTED"


class ActionClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    EXTERNAL = "EXTERNAL"
    DESTRUCTIVE = "DESTRUCTIVE"
    SECURITY_CRITICAL = "SECURITY_CRITICAL"


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    action_class: ActionClass
    description: str
    backup_verified: bool = False
    rollback_available: bool = False
    human_approval: bool = False
    audit_healthy: bool = False
    target_authorized: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    state: RuntimeState
    reason: str
    requirements: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        result["requirements"] = list(self.requirements)
        return result


def evaluate_action(
    request: ActionRequest,
    state: RuntimeState,
) -> Decision:
    """Evaluate an action without executing it or trusting model assertions."""
    if not request.action_id.strip():
        return Decision(False, state, "missing_action_id", ("valid_action_id",))

    if not request.description.strip():
        return Decision(False, state, "missing_description", ("description",))

    if request.action_class == ActionClass.READ_ONLY:
        return Decision(True, state, "read_only_permitted", ())

    if request.action_class == ActionClass.SECURITY_CRITICAL:
        return Decision(
            False, state, "security_critical_requires_separate_admin_workflow",
            ("administrator_workflow",),
        )

    if request.action_class == ActionClass.DESTRUCTIVE:
        if state == RuntimeState.RESTRICTED:
            return Decision(
                False, state, "restricted_runtime_state",
                ("NORMAL_or_DEGRADED_runtime_state",),
            )
        if not request.human_approval:
            return Decision(False, state, "human_approval_required",
                            ("human_approval",))
        if not request.backup_verified:
            return Decision(False, state, "verified_backup_required",
                            ("verified_backup",))
        if not request.rollback_available:
            return Decision(False, state, "rollback_required",
                            ("rollback_plan",))
        if not request.audit_healthy:
            return Decision(False, state, "audit_chain_unhealthy",
                            ("healthy_audit_chain",))
        return Decision(True, state, "approved_destructive_action", ())

    if request.action_class == ActionClass.EXTERNAL:
        if state != RuntimeState.NORMAL:
            return Decision(False, state, "external_action_blocked_by_runtime_state",
                            ("NORMAL_runtime_state",))
        if not request.target_authorized:
            return Decision(False, state, "external_target_not_authorized",
                            ("authorized_target",))
        if not request.audit_healthy:
            return Decision(False, state, "audit_chain_unhealthy",
                            ("healthy_audit_chain",))
        return Decision(True, state, "authorized_external_action", ())

    if request.action_class == ActionClass.REVERSIBLE:
        if state == RuntimeState.RESTRICTED:
            return Decision(False, state, "restricted_runtime_state",
                            ("NORMAL_or_DEGRADED_runtime_state",))
        if not request.backup_verified:
            return Decision(False, state, "verified_backup_required",
                            ("verified_backup",))
        if not request.rollback_available:
            return Decision(False, state, "rollback_required",
                            ("rollback_plan",))
        if not request.audit_healthy:
            return Decision(False, state, "audit_chain_unhealthy",
                            ("healthy_audit_chain",))
        return Decision(True, state, "reversible_action_permitted", ())

    return Decision(False, state, "unknown_action_class", ("recognized_action_class",))
