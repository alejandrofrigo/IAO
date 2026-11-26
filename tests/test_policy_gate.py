from omega.policy_gate import (
    ActionClass, ActionRequest, RuntimeState, evaluate_action,
)


def req(kind, **kwargs):
    return ActionRequest("test-1", kind, "test action", **kwargs)


def test_read_only_allowed_when_degraded():
    d = evaluate_action(req(ActionClass.READ_ONLY), RuntimeState.DEGRADED)
    assert d.allowed


def test_reversible_requires_backup_and_rollback():
    d = evaluate_action(req(ActionClass.REVERSIBLE), RuntimeState.NORMAL)
    assert not d.allowed
    assert d.reason == "verified_backup_required"


def test_reversible_allowed_with_evidence():
    d = evaluate_action(
        req(ActionClass.REVERSIBLE, backup_verified=True,
            rollback_available=True, audit_healthy=True),
        RuntimeState.NORMAL,
    )
    assert d.allowed


def test_external_blocked_when_audit_unhealthy():
    d = evaluate_action(
        req(ActionClass.EXTERNAL, target_authorized=True),
        RuntimeState.NORMAL,
    )
    assert not d.allowed
    assert d.reason == "audit_chain_unhealthy"


def test_external_requires_normal_state_and_authorized_target():
    d = evaluate_action(
        req(ActionClass.EXTERNAL, target_authorized=True, audit_healthy=True),
        RuntimeState.DEGRADED,
    )
    assert not d.allowed


def test_destructive_requires_human_approval():
    d = evaluate_action(
        req(ActionClass.DESTRUCTIVE, backup_verified=True,
            rollback_available=True, audit_healthy=True),
        RuntimeState.NORMAL,
    )
    assert not d.allowed
    assert d.reason == "human_approval_required"


def test_security_critical_never_autonomously_allowed():
    d = evaluate_action(
        req(ActionClass.SECURITY_CRITICAL, human_approval=True,
            backup_verified=True, rollback_available=True, audit_healthy=True),
        RuntimeState.NORMAL,
    )
    assert not d.allowed


def test_restricted_state_blocks_reversible_actions():
    d = evaluate_action(
        req(ActionClass.REVERSIBLE, backup_verified=True,
            rollback_available=True, audit_healthy=True),
        RuntimeState.RESTRICTED,
    )
    assert not d.allowed


def test_decision_is_serializable():
    d = evaluate_action(req(ActionClass.READ_ONLY), RuntimeState.NORMAL)
    assert d.to_dict()["state"] == "NORMAL"
    assert d.to_dict()["allowed"] is True


def test_destructive_is_blocked_in_restricted_even_with_all_evidence():
    d = evaluate_action(
        req(
            ActionClass.DESTRUCTIVE,
            human_approval=True,
            backup_verified=True,
            rollback_available=True,
            audit_healthy=True,
        ),
        RuntimeState.RESTRICTED,
    )
    assert not d.allowed
    assert d.reason == "restricted_runtime_state"


def test_destructive_remains_allowed_in_normal_with_all_evidence():
    d = evaluate_action(
        req(
            ActionClass.DESTRUCTIVE,
            human_approval=True,
            backup_verified=True,
            rollback_available=True,
            audit_healthy=True,
        ),
        RuntimeState.NORMAL,
    )
    assert d.allowed
