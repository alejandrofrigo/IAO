from __future__ import annotations

from omega.service import OmegaService


class _RecoveryStore:
    def __init__(self):
        self.events = []

    def recover_interrupted_tasks(self):
        return [
            {"id": "private-task-id-1", "owner": "private-owner-1"},
            {"id": "private-task-id-2", "owner": "private-owner-2"},
        ]

    def audit(self, *args, **kwargs):
        self.events.append((args, kwargs))


def test_startup_recovery_audit_aggregates_without_task_or_owner_identifiers():
    store = _RecoveryStore()
    OmegaService(store, object(), "x" * 32)

    assert len(store.events) == 1
    args, metadata = store.events[0]
    assert args == ("system", "TASK_INTERRUPTED_ON_RESTART", "task_recovery")
    assert metadata == {
        "recovered_count": 2,
        "decision": "FAIL_CLOSED",
        "reason": "PROCESS_INTERRUPTED",
    }
    serialized = repr(store.events)
    assert "private-task-id" not in serialized
    assert "private-owner" not in serialized
