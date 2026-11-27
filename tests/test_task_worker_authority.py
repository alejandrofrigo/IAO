from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from omega.service import POLICY_VERSION
from omega.task_worker import TaskWorker
from omega.tools.registry import ToolRegistry, ToolSpec


class _ClaimedTaskStore:
    def __init__(self, intent: dict) -> None:
        self.task = {
            "id": "queued-task-1",
            "lease_generation": 1,
            "owner": "operator:test-owner",
            "intent_json": json.dumps(intent),
        }
        self.final_state = None
        self.final_result = None
        self.cancel_requested = False
        self.executions = []
        self.events = []

    def claim_next_task(self, worker_id: str, *, lease_seconds: int = 60):
        task, self.task = self.task, None
        return task

    def update_claimed_task(
        self, task_id, worker_id, state, result=None, *, release=False, lease_generation=None
    ):
        self.final_state = state
        self.final_result = result
        return True

    def task_cancel_requested(self, task_id, worker_id, lease_generation):
        return self.cancel_requested

    def renew_task_lease(self, task_id, worker_id, lease_generation, lease_seconds):
        return not self.cancel_requested and lease_generation == self.task["lease_generation"]

    def audit(self, *args, **kwargs):
        self.events.append((args, kwargs))

    def add_tool_execution(self, *args, **kwargs):
        self.executions.append((args, kwargs))


class _RevokedAuthority:
    def verify_primary_device_for_session_digest(
        self, owner: str, session_digest: str, device_id: str
    ) -> bool:
        raise RuntimeError("authority revoked")



def _inline_tool_executor(run, verify, payload, _timeout):
    output = run(payload)
    return output, verify(output)


def _worker(authority):
    calls = []
    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="knowledge.search",
        version="1",
        scope="knowledge.search",
        effect_class="READ_ONLY",
        timeout_seconds=2,
        validate_input=lambda value: value,
        run=lambda value: calls.append(value) or {"items": []},
        verify=lambda value: "PASS",
    ))
    intent = {
        "allowed_capabilities": ["knowledge.search"],
        "authorized_scopes": ["knowledge.search"],
        "input": {"query": "safe test"},
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "policy_version": POLICY_VERSION,
        "budget": {"timeout_seconds": 2},
        "operator_session_digest": "a" * 64,
        "operator_device_id": "b" * 64,
    }
    store = _ClaimedTaskStore(intent)
    return TaskWorker(
        store, registry, worker_id="authority-test-worker",
        operator_identity_authority=authority,
        tool_executor=_inline_tool_executor,
    ), store, calls



def test_interruption_after_tool_invocation_is_not_replayed(tmp_path, monkeypatch):
    from omega.store import Store

    class SimulatedProcessInterruption(BaseException):
        pass

    store = Store(tmp_path / "worker-interruption.db", b"worker-test-audit-key-0123456789")
    calls = []
    task_id = "interrupted-task"
    owner = "operator:test-owner"
    intent = {
        "allowed_capabilities": ["knowledge.search"],
        "authorized_scopes": ["knowledge.search"],
        "input": {"query": "fault injection"},
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "policy_version": POLICY_VERSION,
        "budget": {"timeout_seconds": 2},
        "operator_session_digest": "a" * 64,
        "operator_device_id": "b" * 64,
    }
    task, created = store.create_task(task_id, owner, intent, None)
    assert created is True
    store.set_task_state(task["id"], "AUTHORIZED")
    assert store.queue_task(task["id"]) is True

    def run_tool(_payload):
        calls.append("invoked")
        raise SimulatedProcessInterruption()

    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="knowledge.search",
        version="1",
        scope="knowledge.search",
        effect_class="READ_ONLY",
        timeout_seconds=2,
        validate_input=lambda value: value,
        run=run_tool,
        verify=lambda value: "PASS",
    ))

    class ActiveAuthority:
        def verify_primary_device_for_session_digest(self, *_args):
            return True

    worker = TaskWorker(
        store, registry, worker_id="fault-injection-worker",
        operator_identity_authority=ActiveAuthority(),
        tool_executor=_inline_tool_executor,
    )
    try:
        with pytest.raises(SimulatedProcessInterruption):
            worker.run_once()

        assert calls == ["invoked"]
        running = store.get_task(task_id, owner)
        assert running["state"] == "RUNNING"

        recovered = store.recover_interrupted_tasks(
            now="2999-01-01T00:00:00+00:00"
        )
        assert recovered == [{"id": task_id, "owner": owner}]
        failed = store.get_task(task_id, owner)
        assert failed["state"] == "FAILED"
        assert failed["result_json"] == (
            '{"decision": "INTERRUPTED", "error": "PROCESS_INTERRUPTED"}'
        )
        assert store.claim_next_task("replacement-worker") is None
        assert calls == ["invoked"]
    finally:
        store.close()


def test_worker_rejects_unreviewed_read_only_tool_even_if_persisted():
    worker, store, calls = _worker(None)
    intent = json.loads(store.task["intent_json"])
    intent["allowed_capabilities"] = ["test.remote_read"]
    intent["authorized_scopes"] = ["test.remote_read"]
    store.task["intent_json"] = json.dumps(intent)
    worker.registry.register(ToolSpec(
        name="test.remote_read",
        version="1",
        scope="test.remote_read",
        effect_class="READ_ONLY",
        timeout_seconds=2,
        validate_input=lambda value: value,
        run=lambda value: calls.append(value) or {"items": []},
        verify=lambda value: "PASS",
    ))

    assert worker.run_once() is True

    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "WORKER_TOOL_NOT_ALLOWLISTED"

def test_worker_fails_closed_when_operator_authority_is_unavailable():
    worker, store, calls = _worker(None)

    assert worker.run_once() is True

    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "WORKER_OPERATOR_AUTHORITY_UNAVAILABLE"


def test_worker_fails_closed_when_primary_device_or_session_was_revoked():
    worker, store, calls = _worker(_RevokedAuthority())

    assert worker.run_once() is True

    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "WORKER_OPERATOR_AUTHORITY_REVOKED"
    denied = [
        (args, kwargs) for args, kwargs in store.events
        if args and args[1] == "TASK_WORKER_OPERATOR_AUTHORITY_DENIED"
    ]
    assert len(denied) == 1
    assert denied[0][1]["decision"] == "FAIL_CLOSED"
    assert "session_digest" not in denied[0][1]
    assert "device_id" not in denied[0][1]



def test_worker_honors_cancel_requested_during_read_only_tool_execution():
    worker, store, calls = _worker(type("ActiveAuthority", (), {
        "verify_primary_device_for_session_digest": lambda self, *_args: True
    })())

    def cancel_during_execution(run, verify, payload, _timeout):
        output = run(payload)
        store.cancel_requested = True
        return output, verify(output)

    worker.tool_executor = cancel_during_execution
    assert worker.run_once() is True
    assert calls == [{"query": "safe test"}]
    assert store.final_state == "CANCELLED"
    assert store.final_result == {
        "decision": "CANCELLED",
        "reason": "COOPERATIVE_CANCELLATION",
    }
