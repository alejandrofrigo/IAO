from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from omega.service import POLICY_VERSION
from omega.operator_identity import OperatorIdentityError
from omega.task_worker import TaskWorker
from omega.tools.registry import ToolRegistry, ToolSpec


class _ClaimedTaskStore:
    def __init__(self, intent: dict) -> None:
        self.task = {
            "id": "queued-task-1",
            "owner": "operator:test-owner",
            "intent_json": json.dumps(intent),
        }
        self.final_state = None
        self.final_result = None
        self.executions = []
        self.events = []

    def claim_next_task(self, worker_id: str, *, lease_seconds: int = 60):
        task, self.task = self.task, None
        return task

    def update_claimed_task(
        self, task_id, worker_id, state, result=None, *, release=False
    ):
        self.final_state = state
        self.final_result = result
        return True

    def audit(self, *args, **kwargs):
        self.events.append((args, kwargs))

    def add_tool_execution(self, *args, **kwargs):
        self.executions.append((args, kwargs))


class _RevokedAuthority:
    @contextmanager
    def authorize_tool_execution(self, owner: str, session_digest: str, device_id: str):
        raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        yield False


class _ActiveAuthority:
    @contextmanager
    def authorize_tool_execution(self, *_args):
        yield True



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


class _FalseAuthority:
    @contextmanager
    def authorize_tool_execution(self, *_args):
        yield False


def test_worker_fails_closed_when_authority_returns_false():
    worker, store, calls = _worker(_FalseAuthority())

    assert worker.run_once() is True

    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "WORKER_OPERATOR_AUTHORITY_REVOKED"


def test_worker_recovers_expired_leases_while_process_remains_alive():
    class RecoveryStore:
        def __init__(self):
            self.recovery_calls = 0
            self.events = []

        def recover_interrupted_tasks(self):
            self.recovery_calls += 1
            if self.recovery_calls == 1:
                return [{"id": "expired-secret-task-id", "owner": "private-owner"}]
            return []

        def claim_next_task(self, *_args, **_kwargs):
            return None

        def audit(self, *args, **kwargs):
            self.events.append((args, kwargs))

    class StopAfterWait:
        def __init__(self):
            self.stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True

        def set(self):
            self.stopped = True

    store = RecoveryStore()
    worker = TaskWorker(store, ToolRegistry(), worker_id="recovery-test-worker")
    worker._stop = StopAfterWait()

    worker.run_forever()

    assert store.recovery_calls == 1
    recovery_events = [
        (args, kwargs) for args, kwargs in store.events
        if args and args[1] == "TASK_WORKER_INTERRUPTED_RECOVERED"
    ]
    assert len(recovery_events) == 1
    assert recovery_events[0][1]["recovered_count"] == 1
    assert recovery_events[0][1]["decision"] == "FAIL_CLOSED"
    assert "expired-secret-task-id" not in repr(recovery_events)
    assert "private-owner" not in repr(recovery_events)


@pytest.mark.parametrize(
    "timeout_value",
    [True, 10**400, float("inf"), float("nan"), 0, -1],
)
def test_worker_rejects_invalid_timeout_budget_before_tool_execution(timeout_value):
    worker, store, calls = _worker(_ActiveAuthority())
    intent = json.loads(store.task["intent_json"])
    intent["budget"]["timeout_seconds"] = timeout_value
    store.task["intent_json"] = json.dumps(intent)

    assert worker.run_once() is True
    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "INVALID_TOOL_TIMEOUT_POLICY"


def test_worker_rejects_lease_without_timeout_and_cleanup_margin():
    worker, store, calls = _worker(_ActiveAuthority())
    worker.lease_seconds = 7  # tool timeout is 2s; required margin is 5s

    assert worker.run_once() is True
    assert calls == []
    assert store.executions == []
    assert store.final_state == "FAILED"
    assert store.final_result["error"] == "WORKER_LEASE_TOO_SHORT_FOR_TOOL_TIMEOUT"


@pytest.mark.parametrize("lease_seconds", [True, 0, -1, 1.5, "60", 3601])
def test_worker_rejects_invalid_lease_configuration(lease_seconds):
    with pytest.raises(ValueError, match="INVALID_LEASE_SECONDS"):
        TaskWorker(_ClaimedTaskStore({}), ToolRegistry(), lease_seconds=lease_seconds)


@pytest.mark.parametrize("poll_seconds", [True, 0, -1, float("inf"), float("nan"), 10**400, "1"])
def test_worker_rejects_invalid_poll_configuration(poll_seconds):
    with pytest.raises(ValueError, match="INVALID_WORKER_POLL_SECONDS"):
        TaskWorker(_ClaimedTaskStore({}), ToolRegistry(), poll_seconds=poll_seconds)
