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
    def verify_primary_device_for_session_digest(
        self, owner: str, session_digest: str, device_id: str
    ) -> bool:
        raise RuntimeError("authority revoked")


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
    ), store, calls


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
