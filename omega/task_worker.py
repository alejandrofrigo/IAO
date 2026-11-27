"""Independent, lease-fenced worker for explicitly queued tasks.

Run with: python -m omega.task_worker
The HTTP server does not start this worker implicitly.
"""
from __future__ import annotations

import json
import os
import math
import time
import signal
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.policy import authorize
from omega.effect_policy import authorize_effect
from omega.server import build_service
from omega.env_loader import load_env_files
from omega.config import load_settings
from omega.service import POLICY_VERSION, _digest
from omega.store import Store
from omega.tools.registry import QUEUED_TOOL_ALLOWLIST, ToolRegistry
from omega.tools.process_runner import ToolProcessTimeout, run_tool_isolated


class TaskWorker:
    def __init__(
        self,
        store: Store,
        registry: ToolRegistry,
        worker_id: str | None = None,
        *,
        lease_seconds: int = 60,
        poll_seconds: float = 1.0,
        operator_identity_authority: Any = None,
        tool_executor: Any = None,
        heartbeat_path: Path | None = None,
        heartbeat_stale_after_seconds: int | None = None,
    ) -> None:
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds < 1:
            raise ValueError("INVALID_WORKER_LEASE")
        if (
            isinstance(poll_seconds, bool)
            or not isinstance(poll_seconds, (int, float))
            or not math.isfinite(float(poll_seconds))
            or poll_seconds <= 0
        ):
            raise ValueError("INVALID_WORKER_POLL_INTERVAL")
        self.store = store
        self.registry = registry
        self.operator_identity_authority = operator_identity_authority
        self.tool_executor = tool_executor or run_tool_isolated
        self.worker_id = worker_id or ("worker-" + uuid.uuid4().hex)
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self.heartbeat_path = Path(heartbeat_path) if heartbeat_path is not None else None
        self._heartbeat_interval = max(1, math.ceil(float(poll_seconds)))
        configured_stale_after = (
            max(60, lease_seconds * 2)
            if heartbeat_stale_after_seconds is None
            else heartbeat_stale_after_seconds
        )
        if (
            isinstance(configured_stale_after, bool)
            or not isinstance(configured_stale_after, int)
            or configured_stale_after < self._heartbeat_interval
        ):
            raise ValueError("INVALID_WORKER_HEARTBEAT_STALENESS")
        self._heartbeat_stale_after = configured_stale_after
        self._last_cycle_completed_at: float | None = None
        self._last_cycle_result: bool | None = None
        self._last_run_succeeded = True

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> bool:
        task = self.store.claim_next_task(
            self.worker_id, lease_seconds=self.lease_seconds
        )
        if task is None:
            return False

        task_id = task["id"]
        owner = task["owner"]
        self._active_lease_generation = task.get("lease_generation")
        try:
            intent = json.loads(task["intent_json"])
            capability = (intent.get("allowed_capabilities") or [None])[0]
            scopes = intent.get("authorized_scopes", [])
            payload = intent.get("input")
            expires_at = datetime.fromisoformat(intent["expires_at"])
            if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
                return self._finish(
                    task_id, owner, "EXPIRED",
                    {"decision": "DENY", "error": "TASK_EXPIRED"},
                )
            if intent.get("policy_version") != POLICY_VERSION:
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "POLICY_VERSION_CHANGED"},
                )
            if not isinstance(capability, str) or not isinstance(payload, dict):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "INVALID_PERSISTED_INTENT"},
                )
            if not isinstance(scopes, list) or not all(
                isinstance(scope, str) for scope in scopes
            ):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "INVALID_AUTHORIZATION_SNAPSHOT"},
                )

            spec = self.registry.get(capability)
            decision = authorize(
                capability,
                authenticated=True,
                approved_capabilities=set(scopes) & self.registry.names(),
            )
            if not decision.allowed or spec is None:
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "AUTHORIZATION_REVALIDATION_FAILED"},
                )
            effect_decision = authorize_effect(
                spec.effect_class, approved_effects={"READ_ONLY"}
            )
            if not effect_decision.allowed:
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_READ_ONLY_ONLY"},
                )
            if capability not in QUEUED_TOOL_ALLOWLIST:
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_TOOL_NOT_ALLOWLISTED"},
                )

            try:
                clean = spec.validate_input(payload)
            except (TypeError, ValueError):
                self.store.add_tool_execution(
                    task_id, spec.name, spec.version, "DENIED",
                    _digest(payload), None, "INVALID_INPUT", None,
                    datetime.now(timezone.utc).isoformat(),
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "ALLOW", "error": "INVALID_INPUT", "verification": "FAIL"},
                )

            # Revalidate revocation, root-key version, exact bearer-session
            # digest and primary-device binding immediately before tool execution.
            # The bearer token itself is never persisted in the task intent.
            session_digest = intent.get("operator_session_digest")
            device_id = intent.get("operator_device_id")
            if (
                self.operator_identity_authority is None
                or not isinstance(session_digest, str)
                or not isinstance(device_id, str)
            ):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_OPERATOR_AUTHORITY_UNAVAILABLE"},
                )
            try:
                self.operator_identity_authority.verify_primary_device_for_session_digest(
                    owner, session_digest, device_id,
                )
                active_capabilities = self.operator_identity_authority.active_capabilities_for_session_digest(
                    owner, session_digest, device_id, policy_version=POLICY_VERSION,
                )
                if capability not in active_capabilities:
                    raise PermissionError("TASK_CAPABILITY_GRANT_REVOKED")
            except Exception:
                self.store.audit(
                    owner, "TASK_WORKER_OPERATOR_AUTHORITY_DENIED", task_id,
                    decision="FAIL_CLOSED",
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_OPERATOR_AUTHORITY_REVOKED"},
                )

            if self._cancel_requested(task_id):
                return self._finish(
                    task_id, owner, "CANCELLED",
                    {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"},
                )

            started = datetime.now(timezone.utc).isoformat()
            digest_in = _digest(clean)
            budget = intent.get("budget", {})
            timeout = min(
                float(spec.timeout_seconds),
                float(budget.get("timeout_seconds", 20)),
            )
            input_size = len(json.dumps(
                clean, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8"))
            generation = self._active_lease_generation
            if (
                input_size > int(budget.get("max_input_bytes", 65_536))
                or not self.store.consume_task_budget(
                    task_id, self.worker_id, generation, "input_bytes", input_size,
                )
                or not self.store.consume_task_budget(
                    task_id, self.worker_id, generation, "tool_calls", 1,
                )
            ):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "TASK_BUDGET_EXCEEDED"},
                )
            generation = self._active_lease_generation
            required_lease = max(self.lease_seconds, math.ceil(timeout) + 10)
            if not self.store.renew_task_lease(
                task_id, self.worker_id, generation, required_lease,
            ):
                if self._cancel_requested(task_id):
                    return self._finish(
                        task_id, owner, "CANCELLED",
                        {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"},
                    )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "TASK_LEASE_RENEWAL_FAILED"},
                )
            try:
                output, verdict = self.tool_executor(
                    spec.run, spec.verify, clean, timeout
                )
            except ToolProcessTimeout:
                self.store.add_tool_execution(
                    task_id, spec.name, spec.version, "TIMED_OUT",
                    digest_in, None, "TIMED_OUT", started,
                    datetime.now(timezone.utc).isoformat(),
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "ALLOW", "error": "TIMED_OUT"},
                )
            except Exception:
                self.store.add_tool_execution(
                    task_id, spec.name, spec.version, "FAILED",
                    digest_in, None, "TOOL_ERROR", started,
                    datetime.now(timezone.utc).isoformat(),
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "ALLOW", "error": "TOOL_ERROR"},
                )

            if self._cancel_requested(task_id):
                return self._finish(
                    task_id, owner, "CANCELLED",
                    {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"},
                )
            try:
                output_size = len(json.dumps(
                    output, ensure_ascii=False, separators=(",", ":"), allow_nan=False
                ).encode("utf-8"))
            except (TypeError, ValueError, UnicodeEncodeError):
                output_size = int(budget.get("max_output_bytes", 1_048_576)) + 1
            if (
                output_size > int(budget.get("max_output_bytes", 1_048_576))
                or not self.store.consume_task_budget(
                    task_id, self.worker_id, generation, "output_bytes", output_size,
                )
            ):
                self.store.add_tool_execution(
                    task_id, spec.name, spec.version, "FAILED",
                    digest_in, None, "TASK_BUDGET_EXCEEDED", started,
                    datetime.now(timezone.utc).isoformat(),
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "TASK_BUDGET_EXCEEDED"},
                )
            self.store.add_tool_execution(
                task_id, spec.name, spec.version, "SUCCEEDED",
                digest_in, _digest(output), None, started,
                datetime.now(timezone.utc).isoformat(),
            )
            if self._cancel_requested(task_id):
                return self._finish(
                    task_id, owner, "CANCELLED",
                    {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"},
                )
            if not self.store.update_claimed_task(
                task_id, self.worker_id, "VERIFYING",
                lease_generation=self._active_lease_generation,
            ):
                if self._cancel_requested(task_id):
                    return self._finish(
                        task_id, owner, "CANCELLED",
                        {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"},
                    )
                self.store.audit(
                    "system", "TASK_WORKER_STALE_CLAIM", task_id,
                    worker=self.worker_id, decision="REJECT",
                )
                return True
            self.store.audit(
                owner, "TASK_STATE", task_id, to="VERIFYING",
                worker=self.worker_id,
            )
            result: dict[str, Any] = {
                "decision": "ALLOW",
                "verification": verdict,
                "result": output,
            }
            self.store.audit(
                owner, "EVIDENCE", task_id,
                decision=verdict,
                method="schema+source_hash+snippet_provenance",
                output_digest=_digest(output),
            )
            if verdict == "PASS":
                return self._finish(task_id, owner, "SUCCEEDED", result)
            result["error"] = "VERIFICATION_" + str(verdict)
            return self._finish(task_id, owner, "FAILED", result)
        except Exception:
            # No automatic retry: an unexpected worker failure leaves the lease
            # to expire, after which startup recovery marks it FAILED.
            self._last_run_succeeded = False
            self.store.audit(
                owner, "TASK_WORKER_ERROR", task_id,
                worker=self.worker_id, decision="FAIL_CLOSED",
            )
            return True

    def _cancel_requested(self, task_id: str) -> bool:
        checker = getattr(self.store, "task_cancel_requested", None)
        if not callable(checker):
            return False
        return bool(checker(
            task_id, self.worker_id,
            getattr(self, "_active_lease_generation", None),
        ))

    def _finish(
        self, task_id: str, owner: str, state: str, result: dict[str, Any]
    ) -> bool:
        generation = getattr(self, "_active_lease_generation", None)
        if state != "CANCELLED" and self._cancel_requested(task_id):
            state = "CANCELLED"
            result = {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"}
        updated = self.store.update_claimed_task(
            task_id, self.worker_id, state, result, release=True,
            lease_generation=generation,
        )
        if not updated and state != "CANCELLED" and self._cancel_requested(task_id):
            state = "CANCELLED"
            result = {"decision": "CANCELLED", "reason": "COOPERATIVE_CANCELLATION"}
            updated = self.store.update_claimed_task(
                task_id, self.worker_id, state, result, release=True,
                lease_generation=generation,
            )
        if not updated:
            self.store.audit(
                "system", "TASK_WORKER_STALE_COMPLETION", task_id,
                worker=self.worker_id, attempted_state=state,
                decision="REJECT",
            )
            return True
        self.store.audit(
            owner, "TASK_STATE", task_id,
            to=state, worker=self.worker_id,
            error=result.get("error"),
            verification=result.get("verification"),
        )
        return True

    def _heartbeat(self, phase: str, *, cycle_result: bool | None = None) -> None:
        if self.heartbeat_path is None:
            return
        from omega.supervision import write_heartbeat

        write_heartbeat(
            self.heartbeat_path,
            component="TASK_WORKER",
            pid=os.getpid(),
            phase=phase,
            interval_seconds=self._heartbeat_interval,
            stale_after_seconds=self._heartbeat_stale_after,
            last_cycle_completed_at=self._last_cycle_completed_at,
            last_cycle_result=(
                cycle_result if phase == "cycle_completed" else self._last_cycle_result
            ),
        )
        if phase == "cycle_completed":
            self._last_cycle_completed_at = time.time()
            self._last_cycle_result = cycle_result

    def run_forever(self) -> None:
        self._heartbeat("starting")
        while not self._stop.is_set():
            self._heartbeat("cycle_running")
            self._last_run_succeeded = True
            try:
                self.run_once()
            except Exception:
                self._heartbeat("cycle_completed", cycle_result=False)
                raise
            self._heartbeat(
                "cycle_completed", cycle_result=self._last_run_succeeded,
            )
            if not self._stop.is_set():
                self._stop.wait(self.poll_seconds)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    load_env_files((root / ".env", Path.home() / ".iao-runtime.env"))
    settings = load_settings()
    token_key = session_signing_key()
    if len(token_key) < 32:
        raise RuntimeError("PERSISTENT_SESSION_SIGNING_KEY_REQUIRED")
    if settings.app_env == "production":
        from omega.tools.process_runner import verify_os_sandbox

        verify_os_sandbox()
    state_dir = Path(os.environ.get("IAO_STATE_DIR", os.environ.get("OMEGA_STATE_DIR", ".state")))
    service = build_service(
        state_dir,
        token_key,
        Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus")),
        identity_rollback_anchor_enabled=settings.app_env == "production",
    )
    worker = TaskWorker(
        service.store,
        service.registry,
        worker_id=os.environ.get("IAO_WORKER_ID") or None,
        lease_seconds=int(os.environ.get("IAO_WORKER_LEASE_SECONDS", "60")),
        poll_seconds=float(os.environ.get("IAO_WORKER_POLL_SECONDS", "1")),
        operator_identity_authority=service.operator_identity_authority,
        heartbeat_path=state_dir / "task-worker-heartbeat.json",
    )
    # Startup reconciliation is fail-closed: expired RUNNING and VERIFYING
    # leases are marked FAILED and are never automatically re-enqueued.
    recovered = service.store.recover_interrupted_tasks()
    if recovered:
        # Keep owner subjects and per-task identifiers out of audit metadata.
        service.store.audit(
            "system",
            "TASK_WORKER_INTERRUPTED_RECOVERED",
            "task_worker",
            recovered_count=len(recovered),
            decision="FAIL_CLOSED",
        )

    def request_stop(*_: object) -> None:
        worker.stop()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    service.store.audit("system", "TASK_WORKER_START", "task_worker")
    try:
        worker.run_forever()
    finally:
        service.store.audit("system", "TASK_WORKER_STOP", "task_worker")
        service.store.close()


if __name__ == "__main__":
    main()
