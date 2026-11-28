"""Independent, lease-fenced worker for explicitly queued tasks.

Run with: python -m omega.task_worker
The HTTP server does not start this worker implicitly.
"""
from __future__ import annotations

import json
import math
import os
import signal
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.policy import authorize
from omega.operator_identity import OperatorIdentityError
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
    ) -> None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("INVALID_LEASE_SECONDS")
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)):
            raise ValueError("INVALID_WORKER_POLL_SECONDS")
        try:
            poll_interval = float(poll_seconds)
        except (OverflowError, TypeError, ValueError):
            raise ValueError("INVALID_WORKER_POLL_SECONDS") from None
        if not math.isfinite(poll_interval) or not 0 < poll_interval <= 3600:
            raise ValueError("INVALID_WORKER_POLL_SECONDS")
        self.store = store
        self.registry = registry
        self.operator_identity_authority = operator_identity_authority
        self.tool_executor = tool_executor or run_tool_isolated
        self.worker_id = worker_id or ("worker-" + uuid.uuid4().hex)
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_interval
        self._stop = threading.Event()

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
            if spec.effect_class != "READ_ONLY":
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
            # The authority context holds a cross-process SQLite write
            # reservation through the bounded tool call. A concurrent root
            # revocation therefore cannot commit between authorization and
            # tool completion. No tool is invoked if the gate cannot be acquired.
            started = datetime.now(timezone.utc).isoformat()
            digest_in = _digest(clean)
            budget = intent.get("budget", {})
            budget_timeout = (
                budget.get("timeout_seconds", 20)
                if isinstance(budget, dict) else None
            )
            spec_timeout = spec.timeout_seconds
            def valid_timeout(value: Any) -> bool:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                ):
                    return False
                try:
                    numeric = float(value)
                except (OverflowError, TypeError, ValueError):
                    return False
                return math.isfinite(numeric) and numeric > 0

            if not all(valid_timeout(value) for value in (budget_timeout, spec_timeout)):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "INVALID_TOOL_TIMEOUT_POLICY"},
                )
            timeout = min(float(spec_timeout), float(budget_timeout))
            # The process runner may need up to two additional seconds to
            # terminate/reap a timed-out child. Keep a further three-second
            # scheduling margin so a live tool cannot outlast its task lease.
            if (
                isinstance(self.lease_seconds, bool)
                or not isinstance(self.lease_seconds, int)
                or timeout + 5 >= self.lease_seconds
            ):
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_LEASE_TOO_SHORT_FOR_TOOL_TIMEOUT"},
                )
            try:
                with self.operator_identity_authority.authorize_tool_execution(
                    owner, session_digest, device_id,
                ) as authority_valid:
                    if authority_valid is not True:
                        raise OperatorIdentityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
                    # A worker can wait for the identity DB write reservation.
                    # Recheck the actual task lease after acquiring that gate,
                    # not just the configured lease duration, before invoking
                    # any tool. Leave enough time for the bounded call and reap.
                    try:
                        lease_until = datetime.fromisoformat(task["lease_until"])
                        if lease_until.tzinfo is None:
                            raise ValueError("naive lease timestamp")
                        remaining_lease = (
                            lease_until - datetime.now(timezone.utc)
                        ).total_seconds()
                    except (KeyError, TypeError, ValueError):
                        remaining_lease = 0.0
                    if remaining_lease <= timeout + 5:
                        self.store.add_tool_execution(
                            task_id, spec.name, spec.version, "DENIED",
                            digest_in, None, "LEASE_EXPIRING", started,
                            datetime.now(timezone.utc).isoformat(),
                        )
                        return self._finish(
                            task_id, owner, "FAILED",
                            {
                                "decision": "DENY",
                                "error": "WORKER_LEASE_EXPIRING_BEFORE_TOOL",
                            },
                        )
                    output, verdict = self.tool_executor(
                        spec.run, spec.verify, clean, timeout
                    )
            except OperatorIdentityError:
                self.store.audit(
                    owner, "TASK_WORKER_OPERATOR_AUTHORITY_DENIED", task_id,
                    decision="FAIL_CLOSED",
                )
                return self._finish(
                    task_id, owner, "FAILED",
                    {"decision": "DENY", "error": "WORKER_OPERATOR_AUTHORITY_REVOKED"},
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

            result: dict[str, Any] = {
                "decision": "ALLOW",
                "verification": verdict,
                "result": output,
            }
            final_state = "SUCCEEDED" if verdict == "PASS" else "FAILED"
            if final_state == "FAILED":
                result["error"] = "VERIFICATION_" + str(verdict)
            committed = self.store.finalize_claimed_tool_execution(
                task_id, self.worker_id, owner, final_state, result,
                spec.name, spec.version, digest_in, _digest(output),
                started, datetime.now(timezone.utc).isoformat(),
            )
            # The store commits terminal task state, truthful execution status,
            # and the corresponding audit events in one SQLite transaction.
            # It also records stale completion (including a missing task), so
            # the worker must not append a second, non-atomic audit event here.
            return True
        except Exception:
            # No automatic retry: an unexpected worker failure leaves the lease
            # to expire, after which startup recovery marks it FAILED.
            self.store.audit(
                owner, "TASK_WORKER_ERROR", task_id,
                worker=self.worker_id, decision="FAIL_CLOSED",
            )
            return True

    def _finish(
        self, task_id: str, owner: str, state: str, result: dict[str, Any]
    ) -> bool:
        if not self.store.update_claimed_task(
            task_id, self.worker_id, state, result, release=True
        ):
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

    def recover_interrupted(self) -> int:
        """Fail closed expired in-flight tasks without re-enqueueing or replaying them."""
        recovered = self.store.recover_interrupted_tasks()
        if recovered:
            # Keep owner subjects and task identifiers out of audit metadata.
            self.store.audit(
                "system",
                "TASK_WORKER_INTERRUPTED_RECOVERED",
                "task_worker",
                recovered_count=len(recovered),
                decision="FAIL_CLOSED",
            )
        return len(recovered)

    def run_forever(self) -> None:
        while not self._stop.is_set():
            # Recovery must run periodically, not only at process startup:
            # otherwise an expired lease can remain RUNNING indefinitely
            # while this worker stays alive.
            self.recover_interrupted()
            if not self.run_once():
                self._stop.wait(self.poll_seconds)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    load_env_files((root / ".env", Path.home() / ".iao-runtime.env"))
    settings = load_settings()
    if settings.app_env == "production":
        raise RuntimeError("BLOCKED_EXTERNAL: configure production identity before worker startup")
    token_key = os.environ.get("OMEGA_DEV_TOKEN_KEY", "")
    if len(token_key) < 16:
        raise RuntimeError("OMEGA_DEV_TOKEN_KEY is required")
    state_dir = Path(os.environ.get("OMEGA_STATE_DIR", ".state"))
    service = build_service(
        state_dir,
        token_key,
        Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus")),
    )
    worker = TaskWorker(
        service.store,
        service.registry,
        worker_id=os.environ.get("IAO_WORKER_ID") or None,
        lease_seconds=int(os.environ.get("IAO_WORKER_LEASE_SECONDS", "60")),
        poll_seconds=float(os.environ.get("IAO_WORKER_POLL_SECONDS", "1")),
        operator_identity_authority=service.operator_identity_authority,
    )
    # Initial reconciliation; run_forever repeats it to catch leases expiring
    # while this process remains alive.
    worker.recover_interrupted()

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
