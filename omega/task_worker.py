"""Independent, lease-fenced worker for explicitly queued tasks.

Run with: python -m omega.task_worker
The HTTP server does not start this worker implicitly.
"""
from __future__ import annotations

import json
import os
import signal
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.policy import authorize
from omega.server import build_service
from omega.env_loader import load_env_files
from omega.config import load_settings
from omega.service import POLICY_VERSION, _digest
from omega.store import Store
from omega.tools.registry import ToolRegistry


_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="iao-task")


class TaskWorker:
    def __init__(
        self,
        store: Store,
        registry: ToolRegistry,
        worker_id: str | None = None,
        *,
        lease_seconds: int = 60,
        poll_seconds: float = 1.0,
    ) -> None:
        self.store = store
        self.registry = registry
        self.worker_id = worker_id or ("worker-" + uuid.uuid4().hex)
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
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

            started = datetime.now(timezone.utc).isoformat()
            digest_in = _digest(clean)
            timeout = min(
                float(spec.timeout_seconds),
                float(intent.get("budget", {}).get("timeout_seconds", 20)),
            )
            future = _EXECUTOR.submit(spec.run, clean)
            try:
                output = future.result(timeout=timeout)
            except FutureTimeout:
                future.cancel()
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

            self.store.add_tool_execution(
                task_id, spec.name, spec.version, "SUCCEEDED",
                digest_in, _digest(output), None, started,
                datetime.now(timezone.utc).isoformat(),
            )
            if not self.store.update_claimed_task(
                task_id, self.worker_id, "VERIFYING"
            ):
                self.store.audit(
                    "system", "TASK_WORKER_STALE_CLAIM", task_id,
                    worker=self.worker_id, decision="REJECT",
                )
                return True
            self.store.audit(
                owner, "TASK_STATE", task_id, to="VERIFYING",
                worker=self.worker_id,
            )
            try:
                verdict = spec.verify(output)
            except Exception:
                verdict = "UNKNOWN"
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

    def run_forever(self) -> None:
        while not self._stop.is_set():
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
        _EXECUTOR.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
