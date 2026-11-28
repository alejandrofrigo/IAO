import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.1"
POLICY = "IAO_AUTONOMOUS_CORE_POLICY_V1"

class AutonomousCoreError(RuntimeError):
    pass

class AutonomousCore:
    def __init__(self, state_dir=".state/iao-autonomous-core"):
        self.root = Path(state_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.tasks_path = self.root / "tasks.json"
        self.events_path = self.root / "events.jsonl"
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker = None
        self._load()

    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    def _load(self):
        if not self.tasks_path.exists():
            self._save({"version": 1, "tasks": []})
        data = json.loads(self.tasks_path.read_text("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
            raise AutonomousCoreError("INVALID_TASK_DATABASE")

    def recover_interrupted_tasks(self):
        """Requeue RUNNING tasks after this process owns the worker lock."""
        recovered = []
        with self.lock:
            data = json.loads(self.tasks_path.read_text("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
                raise AutonomousCoreError("INVALID_TASK_DATABASE")
            for task in data["tasks"]:
                if isinstance(task, dict) and task.get("status") == "RUNNING":
                    task["status"] = "QUEUED"
                    task["updated_at"] = self._now()
                    task["recovery_reason"] = "WORKER_PROCESS_INTERRUPTED"
                    recovered.append(str(task.get("id", "")))
            if recovered:
                self._save(data)
                for task_id in recovered:
                    self._event("TASK_RECOVERED", {
                        "id": task_id,
                        "reason": "WORKER_PROCESS_INTERRUPTED",
                    })
        return recovered

    def _save(self, data):
        tmp = self.tasks_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.tasks_path)

    def _event(self, event, details):
        record = {"at": self._now(), "event": event,
                  "details": details, "policy": POLICY}
        fd = os.open(self.events_path,
                     os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def submit(self, kind, payload=None, source="IAO", created_at=None):
        allowed = {"self_check", "capability_scan", "improvement_plan"}
        if kind not in allowed:
            raise AutonomousCoreError("TASK_TYPE_NOT_ALLOWED")
        payload = payload or {}
        if not isinstance(payload, dict) or len(json.dumps(payload)) > 8192:
            raise AutonomousCoreError("INVALID_PAYLOAD")

        if created_at is None:
            timestamp = self._now()
        else:
            if isinstance(created_at, datetime):
                parsed = created_at
            elif isinstance(created_at, str):
                try:
                    parsed = datetime.fromisoformat(created_at)
                except ValueError as exc:
                    raise AutonomousCoreError("INVALID_CREATED_AT") from exc
            else:
                raise AutonomousCoreError("INVALID_CREATED_AT")

            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise AutonomousCoreError("INVALID_CREATED_AT")

            timestamp = parsed.astimezone(timezone.utc).isoformat()

        task = {
            "id": uuid.uuid4().hex, "kind": kind, "payload": payload,
            "source": str(source)[:80], "status": "QUEUED",
            "created_at": timestamp, "updated_at": timestamp,
            "result": None,
        }
        with self.lock:
            data = json.loads(self.tasks_path.read_text("utf-8"))
            if len(data["tasks"]) >= 5000:
                raise AutonomousCoreError("QUEUE_LIMIT")
            data["tasks"].append(task)
            self._save(data)
            self._event("TASK_SUBMITTED", {"id": task["id"], "kind": kind})
        return task

    def schedule_maintenance(self, now=None):
        """Enqueue bounded recurring diagnostics without duplicating active work."""
        from datetime import timedelta

        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise AutonomousCoreError("INVALID_SCHEDULER_TIME")
        current = current.astimezone(timezone.utc)
        schedules = {
            "self_check": 60 * 60,
            "capability_scan": 6 * 60 * 60,
            "improvement_plan": 24 * 60 * 60,
        }
        schedule_path = self.root / "scheduler.json"
        with self.lock:
            try:
                state = json.loads(schedule_path.read_text("utf-8"))
                if not isinstance(state, dict):
                    raise ValueError("invalid scheduler state")
            except FileNotFoundError:
                state = {}
            except (ValueError, OSError, UnicodeError) as exc:
                raise AutonomousCoreError("INVALID_SCHEDULER_STATE") from exc
            data = json.loads(self.tasks_path.read_text("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
                raise AutonomousCoreError("INVALID_TASK_DATABASE")
            active = {
                item.get("kind") for item in data["tasks"]
                if isinstance(item, dict) and item.get("status") in {"QUEUED", "RUNNING"}
            }
            terminal = [
                item for item in data["tasks"]
                if isinstance(item, dict)
                and item.get("status") in {"COMPLETED", "FAILED", "BLOCKED"}
            ]
            terminal.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
            retained_terminal = {item.get("id") for item in terminal[:1000]}
            before_prune = len(data["tasks"])
            data["tasks"] = [
                item for item in data["tasks"]
                if not isinstance(item, dict)
                or item.get("status") not in {"COMPLETED", "FAILED", "BLOCKED"}
                or item.get("id") in retained_terminal
            ]
            pruned = before_prune - len(data["tasks"])
            if pruned:
                self._event("TASK_HISTORY_PRUNED", {"count": pruned})
            scheduled = []
            for kind, interval in schedules.items():
                previous = state.get(kind)
                try:
                    due = datetime.fromisoformat(previous) if previous else None
                    if due is not None and (due.tzinfo is None or due.utcoffset() is None):
                        due = None
                except (TypeError, ValueError):
                    due = None
                if due is not None and due > current:
                    continue
                if kind not in active:
                    if len(data["tasks"]) >= 5000:
                        raise AutonomousCoreError("QUEUE_LIMIT")
                    timestamp = current.isoformat()
                    task = {
                        "id": uuid.uuid4().hex, "kind": kind, "payload": {},
                        "source": "IAO_MAINTENANCE_SCHEDULER", "status": "QUEUED",
                        "created_at": timestamp, "updated_at": timestamp, "result": None,
                    }
                    data["tasks"].append(task)
                    scheduled.append(task["id"])
                    self._event("TASK_SUBMITTED", {"id": task["id"], "kind": kind})
                state[kind] = (current + timedelta(seconds=interval)).isoformat()
            self._save(data)
            tmp = schedule_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, schedule_path)
        return scheduled

    def _federation_capability_scan(self):
        """Inspect federation state locally; never infer connectivity or trust."""
        import sqlite3

        repo = Path.cwd()
        home = Path.home()
        state = repo / ".state"
        config_path = home / ".config/iao/node-network.json"
        db_path = home / ".local/share/iao/node-network/network.sqlite3"

        result = {
            "scan_version": 2,
            "mode": "LOCAL_READ_ONLY",
            "network_requests": 0,
            "identity": {"config_present": config_path.is_file()},
            "registry": {},
            "database": {"present": db_path.is_file()},
            "policy": {},
            "reports": {},
            "connectivity": {
                "external_network_probed": False,
                "live_peers_verified": False,
                "cryptographic_handshake_verified": False,
                "reason": "No se realizó ninguna conexión externa.",
            },
        }

        def read_json(path):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                return value if isinstance(value, dict) else None
            except (OSError, ValueError, UnicodeError):
                return None

        config = read_json(config_path)
        if config is not None:
            result["identity"].update({
                "config_valid": True,
                "node_id_configured": bool(config.get("node_id")),
                "cluster_id_configured": bool(config.get("cluster_id")),
                "public_endpoint_configured": bool(config.get("public_endpoint")),
                "capabilities_configured": len(
                    config.get("capabilities", [])
                ) if isinstance(config.get("capabilities"), list) else 0,
            })
        else:
            result["identity"]["config_valid"] = False

        policy_path = state / "iao-node-network/federation-policy.json"
        policy = read_json(policy_path)
        if policy is not None:
            safe_fields = (
                "enabled",
                "automatic_admission",
                "automatic_candidate_staging",
                "automatic_revalidation",
                "automatic_revocation_on_failed_verification",
                "require_trusted_directory_signature",
                "require_mutual_tls",
                "remote_code_execution",
                "remote_policy_changes",
                "remote_security_administration",
                "padge_mode",
            )
            result["policy"] = {
                key: policy[key] for key in safe_fields if key in policy
            }
            allowed = policy.get("allowed_capabilities", [])
            result["policy"]["allowed_capabilities_count"] = (
                len(allowed) if isinstance(allowed, list) else 0
            )
            result["policy"]["file_valid"] = True
        else:
            result["policy"] = {"file_valid": False}

        registry_specs = (
            ("authorized_peers", state / "iao-node-network/authorized-peers.json",
             "authorized_peers"),
            ("node_registry", state / "iao-node-network/nodes.json", "nodes"),
            ("external_nodes", state / "iao-external-nodes.json", "nodes"),
            ("federation_sources", state / "iao-federation-sources.json", "feeds"),
        )

        for name, path, list_key in registry_specs:
            data = read_json(path)
            items = data.get(list_key) if isinstance(data, dict) else None

            # El registro principal de nodos usa un diccionario por node_id.
            # Los otros registros indicados aquí usan listas.
            expected_type = dict if name == "node_registry" else list
            valid = isinstance(items, expected_type)

            entry = {
                "present": path.is_file(),
                "valid": valid,
                "container_type": type(items).__name__ if items is not None else "missing",
                "expected_container_type": "dict" if name == "node_registry" else "list",
                "count": len(items) if valid else 0,
            }

            if name in ("authorized_peers", "external_nodes") and valid:
                entry["authorized_count"] = sum(
                    1 for item in items
                    if isinstance(item, dict)
                    and (
                        item.get("authorized") is True
                        or item.get("status") == "AUTHORIZED"
                    )
                )

            result["registry"][name] = entry

        if db_path.is_file():
            try:
                con = sqlite3.connect(
                    db_path.as_uri() + "?mode=ro", uri=True, timeout=5
                )
                tables = {
                    row[0] for row in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                counts = {}
                status_counts = {}

                for table in ("nodes", "peers", "directories",
                              "invitations", "tasks", "events"):
                    if table not in tables:
                        continue

                    count = con.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
                    counts[table] = count

                    columns = {
                        row[1] for row in con.execute(
                            f'PRAGMA table_info("{table}")'
                        )
                    }

                    if table == "peers" and "authorized" in columns:
                        authorized = con.execute(
                            "SELECT COUNT(*) FROM peers WHERE authorized=1"
                        ).fetchone()[0]
                        status_counts["authorized_peers"] = authorized

                    if table in ("nodes", "directories", "tasks") and "status" in columns:
                        status_counts[table] = dict(
                            con.execute(
                                f'SELECT status, COUNT(*) FROM "{table}" GROUP BY status'
                            ).fetchall()
                        )

                con.close()
                result["database"].update({
                    "readable": True,
                    "tables": counts,
                    "status_counts": status_counts,
                })
            except Exception as exc:
                result["database"].update({
                    "readable": False,
                    "error_type": type(exc).__name__,
                })
        else:
            result["database"]["readable"] = False

        report_specs = (
            ("agent", state / "iao-federation-agent-report.json"),
            ("autonomy", state / "iao-federation-autonomy-report.json"),
            ("worker", state / "iao-federation-worker-report.json"),
        )
        for name, path in report_specs:
            data = read_json(path)
            if data is None:
                result["reports"][name] = {
                    "present": path.is_file(),
                    "valid": False,
                }
                continue

            # Only non-secret summary fields are exposed.
            fields = (
                "created_utc", "mode", "config_status",
                "authorized_node_count", "active_authorized_feeds",
                "candidate_total", "new_candidates", "errors",
                "capability_exchange_performed",
                "identity_verification_performed",
                "peer_enrollment_performed",
                "enrollment_performed", "authorization_granted",
                "secrets_printed",
            )
            result["reports"][name] = {
                "present": True,
                "valid": True,
                **{key: data[key] for key in fields if key in data},
            }

        peer_count = result["database"].get("tables", {}).get("peers", 0)
        node_count = result["database"].get("tables", {}).get("nodes", 0)
        result["summary"] = {
            "local_configuration_present": config is not None,
            "federation_policy_present": policy is not None,
            "database_readable": result["database"].get("readable") is True,
            "registered_database_nodes": node_count,
            "registered_database_peers": peer_count,
            "authorized_database_peers": result["database"].get(
                "status_counts", {}
            ).get("authorized_peers", 0),
            "external_connectivity_confirmed": False,
            "cryptographic_trust_confirmed": False,
        }
        result["scanned_at"] = self._now()
        return result

    def _build_improvement_plan(self):
        """Build a deterministic, read-only repository quality-gap report."""
        repo = Path(__file__).resolve().parent.parent
        omega_dir = repo / "omega"
        tests_dir = repo / "tests"
        if not omega_dir.is_dir() or not tests_dir.is_dir():
            return {
                "status": "INCOMPLETE_REPOSITORY_LAYOUT",
                "code_changes_applied": False,
                "candidate_code_executed": False,
            }

        modules = sorted(
            path.stem for path in omega_dir.rglob("*.py")
            if path.name != "__init__.py"
            and "__pycache__" not in path.parts
        )
        test_names = {
            path.stem[len("test_"):]
            for path in tests_dir.rglob("test_*.py")
            if "__pycache__" not in path.parts
        }
        uncovered = [
            name for name in modules
            if name not in test_names and name.replace("_", "") not in {
                item.replace("_", "") for item in test_names
            }
        ]
        return {
            "status": "READ_ONLY_REPOSITORY_SCAN",
            "module_count": len(modules),
            "test_file_count": len(test_names),
            "modules_without_directly_named_test_file": uncovered[:50],
            "unpaired_module_count": len(uncovered),
            "recommendations": [
                "Add focused regression tests for modules without a directly named test file.",
                "Run the complete CI matrix before accepting candidate changes.",
                "Require functional and security tests in an OS-isolated candidate workspace.",
            ],
            "coverage_interpretation": (
                "Heuristic filename mapping only; this is not measured code coverage "
                "and does not prove that listed modules lack indirect tests."
            ),
            "code_changes_applied": False,
            "candidate_code_executed": False,
        }

    def _execute(self, task):
        kind = task["kind"]
        if kind == "self_check":
            import importlib.util
            modules = ["omega.federation", "omega.federation_assimilation"]
            checks = {m: importlib.util.find_spec(m) is not None for m in modules}
            return {"checks": checks, "all_available": all(checks.values())}
        if kind == "capability_scan":
            return self._federation_capability_scan()
        if kind == "improvement_plan":
            return self._build_improvement_plan()
        raise AutonomousCoreError("UNKNOWN_TASK")

    def run_one(self):
        with self.lock:
            data = json.loads(self.tasks_path.read_text("utf-8"))
            task = next((t for t in data["tasks"] if t["status"] == "QUEUED"), None)
            if task is None:
                return None
            # Every queued task must pass the deterministic policy gate.
            # The current task allowlist contains read-only operations only.
            from omega.policy_gate import (
                ActionClass,
                ActionRequest,
                RuntimeState,
                evaluate_action,
            )

            decision = evaluate_action(
                ActionRequest(
                    action_id=task["id"],
                    action_class=ActionClass.READ_ONLY,
                    description="autonomous task: " + str(task["kind"]),
                ),
                # Conservative until runtime health can be independently proven.
                RuntimeState.DEGRADED,
            )
            task["policy_decision"] = decision.to_dict()

            if not decision.allowed:
                task["status"] = "BLOCKED"
                task["result"] = {
                    "error": "POLICY_GATE_DENIED",
                    "reason": decision.reason,
                    "requirements": list(decision.requirements),
                }
                task["updated_at"] = self._now()
                self._save(data)
                self._event("TASK_BLOCKED_BY_POLICY", {
                    "id": task["id"],
                    "reason": decision.reason,
                })
                return task

            self._event("TASK_POLICY_ALLOWED", {
                "id": task["id"],
                "action_class": ActionClass.READ_ONLY.value,
                "runtime_state": RuntimeState.DEGRADED.value,
            })
            task["status"] = "RUNNING"
            task["updated_at"] = self._now()
            self._save(data)
            self._event("TASK_STARTED", {"id": task["id"], "kind": task["kind"]})
        try:
            result = self._execute(task)
            status = "COMPLETED"
        except Exception as exc:
            result = {"error": type(exc).__name__, "message": str(exc)[:300]}
            status = "FAILED"
        with self.lock:
            data = json.loads(self.tasks_path.read_text("utf-8"))
            current = next(t for t in data["tasks"] if t["id"] == task["id"])
            current.update(status=status, result=result, updated_at=self._now())
            self._save(data)
            self._event("TASK_" + status, {"id": task["id"]})
            return current

    def cycle(self, limit=3):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
            raise AutonomousCoreError("INVALID_CYCLE_LIMIT")
        results = []
        for _ in range(limit):
            if self.stop_event.is_set():
                break
            task = self.run_one()
            if task is None:
                break
            results.append(task)
        return results

    def status(self):
        data = json.loads(self.tasks_path.read_text("utf-8"))
        counts = {}
        for task in data["tasks"]:
            counts[task["status"]] = counts.get(task["status"], 0) + 1
        return {
            "version": VERSION, "policy": POLICY,
            "task_count": len(data["tasks"]), "task_states": counts,
            "worker_running": bool(self.worker and self.worker.is_alive()),
        }

    def start_worker(self, interval=30):
        """Start one managed background worker; repeated starts are harmless."""
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            raise AutonomousCoreError("INVALID_WORKER_INTERVAL")
        if not 1 <= interval <= 3600:
            raise AutonomousCoreError("INVALID_WORKER_INTERVAL")

        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                return False

            self.stop_event.clear()
            self.worker = threading.Thread(
                target=self.serve,
                kwargs={"interval": interval},
                name="iao-autonomous-core",
                daemon=True,
            )
            self.worker.start()
            self._event("WORKER_START_REQUESTED", {
                "interval_seconds": interval,
            })
            return True

    def stop_worker(self, timeout=5):
        """Request a graceful stop and wait a bounded amount of time."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise AutonomousCoreError("INVALID_WORKER_TIMEOUT")
        if not 0 <= timeout <= 30:
            raise AutonomousCoreError("INVALID_WORKER_TIMEOUT")

        with self.lock:
            worker = self.worker
            if worker is None or not worker.is_alive():
                self.stop_event.set()
                return True
            self.stop_event.set()

        if worker is threading.current_thread():
            return False

        worker.join(timeout=timeout)
        stopped = not worker.is_alive()

        if stopped:
            with self.lock:
                self._event("WORKER_STOPPED", {})
        return stopped

    def serve(self, interval=30):
        self._event("FOREGROUND_WORKER_STARTED", {"interval": interval})
        while not self.stop_event.is_set():
            try:
                self.schedule_maintenance()
                self.cycle()
            except Exception as exc:
                self._event("MAINTENANCE_CYCLE_FAILED", {
                    "error_type": type(exc).__name__,
                })
            self.stop_event.wait(interval)
