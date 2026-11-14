#!/usr/bin/env python3
"""Coordinador universal IAO con recuperación y checkpoints persistentes."""
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
POLICY = STATE / "iao-real-operation-policy.json"
STATUS = STATE / "iao-universal-cycle-status.json"
LOCK = STATE / "iao-universal-cycle.lock"
INTERVAL = 3600
RECOVERY_AFTER = 300

STEPS = [
    ("sync", "tools/iao_universal_sync.py", ["--discover-github"], 130),
    ("evaluate", "tools/iao_universal_evaluate.py", [], 45),
    ("integrate_discovery", "tools/iao_universal_integrator.py", [], 45),
]

def utc():
    return datetime.now(timezone.utc).isoformat()

def read(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iao-cycle-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def age_seconds(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - stamp).total_seconds())
    except Exception:
        return 10**12

def main():
    force = "--force" in sys.argv
    if "--check" in sys.argv:
        p = read(POLICY, {})
        enabled = p.get("universal_integration_policy", {}).get("enabled") is True
        target = p.get("assimilation_target", {})
        print("POLICY_ENABLED:", enabled)
        print("HOURLY_INTERVAL:", target.get("period_seconds"))
        print("PENDING_RECOVERY_SECONDS:", RECOVERY_AFTER)
        print("STEP_TIMEOUTS:", [x[3] for x in STEPS])
        return 0 if enabled and target.get("period_seconds") == INTERVAL else 1

    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("UNIVERSAL_CYCLE=SKIPPED_LOCKED")
            return 0

        policy = read(POLICY, {})
        if policy.get("universal_integration_policy", {}).get("enabled") is not True:
            print("UNIVERSAL_CYCLE=DISABLED_BY_POLICY")
            return 0

        previous = read(STATUS, {})
        old = previous.get("last_report") or {}
        age = age_seconds(previous.get("last_attempt", ""))
        old_status = old.get("status", "PENDING")
        pending = (
            old_status in ("PENDING", "PIPELINE_INCOMPLETE")
            or not old.get("finished_at")
        )

        if not force:
            if pending and age < RECOVERY_AFTER:
                print("UNIVERSAL_CYCLE=RECOVERY_WAIT")
                print("RETRY_AFTER_SECONDS:", int(RECOVERY_AFTER - age))
                return 0
            if not pending and age < INTERVAL:
                print("UNIVERSAL_CYCLE=NOT_DUE")
                return 0

        started = utc()
        report = {
            "schema": "IAO_UNIVERSAL_PERIODIC_CYCLE_V1",
            "started_at": started,
            "target_per_hour": 2,
            "recovery_of_previous_attempt": pending,
            "steps": [],
            "assimilation_count": 0,
            "assimilation_claim": False,
            "status": "PENDING",
        }
        save(STATUS, {"last_attempt": started, "last_report": report})
        print("UNIVERSAL_CYCLE=STARTED")
        print("RECOVERY:", pending)

        for name, script, args, timeout in STEPS:
            command = [sys.executable, str(ROOT / script), *args]
            try:
                result = subprocess.run(
                    command, cwd=str(ROOT), capture_output=True,
                    text=True, timeout=timeout, check=False,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
                step = {
                    "name": name,
                    "returncode": result.returncode,
                    "status": "PASS" if result.returncode == 0 else "ERROR",
                    "output_tail": (result.stdout or "")[-1800:],
                    "error_tail": (result.stderr or "")[-900:],
                }
            except subprocess.TimeoutExpired:
                step = {"name": name, "status": "TIMEOUT", "timeout_seconds": timeout}
            except Exception as exc:
                step = {"name": name, "status": "ERROR", "error": type(exc).__name__}

            report["steps"].append(step)
            report["updated_at"] = utc()
            save(STATUS, {"last_attempt": started, "last_report": report})
            print("STEP:", name, step["status"])

            if step["status"] != "PASS":
                break

        complete = (
            len(report["steps"]) == len(STEPS)
            and all(x["status"] == "PASS" for x in report["steps"])
        )
        report["finished_at"] = utc()
        report["status"] = (
            "PIPELINE_PASS_DISCOVERY_ONLY" if complete else "PIPELINE_INCOMPLETE"
        )
        report["assimilation_count"] = 0
        report["assimilation_claim"] = False
        report["note"] = (
            "Descubrimiento y evaluación no equivalen a asimilación. "
            "No se cuentan recursos sin operación real, permisos y evidencia."
        )
        save(STATUS, {"last_attempt": started,
                      "last_finished": report["finished_at"],
                      "last_report": report})

        print("UNIVERSAL_CYCLE:", report["status"])
        print("STEPS_COMPLETED:", len(report["steps"]), "/", len(STEPS))
        print("REAL_ASSIMILATIONS_REPORTED: 0")
        print("STATUS_FILE:", STATUS)
        return 0 if complete else 1

if __name__ == "__main__":
    raise SystemExit(main())
