#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "iao-autonomy"
REPORTS = ROOT / ".state" / "padge" / "reports"
EVENTS = STATE / "coordinator-events.jsonl"
LOCK = STATE / "coordinator.lock"
HEARTBEAT = STATE / "coordinator-heartbeat.json"

INTERVAL = 300

COMPONENTS = {
    "PADGE": [
        "omega/padge.py",
        "omega/padge_autonomy_policy.py",
        "omega/autonomous_authority.py",
    ],
    "CONTINUOUS_AUTONOMY": [
        "tools/iao_padge_autonomous_runner.py",
        "tools/iao_autonomy.py",
        "tools/iao_autonomy_cycle.py",
        "tools/iao_autonomy_daemon.py",
        "tools/iao_autonomous_worker_supervisor.py",
    ],
    "GUARDIAN": [
        "tools/iao_guardian.py",
        "tools/iao_internet_guardian.py",
        "tools/iao_watchdog.py",
    ],
    "NODE_NETWORK": [
        "tools/iao_node_network_engine.py",
        "tools/iao_federation_discover.py",
        "tools/iao_federation_identity.py",
        "tools/iao_federation_candidate_verify.py",
    ],
    "DISTRIBUTED_INTELLIGENCE": [
        "tools/iao_federation_agent.py",
        "tools/iao_federation_worker.py",
        "tools/iao_federation_autonomy.py",
        "tools/iao_universal_cycle.py",
        "omega/federation.py",
        "omega/llm_router.py",
    ],
}


def now():
    return datetime.now(timezone.utc).isoformat()


def log(event, **data):
    STATE.mkdir(parents=True, exist_ok=True)
    record = {"time": now(), "event": event, **data}
    with EVENTS.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False), flush=True)


def inventory():
    result = {}
    for component, paths in COMPONENTS.items():
        present = [p for p in paths if (ROOT / p).is_file()]
        result[component] = {
            "present": present,
            "missing": [p for p in paths if p not in present],
            "discovered": len(present),
            "expected": len(paths),
            "state": "DISCOVERED" if present else "MISSING",
        }
    return result


def latest_report():
    if not REPORTS.is_dir():
        return None
    files = list(REPORTS.glob("*.json"))
    return max(files, key=lambda p: p.stat().st_mtime_ns) if files else None


def report_status(report):
    if report is None:
        return {"state": "NO_REPORT", "confirmed": False}

    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "state": "INVALID_REPORT",
            "error": str(exc),
            "confirmed": False,
        }

    status = str(data.get("status", "")).upper()
    promotion = data.get("promotion")
    promotion_text = json.dumps(
        promotion, ensure_ascii=False
    ).upper()

    rejected = any(word in status for word in (
        "REJECT", "DENIED", "FAIL", "ERROR", "INVALID",
    ))

    explicitly_promoted = (
        "PROMOTED" in status
        or "PROMOTION_SUCCESS" in status
        or "COMMITTED" in promotion_text
        or "PROMOTED" in promotion_text
    )

    denied = (
        "DENIED" in promotion_text
        or "REJECT" in promotion_text
        or (isinstance(promotion, dict)
            and promotion.get("approved") is False)
    )

    confirmed = explicitly_promoted and not rejected and not denied

    return {
        "state": status or "UNKNOWN",
        "promotion": promotion,
        "confirmed": confirmed,
        "report": report.name,
        "goal": data.get("goal"),
        "policy": data.get("policy"),
    }


def coordinator_lock_held():
    """Check the advisory lock, not a PID file, before reporting active."""
    from omega.supervision import read_lock_owner

    return read_lock_owner(LOCK) is not None

def write_coordinator_heartbeat(phase, interval, last_result=None):
    try:
        previous = json.loads(HEARTBEAT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {}
    completed_at = previous.get("last_cycle_completed_at")
    previous_result = previous.get("last_cycle_result")
    if phase == "cycle_completed":
        previous_result = last_result
    from omega.supervision import write_heartbeat

    return write_heartbeat(
        HEARTBEAT,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase=phase,
        interval_seconds=interval,
        stale_after_seconds=max(1800, interval * 2 + 900),
        last_cycle_completed_at=completed_at,
        last_cycle_result=previous_result,
    )


def status():
    print("\nIAO — ESTADO DEL COORDINADOR")
    print("==========================================")

    for name, item in inventory().items():
        print(
            f"{name}: {item['state']} "
            f"({item['discovered']}/{item['expected']})"
        )
        if item["missing"]:
            print("  AUSENTES:", ", ".join(item["missing"]))

    result = report_status(latest_report())
    print("\nULTIMO RESULTADO PADGE:")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    from omega.supervision import read_heartbeat, read_lock_owner

    heartbeat = read_heartbeat(
        HEARTBEAT, expected_component="PADGE_AUTONOMY",
    )
    lock_owner = read_lock_owner(LOCK)
    lock_held = lock_owner is not None
    active = lock_held and lock_owner == heartbeat.get("pid")
    if not lock_held:
        state = "STOPPED"
    elif not active:
        state = "DEGRADED_UNVERIFIED"
    elif heartbeat["status"] in {"HEALTHY", "CYCLE_IN_PROGRESS"}:
        state = heartbeat["status"]
    else:
        state = "DEGRADED_UNVERIFIED"
    print("\nCOORDINATOR_STATUS=" + state)
    print("COORDINATOR_LOCK_HELD=" + ("YES" if lock_held else "NO"))
    print("COORDINATOR_PROCESS_MATCH=" + ("YES" if active else "NO"))
    print("COORDINATOR_LOCK_OWNER_PID=" + (str(lock_owner) if lock_owner else "UNKNOWN"))
    print("COORDINATOR_HEARTBEAT=" + json.dumps(heartbeat, sort_keys=True))
    return 0 if state in {"HEALTHY", "CYCLE_IN_PROGRESS"} else 1


def run_expansion_once():
    """Run external discovery independently of PADGE promotion outcomes."""
    command = [
        sys.executable,
        str(ROOT / "tools" / "iao_federation_autonomy.py"),
        "--once",
    ]
    try:
        process = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log("EXPANSION_CYCLE_FAILED", reason="TIMEOUT", timeout_seconds=120)
        return False
    except Exception as exc:
        log("EXPANSION_CYCLE_FAILED", reason=type(exc).__name__)
        return False

    if process.returncode != 0:
        log(
            "EXPANSION_CYCLE_FAILED",
            reason="NONZERO_EXIT",
            returncode=process.returncode,
        )
        return False

    try:
        report = json.loads(process.stdout)
    except (TypeError, ValueError):
        log("EXPANSION_CYCLE_FAILED", reason="INVALID_REPORT")
        return False

    discovery = report.get("libp2p_discovery", {})
    log(
        "EXPANSION_CYCLE_COMPLETED",
        libp2p_status=discovery.get("status", "UNKNOWN"),
        bootstrappers_connected=discovery.get("connected_bootstrappers", 0),
        peers_discovered=discovery.get("routing_peers_discovered", 0),
        new_peers_persisted=discovery.get("persisted_new_peers", 0),
        authorized_feeds=report.get("active_authorized_feeds", 0),
        new_federation_candidates=report.get("new_candidates", 0),
        peer_enrollment_performed=False,
    )
    return True


def run_once():
    events_file = EVENTS
    previous = latest_report()
    previous_name = previous.name if previous else None

    try:
        event_offset = events_file.stat().st_size
    except OSError:
        event_offset = 0

    run_expansion_once()
    log("PADGE_CYCLE_STARTED")

    process = subprocess.run(
        [sys.executable, "-m", "omega.padge", "once"],
        cwd=ROOT,
        check=False,
    )

    new_events = []
    try:
        with events_file.open("r", encoding="utf-8") as stream:
            stream.seek(event_offset)
            for line in stream:
                try:
                    new_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass

    cycle_results = [
        event for event in new_events
        if event.get("event") == "cycle_completed"
    ]

    cycle_result = (
        str(cycle_results[-1].get("result", "")).upper()
        if cycle_results else ""
    )

    if process.returncode != 0:
        log("SAFE_STOP", reason="PADGE_EXIT_NONZERO",
            returncode=process.returncode)
        return False

    current = latest_report()

    if current is None or current.name == previous_name:
        if cycle_result:
            log(
                "PADGE_REJECTION_RECORDED",
                result=cycle_result,
                report_created=False,
            )
            log(
                "SAFE_STOP",
                reason="PADGE_CYCLE_REJECTED",
                result=cycle_result,
            )
        else:
            log("SAFE_STOP", reason="NO_NEW_REPORT_OR_CYCLE_RESULT")
        return False

    result = report_status(current)
    log("PADGE_CYCLE_RESULT", **result)

    if not result["confirmed"]:
        log(
            "SAFE_STOP",
            reason="PROMOTION_NOT_VERIFIED",
            report=result.get("report"),
            status=result.get("state"),
        )
        return False

    log("PADGE_PROMOTION_VERIFIED", report=result["report"])
    return True

def acquire_lock():
    STATE.mkdir(parents=True, exist_ok=True)
    stream = LOCK.open("a+", encoding="utf-8")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        raise RuntimeError("Ya existe otro coordinador activo")
    stream.seek(0)
    stream.truncate()
    stream.write(str(os.getpid()))
    stream.flush()
    os.fsync(stream.fileno())
    return stream


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("status", "once", "loop"),
        nargs="?", default="status",
    )
    parser.add_argument("--interval", type=int, default=INTERVAL)
    args = parser.parse_args()

    if args.interval < 60:
        parser.error("El intervalo mínimo permitido es 60 segundos")

    if args.mode == "status":
        return status()

    try:
        lock = acquire_lock()
    except RuntimeError as exc:
        print("COORDINATOR_LOCKED:", exc)
        return 2

    with lock:
        if args.mode == "once":
            return 0 if run_once() else 1

        log("COORDINATOR_LOOP_STARTED", interval=args.interval)
        write_coordinator_heartbeat("starting", args.interval)

        while True:
            write_coordinator_heartbeat("cycle_running", args.interval)
            padge_promoted = run_once()
            write_coordinator_heartbeat(
                "cycle_completed", args.interval,
                last_result=padge_promoted,
            )
            log(
                "NEXT_CYCLE",
                seconds=args.interval,
                padge_promotion_verified=padge_promoted,
                expansion_runs_independent=True,
            )
            time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
