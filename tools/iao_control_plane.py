#!/usr/bin/env python3
"""IAO federation control plane: orchestration of existing federation engines."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REPORT = STATE / "iao-control-plane-report.json"
LOCK = STATE / "iao-control-plane.lock"

ENGINES = {
    "discovery": [sys.executable, "tools/iao_federation_autonomy.py", "--once"],
    "candidate_verifier": [sys.executable, "tools/iao_federation_candidate_verify.py", "status"],
    "identity_agent": [sys.executable, "tools/iao_federation_agent.py", "status"],
    "local_supervision": [sys.executable, "tools/iao_control_plane_local.py"],
}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def sha256_file(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None

def interval_seconds():
    path = STATE / "iao-federation-sources.json"
    try:
        value = int(json.loads(path.read_text()).get("interval_seconds", 300))
    except Exception:
        value = 300
    return max(60, min(value, 86400))

def run_engine(name, command):
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True,
            timeout=90, check=False,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        return {
            "engine": name,
            "exit_code": result.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": result.stdout[-6000:],
            "stderr": result.stderr[-3000:],
            "status": "OK" if result.returncode == 0 else "ERROR",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "engine": name, "status": "TIMEOUT",
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": str(exc.stdout or "")[-3000:],
            "stderr": str(exc.stderr or "")[-3000:],
        }
    except Exception as exc:
        return {"engine": name, "status": "ERROR", "error": str(exc)}

def atomic_report(data):
    STATE.mkdir(parents=True, exist_ok=True)
    temp = REPORT.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    os.chmod(temp, 0o600)
    with temp.open("rb") as handle:
        os.fsync(handle.fileno())
    temp.replace(REPORT)
    return hashlib.sha256(REPORT.read_bytes()).hexdigest()

def cycle():
    results = []
    for name, command in ENGINES.items():
        result = run_engine(name, command)
        results.append(result)
        print(f"[{name}] {result['status']} exit={result.get('exit_code', '-')}")
        if result.get("stdout"):
            print(result["stdout"].rstrip())
        if result.get("stderr"):
            print("STDERR:", result["stderr"].rstrip())

    config = STATE / "iao-external-nodes.json"
    try:
        nodes = json.loads(config.read_text()).get("nodes", []) if config.exists() else []
        authorized_nodes = sum(1 for n in nodes if isinstance(n, dict) and n.get("authorized") is True)
    except Exception:
        authorized_nodes = 0

    report = {
        "component": "IAO_CONTROL_PLANE",
        "version": 1,
        "timestamp": utc_now(),
        "cycle": "INTEGRATED_LOCAL_AND_FEDERATION_SUPERVISION",
        "engines": results,
        "local_supervision": next((
            json.loads(item["stdout"]) for item in results
            if item.get("engine") == "local_supervision"
            and item.get("status") == "OK" and item.get("stdout")
        ), None),
        "authorized_external_nodes_configured": authorized_nodes,
        "identity_verification": "DELEGATED_TO_EXISTING_VERIFIERS",
        "peer_enrollment": "NOT_PERFORMED",
        "capability_exchange": "NOT_PERFORMED",
        "reason": "Local supervision is aggregated; federation enrollment and capability exchange remain disabled until a peer has a verified identity and service offer.",
        "automatic_enrollment": False,
        "unauthorized_node_access": False,
        "source_hashes": {
            name: sha256_file(ROOT / name)
            for name in (
                "omega/federation.py",
                "omega/federation_assimilation.py",
                "tools/iao_federation_autonomy.py",
                "tools/iao_federation_candidate_verify.py",
                "tools/iao_federation_agent.py",
            )
        },
    }
    digest = atomic_report(report)
    print("CONTROL_REPORT=" + str(REPORT))
    print("CONTROL_REPORT_SHA256=" + digest)
    print("AUTHORIZED_EXTERNAL_NODES=" + str(authorized_nodes))
    print("PEER_ENROLLMENT=NOT_PERFORMED")
    print("CAPABILITY_EXCHANGE=NOT_PERFORMED")
    errors = sum(1 for item in results if item.get("status") != "OK")
    print("ENGINE_ERRORS=" + str(errors))
    return 1 if errors else 0

def main():
    parser = argparse.ArgumentParser(description="IAO integrated federation control plane")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--status", action="store_true")
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()

    STATE.mkdir(parents=True, exist_ok=True)
    if args.status:
        print("IAO CONTROL PLANE")
        print("REPORT_EXISTS=" + str(REPORT.is_file()))
        print("INTERVAL_SECONDS=" + str(interval_seconds()))
        print("AUTOMATIC_ENROLLMENT=NOT_YET_INTEGRATED")
        print("UNAUTHORIZED_ENROLLMENT=DISABLED")
        if REPORT.is_file():
            try:
                data = json.loads(REPORT.read_text())
                print("LAST_CYCLE=" + str(data.get("timestamp")))
                print("LAST_AUTHORIZED_NODES=" + str(data.get("authorized_external_nodes_configured")))
            except Exception:
                print("LAST_REPORT=INVALID")
        return 0

    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("CONTROL_PLANE_ALREADY_RUNNING")
            return 2

        if args.once:
            return cycle()

        stopping = False
        def stop_handler(signum, frame):
            nonlocal stopping
            stopping = True
            print("STOP_REQUESTED")
        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)
        print("IAO_CONTROL_PLANE_DAEMON=STARTED")
        while not stopping:
            cycle()
            remaining = interval_seconds()
            print("NEXT_CYCLE_SECONDS=" + str(remaining))
            for _ in range(remaining):
                if stopping:
                    break
                time.sleep(1)
        print("IAO_CONTROL_PLANE_DAEMON=STOPPED")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
