#!/usr/bin/env python3
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
LOGDIR = ROOT / "logs"
PIDFILE = STATE / "iao-federation-worker.pid"
REPORT = STATE / "iao-federation-worker-report.json"
LOG = LOGDIR / "iao-federation-worker.log"
INTERVAL = 300
TIMEOUT = 150
STOP = False
HEARTBEAT_STATE = Path(
    os.environ.get("IAO_STATE_DIR", os.environ.get("OMEGA_STATE_DIR", str(ROOT / ".state")))
)
HEARTBEAT_PATH = HEARTBEAT_STATE / "distributed-intelligence-heartbeat.json"


def heartbeat(phase, result=None):
    from omega.supervision import write_heartbeat

    return write_heartbeat(
        HEARTBEAT_PATH,
        component="DISTRIBUTED_INTELLIGENCE",
        pid=os.getpid(),
        phase=phase,
        interval_seconds=INTERVAL,
        stale_after_seconds=INTERVAL * 3,
        last_cycle_result=result,
    )


def now():
    return datetime.now(timezone.utc).isoformat()

def log(message):
    from omega.operational_log import append_private_jsonl

    entry = append_private_jsonl(
        LOG,
        {"time": now(), "event": "FEDERATION_WORKER_LOG", "message": message},
    )
    print(json.dumps(entry, ensure_ascii=False, sort_keys=True), flush=True)

def stop_handler(signum, frame):
    global STOP
    STOP = True
    log(f"STOP_SIGNAL={signum}")

def run_engine(name, args):
    command = [sys.executable, str(ROOT / args[0]), *args[1:]]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT,
            check=False,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        output = (result.stdout or "").strip()
        if output:
            for line in output.splitlines()[-35:]:
                log(f"{name}: {line[:1200]}")
        return {
            "engine": name,
            "exit_code": result.returncode,
            "status": "PASS" if result.returncode == 0 else "ERROR",
        }
    except subprocess.TimeoutExpired:
        log(f"{name}: TIMEOUT after {TIMEOUT}s")
        return {"engine": name, "status": "TIMEOUT"}
    except Exception as exc:
        log(f"{name}: ERROR {type(exc).__name__}: {exc}")
        return {"engine": name, "status": "ERROR"}

def save_report(cycle, results):
    data = {
        "schema": "IAO_CONTINUOUS_FEDERATION_WORKER_V1",
        "updated_at": now(),
        "cycle": cycle,
        "interval_seconds": INTERVAL,
        "results": results,
        "continuous_discovery": True,
        "identity_verification_attempted": True,
        "automatic_enrollment": False,
        "capability_exchange": False,
        "external_nodes_confirmed": 0,
        "claim_of_network_growth": False,
    }
    REPORT.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(REPORT, 0o600)

def main():
    STATE.mkdir(exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    LOGDIR.mkdir(exist_ok=True, mode=0o700)
    os.chmod(LOGDIR, 0o700)

    if PIDFILE.exists():
        try:
            old_pid = int(PIDFILE.read_text().strip())
            os.kill(old_pid, 0)
            print(f"WORKER_ALREADY_RUNNING pid={old_pid}", flush=True)
            return 0
        except (ValueError, ProcessLookupError, PermissionError):
            pass

    PIDFILE.write_text(str(os.getpid()), encoding="utf-8")
    os.chmod(PIDFILE, 0o600)
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    log(f"WORKER_STARTED pid={os.getpid()} interval={INTERVAL}s")
    heartbeat("starting")
    cycle = 0
    try:
        while not STOP:
            cycle += 1
            heartbeat("cycle_running")
            log(f"CYCLE={cycle} START")

            results = []
            results.append(run_engine(
                "FEDERATION_DISCOVERY",
                ["tools/iao_federation_autonomy.py", "--once"],
            ))
            if STOP:
                break

            results.append(run_engine(
                "IDENTITY_VERIFICATION",
                ["tools/iao_federation_candidate_verify.py", "probe"],
            ))

            save_report(cycle, results)
            heartbeat("cycle_completed", all(item.get("status") == "PASS" for item in results))
            log(f"CYCLE={cycle} FINISHED")
            for _ in range(INTERVAL):
                if STOP:
                    break
                time.sleep(1)
    finally:
        try:
            PIDFILE.unlink()
        except FileNotFoundError:
            pass
        log("WORKER_STOPPED")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
