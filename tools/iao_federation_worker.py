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

def now():
    return datetime.now(timezone.utc).isoformat()

def log(message):
    line = f"{now()} {message}"
    print(line, flush=True)
    LOGDIR.mkdir(exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

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

def main():
    STATE.mkdir(exist_ok=True)
    LOGDIR.mkdir(exist_ok=True)

    if PIDFILE.exists():
        try:
            old_pid = int(PIDFILE.read_text().strip())
            os.kill(old_pid, 0)
            print(f"WORKER_ALREADY_RUNNING pid={old_pid}", flush=True)
            return 0
        except (ValueError, ProcessLookupError, PermissionError):
            pass

    PIDFILE.write_text(str(os.getpid()), encoding="utf-8")
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    log(f"WORKER_STARTED pid={os.getpid()} interval={INTERVAL}s")
    cycle = 0
    try:
        while not STOP:
            cycle += 1
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
