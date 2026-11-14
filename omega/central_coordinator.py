"""
IAO Central Coordinator
Orquesta los motores existentes sin duplicar sus procesos.
Los motores conservan su autoridad y sus propias políticas.
"""
from __future__ import annotations

import fcntl
import importlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "iao-central"
REPORT = STATE / "status.json"
EVENTS = STATE / "events.jsonl"
LOCK = STATE / "coordinator.lock"
INTERVAL = max(60, int(os.environ.get("IAO_CENTRAL_INTERVAL", "120")))

# Procesos que ya tienen sus propios supervisores.
# El coordinador los descubre; nunca los vuelve a lanzar.
ENGINES = {
    "padge": {
        "module": "omega.padge",
        "process": "omega.padge",
        "status": ".state/padge/status.json",
    },
    "autoconstruction": {
        "module": "omega.autoconstruction",
        "process": "omega.autoconstruction",
        "status": ".state/autoconstruction/status.json",
    },
    "autobuilder": {
        "module": "omega.autobuilder",
        "process": "omega.autobuilder",
        "status": ".state/autobuilder/status.json",
    },
    "autonomy": {
        "module": None,
        "process": "iao_autonomy_daemon.py",
        "status": None,
    },
    "workers": {
        "module": None,
        "process": "iao_autonomous_worker",
        "status": None,
    },
    "federation": {
        "module": None,
        "process": "iao_federation_worker.py",
        "status": None,
    },
    "llm_router": {
        "module": "omega.llm_router",
        "process": None,
        "status": None,
    },
    "guardian": {
        "module": None,
        "process": "iao_guardian",
        "status": None,
    },
    "watchdog": {
        "module": None,
        "process": "iao_watchdog",
        "status": None,
    },
    "control_plane": {
        "module": "tools.iao_control_plane",
        "process": "iao_control_plane.py",
        "status": ".state/iao-control-plane-report.json",
    },
}

def now():
    return datetime.now(timezone.utc).isoformat()

def emit(event, **data):
    STATE.mkdir(parents=True, exist_ok=True)
    record = {"time": now(), "event": event, **data}
    with EVENTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def processes():
    found = []
    proc = Path("/proc")
    if not proc.exists():
        return found
    for p in proc.iterdir():
        if not p.name.isdigit():
            continue
        try:
            raw = (p / "cmdline").read_bytes()
            cmd = raw.replace(b"\0", b" ").decode(errors="replace").strip()
            if cmd:
                found.append({"pid": int(p.name), "cmd": cmd})
        except OSError:
            continue
    return found

def discover():
    ps = processes()
    result = {}
    for name, spec in ENGINES.items():
        needle = spec["process"]
        matches = [
            p for p in ps
            if needle and needle in p["cmd"]
            and "central_coordinator.py" not in p["cmd"]
        ]
        result[name] = {
            "process_count": len(matches),
            "pids": [p["pid"] for p in matches],
            "running": bool(matches),
        }
        module = spec["module"]
        if module:
            try:
                importlib.import_module(module)
                result[name]["importable"] = True
            except Exception as exc:
                result[name]["importable"] = False
                result[name]["import_error"] = type(exc).__name__
    return result

def read_status():
    result = {}
    for name, spec in ENGINES.items():
        rel = spec["status"]
        if not rel:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            result[name] = data
        except Exception as exc:
            result[name] = {"read_error": type(exc).__name__}
    return result

def cycle():
    engines = discover()
    reports = read_status()

    # No se arrancan motores aquí. Sus supervisores originales
    # mantienen el ciclo de vida y la exclusión mutua.
    running = [k for k, v in engines.items() if v.get("running")]
    missing = [k for k, v in engines.items() if not v.get("running")]

    state = {
        "timestamp": now(),
        "coordinator": "IAO_CENTRAL",
        "mode": "COORDINATION_ONLY",
        "health": "NORMAL" if not missing else "DEGRADED",
        "engines": engines,
        "running_engines": running,
        "not_detected": missing,
        "engine_status_reports": reports,
        "duplicate_processes": {
            k: v["pids"] for k, v in engines.items()
            if v.get("process_count", 0) > 1
        },
        "policy": {
            "start_existing_engines": False,
            "spawn_workers": False,
            "spawn_padge": False,
            "spawn_supervisors": False,
            "automatic_federation_enrollment": False,
            "automatic_code_promotion": False,
            "destructive_changes": False,
            "llm_output_is_authoritative": False,
        },
    }

    STATE.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp.replace(REPORT)
    emit(
        "coordination_cycle",
        health=state["health"],
        running=running,
        missing=missing,
        duplicates=state["duplicate_processes"],
    )
    print(json.dumps({
        "health": state["health"],
        "running_engines": running,
        "not_detected": missing,
        "duplicate_processes": state["duplicate_processes"],
        "report": str(REPORT),
    }, indent=2, ensure_ascii=False))
    return state

def main():
    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("IAO_CENTRAL_ALREADY_RUNNING")
            return 0

        emit("coordinator_started", pid=os.getpid())
        print("IAO CENTRAL COORDINATOR ACTIVO")
        print("Modo: coordinación sin duplicación de motores")

        while True:
            try:
                cycle()
            except Exception as exc:
                emit("cycle_error", error=type(exc).__name__)
                print("CYCLE_ERROR:", type(exc).__name__, flush=True)
            time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("IAO CENTRAL: cierre solicitado")
