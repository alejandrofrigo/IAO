#!/usr/bin/env python3
import os
import sys
import time
import json
import fcntl
import signal
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state/iao-integrated-operations"
LOGS = STATE / "logs"
LOG = LOGS / "central-supervisor.log"
STATUS = STATE / "status.json"
LOCK = STATE / "central-supervisor.lock"

LOGS.mkdir(parents=True, exist_ok=True)

os.chdir(ROOT)

def log(message):
    line = f"{datetime.now(timezone.utc).isoformat()} {message}"
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)

# Únicas instancias administradas por esta capa.
# No se inicia un trabajador individual: lo administra
# el supervisor de trabajadores existente.
COMPONENTS = {
    "PADGE": [
        sys.executable, "-m", "omega.padge", "loop"
    ],
    "AUTONOMY_DAEMON": [
        sys.executable, "tools/iao_autonomy_daemon.py"
    ],
    "WORKER_SUPERVISOR": [
        sys.executable, "tools/iao_autonomous_worker_supervisor.py"
    ],
    "GUARDIAN": [
        sys.executable, "tools/iao_guardian.py"
    ],
    "FEDERATION_WORKER": [
        sys.executable, "tools/iao_federation_worker.py"
    ],
}

def process_matches(spec):
    result = []
    expected = spec[1:]

    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            argv = [
                x.decode(errors="replace")
                for x in raw.split(b"\0") if x
            ]
            if not argv:
                continue

            # Coincidencia de argumentos sin buscar por texto
            # dentro de comandos de shell.
            if len(argv) >= len(expected):
                for i in range(len(argv) - len(expected) + 1):
                    if argv[i:i + len(expected)] == expected:
                        result.append(pid)
                        break
        except (OSError, PermissionError):
            continue
    return result

children = {}
stopping = False

def save_status():
    data = {
        "supervisor": "ACTIVE",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "components": {},
        "policy": {
            "duplicate_workers_created": False,
            "existing_components_reused": True,
            "readiness_manually_overridden": False
        }
    }

    for name, spec in COMPONENTS.items():
        matches = process_matches(spec)
        data["components"][name] = {
            "status": "ACTIVE" if matches else "NOT_RUNNING",
            "pids": matches
        }

    tmp = STATUS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(STATUS)

def stop_handler(signum, frame):
    global stopping
    stopping = True
    log(f"SEÑAL_DE_PARADA={signum}")

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)

with LOCK.open("w") as lockfile:
    try:
        fcntl.flock(
            lockfile.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB
        )
    except BlockingIOError:
        print("SUPERVISOR_CENTRAL_YA_ACTIVO")
        sys.exit(0)

    log("SUPERVISOR_CENTRAL_INICIADO")

    while not stopping:
        for name, spec in COMPONENTS.items():
            if stopping:
                break

            script = spec[-1]

            if name == "PADGE":
                if not (ROOT / "omega/padge.py").is_file():
                    log("PADGE: ARCHIVO_AUSENTE")
                    continue
            elif not (ROOT / script).is_file():
                log(f"{name}: ARCHIVO_AUSENTE")
                continue

            existing = process_matches(spec)

            if existing:
                log(f"{name}: REUTILIZADO PID={existing}")
                continue

            try:
                out = (LOGS / f"{name.lower()}.log").open(
                    "a", encoding="utf-8"
                )
                child = subprocess.Popen(
                    spec,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
                children[name] = child
                log(f"{name}: INICIADO PID={child.pid}")
            except Exception as exc:
                log(f"{name}: ERROR={type(exc).__name__}: {exc}")

        save_status()

        for _ in range(20):
            if stopping:
                break
            time.sleep(1)

    save_status()
    log("SUPERVISOR_CENTRAL_DETENIDO")
