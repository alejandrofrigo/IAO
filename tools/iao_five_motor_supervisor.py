#!/usr/bin/env python3
"""IAO: supervisor de cinco motores con procesos aislados."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "iao-five-motors"
LOGS = STATE / "logs"
PID_FILE = STATE / "supervisor.pid"
COORDINATOR_LOCK = ROOT / ".state" / "iao-autonomy" / "coordinator.lock"
CHILD_FILE = STATE / "children.json"
EVENTS = STATE / "events.jsonl"
CONFIG = STATE / "adapters.json"

STOP = False
MAX_RESTARTS = 3
RESTART_WINDOW = 600
CHECK_INTERVAL = 5


def now():
    return datetime.now(timezone.utc).isoformat()


def event(name, **data):
    from omega.operational_log import append_private_jsonl

    entry = append_private_jsonl(
        EVENTS, {"time": now(), "event": name, **data},
    )
    print(json.dumps(entry, ensure_ascii=False), flush=True)


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def adapters():
    if not CONFIG.exists():
        save_json(CONFIG, {
            "motors": {
                "PADGE": {
                    "command": [
                        sys.executable,
                        "tools/iao_autonomous_coordinator.py",
                        "loop",
                    ],
                    "enabled": True,
                    "group": "PADGE + AUTONOMIA CONTINUA",
                },
                "GUARDIAN": {
                    "command": [],
                    "enabled": False,
                    "group": "VIGILANCIA Y RECUPERACION",
                },
                "NODE_NETWORK": {
                    "command": [],
                    "enabled": False,
                    "group": "RED DE NODOS",
                },
                "DISTRIBUTED_INTELLIGENCE": {
                    "command": [],
                    "enabled": False,
                    "group": "WORKERS + MULTI-LLM",
                },
            }
        })
    return load_json(CONFIG, {}).get("motors", {})


def read_children():
    return load_json(CHILD_FILE, {})


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # The process exists, but the current user cannot signal it.
        return True
    except (TypeError, ValueError, OverflowError):
        return False


def status():
    children = read_children()
    configured = adapters()
    print("\nIAO — ESTADO DE LOS CINCO MOTORES")
    print("=" * 48)

    for name in (
        "PADGE",
        "AUTONOMY_CONTINUOUS",
        "GUARDIAN",
        "NODE_NETWORK",
        "DISTRIBUTED_INTELLIGENCE",
    ):
        spec = configured.get(name, {})
        child = children.get(name, {})
        pid = child.get("pid")
        alive = bool(pid and process_alive(pid))

        if alive:
            state = "PROCESS_ALIVE_UNVERIFIED"
            if name in {"PADGE", "AUTONOMY_CONTINUOUS"}:
                from omega.supervision import read_heartbeat, read_lock_owner

                heartbeat = read_heartbeat(
                    ROOT / ".state" / "iao-autonomy" / "coordinator-heartbeat.json",
                    expected_component="PADGE_AUTONOMY",
                )
                lock_owner = read_lock_owner(COORDINATOR_LOCK)
                if heartbeat.get("pid") == int(pid) == lock_owner:
                    if heartbeat["status"] in {"HEALTHY", "CYCLE_IN_PROGRESS"}:
                        state = heartbeat["status"]
                    elif heartbeat["status"] == "STALE":
                        state = "STALE_HEARTBEAT"
        elif not spec.get("enabled") or not spec.get("command"):
            state = "NOT_CONFIGURED"
        else:
            state = "STOPPED"

        print(f"{name}: {state}")
        if alive:
            print(f"  PID={pid}")
        elif spec.get("command"):
            print("  COMMAND_CONFIGURED=YES")
        else:
            print("  COMMAND_CONFIGURED=NO")

    print("\nPADGE y autonomía continua comparten el coordinador.")
    print("Solo un heartbeat reciente del ciclo valida el coordinador; los demás PID quedan sin verificar.")
    print(f"EVENTS={EVENTS}")


def stop_children():
    children = read_children()

    for name, child in children.items():
        pid = child.get("pid")
        if not pid or not process_alive(pid):
            continue
        try:
            os.killpg(int(pid), signal.SIGTERM)
            event("stop_requested", motor=name, pid=pid)
        except ProcessLookupError:
            pass

    deadline = time.time() + 15
    while time.time() < deadline:
        remaining = [
            (name, child.get("pid"))
            for name, child in children.items()
            if child.get("pid") and process_alive(child["pid"])
        ]
        if not remaining:
            break
        time.sleep(1)

    for name, child in children.items():
        pid = child.get("pid")
        if pid and process_alive(pid):
            try:
                os.killpg(int(pid), signal.SIGKILL)
                event("forced_stop", motor=name, pid=pid)
            except ProcessLookupError:
                pass

    save_json(CHILD_FILE, {})
    event("all_children_stopped")


def launch(name, spec):
    command = spec.get("command")
    if not isinstance(command, list) or not command:
        event("adapter_not_configured", motor=name)
        return None

    if not spec.get("enabled", False):
        event("adapter_disabled", motor=name)
        return None

    executable = command[0]
    if executable == sys.executable:
        if len(command) < 2:
            event("invalid_command", motor=name)
            return None
        target = ROOT / command[1]
        if not target.is_file():
            event("entrypoint_missing", motor=name)
            return None

    LOGS.mkdir(parents=True, exist_ok=True)
    os.chmod(LOGS, 0o700)
    log_path = LOGS / f"{name.lower()}.log"
    stream = log_path.open("a", encoding="utf-8")
    os.fchmod(stream.fileno(), 0o600)
    stream.write(f"\n--- START {now()} ---\n")
    stream.flush()

    try:
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    except Exception as exc:
        stream.close()
        event("launch_failed", motor=name, error=type(exc).__name__)
        return None

    child = {
        "pid": proc.pid,
        "started": now(),
    }
    children = read_children()
    children[name] = child
    save_json(CHILD_FILE, children)
    event("motor_started", motor=name, pid=proc.pid)
    return proc


def handle_signal(_signum, _frame):
    global STOP
    STOP = True


def run():
    global STOP
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    LOGS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    os.chmod(LOGS, 0o700)

    if PID_FILE.exists():
        old_pid = PID_FILE.read_text(errors="replace").strip()
        if old_pid.isdigit() and process_alive(old_pid):
            print(f"Supervisor ya activo: PID={old_pid}")
            return 2

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    specs = adapters()
    processes = {}
    restart_history = {name: [] for name in specs}

    event("supervisor_started", pid=os.getpid())

    try:
        for name, spec in specs.items():
            if spec.get("enabled"):
                proc = launch(name, spec)
                if proc:
                    processes[name] = proc

        if not processes:
            event("no_motor_started")
            return 3

        while not STOP:
            for name, proc in list(processes.items()):
                code = proc.poll()
                if code is None:
                    continue

                event("motor_exited", motor=name, exit_code=code)
                history = [
                    t for t in restart_history[name]
                    if time.time() - t < RESTART_WINDOW
                ]
                restart_history[name] = history

                if STOP or len(history) >= MAX_RESTARTS:
                    event("restart_limit_or_stop", motor=name)
                    del processes[name]
                    continue

                history.append(time.time())
                time.sleep(2)
                replacement = launch(name, specs[name])
                if replacement:
                    processes[name] = replacement
                else:
                    del processes[name]

            time.sleep(CHECK_INTERVAL)

    finally:
        STOP = True
        stop_children()
        try:
            PID_FILE.unlink()
        except FileNotFoundError:
            pass
        event("supervisor_stopped")

    return 0


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "status"

    if command == "status":
        status()
        return 0
    if command == "start":
        return run()
    if command == "stop":
        pid = None
        try:
            raw = PID_FILE.read_text().strip()
            if raw.isdigit():
                pid = int(raw)
        except FileNotFoundError:
            pass

        if pid and pid != os.getpid() and process_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

            deadline = time.time() + 20
            while time.time() < deadline and process_alive(pid):
                time.sleep(1)

            if process_alive(pid):
                print("STOP_FAILED: supervisor sigue activo; no se forzó su terminación")
                return 1

            print("SUPERVISOR_STOPPED")
            return 0

        stop_children()
        try:
            PID_FILE.unlink()
        except FileNotFoundError:
            pass
        print("STALE_CHILDREN_CLEANED")
        return 0

    print("Uso: python tools/iao_five_motor_supervisor.py "
          "{status|start|stop}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
