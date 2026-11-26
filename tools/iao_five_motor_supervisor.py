#!/usr/bin/env python3
"""IAO: supervisor de cinco motores con procesos aislados."""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "iao-five-motors"
LOGS = STATE / "logs"
PID_FILE = STATE / "supervisor.pid"
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
    STATE.mkdir(parents=True, exist_ok=True)
    record = {"time": now(), "event": name, **data}
    with EVENTS.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False), flush=True)


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


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



def proc_starttime(pid):
    """Devuelve el starttime del proceso desde /proc/PID/stat."""
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text()
        tail = raw[raw.rfind(")") + 2:].split()
        return int(tail[19])
    except (OSError, ValueError, IndexError, TypeError):
        return None


def reconcile_children_before_start():
    """Conserva hijos vivos verificados y elimina solo registros obsoletos."""
    children = read_children()
    if not isinstance(children, dict):
        print("START_BLOCKED: children.json no es un objeto válido")
        event("startup_blocked_invalid_children_file")
        return False

    kept = {}
    stale = []

    for name, child in children.items():
        if not isinstance(child, dict):
            print(f"START_BLOCKED: registro inválido motor={name}")
            event("startup_blocked_invalid_child_record", motor=name)
            return False

        pid = child.get("pid")
        if type(pid) is not int or pid <= 0:
            print(f"START_BLOCKED: PID inválido motor={name}")
            event("startup_blocked_invalid_child_pid", motor=name)
            return False

        if not process_alive(pid):
            stale.append(name)
            continue

        if not child_group_matches(child):
            print(f"START_BLOCKED: identidad no verificada motor={name} pid={pid}")
            event("startup_blocked_existing_child", motor=name, pid=pid,
                  identity="IDENTITY_UNVERIFIED")
            return False

        starttime = proc_starttime(pid)
        if starttime is None:
            print(f"START_BLOCKED: no se pudo verificar starttime motor={name}")
            event("startup_blocked_starttime_unavailable", motor=name, pid=pid)
            return False

        updated = dict(child)
        updated["starttime"] = starttime
        kept[name] = updated
        event("existing_child_verified_for_adoption", motor=name, pid=pid)

    if stale:
        event("stale_child_records_reconciled", motors=stale)

    if stale or kept != children:
        save_json(CHILD_FILE, kept)

    print("VERIFIED_CHILDREN=" + ",".join(kept.keys()))
    print("STALE_CHILDREN=" + ",".join(stale))
    return True


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        # El proceso existe, aunque este usuario no pueda señalizarlo.
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False


def process_command(pid):
    try:
        raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
        return [part.decode("utf-8", "replace")
                for part in raw.split(b"\0") if part]
    except (OSError, ValueError, TypeError):
        return []


def process_matches(pid, command=None, token=None):
    if not pid or not process_alive(pid):
        return False

    actual = process_command(pid)
    if not actual:
        return False

    if command:
        import shutil

        expected = [str(part) for part in command]
        if not expected:
            return False

        expected_path = shutil.which(expected[0]) or expected[0]
        expected_exe = os.path.realpath(expected_path)
        actual_exe = os.path.realpath(actual[0])

        if os.path.basename(actual_exe) != os.path.basename(expected_exe):
            return False

        # Forma habitual: python script.py argumentos...
        normal_argv = actual[1:] == expected[1:]

        # Forma observada en Termux: python python script.py argumentos...
        duplicated_termux_argv = (
            len(actual) >= 2
            and os.path.realpath(actual[1]) == expected_exe
            and actual[2:] == expected[1:]
        )

        if not (normal_argv or duplicated_termux_argv):
            return False

    if token and not any(token in part for part in actual):
        return False

    return True



def child_group_matches(child):
    pid = child.get("pid")
    command = child.get("command")
    if not process_matches(pid, command=command):
        return False
    try:
        # Cada hijo se crea con start_new_session=True: su PGID debe ser su PID.
        return os.getpgid(int(pid)) == int(pid)
    except (OSError, ValueError, TypeError):
        return False



class AdoptedProcess:
    """Supervisa un proceso adoptado sin provocar relanzamientos por dudas."""
    def __init__(self, pid, command, starttime):
        self.pid = int(pid)
        self.command = list(command)
        self.starttime = int(starttime)
        self.identity_status = "UNVERIFIED"

    def poll(self):
        # Solo la ausencia efectiva del PID significa que el proceso terminó.
        if not process_alive(self.pid):
            self.identity_status = "PROCESS_GONE"
            return 255

        # Cualquier fallo de lectura o discrepancia mantiene reservado el motor.
        current = proc_starttime(self.pid)
        if current is None:
            self.identity_status = "STARTTIME_UNAVAILABLE"
            return None

        if current != self.starttime:
            self.identity_status = "PID_REUSED_OR_CHANGED"
            return None

        if not process_matches(self.pid, command=self.command):
            self.identity_status = "COMMAND_UNVERIFIED"
            return None

        try:
            if os.getpgid(self.pid) != self.pid:
                self.identity_status = "PROCESS_GROUP_UNVERIFIED"
                return None
        except (OSError, ValueError, TypeError):
            self.identity_status = "PROCESS_GROUP_UNAVAILABLE"
            return None

        self.identity_status = "VERIFIED"
        return None

def status():
    children = read_children()
    configured = adapters()
    print("\\nIAO — ESTADO DE LOS CINCO MOTORES")
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
        alive = bool(pid and child_group_matches(child))

        if alive:
            state = "RUNNING"
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

    print("\\nPADGE y autonomía continua comparten el coordinador.")
    print(f"EVENTS={EVENTS}")


def stop_children():
    children = read_children()
    pending = {}

    for name, child in children.items():
        if not isinstance(child, dict):
            pending[name] = child
            event("stop_refused_invalid_record", motor=name)
            continue

        pid = child.get("pid")
        if not pid or not process_alive(pid):
            continue

        if not child_group_matches(child):
            pending[name] = child
            event("stop_refused_identity_mismatch", motor=name, pid=pid)
            continue

        try:
            os.killpg(int(pid), signal.SIGTERM)
            event("stop_requested", motor=name, pid=pid)
        except ProcessLookupError:
            continue
        except (PermissionError, OSError) as exc:
            pending[name] = child
            event("stop_signal_failed", motor=name,
                  pid=pid, error=type(exc).__name__)

    deadline = time.time() + 15
    while time.time() < deadline:
        alive = []
        for name, child in children.items():
            if not isinstance(child, dict):
                continue
            pid = child.get("pid")
            if pid and child_group_matches(child):
                alive.append((name, child))
        if not alive:
            break
        time.sleep(1)

    for name, child in children.items():
        if not isinstance(child, dict):
            continue
        pid = child.get("pid")
        if not pid or not child_group_matches(child):
            continue
        try:
            os.killpg(int(pid), signal.SIGKILL)
            event("forced_stop", motor=name, pid=pid)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            event("forced_stop_failed", motor=name,
                  pid=pid, error=type(exc).__name__)

    # Dar tiempo al sistema para completar la terminación forzada.
    kill_deadline = time.time() + 5
    while time.time() < kill_deadline:
        still_running = []
        for name, child in children.items():
            if isinstance(child, dict) and child_group_matches(child):
                still_running.append(name)
        if not still_running:
            break
        time.sleep(0.25)

    # Conservar registros no verificables o procesos que sigan vivos.
    for name, child in children.items():
        if name in pending or not isinstance(child, dict):
            continue
        pid = child.get("pid")
        if pid and process_alive(pid):
            if child_group_matches(child):
                pending[name] = child
            else:
                pending[name] = child
                event("child_record_preserved", motor=name, pid=pid)

    save_json(CHILD_FILE, pending)
    event("children_stop_finished",
          remaining=list(pending.keys()))


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
            event("entrypoint_missing", motor=name, path=str(target))
            return None

    log_path = LOGS / f"{name.lower()}.log"
    stream = log_path.open("a", encoding="utf-8")
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
        "starttime": proc_starttime(proc.pid),
        "command": command,
        "log": str(log_path),
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
    STATE.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    lock_stream = (STATE / "supervisor.lock").open("a", encoding="utf-8")
    try:
        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_stream.close()
        print("SUPERVISOR_ALREADY_RUNNING")
        return 2

    # Inicializar antes de cualquier salida que pueda activar finally.
    processes = {}
    owned = set()
    pidfile_owned = False
    specs = {}

    try:
        if PID_FILE.exists():
            old_pid = PID_FILE.read_text(errors="replace").strip()
            if old_pid.isdigit() and process_matches(
                old_pid, token="iao_five_motor_supervisor.py"
            ):
                print(f"Supervisor ya activo: PID={old_pid}")
                return 2

        if not reconcile_children_before_start():
            return 4

        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        pidfile_owned = True
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        specs = adapters()
        children = read_children()
        restart_history = {name: [] for name in specs}

        event("supervisor_started", pid=os.getpid())

        # Adoptar procesos existentes; no se crea un segundo ejemplar.
        for name, child in children.items():
            spec = specs.get(name, {})
            if not spec.get("enabled") or not spec.get("command"):
                continue
            pid = child["pid"]
            expected = spec["command"]
            starttime = child.get("starttime")
            if (
                child.get("command") == expected
                and starttime is not None
                and process_matches(pid, command=expected)
                and proc_starttime(pid) == starttime
                and child_group_matches(child)
            ):
                processes[name] = AdoptedProcess(pid, expected, starttime)
                event("motor_adopted", motor=name, pid=pid)
            else:
                # Un PID vivo pero no verificable bloquea el relanzamiento:
                # nunca crear un duplicado por una lectura transitoria.
                if process_alive(pid):
                    guard_starttime = (
                        starttime if type(starttime) is int else -1
                    )
                    guard = AdoptedProcess(pid, expected, guard_starttime)
                    guard.identity_status = "ADOPTION_UNVERIFIED"
                    processes[name] = guard
                    event(
                        "adoption_refused_process_preserved",
                        motor=name,
                        pid=pid,
                        identity="UNVERIFIED_NO_RELAUNCH",
                    )
                else:
                    event("adoption_refused", motor=name, pid=pid)

        # Lanzar solamente motores habilitados que no fueron adoptados.
        for name, spec in specs.items():
            if not spec.get("enabled") or name in processes:
                continue
            proc = launch(name, spec)
            if proc:
                processes[name] = proc
                owned.add(name)

        if not processes:
            event("no_motor_started")
            return 3

        while not STOP:
            for name, proc in list(processes.items()):
                code = proc.poll()
                if code is None:
                    continue

                event("motor_exited", motor=name, exit_code=code,
                      ownership="OWNED" if name in owned else "ADOPTED")

                del processes[name]
                owned.discard(name)

                history = [
                    t for t in restart_history[name]
                    if time.time() - t < RESTART_WINDOW
                ]
                restart_history[name] = history

                if STOP or len(history) >= MAX_RESTARTS:
                    event("restart_limit_or_stop", motor=name)
                    current = read_children()
                    record = current.get(name, {})
                    if record.get("pid") == proc.pid:
                        current.pop(name, None)
                        save_json(CHILD_FILE, current)
                    continue

                history.append(time.time())
                time.sleep(2)
                replacement = launch(name, specs[name])
                if replacement:
                    processes[name] = replacement
                    owned.add(name)

            time.sleep(CHECK_INTERVAL)

    finally:
        STOP = True

        # Terminar exclusivamente procesos creados en ESTA ejecución.
        current = read_children()
        for name in list(owned):
            child = current.get(name, {})
            pid = child.get("pid")
            proc = processes.get(name)
            if not pid or proc is None:
                continue
            expected_start = child.get("starttime")
            if (
                expected_start is not None
                and proc_starttime(pid) == expected_start
                and process_matches(pid, command=child.get("command"))
                and child_group_matches(child)
            ):
                try:
                    os.killpg(int(pid), signal.SIGTERM)
                    event("owned_child_stop_requested", motor=name, pid=pid)
                except (ProcessLookupError, PermissionError, OSError) as exc:
                    event("owned_child_stop_failed", motor=name, pid=pid,
                          error=type(exc).__name__)

        deadline = time.time() + 8
        while time.time() < deadline:
            alive_owned = []
            for name in list(owned):
                child = current.get(name, {})
                pid = child.get("pid")
                if pid and process_alive(pid) and child_group_matches(child):
                    alive_owned.append(name)
            if not alive_owned:
                break
            time.sleep(0.25)

        # Quitar del registro solo los hijos propios que ya terminaron.
        latest = read_children()
        for name in list(owned):
            child = latest.get(name, {})
            pid = child.get("pid")
            if not pid or not process_alive(pid):
                latest.pop(name, None)
        save_json(CHILD_FILE, latest)

        try:
            if pidfile_owned and PID_FILE.exists():
                try:
                    if PID_FILE.read_text(encoding='utf-8').strip() == str(os.getpid()):
                        PID_FILE.unlink()
                except OSError as exc:
                    print(f'PIDFILE_CLEANUP_WARNING: {type(exc).__name__}')
        except OSError:
            pass

        event("supervisor_stopped",
              adopted_preserved=True,
              owned_motors=list(owned))

        try:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
        finally:
            lock_stream.close()

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
            if not process_matches(pid, token="iao_five_motor_supervisor.py"):
                print("STOP_REFUSED: PID ocupado por un proceso no identificado como supervisor")
                return 1
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

        # Un PID de supervisor obsoleto no autoriza detener motores.
        # Los registros de hijos se conservan intactos.
        print("STOP_REFUSED_STALE_SUPERVISOR: hijos preservados; no se enviaron señales")
        return 1

    print("Uso: python tools/iao_five_motor_supervisor.py "
          "{status|start|stop}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
