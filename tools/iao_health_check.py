#!/usr/bin/env python3
"""Verificador de latido de los cinco motores IAO. Solo stdlib, solo lectura.

Estados: OK_HEARTBEAT | DEGRADED | STALE | DEAD | UNKNOWN
(UNKNOWN != PASS: significa que no hay evidencia suficiente.)
Salida: 0 = todo OK_HEARTBEAT, 1 = hay DEAD/STALE/DEGRADED, 2 = solo UNKNOWN pendientes.
"""
import glob
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = Path(os.environ.get("IAO_STATE_DIR", ROOT / ".state" / "iao-five-motors"))
LOGS = STATE / "logs"

MOTORS = [
    ("GUARDIAN", "guardian.log", 900),
    ("NODE_NETWORK", "node_network.log", 900),
    ("DISTRIBUTED_INTELLIGENCE", "distributed_intelligence.log", 900),
    ("PADGE", "padge*.log", 900),
    ("AUTONOMY_CONTINUOUS", "autonomy_continuous.log", None),
]
FAIL_MARKERS = ("FAILED", "cycle_error", "Traceback", "Error", "ALL_PROVIDERS_FAILED")
TAIL_LINES = 3


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(path: Path):
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def newest(pattern: str):
    files = glob.glob(str(LOGS / pattern))
    return max(files, key=os.path.getmtime) if files else None


def tail(path: str, n: int = TAIL_LINES):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 16384))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    return [ln for ln in data.splitlines() if ln.strip()][-n:]


def supervised_pids():
    """PID vigente de cada motor segun los eventos del supervisor (no segun .pid obsoletos)."""
    import json
    events = []
    for f in glob.glob(str(LOGS / "supervisor*.log")):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    try:
                        ev = json.loads(ln)
                    except ValueError:
                        continue
                    if isinstance(ev, dict) and "time" in ev:
                        events.append(ev)
        except OSError:
            pass
    events.sort(key=lambda e: e["time"])
    pids, seen, sup = {}, set(), None
    for ev in events:
        kind, motor = ev.get("event"), ev.get("motor")
        if motor:
            seen.add(motor)
        if kind == "supervisor_started":
            sup = ev.get("pid")
        elif kind == "supervisor_stopped":
            sup = None
        elif kind == "motor_started" and motor:
            pids[motor] = ev.get("pid")
        elif kind in ("motor_exited", "forced_stop", "stop_requested") and motor:
            pids.pop(motor, None)
    return pids, sup, seen


def find_by_cmdline(fragment):
    """PID de un proceso Python vivo cuya linea de comandos contiene `fragment` (via ps)."""
    import subprocess
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid,args"], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    me = os.getpid()
    for ln in out.splitlines()[1:]:
        parts = ln.strip().split(None, 1)
        if (len(parts) == 2 and parts[0].isdigit() and int(parts[0]) != me
                and fragment in parts[1] and "python" in parts[1].split()[0]):
            return int(parts[0])
    return None


SUP_PIDS, SUP_PID, SUP_SEEN = supervised_pids()


def check(name: str, pattern: str, max_age):
    pid = SUP_PIDS.get(name)
    if name not in SUP_SEEN:
        pid = read_pid(STATE / f"{name}.pid")
    if pid is None and name == "AUTONOMY_CONTINUOUS":
        pid = find_by_cmdline("iao_autonomy_daemon.py")  # corre fuera del supervisor
    if pid is None:
        return "DEAD", "sin PID vigente (supervisor, .pid o proceso)"
    if not pid_alive(pid):
        return "DEAD", f"PID {pid} no existe"
    log = newest(pattern)
    if log is None:
        return "UNKNOWN", f"PID {pid} vivo pero no hay log ({pattern})"
    age = time.time() - os.path.getmtime(log)
    last = tail(log)
    if max_age is None:
        return "UNKNOWN", f"PID {pid} vivo; sin latido definido (log hace {int(age)}s)"
    if age > max_age:
        return "STALE", f"PID {pid} vivo pero {os.path.basename(log)} no avanza hace {int(age)}s"
    bad = [ln for ln in last if any(m in ln for m in FAIL_MARKERS)]
    if bad:
        return "DEGRADED", f"PID {pid}, log fresco pero con fallo: {bad[-1][:160]}"
    return "OK_HEARTBEAT", f"PID {pid}, log avanzo hace {int(age)}s"


def main() -> int:
    print(f"IAO HEALTH CHECK  estado={STATE}")
    results = []
    for name, pattern, max_age in MOTORS:
        status, detail = check(name, pattern, max_age)
        results.append(status)
        print(f"{name:26} {status:13} {detail}")
    sup = SUP_PID
    if sup is None:
        print(f"{'SUPERVISOR':26} {'UNKNOWN':13} sin archivo pid del supervisor")
        results.append("UNKNOWN")
    else:
        st = "OK_HEARTBEAT" if pid_alive(sup) else "DEAD"
        results.append(st)
        print(f"{'SUPERVISOR':26} {st:13} PID {sup}")
    print("NOTA: OK_HEARTBEAT = vivo + log reciente + sin fallos visibles; no es VALIDATED.")
    if any(r in ("DEAD", "STALE", "DEGRADED") for r in results):
        return 1
    if "UNKNOWN" in results:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
