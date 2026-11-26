from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "autoconstruction"
LOG = STATE / "engine.log"
STATUS = STATE / "status.json"
LOCK = STATE / "engine.lock"
STOP = False


def now():
    return datetime.now(timezone.utc).isoformat()


def write_status(**data):
    STATE.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": now(),
        "engine": "IAO Autoconstruction Engine",
        "version": 1,
        **data,
    }
    tmp = STATUS.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, STATUS)


def existing_padge():
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            if pid == os.getpid():
                continue

            stat = (entry / "stat").read_text()
            state = stat[stat.rfind(")") + 2:].split()[0]
            if state in ("Z", "X"):
                continue

            args = (entry / "cmdline").read_bytes().split(b"\\0")
            args = [x.decode(errors="ignore") for x in args if x]

            if (
                "-m" in args
                and "omega.padge" in args
                and "loop" in args
            ):
                os.kill(pid, 0)
                return pid
        except (OSError, PermissionError, ValueError, IndexError):
            continue
    return None


def check():
    errors = []
    if not (ROOT / "omega" / "padge.py").is_file():
        errors.append("No existe omega/padge.py")
    if importlib.util.find_spec("omega.padge") is None:
        errors.append("No se puede importar omega.padge")
    if sys.version_info < (3, 12):
        errors.append("Se requiere Python 3.12 o superior")
    return errors


def stop_handler(signum, frame):
    global STOP
    STOP = True


def run():
    global STOP
    STATE.mkdir(parents=True, exist_ok=True)

    with LOCK.open("a+") as lockfile:
        try:
            fcntl.flock(
                lockfile.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            print("ENGINE_ALREADY_RUNNING")
            return 2

        errors = check()
        if errors:
            write_status(state="BLOCKED", errors=errors)
            print("PRECHECK_FAILED:", "; ".join(errors))
            return 1

        old = existing_padge()
        if old:
            write_status(
                state="EXTERNAL_WORKER_DETECTED",
                worker_pid=old,
                message="No se inicia un segundo PADGE.",
            )
            print(f"PADGE_EXISTENTE_PID={old}")
            print("No se ha iniciado otro constructor.")
            return 3

        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)

        delay = 5
        restarts = 0
        child = None

        with LOG.open("a", encoding="utf-8", buffering=1) as log:
            log.write(f"\n[{now()}] AUTOCONSTRUCTION_START\n")

            while not STOP:
                try:
                    child = subprocess.Popen(
                        [sys.executable, "-m", "omega.padge", "loop"],
                        cwd=ROOT,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )

                    write_status(
                        state="RUNNING",
                        supervisor_pid=os.getpid(),
                        worker_pid=child.pid,
                        restarts=restarts,
                        restart_delay=delay,
                        log=str(LOG),
                    )
                    log.write(
                        f"[{now()}] PADGE_STARTED pid={child.pid}\n"
                    )

                    while child.poll() is None and not STOP:
                        write_status(
                            state="RUNNING",
                            supervisor_pid=os.getpid(),
                            worker_pid=child.pid,
                            restarts=restarts,
                            log=str(LOG),
                        )
                        time.sleep(10)

                    if STOP:
                        child.terminate()
                        try:
                            child.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                        break

                    code = child.returncode
                    log.write(
                        f"[{now()}] PADGE_EXIT code={code}\n"
                    )
                    restarts += 1
                    write_status(
                        state="RESTARTING",
                        last_exit_code=code,
                        restarts=restarts,
                        next_restart_seconds=delay,
                    )

                    time.sleep(delay)
                    delay = min(delay * 2, 300)

                except Exception as exc:
                    log.write(f"[{now()}] SUPERVISOR_ERROR {exc!r}\n")
                    write_status(
                        state="DEGRADED",
                        error=repr(exc),
                        restarts=restarts,
                    )
                    time.sleep(delay)
                    delay = min(delay * 2, 300)

            write_status(
                state="STOPPED",
                supervisor_pid=os.getpid(),
                restarts=restarts,
            )
            log.write(f"[{now()}] AUTOCONSTRUCTION_STOP\n")

    return 0


def status():
    if not STATUS.exists():
        print("STATE=NOT_STARTED")
        return 1

    try:
        data = json.loads(STATUS.read_text(encoding="utf-8"))
        print(json.dumps(data, indent=2, ensure_ascii=False))
        pid = data.get("supervisor_pid")
        if pid:
            try:
                os.kill(int(pid), 0)
                print("SUPERVISOR_PROCESS=ALIVE")
            except OSError:
                print("SUPERVISOR_PROCESS=NOT_RUNNING")
        return 0
    except Exception as exc:
        print("STATUS_ERROR:", repr(exc))
        return 1


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "run", "status"])
    args = parser.parse_args()

    if args.action == "check":
        errors = check()
        if errors:
            print("\n".join(errors))
            return 1
        print("PREFLIGHT=OK")
        print("PYTHON=" + sys.version.split()[0])
        print("PADGE=AVAILABLE")
        print("ROOT=" + str(ROOT))
        return 0

    if args.action == "status":
        return status()

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
