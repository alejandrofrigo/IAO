#!/usr/bin/env python3
"""Supervisor persistente del ciclo de mantenimiento autónomo de IAO."""
from pathlib import Path
import fcntl
import os
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = Path.home() / ".local/state/iao"
LOG = Path.home() / ".local/share/iao/autonomy-daemon.log"
LOCK = STATE / "autonomy-daemon.lock"
PIDFILE = STATE / "autonomy-daemon.pid"
STOP = False
CHILD = None

def stop_handler(_signum, _frame):
    global STOP
    STOP = True
    if CHILD is not None and CHILD.poll() is None:
        CHILD.terminate()

def main():
    global CHILD
    STATE.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)

    if "--self-test" in sys.argv:
        target = ROOT / "tools/iao_autonomy.py"
        assert target.is_file(), "Falta tools/iao_autonomy.py"
        assert (ROOT / "omega/autonomous_coordinator.py").is_file()
        assert (ROOT / "omega/autonomous_core.py").is_file()
        print("DAEMON_SELF_TEST=PASS")
        print("MAINTENANCE_CYCLE=FOUND")
        print("COORDINATOR=FOUND")
        print("LOCKING=fcntl")
        return 0

    lock_file = LOCK.open("a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("DAEMON_ALREADY_RUNNING")
        return 0

    PIDFILE.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    delay = 5
    try:
        with LOG.open("a", encoding="utf-8", buffering=1) as log:
            log.write(f"\nDAEMON_STARTED pid={os.getpid()} utc={time.time()}\n")
            while not STOP:
                try:
                    log.write("MAINTENANCE_CYCLE_START\n")
                    child_env = os.environ.copy()
                    existing_pythonpath = child_env.get("PYTHONPATH", "")
                    child_env["PYTHONPATH"] = (
                        str(ROOT) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
                    )
                    CHILD = subprocess.Popen(
                        [sys.executable, str(ROOT / "tools/iao_autonomy.py"), "--watch"],
                        cwd=str(ROOT),
                        env=child_env,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    code = CHILD.wait()
                    CHILD = None
                    if STOP:
                        break
                    log.write(f"MAINTENANCE_CYCLE_EXIT code={code}; retry_in={delay}s\n")
                except Exception as exc:
                    log.write(f"DAEMON_ERROR {type(exc).__name__}: {str(exc)[:200]}\n")
                time.sleep(delay)
                delay = min(delay * 2, 300)
    finally:
        if CHILD is not None and CHILD.poll() is None:
            CHILD.terminate()
            try:
                CHILD.wait(timeout=10)
            except subprocess.TimeoutExpired:
                CHILD.kill()
                CHILD.wait()
        PIDFILE.unlink(missing_ok=True)
        with LOG.open("a", encoding="utf-8") as log:
            log.write("DAEMON_STOPPED\n")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
