#!/usr/bin/env python3
"""Supervisor persistente del mantenimiento y del worker autónomo de IAO."""
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
WORKER_SUPERVISOR = None


def stop_handler(_signum, _frame):
    global STOP
    STOP = True
    for process in (CHILD, WORKER_SUPERVISOR):
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass


def stop_child(process, timeout=10):
    """Termina un hijo de forma ordenada y limita el tiempo de espera."""
    if process is None or process.poll() is not None:
        return

    try:
        process.terminate()
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()


def launch(command, log, env):
    return subprocess.Popen(
        command,
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def main():
    global CHILD, WORKER_SUPERVISOR

    STATE.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)

    if "--self-test" in sys.argv:
        required = (
            ROOT / "tools/iao_autonomy.py",
            ROOT / "tools/iao_autonomous_worker_supervisor.py",
            ROOT / "tools/iao_autonomous_worker.py",
            ROOT / "omega/autonomous_coordinator.py",
            ROOT / "omega/autonomous_core.py",
        )
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            print("DAEMON_SELF_TEST=FAIL")
            print("MISSING=" + ",".join(missing))
            return 1
        print("DAEMON_SELF_TEST=PASS")
        print("MAINTENANCE_CYCLE=FOUND")
        print("WORKER_SUPERVISOR=FOUND")
        print("WORKER_ENTRYPOINT=FOUND")
        print("PROCESS_OWNERSHIP=DAEMON")
        print("LOCKING=fcntl")
        return 0

    lock_file = LOCK.open("a+")
    try:
        fcntl.flock(
            lock_file.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )
    except BlockingIOError:
        print("DAEMON_ALREADY_RUNNING")
        lock_file.close()
        return 0

    PIDFILE.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    child_env = os.environ.copy()
    existing_pythonpath = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = (
        str(ROOT)
        + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
    )

    services = {
        "MAINTENANCE": {
            "command": [
                sys.executable,
                str(ROOT / "tools/iao_autonomy.py"),
                "--watch",
            ],
            "process": None,
            "started": 0.0,
            "restart_at": 0.0,
            "delay": 5,
        },
        "WORKER_SUPERVISOR": {
            "command": [
                sys.executable,
                str(ROOT / "tools/iao_autonomous_worker_supervisor.py"),
            ],
            "process": None,
            "started": 0.0,
            "restart_at": 0.0,
            "delay": 5,
        },
    }

    def log(message):
        stream.write(message + "\n")
        stream.flush()

    try:
        with LOG.open("a", encoding="utf-8", buffering=1) as stream:
            log(
                f"DAEMON_STARTED pid={os.getpid()} "
                f"utc={time.time()}"
            )

            while not STOP:
                now = time.monotonic()

                for name, state in services.items():
                    process = state["process"]

                    if process is not None:
                        code = process.poll()
                        if code is None:
                            continue

                        runtime = now - state["started"]
                        log(
                            f"{name}_EXIT code={code} "
                            f"runtime={runtime:.1f}s"
                        )
                        state["process"] = None

                        if runtime >= 300:
                            state["delay"] = 5
                        else:
                            state["delay"] = min(
                                state["delay"] * 2, 300
                            )

                        state["restart_at"] = now + state["delay"]
                        continue

                    if now < state["restart_at"]:
                        continue

                    try:
                        log(name + "_LAUNCH_REQUESTED")
                        process = launch(
                            state["command"], stream, child_env
                        )
                        state["process"] = process
                        state["started"] = time.monotonic()

                        if name == "MAINTENANCE":
                            CHILD = process
                        else:
                            WORKER_SUPERVISOR = process

                        log(name + "_STARTED pid=" + str(process.pid))

                    except Exception as exc:
                        log(
                            name + "_LAUNCH_ERROR "
                            + type(exc).__name__ + ":"
                            + str(exc)[:200]
                        )
                        state["restart_at"] = (
                            time.monotonic() + state["delay"]
                        )
                        state["delay"] = min(
                            state["delay"] * 2, 300
                        )

                time.sleep(1)

    finally:
        stop_child(CHILD)
        stop_child(WORKER_SUPERVISOR)

        for state in services.values():
            state["process"] = None

        try:
            if PIDFILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
                PIDFILE.unlink(missing_ok=True)
        except OSError:
            pass

        try:
            with LOG.open("a", encoding="utf-8") as stream:
                stream.write("DAEMON_STOPPED\n")
        except OSError:
            pass

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
