#!/usr/bin/env python
"""IAO Integral Runtime: supervisión local sin duplicar procesos existentes."""

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "integral-runtime"
LOG = STATE / "runtime.jsonl"
PIDFILE = STATE / "runtime.pid"
STOP = False

COMPONENTS = {
    "PADGE": [sys.executable, "-m", "omega.padge", "loop"],
    "AUTONOMOUS_WORKER_SUPERVISOR": [
        sys.executable, "tools/iao_autonomous_worker_supervisor.py"
    ],
    "FEDERATION_WORKER": [
        sys.executable, "tools/iao_federation_worker.py"
    ],
    "INTERNET_GUARDIAN": [
        sys.executable, "tools/iao_internet_guardian.py"
    ],
}

RESTART_BASE = 5
RESTART_MAX = 300
CHECK_INTERVAL = 10


def emit(event, **data):
    record = {
        "timestamp": time.time(),
        "event": event,
        **data,
    }
    STATE.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False), flush=True)


def process_matches(name):
    """Busca procesos reales en /proc; nunca termina procesos ajenos."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            args = raw.replace(b"\0", b" ").decode(errors="replace")
        except (OSError, PermissionError):
            continue

        if name == "PADGE":
            if "-m omega.padge loop" in args:
                return pid
        elif name == "AUTONOMOUS_WORKER_SUPERVISOR":
            if "iao_autonomous_worker_supervisor.py" in args:
                return pid
        elif name == "FEDERATION_WORKER":
            if "tools/iao_federation_worker.py" in args:
                return pid
        elif name == "INTERNET_GUARDIAN":
            if "tools/iao_internet_guardian.py" in args:
                return pid
    return None


def stop_handler(signum, frame):
    global STOP
    STOP = True
    emit("STOP_REQUESTED", signal=signum)


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    lock_path = STATE / "runtime.lock"

    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("INTEGRAL_RUNTIME_ALREADY_RUNNING", flush=True)
            return 0

        PIDFILE.write_text(str(os.getpid()) + "\n", encoding="utf-8")
        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)

        children = {}
        retry_at = {name: 0 for name in COMPONENTS}
        delays = {name: RESTART_BASE for name in COMPONENTS}
        external_seen = set()

        emit(
            "INTEGRAL_RUNTIME_STARTED",
            pid=os.getpid(),
            components=list(COMPONENTS),
        )

        try:
            while not STOP:
                for name, command in COMPONENTS.items():
                    if STOP:
                        break

                    child = children.get(name)

                    if child is not None:
                        code = child.poll()
                        if code is None:
                            continue

                        emit(
                            "MANAGED_COMPONENT_EXITED",
                            component=name,
                            pid=child.pid,
                            exit_code=code,
                        )
                        children.pop(name, None)
                        retry_at[name] = time.monotonic() + delays[name]
                        delays[name] = min(delays[name] * 2, RESTART_MAX)

                    external_pid = process_matches(name)
                    if external_pid is not None:
                        if name not in external_seen:
                            emit(
                                "EXTERNAL_COMPONENT_PRESERVED",
                                component=name,
                                pid=external_pid,
                            )
                            external_seen.add(name)
                        continue

                    external_seen.discard(name)

                    if time.monotonic() < retry_at[name]:
                        continue

                    missing = [
                        item for item in command
                        if item.endswith(".py") and not (ROOT / item).is_file()
                    ]
                    if missing:
                        emit(
                            "COMPONENT_ENTRYPOINT_MISSING",
                            component=name,
                            missing=missing,
                        )
                        retry_at[name] = time.monotonic() + RESTART_MAX
                        continue

                    output_path = STATE / (name.lower() + ".log")
                    output = output_path.open("a", encoding="utf-8")
                    env = os.environ.copy()
                    env["PYTHONUNBUFFERED"] = "1"
                    old_path = env.get("PYTHONPATH", "")
                    env["PYTHONPATH"] = (
                        str(ROOT) +
                        (os.pathsep + old_path if old_path else "")
                    )

                    try:
                        child = subprocess.Popen(
                            command,
                            cwd=str(ROOT),
                            env=env,
                            stdin=subprocess.DEVNULL,
                            stdout=output,
                            stderr=subprocess.STDOUT,
                            start_new_session=True,
                        )
                        output.close()
                        children[name] = child
                        delays[name] = RESTART_BASE
                        emit(
                            "MANAGED_COMPONENT_STARTED",
                            component=name,
                            pid=child.pid,
                            command=command[1:],
                            log=str(output_path),
                        )
                    except Exception as exc:
                        output.close()
                        emit(
                            "COMPONENT_START_ERROR",
                            component=name,
                            error=type(exc).__name__,
                        )
                        retry_at[name] = time.monotonic() + delays[name]
                        delays[name] = min(delays[name] * 2, RESTART_MAX)

                STOP_WAIT = 0
                while STOP_WAIT < CHECK_INTERVAL and not STOP:
                    time.sleep(1)
                    STOP_WAIT += 1

        finally:
            emit("INTEGRAL_RUNTIME_STOPPING")
            for name, child in list(children.items()):
                if child.poll() is None:
                    emit(
                        "MANAGED_COMPONENT_TERMINATE_REQUESTED",
                        component=name,
                        pid=child.pid,
                    )
                    child.terminate()
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
            PIDFILE.unlink(missing_ok=True)
            emit("INTEGRAL_RUNTIME_STOPPED")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
