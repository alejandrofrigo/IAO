"""Dedicated, single-instance process for the IAO autonomous read-only core."""
import fcntl
import json
import signal
import sys
import threading
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from omega.autonomous_core import AutonomousCore


def acquire_instance_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle



SCHEDULE_INTERVALS = {
    "self_check": 3600,
    "capability_scan": 21600,
    "improvement_plan": 86400,
}


def schedule_due_tasks(core, now=None):
    """Enqueue due read-only tasks without duplicating pending work."""
    now = datetime.now(timezone.utc) if now is None else now
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ValueError("SCHEDULER_REQUIRES_TIMEZONE")

    now = now.astimezone(timezone.utc)
    created = []

    for kind, interval in SCHEDULE_INTERVALS.items():
        task = core.submit_periodic_if_due(
            kind,
            interval,
            now,
            source="IAO_PERIODIC_SCHEDULER",
        )

        if task is not None:
            created.append({
                "id": task["id"],
                "kind": kind,
            })

    return created


def main():
    state_dir = ROOT / ".state" / "iao-autonomous-core"
    lock_handle = acquire_instance_lock(state_dir / "worker.lock")
    if lock_handle is None:
        print("WORKER_ALREADY_RUNNING=1", flush=True)
        return 0

    shutdown = threading.Event()

    def request_shutdown(signum, frame):
        shutdown.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    core = AutonomousCore(state_dir=state_dir)
    recovered = core.recover_interrupted_tasks()
    if recovered:
        print("TASKS_RECOVERED=", recovered, flush=True)

    started = core.start_worker(interval=30)
    print(f"WORKER_STARTED={started}", flush=True)

    thread_failed = False
    try:
        initial = schedule_due_tasks(core)
        print("SCHEDULER_INITIAL_TASKS=", initial, flush=True)

        while not shutdown.wait(30):
            scheduled = schedule_due_tasks(core)
            if scheduled:
                print("SCHEDULER_NEW_TASKS=", scheduled, flush=True)

            if core.worker is None or not core.worker.is_alive():
                print("WORKER_THREAD_EXITED=1", flush=True)
                thread_failed = True
                break
    finally:
        stopped = core.stop_worker(timeout=10)
        print(f"WORKER_STOPPED={stopped}", flush=True)
        lock_handle.close()

    return 0 if stopped and not thread_failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
