"""External watchdog for the IAO autonomous worker."""
import fcntl
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "iao-autonomous-core"
LOCK = STATE / "supervisor.lock"
stopping = False
child = None


def request_stop(signum, frame):
    global stopping
    stopping = True


def wait_before_restart(delay):
    end = time.monotonic() + delay
    while not stopping and time.monotonic() < end:
        time.sleep(min(1, max(0, end - time.monotonic())))


def main():
    global child

    if "--check" in sys.argv:
        if not (ROOT / "tools" / "iao_autonomous_worker.py").is_file():
            print("WORKER_ENTRYPOINT_MISSING")
            return 2
        print("SUPERVISOR_CHECK_OK")
        return 0

    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("SUPERVISOR_ALREADY_RUNNING", flush=True)
            return 0

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)

        delay = 5
        print("SUPERVISOR_STARTED", flush=True)

        while not stopping:
            started_at = time.monotonic()
            code = None
            child = None

            try:
                print("WORKER_LAUNCH_REQUESTED", flush=True)
                child = subprocess.Popen(
                    [sys.executable, "-m", "tools.iao_autonomous_worker"],
                    cwd=str(ROOT),
                )
                print(f"WORKER_PID={child.pid}", flush=True)

                while not stopping:
                    code = child.poll()
                    if code is not None:
                        break
                    time.sleep(2)

            except Exception as exc:
                print(
                    "SUPERVISOR_LAUNCH_ERROR="
                    + type(exc).__name__ + ":" + str(exc),
                    flush=True,
                )

            runtime = time.monotonic() - started_at

            if stopping and child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                print("WORKER_TERMINATED_BY_SUPERVISOR", flush=True)

            elif child is not None:
                print(f"WORKER_EXITED={code}", flush=True)

            child = None

            if not stopping:
                if runtime >= 300:
                    delay = 5
                print(f"WORKER_RESTART_WAIT={delay}", flush=True)
                wait_before_restart(delay)
                if runtime < 300:
                    delay = min(delay * 2, 60)

        print("SUPERVISOR_STOPPED", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
