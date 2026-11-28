"""Bounded process supervisor for the IAO API or an explicitly selected worker."""
import signal
import subprocess
import os
import sys
import time
from types import FrameType


def supervise(
    cmd: list[str],
    max_restarts: int = 5,
    window: float = 60.0,
    shutdown_grace: float = 5.0,
) -> int:
    if not cmd or not all(isinstance(part, str) and part for part in cmd):
        raise ValueError("INVALID_SUPERVISOR_COMMAND")
    if type(max_restarts) is not int or max_restarts < 0:
        raise ValueError("INVALID_SUPERVISOR_RESTART_LIMIT")
    if not isinstance(window, (int, float)) or isinstance(window, bool) or not 0 < window <= 86400:
        raise ValueError("INVALID_SUPERVISOR_RESTART_WINDOW")
    if not isinstance(shutdown_grace, (int, float)) or isinstance(shutdown_grace, bool) or not 0 < shutdown_grace <= 120:
        raise ValueError("INVALID_SUPERVISOR_SHUTDOWN_GRACE")

    restarts: list[float] = []
    child: dict[str, subprocess.Popen[bytes] | None] = {"p": None}
    stopping = {"v": False}

    def stop(_s: int, _f: FrameType | None) -> None:
        stopping["v"] = True
        p = child["p"]
        if p is not None and p.poll() is None:
            p.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        if stopping["v"]:
            return 0
        p = subprocess.Popen(cmd, env={**os.environ, "IAO_LLM_ROUTER": "1"})
        child["p"] = p
        shutdown_deadline: float | None = None
        try:
            while p.poll() is None:
                if stopping["v"]:
                    if shutdown_deadline is None:
                        p.terminate()
                        shutdown_deadline = time.monotonic() + shutdown_grace
                    elif time.monotonic() >= shutdown_deadline:
                        p.kill()
                        break
                time.sleep(0.05)
            code = p.wait()
        finally:
            child["p"] = None
        if stopping["v"] or code == 0:
            return 0
        now = time.monotonic()
        restarts = [t for t in restarts if now - t < window] + [now]
        sys.stderr.write(
            f'{{"event":"runtime_exit","code":{code},"restarts_in_window":{len(restarts)}}}\\n'
        )
        if len(restarts) > max_restarts:
            sys.stderr.write('{"event":"HALT","reason":"restart_limit"}\\n')
            return 1
        delay = min(0.25 * 2 ** len(restarts), 5)
        deadline = time.monotonic() + delay
        while not stopping["v"] and time.monotonic() < deadline:
            time.sleep(min(0.1, deadline - time.monotonic()))


if __name__ == "__main__":
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        command = [sys.executable, "-m", "omega.server"]
    raise SystemExit(supervise(command))
