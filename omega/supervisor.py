"""Minimal supervisor: restarts the runtime on crash with backoff; HALTs after too many restarts.
On SIGTERM/SIGINT it stops the child too (no orphans) and exits 0."""
import signal
import subprocess
import sys
import time
from types import FrameType


def supervise(cmd: list[str], max_restarts: int = 5, window: float = 60.0) -> int:
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
        p = subprocess.Popen(cmd)
        child["p"] = p
        if stopping["v"]:
            p.terminate()
        code = p.wait()
        if stopping["v"] or code == 0:
            return 0
        now = time.monotonic()
        restarts = [t for t in restarts if now - t < window] + [now]
        sys.stderr.write(f'{{"event":"runtime_exit","code":{code},"restarts_in_window":{len(restarts)}}}\n')
        if len(restarts) > max_restarts:
            sys.stderr.write('{"event":"HALT","reason":"restart_limit"}\n')
            return 1
        time.sleep(min(0.25 * 2 ** len(restarts), 5))


if __name__ == "__main__":
    raise SystemExit(supervise([sys.executable, "-m", "omega.server"]))
