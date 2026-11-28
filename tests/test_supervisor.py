import os
import signal
import subprocess
import sys
import time
import unittest

from omega.supervisor import supervise


def _launch_supervisor(child_code: str, shutdown_grace: float = 5.0):
    supervisor_code = (
        "import subprocess,sys;from omega.supervisor import supervise;"
        "raise SystemExit(supervise([sys.executable,'-c',sys.argv[1]], "
        "shutdown_grace=float(sys.argv[2])))"
    )
    return subprocess.Popen(
        [sys.executable, "-c", supervisor_code, child_code, str(shutdown_grace)],
        stdout=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )


class SupervisorTests(unittest.TestCase):
    def test_halts_after_restart_limit(self) -> None:
        t0 = time.time()
        self.assertEqual(supervise([sys.executable, "-c", "raise SystemExit(3)"], max_restarts=2, window=60), 1)
        self.assertLess(time.time() - t0, 10)

    def test_sigterm_stops_child_no_orphans(self) -> None:
        child_code = "import os,time;print(os.getpid(),flush=True);time.sleep(60)"
        p = _launch_supervisor(child_code)
        assert p.stdout is not None
        child = int(p.stdout.readline())
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)
        time.sleep(0.1)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_sigterm_kills_child_that_ignores_terminate(self) -> None:
        child_code = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "print(os.getpid(),flush=True);time.sleep(60)"
        )
        p = _launch_supervisor(child_code, shutdown_grace=0.2)
        assert p.stdout is not None
        child = int(p.stdout.readline())
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(5), 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_rejects_invalid_shutdown_grace(self) -> None:
        with self.assertRaises(ValueError):
            supervise([sys.executable, "-c", "pass"], shutdown_grace=0)

    def test_cli_accepts_explicit_command_without_shell(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "omega.supervisor", "--",
             sys.executable, "-c", "raise SystemExit(0)"],
            check=False, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
