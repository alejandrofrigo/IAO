import os
import signal
import subprocess
import sys
import time
import unittest

from omega.supervisor import supervise


class SupervisorTests(unittest.TestCase):
    def test_halts_after_restart_limit(self) -> None:
        t0 = time.time()
        self.assertEqual(supervise([sys.executable, "-c", "raise SystemExit(3)"], max_restarts=2, window=60), 1)
        self.assertLess(time.time() - t0, 10)

    def test_sigterm_stops_child_no_orphans(self) -> None:
        code = ("import subprocess,sys,time;from omega.supervisor import supervise;"
                "raise SystemExit(supervise([sys.executable,'-c','import time;print(__import__(\\"os\\").getpid(),flush=True);time.sleep(60)']))")
        p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": "."})
        assert p.stdout is not None
        child = int(p.stdout.readline())
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)
        time.sleep(0.3)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_sigterm_kills_child_that_ignores_terminate(self) -> None:
        child_code = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "print(os.getpid(),flush=True);time.sleep(60)"
        )
        supervisor_code = (
            "import subprocess,sys;from omega.supervisor import supervise;"
            "raise SystemExit(supervise([sys.executable,'-c',sys.argv[1]], shutdown_grace=0.2))"
        )
        p = subprocess.Popen(
            [sys.executable, "-c", supervisor_code, child_code],
            stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": "."},
        )
        assert p.stdout is not None
        child = int(p.stdout.readline())
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(5), 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_rejects_invalid_shutdown_grace(self) -> None:
        with self.assertRaises(ValueError):
            supervise([sys.executable, "-c", "pass"], shutdown_grace=0)
