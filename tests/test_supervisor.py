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
                "raise SystemExit(supervise([sys.executable,'-c','import time;print(__import__(\"os\").getpid(),flush=True);time.sleep(60)']))")
        p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": "."})
        assert p.stdout is not None
        child = int(p.stdout.readline())
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)
        time.sleep(0.3)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)
