import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import iao_libp2p_discovery as worker


class Libp2pDiscoveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)

    def test_cycle_persists_only_safe_discovery_status(self):
        result = {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 2,
            "routing_peers_discovered": 7,
            "persisted_new_peers": 4,
            "enrollment_performed": False,
            "capabilities_granted": [],
            "remote_code_executed": False,
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", return_value=result
        ):
            report = worker.cycle(timeout=5)
        stored = json.loads((self.state / "discovery-report.json").read_text())
        self.assertEqual(report, stored)
        self.assertEqual(report["status"], "DISCOVERY_COMPLETED")
        self.assertEqual(report["routing_peers_discovered"], 7)
        self.assertFalse(report["enrollment_performed"])
        self.assertEqual(report["capabilities_granted"], [])
        self.assertFalse(report["remote_code_executed"])
        self.assertFalse(report["listener_exposed"])

    def test_optional_dependency_failure_is_not_reported_as_success(self):
        def fail(**kwargs):
            raise ImportError("optional dependency unavailable")
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", side_effect=fail
        ):
            report = worker.cycle()
        self.assertEqual(report["status"], "DISCOVERY_ERROR")
        self.assertEqual(report["error_class"], "ImportError")
        self.assertFalse(report["enrollment_performed"])

    def test_interval_is_bounded(self):
        with patch.dict(os.environ, {"IAO_LIBP2P_DISCOVERY_INTERVAL": "1"}):
            self.assertEqual(worker.read_interval(), worker.MIN_INTERVAL)
        with patch.dict(os.environ, {"IAO_LIBP2P_DISCOVERY_INTERVAL": "999999"}):
            self.assertEqual(worker.read_interval(), worker.MAX_INTERVAL)
        with patch.dict(os.environ, {"IAO_LIBP2P_DISCOVERY_INTERVAL": "bad"}):
            self.assertEqual(worker.read_interval(), worker.DEFAULT_INTERVAL)

    def test_report_refuses_symlink(self):
        target = self.state / "outside"
        target.write_text("{}")
        link = self.state / "discovery-report.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(RuntimeError, "SYMLINK"):
            worker._atomic_report(link, {"status": "x"})
        self.assertEqual(target.read_text(), "{}")


if __name__ == "__main__":
    unittest.main()
