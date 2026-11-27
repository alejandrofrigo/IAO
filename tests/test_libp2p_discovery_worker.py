import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega.p2p_assimilation import assimilate_discovered_peers
from tools import iao_libp2p_discovery as worker


class Libp2pDiscoveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)

    def test_cycle_persists_only_safe_discovery_status(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        result = {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 2,
            "routing_peers_discovered": 1,
            "persisted_new_peers": 1,
            "peers": [{
                "peer_id": "Q" * 40,
                "multiaddrs": ["/ip4/8.8.8.8/tcp/4001"],
            }],
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", return_value=result
        ):
            report = worker.cycle(timeout=5)
        stored = json.loads((self.state / "discovery-report.json").read_text())
        self.assertEqual(report, stored)
        self.assertEqual(report["status"], "DISCOVERY_COMPLETED")
        self.assertEqual(report["routing_peers_discovered"], 1)
        self.assertTrue(report["bootstrap_connection_confirmed"])
        self.assertEqual(report["auto_assimilated_new_peers"], 1)
        self.assertEqual(report["auto_assimilation"], "QUARANTINED_INVENTORY_ONLY")
        self.assertEqual(report["identity_verification"], "NOT_PERFORMED")
        self.assertFalse(report["enrollment_performed"])
        self.assertEqual(report["capabilities_granted"], [])
        self.assertFalse(report["remote_code_executed"])
        self.assertFalse(report["listener_exposed"])
        inventory = json.loads(
            (self.state / "p2p-assimilated-peers.json").read_text()
        )["peers"]["Q" * 40]
        self.assertEqual(inventory["assimilation_state"], "AUTO_ASSIMILATED_UNVERIFIED")
        self.assertEqual(inventory["participation_state"], "CANDIDATE_ONLY")
        self.assertEqual(inventory["capabilities"], [])

    def test_success_without_bootstrap_is_rejected_and_not_assimilated(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        result = {
            "status": "DISCOVERY_COMPLETED",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 1,
            "persisted_new_peers": 0,
            "peers": [{
                "peer_id": "R" * 40,
                "multiaddrs": ["/ip4/8.8.4.4/tcp/4001"],
            }],
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", return_value=result
        ):
            report = worker.cycle()
        self.assertEqual(report["status"], "DISCOVERY_ERROR")
        self.assertEqual(report["error_class"], "RuntimeError")
        self.assertFalse((self.state / "p2p-assimilated-peers.json").exists())

    def test_bootstrap_unavailable_does_not_assimilate(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        result = {
            "status": "BOOTSTRAP_UNAVAILABLE",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
            "peers": [],
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", return_value=result
        ):
            report = worker.cycle()
        self.assertEqual(report["status"], "BOOTSTRAP_UNAVAILABLE")
        self.assertEqual(report["auto_assimilation"], "SKIPPED_NO_BOOTSTRAP")
        self.assertFalse((self.state / "p2p-assimilated-peers.json").exists())

    def test_optional_dependency_failure_is_not_reported_as_success(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        def fail(**kwargs):
            raise ImportError("optional dependency unavailable")
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", side_effect=fail
        ):
            report = worker.cycle()
        self.assertEqual(report["status"], "DISCOVERY_ERROR")
        self.assertEqual(report["error_class"], "ImportError")
        self.assertFalse(report["enrollment_performed"])


    def test_tor_discovery_runs_even_when_libp2p_bootstrap_is_unavailable(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        result = {
            "status": "BOOTSTRAP_UNAVAILABLE",
            "connected_bootstrappers": 0,
            "routing_peers_discovered": 0,
            "persisted_new_peers": 0,
            "peers": [],
        }
        tor = {
            "status": "ONION_DISCOVERY_COMPLETED",
            "feeds_checked": 1,
            "candidates": 2,
            "assimilation": {"new": 2, "observed": 2, "total": 2},
            "enrollment_performed": False,
            "capabilities_granted": [],
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync", return_value=result
        ), patch.object(worker, "tor_discovery_cycle", return_value=tor) as tor_cycle:
            report = worker.cycle()
        tor_cycle.assert_called_once_with()
        self.assertEqual(report["status"], "BOOTSTRAP_UNAVAILABLE")
        self.assertEqual(report["tor_onion_discovery"], tor)

    def test_tor_discovery_runs_even_when_libp2p_raises(self):
        self.env.setenv("IAO_P2P_ALLOW_DIRECT", "true")
        tor = {
            "status": "ONION_DISCOVERY_COMPLETED",
            "feeds_checked": 1,
            "candidates": 1,
            "assimilation": {"new": 1, "observed": 1, "total": 1},
        }
        with patch.object(worker, "state_dir", return_value=self.state), patch.object(
            worker.libp2p_discovery, "discover_sync",
            side_effect=ImportError("libp2p unavailable")
        ), patch.object(worker, "tor_discovery_cycle", return_value=tor):
            report = worker.cycle()
        self.assertEqual(report["status"], "DISCOVERY_ERROR")
        self.assertEqual(report["tor_onion_discovery"], tor)


    def test_multiaddresses_are_classified_without_claiming_connectivity(self):
        from omega.p2p_assimilation import classify_multiaddr
        tcp = classify_multiaddr("/ip4/8.8.8.8/tcp/4001/p2p/" + "A" * 40)
        quic = classify_multiaddr("/ip4/8.8.8.8/udp/4001/quic-v1/p2p/" + "A" * 40)
        relay = classify_multiaddr("/ip4/8.8.8.8/tcp/4001/p2p-circuit/p2p/" + "A" * 40)
        onion = classify_multiaddr("/onion3/" + "a" * 56 + ":443/p2p/" + "A" * 40)
        self.assertEqual(tcp["route_class"], "TCP")
        self.assertEqual(quic["route_class"], "QUIC_UDP")
        self.assertEqual(relay["route_class"], "LIBP2P_RELAY_ADVERTISED")
        self.assertEqual(onion["route_class"], "TOR_ONION_ADVERTISED")
        self.assertTrue(onion["onion_advertised"])
        for item in (tcp, quic, relay, onion):
            self.assertFalse(item["connectivity_verified"])

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

    def test_repeated_observations_merge_without_granting_trust(self):
        peer = {"peer_id": "P" * 40, "multiaddrs": ["/ip4/9.9.9.9/tcp/4001"]}
        first = assimilate_discovered_peers([peer], state_dir=self.state, now="t1")
        second = assimilate_discovered_peers([peer], state_dir=self.state, now="t2")
        saved = json.loads(
            (self.state / "p2p-assimilated-peers.json").read_text()
        )["peers"]["P" * 40]
        self.assertEqual(first, {"new": 1, "observed": 1, "total": 1})
        self.assertEqual(second, {"new": 0, "observed": 1, "total": 1})
        self.assertEqual(saved["first_seen"], "t1")
        self.assertEqual(saved["last_seen"], "t2")
        self.assertEqual(saved["observations"], 2)
        self.assertEqual(saved["identity_state"], "UNVERIFIED")
        self.assertEqual(saved["granted_capabilities"], [])
        self.assertFalse(saved["remote_code_execution"])
        self.assertFalse(saved["control_authority"])

    def test_malformed_peer_is_not_assimilated(self):
        result = assimilate_discovered_peers(
            [{"peer_id": "short", "multiaddrs": ["/ip4/1.1.1.1/tcp/1"]}],
            state_dir=self.state,
        )
        self.assertEqual(result, {"new": 0, "observed": 0, "total": 0})

    def test_assimilation_registry_refuses_symlink(self):
        target = self.state / "outside"
        target.write_text("{}")
        link = self.state / "p2p-assimilated-peers.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(RuntimeError, "SYMLINK"):
            assimilate_discovered_peers([], state_dir=self.state)
        self.assertEqual(target.read_text(), "{}")


if __name__ == "__main__":
    unittest.main()


def test_node_network_heartbeat_is_bound_to_worker_and_supervisor(tmp_path, monkeypatch):
    from tools import iao_five_motor_supervisor

    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("IAO_LIBP2P_DISCOVERY_INTERVAL", "60")
    worker.write_worker_heartbeat(
        "cycle_completed",
        last_completed=time.time(),
        last_result=True,
    )
    assert worker._heartbeat_path() == tmp_path / "node-network-heartbeat.json"
    assert iao_five_motor_supervisor.motor_heartbeat_status(
        "NODE_NETWORK", os.getpid()
    ) == "HEALTHY"
