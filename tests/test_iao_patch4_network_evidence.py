import json
import time
from pathlib import Path
from types import SimpleNamespace

import omega.network_intelligence as ni


def fake_result(stdout, returncode=0):
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


def test_zero_candidates_is_not_success(monkeypatch):
    monkeypatch.setattr(
        ni.subprocess, "run",
        lambda *a, **k: fake_result("CANDIDATES_ADDED= 0\n"),
    )
    result = ni.discover_infrastructure()
    assert result["status"] == "SEARCH_COMPLETED_NO_CANDIDATES"
    assert result["candidates_added"] == 0
    assert result["operational_nodes_confirmed"] == 0


def test_positive_candidates_are_only_candidates(monkeypatch):
    monkeypatch.setattr(
        ni.subprocess, "run",
        lambda *a, **k: fake_result("CANDIDATES_ADDED= 3\n"),
    )
    result = ni.discover_infrastructure()
    assert result["status"] == "CANDIDATES_FOUND"
    assert result["candidates_added"] == 3
    assert result["enrollment_confirmed"] is False


def test_unparseable_output_is_not_success(monkeypatch):
    monkeypatch.setattr(
        ni.subprocess, "run",
        lambda *a, **k: fake_result("Proceso terminado\n"),
    )
    result = ni.discover_infrastructure()
    assert result["status"] == "OUTPUT_UNPARSEABLE"
    assert result["candidates_added"] is None


def test_nonzero_returncode_fails(monkeypatch):
    monkeypatch.setattr(
        ni.subprocess, "run",
        lambda *a, **k: fake_result(
            "CANDIDATES_ADDED= 5\n", returncode=1
        ),
    )
    assert ni.discover_infrastructure()["status"] == "DISCOVERY_FAILED"


def test_ipfs_report_does_not_claim_replication(monkeypatch, tmp_path):
    path = tmp_path / ".state/p2p-rollout/padge-p2p-bridge.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema": "IAO_PADGE_IPFS_P2P_BRIDGE_V1",
        "timestamp": time.time(),
        "local_peer_id": "local-peer",
        "connected_peer_count": 12,
        "connected_peer_sample": ["peer-a"],
        "release_cid": "bafy-example",
        "release_block_available": True,
        "release_pin_available": True,
        "recursive_provider_announcement": "SUCCEEDED",
        "external_provider_count": 2,
        "external_replication_confirmed": True,
    }), encoding="utf-8")

    monkeypatch.setattr(ni, "ROOT", tmp_path)
    result = ni.read_ipfs_evidence()
    assert result["status"] == "FRESH_EVIDENCE"
    assert result["connected_peer_count"] == 12
    assert result["external_provider_observed_count"] == 2
    assert result["external_replication_confirmed"] is False
    assert result["peer_identity_as_iao_node"] is False


def test_missing_ipfs_report(monkeypatch, tmp_path):
    monkeypatch.setattr(ni, "ROOT", tmp_path)
    assert ni.read_ipfs_evidence()["status"] == "NO_BRIDGE_REPORT"


def test_stale_ipfs_report_is_rejected(monkeypatch, tmp_path):
    path = tmp_path / ".state/p2p-rollout/padge-p2p-bridge.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema": "IAO_PADGE_IPFS_P2P_BRIDGE_V1",
        "timestamp": time.time() - 5000,
        "connected_peer_count": 99,
    }), encoding="utf-8")

    monkeypatch.setattr(ni, "ROOT", tmp_path)
    assert ni.read_ipfs_evidence()["status"] == "STALE_REPORT"


def test_bridge_provider_is_not_replication_proof():
    source = Path(
        "tools/iao_p2p_autonomy_bridge.py"
    ).read_text(encoding="utf-8")
    assert '"external_replication_confirmed": False' in source
    assert '"provider_announcement_is_not_replica_proof": True' in source
