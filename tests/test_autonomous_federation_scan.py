import json
import sqlite3
from pathlib import Path

from omega.autonomous_core import AutonomousCore


def test_capability_scan_reads_real_local_federation_state(tmp_path, monkeypatch):
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(repo)

    config = home / ".config/iao/node-network.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({
        "node_id": "local-test-node",
        "cluster_id": "local-test-cluster",
        "public_endpoint": "",
        "capabilities": ["heartbeat"],
    }))

    policy = repo / ".state/iao-node-network/federation-policy.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(json.dumps({
        "enabled": True,
        "require_mutual_tls": True,
        "remote_code_execution": False,
        "allowed_capabilities": ["heartbeat"],
    }))

    db = home / ".local/share/iao/node-network/network.sqlite3"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE nodes(node_id TEXT, endpoint TEXT, capabilities TEXT,
                           last_seen INTEGER, status TEXT);
        CREATE TABLE peers(node_id TEXT, endpoint TEXT, shared_key TEXT,
                           authorized INTEGER);
        CREATE TABLE directories(endpoint TEXT, last_check INTEGER, status TEXT);
        CREATE TABLE invitations(token_hash TEXT, expires INTEGER, used INTEGER);
        CREATE TABLE tasks(task_id TEXT, task_type TEXT, payload TEXT,
                           target TEXT, status TEXT, result TEXT,
                           created INTEGER, updated INTEGER);
        CREATE TABLE events(id INTEGER, timestamp INTEGER, event TEXT, details TEXT);
        INSERT INTO peers VALUES ('peer-1', 'https://example.invalid',
                                  'secret-must-not-appear', 1);
    """)
    con.commit()
    con.close()

    core = AutonomousCore(repo / ".state/iao-autonomous-core")
    task = core.submit("capability_scan")
    result = core.run_one()

    assert result["status"] == "COMPLETED"
    scan = result["result"]
    assert scan["database"]["readable"] is True
    assert scan["database"]["tables"]["peers"] == 1
    assert scan["database"]["status_counts"]["authorized_peers"] == 1
    assert scan["connectivity"]["external_network_probed"] is False
    assert scan["summary"]["external_connectivity_confirmed"] is False
    assert "secret-must-not-appear" not in json.dumps(scan)
