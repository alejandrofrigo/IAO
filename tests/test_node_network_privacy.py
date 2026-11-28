"""Node Network operational events must not persist peer or task identifiers."""
from tools import iao_node_network_engine as node_engine


def test_node_network_event_details_are_hashed(tmp_path, monkeypatch):
    monkeypatch.setattr(node_engine, "DATA", tmp_path)
    monkeypatch.setattr(node_engine, "DB", tmp_path / "network.sqlite3")
    marker = "private-peer-identity-marker"
    node_engine.log_event("TASK_EXECUTED", marker)
    db = node_engine.dbopen()
    try:
        row = db.execute(
            "SELECT event, details FROM events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    finally:
        db.close()
    assert row[0] == "TASK_EXECUTED"
    assert row[1].startswith("sha256:")
    assert marker not in row[1]
    assert node_engine.DATA.stat().st_mode & 0o777 == 0o700
    assert node_engine.DB.stat().st_mode & 0o777 == 0o600


def test_node_network_heartbeat_publishes_current_process(tmp_path, monkeypatch):
    from omega.supervision import read_heartbeat

    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path))
    node_engine.write_node_network_heartbeat(
        "cycle_completed", interval_seconds=60, result=True,
    )
    result = read_heartbeat(
        tmp_path / "node-network-heartbeat.json",
        expected_component="NODE_NETWORK",
    )
    assert result["status"] == "HEALTHY"
    assert result["pid"] == __import__("os").getpid()
