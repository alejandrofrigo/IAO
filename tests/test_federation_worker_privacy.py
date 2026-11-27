"""Federation worker heartbeats and logs are process-bound and privacy-safe."""
import os

from omega.supervision import read_heartbeat
from tools import iao_federation_worker as worker


def test_federation_worker_heartbeat_is_bound_to_current_process(tmp_path, monkeypatch):
    path = tmp_path / "distributed-intelligence-heartbeat.json"
    monkeypatch.setattr(worker, "HEARTBEAT_PATH", path)
    worker.heartbeat("cycle_completed", True)
    result = read_heartbeat(
        path, expected_component="DISTRIBUTED_INTELLIGENCE",
    )
    assert result["status"] == "HEALTHY"
    assert result["pid"] == os.getpid()
    assert result["last_cycle_result"] is True


def test_federation_worker_logs_hash_free_form_output(tmp_path, monkeypatch):
    path = tmp_path / "private" / "worker.log"
    monkeypatch.setattr(worker, "LOG", path)
    marker = "private.operator@example.invalid"
    worker.log("engine output " + marker)
    content = path.read_text(encoding="utf-8")
    assert marker not in content
    assert "message_digest" in content
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
