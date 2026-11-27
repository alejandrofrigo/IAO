"""TaskWorker emits lifecycle heartbeats without task or operator identifiers."""
import os
from pathlib import Path

from omega.supervision import read_heartbeat
from omega.task_worker import TaskWorker


class IdleStore:
    def claim_next_task(self, *_args, **_kwargs):
        return None


class OneCycleWorker(TaskWorker):
    def run_once(self):
        self.stop()
        return False


def test_task_worker_writes_private_heartbeat_after_poll_cycle(tmp_path):
    heartbeat = tmp_path / "private" / "task-worker-heartbeat.json"
    worker = OneCycleWorker(
        IdleStore(), object(), poll_seconds=0.01, heartbeat_path=heartbeat,
    )
    worker.run_forever()
    result = read_heartbeat(heartbeat, expected_component="TASK_WORKER")
    assert result["status"] == "HEALTHY"
    assert result["pid"] == os.getpid()
    assert result["last_cycle_result"] is True
    assert heartbeat.stat().st_mode & 0o777 == 0o600
    assert heartbeat.parent.stat().st_mode & 0o777 == 0o700
    content = heartbeat.read_text(encoding="utf-8")
    assert "owner" not in content
    assert "task_id" not in content
    assert "worker_id" not in content


class FailingWorker(TaskWorker):
    def run_once(self):
        raise RuntimeError("private-task-marker")


def test_task_worker_failure_leaves_bounded_cycle_evidence(tmp_path):
    heartbeat = tmp_path / "task-worker-heartbeat.json"
    worker = FailingWorker(
        IdleStore(), object(), poll_seconds=0.01, heartbeat_path=heartbeat,
    )
    try:
        worker.run_forever()
    except RuntimeError as exc:
        assert str(exc) == "private-task-marker"
    else:
        raise AssertionError("worker failure was hidden")
    result = read_heartbeat(heartbeat, expected_component="TASK_WORKER")
    assert result["status"] == "DEGRADED"
    assert result["phase"] == "cycle_completed"
    assert result["last_cycle_result"] is False
    assert "private-task-marker" not in heartbeat.read_text(encoding="utf-8")