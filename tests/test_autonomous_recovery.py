import json

from omega.autonomous_core import AutonomousCore


def test_interrupted_running_task_is_requeued_and_audited(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    task = core.submit("self_check")

    data = json.loads(core.tasks_path.read_text("utf-8"))
    data["tasks"][0]["status"] = "RUNNING"
    core._save(data)

    recovered = core.recover_interrupted_tasks()

    assert recovered == [task["id"]]
    state = json.loads(core.tasks_path.read_text("utf-8"))
    assert state["tasks"][0]["status"] == "QUEUED"
    assert state["tasks"][0]["recovery_reason"] == "WORKER_PROCESS_INTERRUPTED"

    events = [
        json.loads(line)
        for line in core.events_path.read_text("utf-8").splitlines()
    ]
    assert any(
        event["event"] == "TASK_RECOVERED"
        and event["details"]["id"] == task["id"]
        for event in events
    )


def test_recovery_does_not_change_completed_tasks(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    task = core.submit("self_check")
    core.run_one()

    assert core.recover_interrupted_tasks() == []
    state = json.loads(core.tasks_path.read_text("utf-8"))
    saved = next(t for t in state["tasks"] if t["id"] == task["id"])
    assert saved["status"] == "COMPLETED"


def test_task_started_event_is_audited(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    task = core.submit("self_check")
    result = core.run_one()

    assert result["status"] == "COMPLETED"
    events = [
        json.loads(line)
        for line in core.events_path.read_text("utf-8").splitlines()
    ]
    assert any(
        event["event"] == "TASK_STARTED"
        and event["details"]["id"] == task["id"]
        for event in events
    )
