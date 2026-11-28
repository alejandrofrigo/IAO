import tempfile
from pathlib import Path
from omega.autonomous_core import AutonomousCore

def test_execution_and_persistence():
    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        task = core.submit("self_check")
        result = core.run_one()
        assert result["id"] == task["id"]
        assert result["status"] == "COMPLETED"
        assert AutonomousCore(tmp).status()["task_states"]["COMPLETED"] == 1

def test_unknown_task_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        try:
            core.submit("arbitrary_shell")
        except Exception as exc:
            assert "NOT_ALLOWED" in str(exc)
        else:
            raise AssertionError("unapproved task accepted")

def test_audit_created():
    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        core.submit("capability_scan")
        core.cycle()
        assert Path(tmp, "events.jsonl").exists()


def test_maintenance_scheduler_enqueues_deduplicated_periodic_work():
    from datetime import datetime, timedelta, timezone

    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        now = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
        first = core.schedule_maintenance(now)
        assert len(first) == 3
        assert core.schedule_maintenance(now + timedelta(minutes=1)) == []
        data = __import__("json").loads(core.tasks_path.read_text("utf-8"))
        assert {task["kind"] for task in data["tasks"]} == {
            "self_check", "capability_scan", "improvement_plan",
        }
        assert all(task["source"] == "IAO_MAINTENANCE_SCHEDULER" for task in data["tasks"])


def test_maintenance_scheduler_respects_independent_intervals():
    from datetime import datetime, timedelta, timezone
    import json

    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        now = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
        core.schedule_maintenance(now)
        with core.lock:
            data = json.loads(core.tasks_path.read_text("utf-8"))
            for task in data["tasks"]:
                task["status"] = "COMPLETED"
            core._save(data)
        due = core.schedule_maintenance(now + timedelta(hours=1, seconds=1))
        assert len(due) == 1
        data = json.loads(core.tasks_path.read_text("utf-8"))
        added = next(task for task in data["tasks"] if task["id"] == due[0])
        assert added["kind"] == "self_check"


def test_maintenance_scheduler_rejects_naive_clock():
    from datetime import datetime

    with tempfile.TemporaryDirectory() as tmp:
        core = AutonomousCore(tmp)
        try:
            core.schedule_maintenance(datetime(2026, 11, 27, 12, 0))
        except Exception as exc:
            assert "SCHEDULER_TIME" in str(exc)
        else:
            raise AssertionError("naive scheduler time accepted")
