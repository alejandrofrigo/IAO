from datetime import datetime, timedelta, timezone

from omega.autonomous_core import AutonomousCore
from tools.iao_autonomous_worker import schedule_due_tasks


def test_scheduler_creates_initial_read_only_tasks(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)

    created = schedule_due_tasks(core, now)

    assert {item["kind"] for item in created} == {
        "self_check", "capability_scan", "improvement_plan"
    }
    assert len(created) == 3


def test_scheduler_does_not_duplicate_recent_tasks(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)

    first = schedule_due_tasks(core, now)
    second = schedule_due_tasks(core, now + timedelta(minutes=5))

    assert len(first) == 3
    assert second == []


def test_scheduler_respects_individual_intervals(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)

    first = schedule_due_tasks(core, now)
    assert [item["kind"] for item in first] == [
        "self_check", "capability_scan", "improvement_plan"
    ]

    # La prueba representa que las tareas iniciales ya terminaron.
    data = __import__("json").loads(
        core.tasks_path.read_text(encoding="utf-8")
    )
    for task in data["tasks"]:
        task["status"] = "COMPLETED"
    core._save(data)

    later = schedule_due_tasks(core, now + timedelta(hours=1))
    assert [item["kind"] for item in later] == ["self_check"]


def test_pending_tasks_are_not_duplicated(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)

    core.submit("self_check", source="existing")
    created = schedule_due_tasks(core, now)

    assert "self_check" not in {item["kind"] for item in created}


def test_scheduler_rejects_naive_datetime(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0)

    try:
        schedule_due_tasks(core, now)
    except ValueError as exc:
        assert str(exc) == "SCHEDULER_REQUIRES_TIMEZONE"
    else:
        raise AssertionError("Naive datetime unexpectedly accepted")


def test_scheduler_persists_the_supplied_aware_timestamp(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)

    created = schedule_due_tasks(core, now)
    data = __import__("json").loads(core.tasks_path.read_text("utf-8"))

    for item in created:
        task = next(t for t in data["tasks"] if t["id"] == item["id"])
        assert task["created_at"] == now.isoformat()
        assert task["updated_at"] == now.isoformat()


def test_core_rejects_naive_created_at(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    naive = datetime(2026, 11, 1, 16, 0)

    try:
        core.submit("self_check", created_at=naive)
    except Exception as exc:
        assert str(exc) == "INVALID_CREATED_AT"
    else:
        raise AssertionError("Naive created_at unexpectedly accepted")
