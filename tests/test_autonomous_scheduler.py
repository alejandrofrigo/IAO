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


def test_scheduler_is_atomic_across_independent_core_instances(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    now = datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc)
    cores = [AutonomousCore(state_dir=tmp_path) for _ in range(12)]

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(
            pool.map(lambda core: schedule_due_tasks(core, now), cores)
        )

    assert sum(len(result) for result in results) == 3

    data = __import__("json").loads(
        (tmp_path / "tasks.json").read_text(encoding="utf-8")
    )

    assert len(data["tasks"]) == 3
    assert {task["kind"] for task in data["tasks"]} == {
        "self_check", "capability_scan", "improvement_plan"
    }


# IAO_MULTIPROCESS_SCHEDULER_TEST_V1
def _iao_multiprocess_periodic_submit(state_dir, start_event, result_queue):
    from datetime import datetime, timezone
    from omega.autonomous_core import AutonomousCore

    if not start_event.wait(20):
        raise RuntimeError("START_EVENT_TIMEOUT")

    core = AutonomousCore(state_dir=state_dir)
    result = core.submit_periodic_if_due(
        "self_check",
        3600,
        datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
        source="IAO_MULTIPROCESS_TEST",
    )
    result_queue.put("CREATED" if result is not None else "SKIPPED")


def test_periodic_scheduler_is_atomic_across_processes(tmp_path):
    import json
    import multiprocessing
    import pytest
    from omega.autonomous_core import AutonomousCore

    try:
        ctx = multiprocessing.get_context("fork")
    except ValueError:
        pytest.skip("El sistema no ofrece multiprocessing fork")

    state_dir = str(tmp_path / "multiprocess-state")
    core = AutonomousCore(state_dir=state_dir)

    process_count = 12
    start_event = ctx.Event()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_iao_multiprocess_periodic_submit,
            args=(state_dir, start_event, result_queue),
        )
        for _ in range(process_count)
    ]

    for process in processes:
        process.start()

    start_event.set()

    for process in processes:
        process.join(30)

    alive = [process.pid for process in processes if process.is_alive()]
    assert not alive, f"PROCESSES_STILL_RUNNING: {alive}"

    exit_codes = [process.exitcode for process in processes]
    assert exit_codes == [0] * process_count, f"PROCESS_EXIT_CODES: {exit_codes}"

    outcomes = [result_queue.get(timeout=10) for _ in processes]
    assert outcomes.count("CREATED") == 1, outcomes
    assert outcomes.count("SKIPPED") == process_count - 1, outcomes

    data = json.loads(core.tasks_path.read_text(encoding="utf-8"))
    queued = [
        task for task in data["tasks"]
        if task.get("kind") == "self_check"
        and task.get("status") == "QUEUED"
    ]
    assert len(queued) == 1, f"QUEUED_SELF_CHECK_COUNT: {len(queued)}"

    result_queue.close()
    result_queue.join_thread()
