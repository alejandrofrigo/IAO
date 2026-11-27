"""Functional health checks must distinguish live processes from fresh cycle evidence."""
import fcntl
import os
import stat

from omega.supervision import read_heartbeat, write_heartbeat
from tools import iao_autonomous_coordinator as coordinator
from tools import iao_five_motor_supervisor as supervisor


def test_heartbeat_reports_cycle_completion_and_staleness(tmp_path):
    path = tmp_path / "heartbeat.json"
    write_heartbeat(
        path,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase="cycle_completed",
        interval_seconds=60,
        stale_after_seconds=1800,
        last_cycle_result=False,
        now=1000,
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    fresh = read_heartbeat(
        path, expected_component="PADGE_AUTONOMY", now=1010,
    )
    assert fresh["status"] == "HEALTHY"
    assert fresh["last_cycle_result"] is False

    stale = read_heartbeat(
        path, expected_component="PADGE_AUTONOMY", now=2801,
    )
    assert stale["status"] == "STALE"


def test_heartbeat_distinguishes_cycle_in_progress_and_wrong_component(tmp_path):
    path = tmp_path / "heartbeat.json"
    write_heartbeat(
        path,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase="cycle_running",
        interval_seconds=60,
        stale_after_seconds=1800,
        now=1000,
    )
    assert read_heartbeat(
        path, expected_component="PADGE_AUTONOMY", now=1010,
    )["status"] == "CYCLE_IN_PROGRESS"
    assert read_heartbeat(
        path, expected_component="OTHER", now=1010,
    )["status"] == "UNVERIFIED"


def test_heartbeat_rejects_invalid_identity_and_timing(tmp_path):
    path = tmp_path / "heartbeat.json"
    for kwargs in (
        {"pid": True},
        {"pid": 0},
        {"interval_seconds": True},
        {"stale_after_seconds": 30},
    ):
        values = {
            "component": "PADGE_AUTONOMY",
            "pid": os.getpid(),
            "phase": "starting",
            "interval_seconds": 60,
            "stale_after_seconds": 1800,
            "now": 1000,
        }
        values.update(kwargs)
        try:
            write_heartbeat(path, **values)
        except ValueError as exc:
            assert str(exc) == "INVALID_HEARTBEAT"
        else:
            raise AssertionError("invalid heartbeat accepted")


def test_coordinator_status_requires_lock_and_fresh_heartbeat(tmp_path, monkeypatch, capsys):
    lock_path = tmp_path / "coordinator.lock"
    heartbeat_path = tmp_path / "coordinator-heartbeat.json"
    monkeypatch.setattr(coordinator, "LOCK", lock_path)
    monkeypatch.setattr(coordinator, "HEARTBEAT", heartbeat_path)
    monkeypatch.setattr(coordinator, "REPORTS", tmp_path / "reports")
    monkeypatch.setattr(coordinator, "COMPONENTS", {})

    write_heartbeat(
        heartbeat_path,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase="cycle_completed",
        interval_seconds=60,
        stale_after_seconds=1800,
    )
    assert coordinator.status() == 1
    assert "COORDINATOR_STATUS=STOPPED" in capsys.readouterr().out

    with lock_path.open("a+", encoding="utf-8") as stream:
        stream.write(str(os.getpid() + 1))
        stream.flush()
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert coordinator.status() == 1
        assert "COORDINATOR_STATUS=DEGRADED_UNVERIFIED" in capsys.readouterr().out

        stream.seek(0)
        stream.truncate()
        stream.write(str(os.getpid()))
        stream.flush()
        assert coordinator.status() == 0
        assert "COORDINATOR_STATUS=HEALTHY" in capsys.readouterr().out
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def test_supervisor_does_not_equate_pid_with_functional_health(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(supervisor, "ROOT", tmp_path)
    monkeypatch.setattr(
        supervisor,
        "COORDINATOR_LOCK",
        tmp_path / ".state" / "iao-autonomy" / "coordinator.lock",
    )
    monkeypatch.setattr(
        supervisor,
        "read_children",
        lambda: {
            "PADGE": {"pid": os.getpid()},
            "GUARDIAN": {"pid": os.getpid()},
        },
    )
    monkeypatch.setattr(
        supervisor,
        "adapters",
        lambda: {
            "PADGE": {"enabled": True, "command": ["python", "coordinator.py"]},
            "GUARDIAN": {"enabled": True, "command": ["python", "guardian.py"]},
        },
    )
    heartbeat_path = tmp_path / ".state" / "iao-autonomy" / "coordinator-heartbeat.json"
    write_heartbeat(
        heartbeat_path,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase="cycle_completed",
        interval_seconds=60,
        stale_after_seconds=1800,
    )

    lock_path = tmp_path / ".state" / "iao-autonomy" / "coordinator.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as stream:
        stream.write(str(os.getpid()))
        stream.flush()
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        supervisor.status()
        output = capsys.readouterr().out
        assert "PADGE: HEALTHY" in output
        assert "GUARDIAN: PROCESS_ALIVE_UNVERIFIED" in output
        assert "GUARDIAN: RUNNING" not in output
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
