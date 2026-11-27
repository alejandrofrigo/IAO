"""Functional health checks must distinguish live processes from fresh cycle evidence."""
import fcntl
import os
import stat

from omega.supervision import read_heartbeat, read_lock_owner, write_heartbeat
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
    assert fresh["status"] == "DEGRADED"
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


def test_coordinator_lock_is_private_and_records_its_owner(tmp_path, monkeypatch):
    state = tmp_path / "private-state"
    monkeypatch.setattr(coordinator, "STATE", state)
    monkeypatch.setattr(coordinator, "LOCK", state / "coordinator.lock")

    with coordinator.acquire_lock() as stream:
        assert stream.readable()
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert stat.S_IMODE(coordinator.LOCK.stat().st_mode) == 0o600
        assert coordinator.LOCK.read_text(encoding="utf-8") == str(os.getpid())


def test_supervisor_json_state_is_atomic_and_private(tmp_path):
    path = tmp_path / "private-state" / "children.json"
    supervisor.save_json(path, {"PADGE": {"pid": os.getpid()}})
    assert supervisor.load_json(path, {}) == {"PADGE": {"pid": os.getpid()}}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


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

def test_heartbeat_and_lock_readers_reject_symlink_paths(tmp_path):
    real_heartbeat = tmp_path / "real-heartbeat.json"
    write_heartbeat(
        real_heartbeat,
        component="PADGE_AUTONOMY",
        pid=os.getpid(),
        phase="cycle_completed",
        interval_seconds=60,
        stale_after_seconds=1800,
    )
    heartbeat_link = tmp_path / "heartbeat-link.json"
    heartbeat_link.symlink_to(real_heartbeat)
    assert read_heartbeat(
        heartbeat_link, expected_component="PADGE_AUTONOMY",
    ) == {"status": "UNVERIFIED"}

    real_lock = tmp_path / "real-lock"
    real_lock.write_text(str(os.getpid()), encoding="ascii")
    lock_link = tmp_path / "lock-link"
    lock_link.symlink_to(real_lock)
    assert read_lock_owner(lock_link) is None

def test_coordinator_lock_creation_rejects_symlink_substitution(tmp_path, monkeypatch):
    state = tmp_path / "private-state"
    state.mkdir(mode=0o700)
    target = tmp_path / "unrelated-file"
    target.write_text("do-not-overwrite", encoding="utf-8")
    lock = state / "coordinator.lock"
    lock.symlink_to(target)
    monkeypatch.setattr(coordinator, "STATE", state)
    monkeypatch.setattr(coordinator, "LOCK", lock)

    try:
        coordinator.acquire_lock()
    except RuntimeError as exc:
        assert str(exc) == "COORDINATOR_LOCK_UNAVAILABLE"
    else:
        raise AssertionError("symlinked coordinator lock was accepted")
    assert target.read_text(encoding="utf-8") == "do-not-overwrite"

def test_supervisor_treats_permission_denied_process_probe_as_alive(monkeypatch):
    def denied(_pid, _signal):
        raise PermissionError

    monkeypatch.setattr(supervisor.os, "kill", denied)
    assert supervisor.process_alive(12345) is True

    def missing(_pid, _signal):
        raise ProcessLookupError

    monkeypatch.setattr(supervisor.os, "kill", missing)
    assert supervisor.process_alive(12345) is False

def test_supervisor_rejects_boolean_and_invalid_pids_before_probing(monkeypatch):
    def must_not_probe(*_args):
        raise AssertionError("invalid PID reached os.kill")

    monkeypatch.setattr(supervisor.os, "kill", must_not_probe)
    assert supervisor.process_alive(True) is False
    assert supervisor.process_alive(1) is False
    assert supervisor.process_alive("1") is False
    assert supervisor.process_alive(1.5) is False


def test_supervisor_only_signals_its_own_session_process_group(monkeypatch):
    monkeypatch.setattr(supervisor, "process_alive", lambda _pid: True)
    monkeypatch.setattr(supervisor.os, "getpgid", lambda pid: pid)
    assert supervisor.managed_process_group(999) is True
    monkeypatch.setattr(supervisor.os, "getpgid", lambda pid: pid + 1)
    assert supervisor.managed_process_group(999) is False
    def missing(_pid):
        raise ProcessLookupError
    monkeypatch.setattr(supervisor.os, "getpgid", missing)
    assert supervisor.managed_process_group(999) is False

def test_supervisor_binds_child_identity_to_process_start_ticks(monkeypatch):
    ticks = supervisor.process_start_ticks(os.getpid())
    assert isinstance(ticks, str) and ticks.isdigit()
    child = {"pid": os.getpid(), "process_start_ticks": ticks}
    assert supervisor.process_identity_matches(child) is True

    monkeypatch.setattr(supervisor, "process_start_ticks", lambda _pid: str(int(ticks) + 1))
    assert supervisor.process_identity_matches(child) is False
    assert supervisor.process_identity_matches({"pid": os.getpid()}) is False
