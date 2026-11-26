import time

import pytest

from omega.autonomous_core import AutonomousCore, AutonomousCoreError


def test_worker_starts_and_stops(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    assert core.start_worker(interval=1) is True
    assert core.worker is not None
    assert core.worker.is_alive()
    assert core.stop_worker(timeout=5) is True
    assert not core.worker.is_alive()


def test_repeated_start_does_not_create_second_worker(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    assert core.start_worker(interval=1) is True
    first = core.worker
    assert core.start_worker(interval=1) is False
    assert core.worker is first
    assert core.stop_worker(timeout=5) is True


def test_worker_can_restart_after_graceful_stop(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    assert core.start_worker(interval=1) is True
    assert core.stop_worker(timeout=5) is True
    assert core.start_worker(interval=1) is True
    assert core.stop_worker(timeout=5) is True


@pytest.mark.parametrize("interval", [0, -1, 3601, True, "1"])
def test_invalid_worker_interval_is_rejected(tmp_path, interval):
    core = AutonomousCore(state_dir=tmp_path)
    with pytest.raises(AutonomousCoreError):
        core.start_worker(interval=interval)


@pytest.mark.parametrize("timeout", [-1, 31, True, "5"])
def test_invalid_worker_timeout_is_rejected(tmp_path, timeout):
    core = AutonomousCore(state_dir=tmp_path)
    with pytest.raises(AutonomousCoreError):
        core.stop_worker(timeout=timeout)


def test_stop_when_worker_is_not_running_is_safe(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    assert core.stop_worker() is True
    assert core.status()["worker_running"] is False
