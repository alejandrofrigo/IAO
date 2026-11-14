from tools.iao_autonomous_worker import acquire_instance_lock


def test_worker_process_lock_excludes_second_instance(tmp_path):
    lock_path = tmp_path / "worker.lock"
    first = acquire_instance_lock(lock_path)
    assert first is not None

    second = acquire_instance_lock(lock_path)
    assert second is None

    first.close()

    third = acquire_instance_lock(lock_path)
    assert third is not None
    third.close()
