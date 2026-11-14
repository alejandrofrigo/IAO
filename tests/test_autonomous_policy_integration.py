from omega.autonomous_core import AutonomousCore


def test_autonomous_task_passes_policy_gate(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    submitted = core.submit("self_check")
    result = core.run_one()

    assert result is not None
    assert result["id"] == submitted["id"]
    assert result["status"] == "COMPLETED"
    assert result["policy_decision"]["allowed"] is True
    assert result["policy_decision"]["state"] == "DEGRADED"


def test_autonomous_policy_decision_is_recorded(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    core.submit("capability_scan")
    result = core.run_one()

    assert result["policy_decision"]["reason"] == "read_only_permitted"
    events = core.events_path.read_text(encoding="utf-8")
    assert "TASK_POLICY_ALLOWED" in events


def test_unknown_task_is_rejected_before_submission(tmp_path):
    core = AutonomousCore(state_dir=tmp_path)
    try:
        core.submit("modify_source_code")
    except Exception as exc:
        assert str(exc) == "TASK_TYPE_NOT_ALLOWED"
    else:
        raise AssertionError("Unsupported task unexpectedly accepted")
