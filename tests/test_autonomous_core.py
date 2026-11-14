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
