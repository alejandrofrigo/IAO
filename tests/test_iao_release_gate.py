import json
from pathlib import Path

from tools.iao_release_gate import ReleaseGate


def test_release_is_blocked_when_critical_file_missing(tmp_path):
    gate = ReleaseGate(tmp_path)
    report = gate.run()
    assert report["release_authorized"] is False
    assert report["status"] == "BLOCKED"


def test_report_never_claims_deployment(tmp_path):
    report = ReleaseGate(tmp_path).run()
    assert report["deployment_performed"] is False
    assert report["external_service_verified"] is False


def test_missing_trust_and_recovery_are_reported(tmp_path):
    gate = ReleaseGate(tmp_path)
    gate.check_trust_store()
    results = {r["check"]: r["ok"] for r in gate.results}
    assert results["federation_trust_store"] is False
    assert results["runtime_recovery"] is False


def test_report_structure_is_machine_readable(tmp_path):
    report = ReleaseGate(tmp_path).run()
    encoded = json.dumps(report)
    decoded = json.loads(encoded)
    assert "checks" in decoded
    assert "release_authorized" in decoded
    assert isinstance(decoded["checks"], list)
