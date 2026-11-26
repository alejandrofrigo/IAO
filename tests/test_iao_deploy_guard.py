import json
import time
import pytest

from tools.iao_deploy_guard import load_gate, health_check


def valid_gate():
    return {
        "release_authorized": True,
        "status": "READY_FOR_SEPARATE_DEPLOYMENT_REVIEW",
        "checks_failed": 0,
        "deployment_performed": False,
        "timestamp": time.time(),
        "checks": [{"check": "compile", "ok": True}],
    }


def test_accepts_current_approved_gate(tmp_path):
    p = tmp_path / "gate.json"
    p.write_text(json.dumps(valid_gate()))
    assert load_gate(p)["release_authorized"] is True


def test_rejects_unauthorized_gate(tmp_path):
    data = valid_gate()
    data["release_authorized"] = False
    p = tmp_path / "gate.json"
    p.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="RELEASE_NOT_AUTHORIZED"):
        load_gate(p)


def test_rejects_stale_gate(tmp_path):
    data = valid_gate()
    data["timestamp"] = time.time() - 1000
    p = tmp_path / "gate.json"
    p.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="STALE"):
        load_gate(p)


def test_rejects_failed_check(tmp_path):
    data = valid_gate()
    data["checks"][0]["ok"] = False
    p = tmp_path / "gate.json"
    p.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="CHECK_FAILED"):
        load_gate(p)


def test_rejects_missing_report(tmp_path):
    with pytest.raises(RuntimeError, match="MISSING"):
        load_gate(tmp_path / "absent.json")


def test_rejects_report_from_after_deployment(tmp_path):
    data = valid_gate()
    data["deployment_performed"] = True
    p = tmp_path / "gate.json"
    p.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="PREDEPLOYMENT"):
        load_gate(p)


def test_health_check_rejects_invalid_url():
    ok, detail = health_check("http://127.0.0.1:1/health/live", timeout=1)
    assert ok is False
    assert detail
