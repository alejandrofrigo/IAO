import ast
import importlib
import json
import os
import pathlib
import time

import pytest

MODULE = importlib.import_module("omega.auto_deployer")


def valid_report():
    return {
        "version": 1,
        "timestamp": time.time(),
        "release_authorized": True,
        "status": "READY_FOR_SEPARATE_DEPLOYMENT_REVIEW",
        "checks_passed": 1,
        "checks_failed": 0,
        "checks": [{"check": "test", "ok": True, "detail": "ok"}],
        "deployment_performed": False,
        "external_service_verified": False,
    }


def set_gate(monkeypatch, tmp_path, report):
    path = tmp_path / "gate.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setenv("IAO_RELEASE_GATE_REQUIRED", "1")
    monkeypatch.setenv("IAO_RELEASE_GATE_REPORT", str(path))
    return path


def test_gate_helper_exists():
    assert callable(getattr(MODULE, "_iao_enforce_release_gate", None))


def test_valid_current_gate_is_accepted(monkeypatch, tmp_path):
    set_gate(monkeypatch, tmp_path, valid_report())
    MODULE._iao_enforce_release_gate()


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(release_authorized=False),
    lambda r: r.update(status="BLOCKED"),
    lambda r: r.update(checks_failed=1),
    lambda r: r.update(deployment_performed=True),
    lambda r: r["checks"][0].update(ok=False),
    lambda r: r.update(timestamp=time.time() - 600),
])
def test_invalid_gate_is_rejected(monkeypatch, tmp_path, mutation):
    report = valid_report()
    mutation(report)
    set_gate(monkeypatch, tmp_path, report)
    with pytest.raises(RuntimeError, match="IAO_RELEASE_GATE_BLOCKED"):
        MODULE._iao_enforce_release_gate()


def test_missing_gate_path_is_rejected(monkeypatch):
    monkeypatch.setenv("IAO_RELEASE_GATE_REQUIRED", "1")
    monkeypatch.delenv("IAO_RELEASE_GATE_REPORT", raising=False)
    with pytest.raises(RuntimeError, match="IAO_RELEASE_GATE_BLOCKED"):
        MODULE._iao_enforce_release_gate()


def test_missing_gate_file_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("IAO_RELEASE_GATE_REQUIRED", "1")
    monkeypatch.setenv("IAO_RELEASE_GATE_REPORT", str(tmp_path / "missing.json"))
    with pytest.raises(RuntimeError, match="IAO_RELEASE_GATE_BLOCKED"):
        MODULE._iao_enforce_release_gate()


def test_deploy_ssh_calls_gate_before_deployment_logic():
    tree = ast.parse(pathlib.Path(MODULE.__file__).read_text(encoding="utf-8"))
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == "AutoDeployer")
    method = next(n for n in cls.body
                  if isinstance(n, ast.FunctionDef) and n.name == "deploy_ssh")
    body = list(method.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(
        body[0].value, ast.Constant
    ) and isinstance(body[0].value.value, str):
        body = body[1:]
    assert body, "deploy_ssh has no executable body"
    first = body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
    assert isinstance(first.value.func, ast.Name)
    assert first.value.func.id == "_iao_enforce_release_gate"


def test_gate_is_optional_only_outside_guarded_deployment(monkeypatch):
    monkeypatch.delenv("IAO_RELEASE_GATE_REQUIRED", raising=False)
    monkeypatch.delenv("IAO_RELEASE_GATE_REPORT", raising=False)
    MODULE._iao_enforce_release_gate()
