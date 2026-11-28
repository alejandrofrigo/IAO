import json

import pytest

from omega import evolution


@pytest.fixture
def isolated_evolution_state(tmp_path, monkeypatch):
    state = tmp_path / "evolution"
    monkeypatch.setattr(evolution, "STATE", state)
    monkeypatch.setattr(evolution, "CANDIDATES", state / "candidates")
    monkeypatch.setattr(evolution, "EVENTS", state / "events.jsonl")
    return state


def proposal():
    return {
        "title": "Add a small deterministic helper",
        "files": {"omega/example_helper.py": "def answer():\n    return 42\n"},
        "checks": ["compileall"],
    }


def test_proposal_records_hashes_and_is_approved_only_for_staging(isolated_evolution_state):
    created = evolution.submit(proposal())
    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "STATIC_CHECKS_PASSED"
    assert evaluated["promotion_eligible"] is False
    assert evaluated["validation"] == {
        "manifest_valid": True,
        "content_hashes_valid": True,
        "syntax_valid": True,
        "candidate_code_executed": False,
    }
    assert evaluated["file_hashes"]["omega/example_helper.py"]
    assert "No se ejecutó el candidato" in evaluated["notice"]


def test_tampered_candidate_is_rejected(isolated_evolution_state):
    created = evolution.submit(proposal())
    candidate = evolution.CANDIDATES / created["id"] / "omega/example_helper.py"
    candidate.write_text("def answer():\n    return 0\n", encoding="utf-8")

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert any("CONTENT_HASH_MISMATCH" in item for item in evaluated["failures"])


def test_tampered_manifest_is_rejected(isolated_evolution_state):
    created = evolution.submit(proposal())
    metadata = evolution.CANDIDATES / created["id"] / "proposal.json"
    value = json.loads(metadata.read_text(encoding="utf-8"))
    value["files"] = ["omega/other.py"]
    metadata.write_text(json.dumps(value), encoding="utf-8")

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert any("MANIFEST_INVALID" in item for item in evaluated["failures"])


def test_candidate_symlink_is_rejected(isolated_evolution_state, tmp_path):
    created = evolution.submit(proposal())
    candidate = evolution.CANDIDATES / created["id"] / "omega/example_helper.py"
    outside = tmp_path / "outside.py"
    outside.write_text("def answer():\n    return 42\n", encoding="utf-8")
    candidate.unlink()
    candidate.symlink_to(outside)

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert any("SYMLINK_REFUSED" in item for item in evaluated["failures"])


def test_unsupported_checks_are_rejected_before_evaluation(isolated_evolution_state):
    value = proposal()
    value["checks"] = ["compileall", "run_candidate"]
    with pytest.raises(ValueError, match="compileall"):
        evolution.submit(value)


def test_evolution_log_detects_tampering(isolated_evolution_state):
    created = evolution.submit(proposal())
    log = evolution.EVENTS
    rows = log.read_text(encoding="utf-8").splitlines()
    value = json.loads(rows[0])
    value["title"] = "altered"
    log.write_text(json.dumps(value) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Registro de evolución"):
        evolution.evaluate(created["id"])
