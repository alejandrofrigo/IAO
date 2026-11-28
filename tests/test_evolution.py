import json

import pytest

from omega import evolution


@pytest.fixture
def isolated_evolution_state(tmp_path, monkeypatch):
    state = tmp_path / "evolution"
    state.mkdir()
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

    with pytest.raises(ValueError, match="MANIFEST_INVALID"):
        evolution.evaluate(created["id"])


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


def test_invalid_python_syntax_is_rejected_without_execution(isolated_evolution_state):
    value = proposal()
    value["files"]["omega/example_helper.py"] = "def answer(:\n    return 42\n"
    created = evolution.submit(value)

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert evaluated["promotion_eligible"] is False
    assert evaluated["validation"]["content_hashes_valid"] is True
    assert evaluated["validation"]["syntax_valid"] is False
    assert any("SYNTAX_INVALID" in item for item in evaluated["failures"])


def test_invalid_utf8_candidate_is_rejected_and_audited(isolated_evolution_state):
    created = evolution.submit(proposal())
    candidate = evolution.CANDIDATES / created["id"] / "omega/example_helper.py"
    candidate.write_bytes(b"\xff\xfe\xfa")
    metadata = json.loads(
        (evolution.CANDIDATES / created["id"] / "proposal.json").read_text(
            encoding="utf-8"
        )
    )
    # Keep the manifest's expected digest so the failure exercises UTF-8 decoding.
    import hashlib
    metadata["file_hashes"]["omega/example_helper.py"] = hashlib.sha256(
        b"\xff\xfe\xfa"
    ).hexdigest()
    # UTF-8 decoding must fail even when the per-file digest matches.
    (evolution.CANDIDATES / created["id"] / "proposal.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert evaluated["validation"]["content_hashes_valid"] is False
    assert any("UTF8_INVALID" in item for item in evaluated["failures"])


def test_proposal_hash_mismatch_is_rejected(isolated_evolution_state):
    created = evolution.submit(proposal())
    metadata = evolution.CANDIDATES / created["id"] / "proposal.json"
    value = json.loads(metadata.read_text(encoding="utf-8"))
    value["proposal_hash"] = "0" * 64
    metadata.write_text(json.dumps(value), encoding="utf-8")

    evaluated = evolution.evaluate(created["id"])

    assert evaluated["status"] == "REJECTED"
    assert evaluated["validation"]["content_hashes_valid"] is False
    assert "PROPOSAL_HASH_MISMATCH" in evaluated["failures"]


def test_submit_rejects_symlinked_candidates_root(isolated_evolution_state, tmp_path, monkeypatch):
    redirected = tmp_path / "outside-candidates"
    redirected.mkdir()
    link = isolated_evolution_state / "candidates"
    link.symlink_to(redirected, target_is_directory=True)
    monkeypatch.setattr(evolution, "CANDIDATES", link)

    with pytest.raises(ValueError, match="SYMLINK_PATH_REFUSED"):
        evolution.submit(proposal())

    assert list(redirected.iterdir()) == []


def test_evolution_log_rejects_symlinked_event_file(isolated_evolution_state, tmp_path, monkeypatch):
    outside = tmp_path / "outside-events.jsonl"
    outside.write_text("", encoding="utf-8")
    link = isolated_evolution_state / "events.jsonl"
    link.symlink_to(outside)
    monkeypatch.setattr(evolution, "EVENTS", link)

    with pytest.raises(ValueError, match="SYMLINK_PATH_REFUSED"):
        evolution.verify_log()

    assert outside.read_text(encoding="utf-8") == ""
