"""Operational event logs redact free-form data and use private filesystem modes."""
import stat

from omega.operational_log import append_private_jsonl, sanitize_log_data


def test_operational_log_redacts_content_paths_and_nested_errors(tmp_path):
    path = tmp_path / "private" / "events.jsonl"
    entry = append_private_jsonl(
        path,
        {
            "time": "2026-11-27T00:00:00Z",
            "event": "privacy_regression",
            "goal": "private-goal-marker",
            "reason": "free-form private reason marker",
            "files": ["/home/private/path.py", "omega/service.py"],
            "error": "RuntimeError('private-exception-marker')",
            "traceback": "private-traceback-marker",
            "decision": {
                "approved": False,
                "reason": "private-policy-detail-marker",
                "path": "/home/private/secret.py",
            },
        },
    )
    serialized = path.read_text(encoding="utf-8")
    for marker in (
        "private-goal-marker",
        "free-form private reason marker",
        "private/path.py",
        "private-exception-marker",
        "private-traceback-marker",
        "private-policy-detail-marker",
        "secret.py",
    ):
        assert marker not in serialized
    assert entry["error_type"] == "RuntimeError"
    assert entry["files_count"] == 2
    assert entry["reason_digest"].startswith("sha256:")
    assert entry["decision"]["path_redacted"] is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_operational_log_preserves_safe_enum_reason():
    safe = sanitize_log_data({"reason": "TIMEOUT"})
    assert safe == {"reason": "TIMEOUT"}


def test_operational_log_does_not_follow_symlink(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "events.jsonl"
    link.symlink_to(target)
    try:
        append_private_jsonl(link, {"event": "test"})
    except OSError:
        pass
    else:
        raise AssertionError("symlink log target was followed")
    assert target.read_text(encoding="utf-8") == "do not overwrite"

def test_operational_log_hashes_unknown_strings_and_untrusted_string_lists():
    safe = sanitize_log_data({
        "time": "2026-11-27T00:00:00+00:00",
        "event": "NODE_CANDIDATE_DISCOVERED",
        "repository": "owner/private-repository-marker",
        "origin": "https://private-host.example/private-path-marker",
        "email": "person@example.invalid",
        "ip_address": 3221226037,
        "authorization": "private-authorization-marker",
        "annotations": ["private-list-marker", "another-private-value"],
        "capabilities": ["knowledge.search"],
        "status": "192.0.2.55",
        "state": "private-state-marker",
    })
    assert safe["time"] == "2026-11-27T00:00:00+00:00"
    assert safe["event"] == "NODE_CANDIDATE_DISCOVERED"
    assert safe["capabilities"] == ["knowledge.search"]
    assert safe["repository_digest"].startswith("sha256:")
    assert safe["origin_digest"] == "[REDACTED]"
    assert safe["email_digest"] == "[REDACTED]"
    assert safe["ip_address_digest"] == "[REDACTED]"
    assert safe["authorization_digest"] == "[REDACTED]"
    assert safe["annotations_digest"].startswith("sha256:")
    assert safe["status_digest"].startswith("sha256:")
    assert safe["state_digest"].startswith("sha256:")
    assert "192.0.2.55" not in str(safe)
    assert "private-state-marker" not in str(safe)
    assert "person@example.invalid" not in str(safe)
    assert "private-authorization-marker" not in str(safe)
    assert "repository" not in safe
    assert "origin" not in safe
    assert "annotations" not in safe
