"""Operational privacy regressions for request diagnostics and runtime logging."""
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from omega.server import build_service


def test_internal_error_audit_redacts_request_path_query_and_exception_text():
    token_key = "privacy-test-token-key-" + "x" * 40
    audit_key = "privacy-test-audit-key-" + "y" * 48
    corpus = Path(__file__).resolve().parents[1] / "docs" / "corpus"
    with tempfile.TemporaryDirectory() as temp_dir:
        with patch.dict(os.environ, {"AUDIT_HMAC_KEY": audit_key}, clear=False):
            service = build_service(
                Path(temp_dir), token_key, corpus,
                identity_rollback_anchor_enabled=False,
            )
        try:
            def fail_route(*_args):
                raise RuntimeError("private-exception-marker")

            service._route = fail_route
            status, payload = service.handle(
                "GET",
                "/v1/private-path-marker?token=private-query-marker",
                {},
                b"",
            )
            assert status == 500
            assert payload["error"] == "INTERNAL_ERROR"
            events = service.store._all_events()
            internal = [event for event in events if event["event_type"] == "API_INTERNAL_ERROR"]
            assert len(internal) == 1
            assert internal[0]["subject"] == "request"
            assert internal[0]["details"]["error_type"] == "RuntimeError"
            serialized = json.dumps(events)
            assert "private-path-marker" not in serialized
            assert "private-query-marker" not in serialized
            assert "private-exception-marker" not in serialized
        finally:
            service.store.close()


def test_production_container_disables_automatic_client_address_access_logs():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    assert "--no-access-log" in dockerfile.read_text(encoding="utf-8")

def test_stdlib_server_bind_log_uses_scope_not_address():
    from omega.server import _bind_scope

    assert _bind_scope("0.0.0.0") == "all_interfaces"
    assert _bind_scope("127.0.0.1") == "loopback"
    assert _bind_scope("192.168.10.25") == "configured"
    assert "192.168.10.25" not in _bind_scope("192.168.10.25")
