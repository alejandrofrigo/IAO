"""End-to-end API adapter tests against a real temporary SQLite store."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from apps.api import main


def configured_client(monkeypatch, tmp_path):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "test-token-key-" + "x" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "test-audit-key-" + "y" * 48)
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("IAO_CORPUS_DIR", str(tmp_path / "corpus"))
    monkeypatch.setenv("MODEL_ADAPTER", "disabled")
    monkeypatch.delenv("IAO_LLM_ROUTER", raising=False)
    monkeypatch.setenv("IAO_DEVICE_ENROLLMENT_CODE", "one-time-enrollment-code-" + "z" * 32)
    monkeypatch.setenv("IAO_DEVICE_ENROLLMENT_ENABLED", "1")
    main._service = None
    main._device_authority = None
    main._federation_node = None
    main._federation_worker_status.update({
        "autojoin": False, "discovery": False, "external_network": False,
    })
    # API contract tests must not launch real network workers.
    monkeypatch.setattr(main, "_ensure_federation", lambda service: None)
    return TestClient(main.app)


def test_liveness_does_not_require_database_or_model() -> None:
    response = TestClient(main.app).get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "live"
    assert response.headers["x-correlation-id"] == response.json()["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_readiness_never_claims_full_production_before_security_gates(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["production_gates"]["device_identity_verification"] == "integrated_read_only"
    assert body["production_gates"]["privileged_device_commands"] == "disabled"
    assert body["production_gates"]["identity_provider"] == "dev_hmac_not_oidc"
    assert body["production_gates"]["independent_federation"] == "not_started_or_unavailable"
    assert body["production_gates"]["model_provider"] == "not_configured"


def test_runtime_refuses_missing_persistent_keys(monkeypatch) -> None:
    monkeypatch.delenv("OMEGA_DEV_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    main._service = None
    response = TestClient(main.app).get("/health/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_public_session_and_conversation_use_persistent_service(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    session = client.post("/v1/public/session", json={})
    assert session.status_code == 201
    token = session.json()["access_token"]
    headers = {"Authorization": "Bearer " + token}

    created = client.post(
        "/v1/conversations",
        headers=headers,
        json={"title": "IAO public session"},
    )
    assert created.status_code == 201
    conversation_id = created.json()["conversation_id"]

    listed = client.get(
        f"/v1/conversations/{conversation_id}/messages",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["messages"] == []

    # The state database is created on disk, not held only in request memory.
    assert (tmp_path / "state" / "omega.db").is_file()


def test_chat_is_audited_and_requires_a_real_model_adapter(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    session = client.post("/v1/public/session", json={})
    token = session.json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    created = client.post(
        "/v1/conversations",
        headers=headers,
        json={"title": "Chat"},
    )
    conversation_id = created.json()["conversation_id"]

    response = client.post(
        "/v1/chat",
        headers=headers,
        json={"conversation_id": conversation_id, "message": "hello"},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "MODEL_ADAPTER_NOT_CONFIGURED"

    audit = client.get("/v1/audit/events", headers=headers)
    assert audit.status_code == 200
    assert any(event["event_type"] == "CHAT_MODEL_ERROR" for event in audit.json()["events"])


def test_v1_routes_reject_missing_authentication(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/v1/me")
    assert response.status_code == 401

def test_device_routes_require_operator_session_and_reject_guest_enrollment(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    guest = client.post("/v1/public/session", json={})
    headers = {"Authorization": "Bearer " + guest.json()["access_token"]}
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    enrolled = client.post(
        "/v1/device/enroll", headers=headers,
        json={
            "code": "one-time-enrollment-code-" + "z" * 32,
            "public_key_pem": public_pem,
        },
    )
    assert enrolled.status_code == 403
    assert enrolled.json()["error"] == "OPERATOR_SESSION_REQUIRED"

    challenge = client.post(
        "/v1/device/challenge", headers=headers,
        json={"device_id": "0" * 64},
    )
    assert challenge.status_code == 403
    assert challenge.json()["error"] == "OPERATOR_SESSION_REQUIRED"

    unauthenticated_status = client.post(
        "/v1/device/command", json={"action": "status"},
    )
    assert unauthenticated_status.status_code == 401


def test_cors_allows_signed_device_task_proof_header():
    cors = next(
        middleware for middleware in main.app.user_middleware
        if middleware.cls.__name__ == "CORSMiddleware"
    )
    allowed = {header.lower() for header in cors.kwargs["allow_headers"]}
    assert "x-iao-device-proof" in allowed


def test_device_routes_do_not_bypass_persistent_service_authentication(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.post(
        "/v1/device/enroll",
        json={"code": "x" * 40, "public_key_pem": "invalid"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_REQUIRED"


def test_federation_status_does_not_claim_unverified_network_is_active(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/v1/federation/status")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unknown"
    assert body["mode"] == "discovery_only"
    assert body["network_nodes"] == []
    assert body["trusted_peer_count"] is None
    assert body["remote_enrollment"] == "disabled"



def test_federation_publication_is_exposed_only_with_explicit_opt_in(monkeypatch, tmp_path):
    class StubNode:
        served = {"knowledge.search"}

        def identity_document(self):
            return {"node_id": "0123456789abcdef", "public_key": "a" * 64}

        def contract_for_self(self, capabilities):
            return {"node_id": "0123456789abcdef", "capabilities": capabilities}

        def identity_publication(self, endpoint, capabilities, consent):
            return {
                "node_id": "0123456789abcdef",
                "endpoint": endpoint,
                "capabilities": capabilities,
                "consent": consent,
            }

    client = configured_client(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_ensure_federation", lambda service: StubNode())
    assert client.get("/fed/v1/identity").status_code == 200
    assert client.get("/fed/v1/contract").status_code == 200

    withheld = client.get("/fed/v1/publication")
    assert withheld.status_code == 404
    assert withheld.json()["error"] == "PUBLIC_PEERING_NOT_OFFERED"

    monkeypatch.setenv("IAO_FEDERATION_PUBLIC_PEERING", "true")
    monkeypatch.setenv("IAO_FEDERATION_PUBLIC_ORIGIN", "https://node.example.org")
    offered = client.get("/fed/v1/publication")
    assert offered.status_code == 200
    assert offered.json()["consent"] is True
    assert offered.json()["endpoint"] == "https://node.example.org/fed/v1/message"


def test_federation_handshake_enforces_bounded_content_length(monkeypatch, tmp_path):
    class StubNode:
        def answer_challenge(self, body):
            return 200, {"accepted": True}

    client = configured_client(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_ensure_federation", lambda service: StubNode())
    missing_length = client.post("/fed/v1/handshake", content=b"{}",
                                 headers={"Transfer-Encoding": "chunked"})
    assert missing_length.status_code == 400
    assert missing_length.json()["error"] == "INVALID_TRANSFER_ENCODING"


def test_federation_initialization_failure_does_not_take_down_local_api(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)

    def unavailable(_service):
        raise RuntimeError("simulated federation outage")

    monkeypatch.setattr(main, "_ensure_federation", unavailable)
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert (tmp_path / "state" / "omega.db").is_file()


def test_known_route_wrong_method_returns_stable_405_and_allow_header(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/v1/chat")
    assert response.status_code == 405
    assert response.json()["error"] == "METHOD_NOT_ALLOWED"
    assert response.json()["allowed_methods"] == ["POST"]
    assert response.headers["allow"] == "POST"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_service_errors_include_correlation_header(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/v1/me")
    assert response.status_code == 401
    assert response.json()["correlation_id"]
    assert response.headers["x-correlation-id"] == response.json()["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_api_rejects_oversized_body_before_service_dispatch(monkeypatch, tmp_path):
    from omega.service import MAX_BODY

    client = configured_client(monkeypatch, tmp_path)
    response = client.post(
        "/v1/chat",
        content=b"x" * (MAX_BODY + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"] == "PAYLOAD_TOO_LARGE"
    assert response.json()["correlation_id"]
    assert response.headers["cache-control"] == "no-store"


def test_device_api_rejects_oversized_body_before_authentication(monkeypatch, tmp_path):
    from omega.service import MAX_BODY

    client = configured_client(monkeypatch, tmp_path)
    response = client.post(
        "/v1/device/command",
        content=b"x" * (MAX_BODY + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"] == "PAYLOAD_TOO_LARGE"


def test_device_route_wrong_method_uses_shared_405_contract(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/v1/device/enroll")
    assert response.status_code == 405
    assert response.json()["error"] == "METHOD_NOT_ALLOWED"
    assert response.json()["allowed_methods"] == ["POST"]
    assert response.headers["allow"] == "POST"
    assert response.headers["x-correlation-id"] == response.json()["correlation_id"]


def test_health_route_wrong_method_uses_shared_405_contract():
    response = TestClient(main.app).post("/health/live")
    assert response.status_code == 405
    assert response.json()["error"] == "METHOD_NOT_ALLOWED"
    assert response.headers["allow"] == "GET"


def test_api_rejects_transfer_encoding_with_stable_error(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    response = client.post(
        "/v1/chat",
        content=b"{}",
        headers={"Transfer-Encoding": "chunked", "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_TRANSFER_ENCODING"
    assert response.headers["x-correlation-id"] == response.json()["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
