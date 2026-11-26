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
    main._service = None
    main._device_authority = None
    return TestClient(main.app)


def test_liveness_does_not_require_database_or_model() -> None:
    response = TestClient(main.app).get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}


def test_readiness_never_claims_full_production_before_security_gates(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["production_gates"]["device_identity_verification"] == "integrated_read_only"
    assert body["production_gates"]["privileged_device_commands"] == "disabled"
    assert body["production_gates"]["identity_provider"] == "dev_hmac_not_oidc"
    assert body["production_gates"]["independent_federation"] == "not_verified"
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

