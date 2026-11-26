"""End-to-end API adapter tests against a real temporary SQLite store."""
import base64
import hashlib
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
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

def test_device_enrollment_challenge_signature_and_replay_protection(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    code = "one-time-enrollment-code-" + "z" * 32

    enrolled = client.post(
        "/v1/device/enroll",
        json={"code": code, "public_key_pem": public_pem},
    )
    assert enrolled.status_code == 201
    device_id = enrolled.json()["device_id"]
    assert enrolled.json()["algorithm"] == "ECDSA-P256-SHA256"

    second_enrollment = client.post(
        "/v1/device/enroll",
        json={"code": code, "public_key_pem": public_pem},
    )
    assert second_enrollment.status_code == 409

    challenge = client.post(
        "/v1/device/challenge",
        json={"device_id": device_id},
    )
    assert challenge.status_code == 200
    nonce = challenge.json()["nonce"]
    timestamp = int(time.time())
    action = "status"
    canonical = json.dumps({"action": action}, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    signed_text = "\\n".join(
        ["POST", "/v1/device/command", str(timestamp), nonce, digest]
    ).encode()
    signature = private_key.sign(signed_text, ec.ECDSA(hashes.SHA256()))
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    payload = {
        "device_id": device_id,
        "nonce": nonce,
        "timestamp": timestamp,
        "action": action,
        "signature": encoded_signature,
    }

    verified = client.post("/v1/device/command", json=payload)
    assert verified.status_code == 200
    assert verified.json()["authority"] == "READ_ONLY_DEVICE_VERIFIED"

    replay = client.post("/v1/device/command", json=payload)
    assert replay.status_code == 401


def test_device_authority_rejects_unsigned_privileged_action(monkeypatch, tmp_path) -> None:
    client = configured_client(monkeypatch, tmp_path)
    response = client.post(
        "/v1/device/command",
        json={
            "device_id": "0" * 64,
            "nonce": "1" * 64,
            "timestamp": int(time.time()),
            "action": "execute",
            "signature": "A" * 96,
        },
    )
    assert response.status_code == 400
