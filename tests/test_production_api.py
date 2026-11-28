"""End-to-end API adapter tests against a real temporary SQLite store."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pathlib import Path

from apps.api import main


def configured_client(monkeypatch, tmp_path):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "test-token-key-" + "x" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "test-audit-key-" + "y" * 48)
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("IAO_CORPUS_DIR", str(tmp_path / "corpus"))
    monkeypatch.setenv("MODEL_ADAPTER", "disabled")
    monkeypatch.setenv("IAO_AUTONOMY_WORKER_ENABLED", "false")
    monkeypatch.delenv("IAO_LLM_ROUTER", raising=False)
    monkeypatch.setenv("IAO_DEVICE_ENROLLMENT_CODE", "one-time-enrollment-code-" + "z" * 32)
    monkeypatch.setenv("IAO_DEVICE_ENROLLMENT_ENABLED", "1")
    main._service = None
    main._device_authority = None
    main._federation_node = None
    if main._autonomous_core is not None:
        main._autonomous_core.stop_worker(timeout=1)
    main._autonomous_core = None
    main._autonomous_core_status.update({"enabled": False, "running": False, "recovered_tasks": 0})
    main._federation_worker_status.update({
        "autojoin": False, "discovery": False, "external_network": False,
    })
    # API contract tests must not launch real network workers.
    monkeypatch.setattr(main, "_ensure_federation", lambda service: None)
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
    assert body["production_gates"]["identity_provider"] == "hmac_token_auth_oidc_unconfigured"
    assert body["production_gates"]["independent_federation"] == "not_started_or_unavailable"
    assert body["production_gates"]["model_provider"] == "not_configured"
    assert body["production_gates"]["network_discovery"]["status"] == "unknown"
    assert body["production_gates"]["network_discovery"]["external_connectivity_confirmed"] is False
    assert body["production_gates"]["network_discovery"]["cryptographic_trust_confirmed"] is False


def test_runtime_refuses_missing_persistent_keys(monkeypatch) -> None:
    monkeypatch.delenv("OMEGA_DEV_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    main._service = None
    with TestClient(main.app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["runtime_startup"] == {
        "status": "blocked", "reason": "PERSISTENT_KEYS_NOT_CONFIGURED",
    }


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

    
def test_autonomous_core_worker_starts_and_recovers_persisted_tasks(monkeypatch, tmp_path):
    from omega.autonomous_core import AutonomousCore
    import json

    monkeypatch.setenv("IAO_AUTONOMY_WORKER_ENABLED", "true")
    monkeypatch.setenv("IAO_AUTONOMY_INTERVAL_SECONDS", "10")
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path / "state"))
    main._autonomous_core = None
    core = AutonomousCore(tmp_path / "state" / "autonomous-core")
    task = core.submit("self_check")
    with core.lock:
        data = json.loads(core.tasks_path.read_text("utf-8"))
        data["tasks"][0]["status"] = "RUNNING"
        core._save(data)

    started = main._ensure_autonomous_core()
    try:
        assert started is main._autonomous_core
        assert started.status()["worker_running"] is True
        assert main._autonomous_core_status["running"] is True
        assert main._autonomous_core_status["recovered_tasks"] == 1
        recovered = json.loads(started.tasks_path.read_text("utf-8"))
        assert recovered["tasks"][0]["status"] in {"QUEUED", "RUNNING", "COMPLETED", "BLOCKED"}
        assert recovered["tasks"][0]["id"] == task["id"]
    finally:
        started.stop_worker(timeout=2)
        main._autonomous_core = None
        main._autonomous_core_status.update({
            "enabled": False, "running": False, "recovered_tasks": 0,
        })


def test_autonomous_core_can_be_disabled_explicitly(monkeypatch, tmp_path):
    monkeypatch.setenv("IAO_AUTONOMY_WORKER_ENABLED", "false")
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path / "state"))
    main._autonomous_core = None
    assert main._ensure_autonomous_core() is None
    assert main._autonomous_core_status["enabled"] is False
    assert main._autonomous_core_status["running"] is False


def test_runtime_startup_failure_is_visible_without_breaking_liveness(monkeypatch):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "x" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "y" * 48)
    monkeypatch.setenv("IAO_AUTONOMY_WORKER_ENABLED", "false")
    main._runtime_startup_status = {"status": "not_started", "reason": None}

    def fail_startup():
        raise RuntimeError("sensitive details must not escape")

    monkeypatch.setattr(main, "_get_service", fail_startup)
    with TestClient(main.app) as client:
        assert client.get("/health/live").status_code == 200

    assert main._runtime_startup_status == {
        "status": "degraded", "reason": "RuntimeError",
    }


def test_runtime_startup_reports_missing_keys_as_blocked(monkeypatch):
    monkeypatch.delenv("OMEGA_DEV_TOKEN_KEY", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    main._runtime_startup_status = {"status": "not_started", "reason": None}
    with TestClient(main.app) as client:
        assert client.get("/health/live").status_code == 200
    assert main._runtime_startup_status == {
        "status": "blocked", "reason": "PERSISTENT_KEYS_NOT_CONFIGURED",
    }




def test_production_runtime_rejects_development_token_key(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "d" * 64)
    monkeypatch.delenv("OMEGA_TOKEN_SIGNING_KEY", raising=False)
    try:
        main._runtime_token_key()
    except RuntimeError as exc:
        assert str(exc) == "PRODUCTION_TOKEN_SIGNING_KEY_REQUIRED"
    else:
        raise AssertionError("production must not accept the development token key")


def test_production_runtime_uses_dedicated_token_signing_key(monkeypatch):
    dedicated = "production-signing-key-" + "p" * 48
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "d" * 64)
    monkeypatch.setenv("OMEGA_TOKEN_SIGNING_KEY", dedicated)
    assert main._runtime_token_key() == dedicated


def test_nonproduction_runtime_keeps_development_key_compatibility(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.delenv("OMEGA_TOKEN_SIGNING_KEY", raising=False)
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "dev-key-" + "x" * 40)
    assert main._runtime_token_key() == "dev-key-" + "x" * 40



def test_production_readiness_blocks_development_secret_even_with_audit_key(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "development-secret-" + "d" * 48)
    monkeypatch.delenv("OMEGA_TOKEN_SIGNING_KEY", raising=False)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "audit-secret-" + "a" * 48)
    main._service = None
    with TestClient(main.app) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["runtime_startup"] == {
        "status": "blocked", "reason": "PRODUCTION_TOKEN_SIGNING_KEY_REQUIRED",
    }


def test_self_hosted_compose_forces_production_auth_mode():
    compose = Path(__file__).resolve().parents[1] / "deploy" / "compose.yaml"
    assert "APP_ENV: production" in compose.read_text(encoding="utf-8")
