"""End-to-end API adapter tests against a real temporary SQLite store."""
from fastapi.testclient import TestClient

from apps.api import main


def configured_client(monkeypatch, tmp_path):
    monkeypatch.setenv("OMEGA_DEV_TOKEN_KEY", "test-token-key-" + "x" * 40)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "test-audit-key-" + "y" * 48)
    monkeypatch.setenv("IAO_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("IAO_CORPUS_DIR", str(tmp_path / "corpus"))
    monkeypatch.setenv("MODEL_ADAPTER", "disabled")
    monkeypatch.delenv("IAO_LLM_ROUTER", raising=False)
    main._service = None
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
    assert body["production_gates"]["device_bound_command_authority"] == "not_integrated"
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
