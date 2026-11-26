"""Contract tests for the production-facing API fail-closed behavior."""
from fastapi.testclient import TestClient

from apps.api import main


client = TestClient(main.app)


def test_liveness_is_independent_of_external_services() -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}


def test_readiness_never_claims_unverified_production() -> None:
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["federation"] == "not_verified"


def test_federation_manifest_does_not_claim_operational_status() -> None:
    body = client.get("/v1/federation/manifest").json()
    assert body["status"] == "development"
    assert body["federation_status"] == "not_verified"
    assert body["registration_enabled"] is False
    assert body["capabilities"] == []


def test_federation_registration_fails_closed() -> None:
    response = client.post("/v1/federation/register", json={})
    assert response.status_code == 503


def test_chat_is_unavailable_without_configured_authority(monkeypatch) -> None:
    monkeypatch.delenv("IAO_API_BEARER_TOKEN", raising=False)
    response = client.post(
        "/v1/chat",
        json={"conversation_id": "contract-test", "message": "hello"},
    )
    assert response.status_code == 503


def test_chat_rejects_invalid_bearer_token(monkeypatch) -> None:
    monkeypatch.setenv("IAO_API_BEARER_TOKEN", "test-secret-token")
    response = client.post(
        "/v1/chat",
        headers={"Authorization": "Bearer wrong-token"},
        json={"conversation_id": "contract-test", "message": "hello"},
    )
    assert response.status_code == 401


def test_chat_uses_configured_adapter_only_after_authentication(monkeypatch) -> None:
    class FakeAdapter:
        def chat(self, messages):
            assert messages == [{"role": "user", "content": "hello"}]
            return "test reply"

    monkeypatch.setenv("IAO_API_BEARER_TOKEN", "test-secret-token")
    monkeypatch.setattr(main, "adapter_from_env", lambda env: FakeAdapter())
    response = client.post(
        "/v1/chat",
        headers={"Authorization": "Bearer test-secret-token"},
        json={"conversation_id": "contract-test", "message": "hello"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "conversation_id": "contract-test",
        "reply": "test reply",
        "authority": "NON_AUTHORITATIVE_MODEL_OUTPUT",
    }
