import unittest

try:
    from fastapi.testclient import TestClient

    from apps.api.main import app
    HAVE = True
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "fastapi/httpx not installed (offline sandbox)")
class HealthTests(unittest.TestCase):
    def test_liveness_is_available(self) -> None:
        r = TestClient(app).get("/health/live")
        self.assertEqual((r.status_code, r.json()["status"]), (200, "live"))

    def test_chat_does_not_claim_model_is_ready(self) -> None:
        r = TestClient(app).post("/v1/chat", json={"conversation_id": "t", "message": "hello"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["detail"]["code"], "MODEL_ADAPTER_NOT_CONFIGURED")
