"""The public federation status must never claim unverified peers are active."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from omega.server import build_service

KEY = "unit-test-key-0123456789"
CORPUS = Path(__file__).resolve().parents[1] / "docs" / "corpus"


class FederationStatusTruthTests(unittest.TestCase):
    def test_status_is_unknown_until_verified_runtime_registry_is_connected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"AUDIT_HMAC_KEY": "unit-test-audit-key-" + "a" * 48},
        ):
            service = build_service(Path(tmp), KEY, CORPUS)
            try:
                status, payload = service.handle(
                    "GET", "/v1/federation/status", {}, b""
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload["status"], "unknown")
                self.assertEqual(payload["mode"], "discovery_only")
                self.assertIsNone(payload["orchestrator"])
                self.assertEqual(payload["network_nodes"], [])
                self.assertIsNone(payload["peer_count"])
                self.assertIsNone(payload["trusted_peer_count"])
                self.assertEqual(
                    payload["identity_verification"], "not_reported"
                )
                self.assertEqual(payload["remote_enrollment"], "disabled")
                self.assertEqual(
                    payload["reason"], "RUNTIME_FEDERATION_STATUS_NOT_WIRED"
                )
            finally:
                service.store.close()


if __name__ == "__main__":
    unittest.main()
