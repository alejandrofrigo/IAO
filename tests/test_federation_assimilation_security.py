import tempfile
import unittest
from pathlib import Path

from omega.federation_assimilation import (
    AssimilationError,
    CandidateRegistry,
    validate_endpoint,
)


class FederationEndpointSafetyTests(unittest.TestCase):
    def test_accepts_public_https_endpoint(self):
        endpoint = "https://federation.example.org/fed/v1/message"
        self.assertEqual(validate_endpoint(endpoint), endpoint)

    def test_rejects_private_and_loopback_ip_literals(self):
        for host in ("127.0.0.1", "10.0.0.8", "192.168.1.2", "169.254.1.1"):
            with self.subTest(host=host):
                with self.assertRaises(AssimilationError):
                    validate_endpoint(
                        f"https://{host}/fed/v1/message"
                    )

    def test_rejects_local_hostnames(self):
        for host in ("localhost", "node.local", "service.internal"):
            with self.subTest(host=host):
                with self.assertRaises(AssimilationError):
                    validate_endpoint(
                        f"https://{host}/fed/v1/message"
                    )

    def test_rejects_non_https_and_wrong_path(self):
        with self.assertRaises(AssimilationError):
            validate_endpoint("http://federation.example.org/fed/v1/message")
        with self.assertRaises(AssimilationError):
            validate_endpoint("https://federation.example.org/other")

    def test_autonomous_authorization_requires_identity_and_evidence(self):
        """El enrolamiento autónomo exige identidad criptográfica verificada."""
        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            self.assertFalse(item["authorized"])
            # Sin identidad verificada, la autorización autónoma debe fallar.
            with self.assertRaisesRegex(
                AssimilationError, "AUTHORIZATION_NOT_PENDING"
            ):
                registry.authorize(item["candidate_id"])  # modo autónomo

    def test_autonomous_authorization_registers_audit_label(self):
        """La autorización autónoma se etiqueta como IAO_AUTONOMOUS_POLICY_V1."""
        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            # Forzar estado AUTHORIZATION_PENDING con evidencia sintética
            # solo para verificar la etiqueta de auditoría.
            with registry._lock:
                data = registry._load()
                cand = next(x for x in data["candidates"]
                            if x["candidate_id"] == item["candidate_id"])
                cand["status"] = "AUTHORIZATION_PENDING"
                cand["node_id"] = "0123456789abcdef"
                cand["verification_evidence"] = {
                    "evidence_sha256": "0" * 64,
                    "transport": {"https_verified": True},
                }
                registry._save(data)
            authorized = registry.authorize(item["candidate_id"])
            self.assertTrue(authorized["authorized"])
            self.assertEqual(authorized["authorized_by"], "IAO_AUTONOMOUS_POLICY_V1")



class LegacyAutoAuthorizationRemovalTests(unittest.TestCase):
    def test_auto_authorized_is_not_a_valid_state(self):
        from omega.federation_assimilation import (
            ACTIVE_STATES, ALL_STATES, TRANSITIONS,
        )
        self.assertNotIn("AUTO_AUTHORIZED", ACTIVE_STATES)
        self.assertNotIn("AUTO_AUTHORIZED", ALL_STATES)
        self.assertNotIn("AUTO_AUTHORIZED", TRANSITIONS)
        self.assertNotIn(
            "AUTO_AUTHORIZED",
            TRANSITIONS["IDENTITY_VERIFIED"],
        )

    def test_administrative_transition_cannot_create_auto_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            with self.assertRaisesRegex(
                AssimilationError, "UNKNOWN_STATE"
            ):
                registry.transition(
                    item["candidate_id"], "AUTO_AUTHORIZED"
                )


if __name__ == "__main__":
    unittest.main()
