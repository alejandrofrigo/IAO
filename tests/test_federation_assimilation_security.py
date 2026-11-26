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

    def test_autonomous_authorization_rejects_forged_evidence(self):
        """Un hash declarado no sustituye la prueba criptográfica original."""
        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            with registry._lock:
                data = registry._load()
                cand = next(
                    x for x in data["candidates"]
                    if x["candidate_id"] == item["candidate_id"]
                )
                cand["status"] = "AUTHORIZATION_PENDING"
                cand["node_id"] = "0123456789abcdef"
                cand["verification_evidence"] = {
                    "evidence_sha256": "0" * 64,
                    "transport": {"https_verified": True, "redirected": False},
                }
                cand["authorization_policy"] = {
                    "id": "IAO_PINNED_IDENTITY_VERIFICATION_V1",
                    "decision": "PENDING_OPERATOR_APPROVAL",
                    "evidence_sha256": "0" * 64,
                }
                registry._save(data)
            with self.assertRaisesRegex(
                AssimilationError, "TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED"
            ):
                registry.authorize(item["candidate_id"])
            self.assertFalse(registry.get(item["candidate_id"])["authorized"])

    def test_operator_approval_cannot_bypass_missing_transport_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            with registry._lock:
                data = registry._load()
                candidate = data["candidates"][0]
                candidate["status"] = "AUTHORIZATION_PENDING"
                candidate["node_id"] = "0123456789abcdef"
                registry._save(data)
            with self.assertRaisesRegex(
                AssimilationError, "TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED"
            ):
                registry.authorize(item["candidate_id"], operator_id="local-operator")
            self.assertFalse(registry.get(item["candidate_id"])["authorized"])

    def test_valid_signed_identity_does_not_bypass_untrusted_transport_gate(self):
        """La revalidación usa la firma Ed25519, nonce y nodo esperado."""
        import hashlib
        import time
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from omega.federation import _sign

        key = Ed25519PrivateKey.generate()
        public_raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        node_id = hashlib.sha256(public_raw).hexdigest()[:16]
        requester_id = "a" * 16
        nonce = "b" * 64
        request_ts = time.time()
        identity = {
            "protocol": "iao-federation",
            "version": 1,
            "node_id": node_id,
            "public_key": public_raw.hex(),
        }
        response = _sign(key, {
            "v": 1,
            "protocol": "iao-federation",
            "from": node_id,
            "to": requester_id,
            "nonce": nonce,
            "request_ts": float(request_ts),
            "ts": float(request_ts),
        })
        evidence = {
            "identity": identity,
            "response": response,
            "requester_id": requester_id,
            "nonce": nonce,
            "request_ts": request_ts,
            "transport": {"https_verified": True, "redirected": False},
        }

        with tempfile.TemporaryDirectory() as td:
            registry = CandidateRegistry(Path(td) / "candidates.json")
            item = registry.discover(
                "https://federation.example.org/fed/v1/message",
                "unit-test",
            )["candidate"]
            # Una firma Ed25519 válida no convierte dos booleanos JSON en
            # evidencia TLS: el adaptador de transporte confiable aún no existe.
            with self.assertRaisesRegex(
                AssimilationError, "TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED"
            ):
                registry.record_verified_identity(
                    item["candidate_id"],
                    expected_node_id=node_id,
                    evidence=evidence,
                )
            self.assertEqual(
                registry.get(item["candidate_id"])["status"], "DISCOVERED"
            )
            self.assertFalse(registry.get(item["candidate_id"])["authorized"])



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
