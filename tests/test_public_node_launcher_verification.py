import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.federation import _sign
from tools.iao_public_node_launcher import (
    _verify_handshake_evidence,
    _persistable_handshake_evidence,
)


class PublicLauncherHandshakeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.node_id = hashlib.sha256(public).hexdigest()[:16]
        self.identity = {
            "protocol": "iao-federation",
            "version": 1,
            "node_id": self.node_id,
            "public_key": public.hex(),
        }
        self.requester = "0123456789abcdef"
        self.nonce = "ab" * 32
        self.request_ts = 1800000000.0
        self.response = _sign(self.key, {
            "v": 1,
            "protocol": "iao-federation",
            "from": self.node_id,
            "to": self.requester,
            "nonce": self.nonce,
            "request_ts": self.request_ts,
            "ts": self.request_ts,
        })

    def verify(self, response=None, nonce=None, identity=None):
        return _verify_handshake_evidence(
            self.identity if identity is None else identity,
            self.response if response is None else response,
            node_id=self.node_id,
            requester=self.requester,
            nonce=self.nonce if nonce is None else nonce,
            request_ts=self.request_ts,
            now=self.request_ts,
        )

    def test_valid_signed_handshake_passes_without_authorizing_peer(self):
        evidence = self.verify()
        self.assertTrue(evidence["cryptographic_verification"]["ok"])
        self.assertFalse(evidence["cryptographic_verification"]["authorization_granted"])
        self.assertFalse(evidence["cryptographic_verification"]["enrollment_performed"])
        self.assertTrue(evidence["transport"]["https_verified"])
        self.assertFalse(evidence["transport"]["redirected"])

    def test_tampered_signature_is_rejected(self):
        altered = dict(self.response)
        altered["signature"] = "00" * 64
        with self.assertRaisesRegex(RuntimeError, "HANDSHAKE_CRYPTOGRAPHIC_VERIFICATION_FAILED"):
            self.verify(response=altered)

    def test_wrong_nonce_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "HANDSHAKE_CRYPTOGRAPHIC_VERIFICATION_FAILED"):
            self.verify(nonce="cd" * 32)

    def test_wrong_identity_is_rejected(self):
        altered = dict(self.identity)
        altered["node_id"] = "0000000000000000"
        with self.assertRaisesRegex(RuntimeError, "EXPECTED_IDENTITY_MISMATCH|HANDSHAKE_CRYPTOGRAPHIC_VERIFICATION_FAILED"):
            self.verify(identity=altered)


    def test_persisted_evidence_is_auditable_and_contains_no_challenge(self):
        evidence = self.verify()
        saved = _persistable_handshake_evidence(evidence)

        self.assertEqual(saved["remote_node_id"], self.node_id)
        self.assertTrue(saved["signature_verified"])
        self.assertTrue(saved["transport"]["https_verified"])
        self.assertFalse(saved["transport"]["redirected"])
        self.assertFalse(saved["authorization_granted"])
        self.assertFalse(saved["enrollment_performed"])
        self.assertEqual(len(saved["evidence_sha256"]), 64)
        self.assertNotIn("nonce", saved)
        self.assertNotIn("response", saved)
        self.assertNotIn("requester_id", saved)

    def test_tampered_signed_response_is_rejected_before_persistence(self):
        first = _persistable_handshake_evidence(self.verify())
        changed = dict(self.response)
        changed["signature"] = "11" * 64

        # Una respuesta manipulada debe fallar en la verificación,
        # antes de que pueda convertirse en evidencia persistible.
        with self.assertRaisesRegex(
            RuntimeError, "HANDSHAKE_CRYPTOGRAPHIC_VERIFICATION_FAILED"
        ):
            self.verify(response=changed)

        self.assertEqual(len(first["evidence_sha256"]), 64)

    def test_persistence_rejects_authorized_or_enrolled_evidence(self):
        evidence = self.verify()
        evidence["cryptographic_verification"] = dict(
            evidence["cryptographic_verification"]
        )
        evidence["cryptographic_verification"]["authorization_granted"] = True
        with self.assertRaisesRegex(RuntimeError, "AUTHORIZATION_STATE_UNSAFE"):
            _persistable_handshake_evidence(evidence)



if __name__ == "__main__":
    unittest.main()
