import base64
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_task_authority import (
    DeviceTaskError,
    signature_message,
    validate_task_request,
    verify_task_signature,
)


class DeviceTaskCryptoTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.public_pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.now = 1800000000
        self.request = {
            "device_id": "test-primary-device",
            "action": "enqueue_task",
            "kind": "self_check",
            "payload": {"origin": "unit-test"},
            "idempotency_key": "test-idempotency-key-0001",
            "timestamp": self.now,
            "nonce": "abcdefghijklmnopQRSTUV",
            "signature": "placeholder",
        }

        # CORRECCIÓN: no validar el marcador provisional.
        # Se firma primero y la validación se realiza después.
        unsigned = dict(self.request)
        unsigned.pop("signature")

        signature = self.private.sign(
            signature_message({
                **unsigned,
                "signature": "AA",
            }),
            ec.ECDSA(hashes.SHA256()),
        )
        self.request["signature"] = (
            base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        )

    def test_valid_p256_signature(self):
        result = verify_task_signature(
            self.public_pem, self.request, now=self.now
        )
        self.assertTrue(result["signature_valid"])

    def test_tampered_payload_rejected(self):
        changed = dict(self.request, payload={"origin": "tampered"})
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)

    def test_tampered_device_rejected(self):
        changed = dict(self.request, device_id="another-device")
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)

    def test_tampered_idempotency_key_rejected(self):
        changed = dict(
            self.request,
            idempotency_key="another-idempotency-key-0001",
        )
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)

    def test_expired_timestamp_rejected(self):
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(
                self.public_pem, self.request, now=self.now + 61
            )

    def test_unsupported_task_kind_rejected(self):
        changed = dict(self.request, kind="arbitrary_shell")
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)

    def test_wrong_curve_rejected(self):
        key = ec.generate_private_key(ec.SECP384R1()).public_key()
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(pem, self.request, now=self.now)

    def test_malformed_signature_rejected(self):
        changed = dict(self.request, signature="not+a+valid+base64url")
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)

    def test_unknown_request_field_rejected(self):
        changed = dict(self.request, extra="unexpected")
        with self.assertRaises(DeviceTaskError):
            verify_task_signature(self.public_pem, changed, now=self.now)


if __name__ == "__main__":
    unittest.main()
