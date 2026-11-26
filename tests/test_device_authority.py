import tempfile
import unittest
import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.store import Store
from omega.device_authority import (
    issue_enrollment, enroll, create_challenge,
    verify_status_command, revoke_device, DeviceError,
)
import hashlib
import json


class DeviceAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "omega.db", audit_key=b"x" * 32)
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.public_pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def enroll_device(self):
        code = issue_enrollment(self.store)
        return enroll(self.store, code, self.public_pem)["device_id"]

    def signed_command(self, device_id, challenge):
        timestamp = int(time.time())
        action = "status"
        canonical = json.dumps(
            {"action": action}, sort_keys=True, separators=(",", ":")
        ).encode()
        signed = (
            "POST\n/v1/device/command\n"
            + str(timestamp) + "\n"
            + challenge["nonce"] + "\n"
            + hashlib.sha256(canonical).hexdigest()
        ).encode()
        signature = self.private.sign(signed, ec.ECDSA(hashes.SHA256()))
        return {
            "device_id": device_id,
            "nonce": challenge["nonce"],
            "timestamp": timestamp,
            "action": action,
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }

    def test_enrollment_code_is_one_use(self):
        code = issue_enrollment(self.store)
        enroll(self.store, code, self.public_pem)
        with self.assertRaises(DeviceError):
            enroll(self.store, code, self.public_pem)

    def test_signed_status_and_replay_denied(self):
        device_id = self.enroll_device()
        challenge = create_challenge(self.store, device_id)
        command = self.signed_command(device_id, challenge)
        self.assertTrue(verify_status_command(self.store, command)["authorized"])
        with self.assertRaises(DeviceError):
            verify_status_command(self.store, command)

    def test_revoked_device_cannot_get_challenge(self):
        device_id = self.enroll_device()
        self.assertTrue(revoke_device(self.store, device_id))
        with self.assertRaises(DeviceError):
            create_challenge(self.store, device_id)

    def test_wrong_action_denied(self):
        device_id = self.enroll_device()
        challenge = create_challenge(self.store, device_id)
        command = self.signed_command(device_id, challenge)
        command["action"] = "execute"
        with self.assertRaises(DeviceError):
            verify_status_command(self.store, command)


    def test_device_challenge_limit(self):
        device_id = self.enroll_device()
        for _ in range(5):
            create_challenge(self.store, device_id)
        with self.assertRaises(DeviceError) as caught:
            create_challenge(self.store, device_id)
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.code, "TOO_MANY_ACTIVE_CHALLENGES")

    def test_expired_challenges_are_pruned(self):
        device_id = self.enroll_device()
        create_challenge(self.store, device_id)
        with self.store.lock:
            self.store.db.execute(
                "UPDATE device_nonce SET expires_at=? WHERE device_id=?",
                (time.time() - 601, device_id),
            )
        create_challenge(self.store, device_id)
        with self.store.lock:
            count = self.store.db.execute(
                "SELECT COUNT(*) FROM device_nonce WHERE device_id=?",
                (device_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)



if __name__ == "__main__":
    unittest.main()
