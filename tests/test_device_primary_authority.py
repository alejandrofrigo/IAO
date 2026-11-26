import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from omega.store import Store
from omega.device_authority import (
    issue_enrollment, enroll, create_challenge, DeviceError
)

class PrimaryDeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "omega.db", audit_key=b"x" * 32)
        key = ec.generate_private_key(ec.SECP256R1())
        self.public = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_first_enrollment_becomes_primary(self):
        result = enroll(self.store, issue_enrollment(self.store), self.public)
        self.assertEqual(result["authority"], "PRIMARY_DEVICE")
        row = self.store.db.execute(
            "SELECT primary_device_id FROM device_authority_state WHERE singleton=1"
        ).fetchone()
        self.assertEqual(row["primary_device_id"], result["device_id"])

    def test_second_device_cannot_replace_primary(self):
        first_code = issue_enrollment(self.store)
        second_code = issue_enrollment(self.store)
        first = enroll(self.store, first_code, self.public)
        with self.assertRaises(DeviceError) as caught:
            enroll(self.store, second_code, self.public)
        self.assertEqual(caught.exception.code, "PRIMARY_DEVICE_ALREADY_REGISTERED")
        self.assertEqual(
            self.store.db.execute("SELECT COUNT(*) FROM trusted_device").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.store.db.execute(
                "SELECT primary_device_id FROM device_authority_state WHERE singleton=1"
            ).fetchone()[0],
            first["device_id"],
        )

    def test_no_new_enrollment_after_primary_exists(self):
        enroll(self.store, issue_enrollment(self.store), self.public)
        with self.assertRaises(DeviceError) as caught:
            issue_enrollment(self.store)
        self.assertEqual(caught.exception.code, "PRIMARY_DEVICE_ALREADY_REGISTERED")

    def test_primary_device_can_get_challenge(self):
        result = enroll(self.store, issue_enrollment(self.store), self.public)
        challenge = create_challenge(self.store, result["device_id"])
        self.assertEqual(challenge["device_id"], result["device_id"])

if __name__ == "__main__":
    unittest.main()
