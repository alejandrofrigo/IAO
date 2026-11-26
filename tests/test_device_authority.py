"""Cryptographic proof and replay tests for primary-device read-only authority."""
import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_authority import DeviceAuthority, DeviceAuthorityError


def _enrolled_authority(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    authority = DeviceAuthority(
        tmp_path / "device-authority.sqlite3",
        enrollment_code="one-time-enrollment-secret-that-is-long-enough",
    )
    enrolled = authority.enroll(
        "one-time-enrollment-secret-that-is-long-enough", public_pem
    )
    return authority, private_key, enrolled["device_id"]


def _signed_status(private_key, device_id, nonce, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    canonical = json.dumps(
        {"action": "status"}, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    signed_text = "\\n".join(
        ["POST", "/v1/device/command", str(timestamp), nonce, digest]
    ).encode("utf-8")
    signature = private_key.sign(signed_text, ec.ECDSA(hashes.SHA256()))
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return {
        "device_id": device_id,
        "nonce": nonce,
        "timestamp": timestamp,
        "action": "status",
        "signature": encoded,
    }


def test_signed_device_status_proof_is_read_only_and_consumes_challenge(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id)
    proof = _signed_status(private_key, device_id, challenge["nonce"])

    result = authority.verify_status(proof)

    assert result == {
        "action": "status",
        "authority": "READ_ONLY_DEVICE_VERIFIED",
        "device_id": device_id,
    }
    with pytest.raises(DeviceAuthorityError, match="CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_status(proof)


def test_device_status_proof_rejects_modified_signature(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id)
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    proof["signature"] = ("A" if proof["signature"][0] != "A" else "B") + proof["signature"][1:]

    with pytest.raises(DeviceAuthorityError, match="INVALID_DEVICE_SIGNATURE"):
        authority.verify_status(proof)


def test_device_authority_rejects_non_status_action(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id)
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    proof["action"] = "task.submit"

    with pytest.raises(DeviceAuthorityError, match="INVALID_REQUEST"):
        authority.verify_status(proof)


def test_device_authority_rejects_expired_timestamp(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id)
    proof = _signed_status(
        private_key, device_id, challenge["nonce"], timestamp=int(time.time()) - 120
    )

    with pytest.raises(DeviceAuthorityError, match="DEVICE_TIMESTAMP_EXPIRED"):
        authority.verify_status(proof)
