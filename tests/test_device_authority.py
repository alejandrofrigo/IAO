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
    code = "one-time-enrollment-secret-that-is-long-enough"
    authority = DeviceAuthority(
        tmp_path / "device-authority.sqlite3", enrollment_code=code
    )
    enrolled = authority.enroll(code, public_pem, owner_subject="operator")
    return authority, private_key, enrolled["device_id"]


def _signed_status(private_key, device_id, nonce, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    canonical = json.dumps(
        {"action": "status"}, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    signed_text = "\n".join(
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
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(private_key, device_id, challenge["nonce"])

    result = authority.verify_status(proof, owner_subject="operator")

    assert result == {
        "action": "status",
        "authority": "READ_ONLY_DEVICE_VERIFIED",
    }
    with pytest.raises(DeviceAuthorityError, match="CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_status(proof, owner_subject="operator")


def test_device_status_proof_rejects_modified_signature(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    first = "A" if proof["signature"][0] != "A" else "B"
    proof["signature"] = first + proof["signature"][1:]

    with pytest.raises(DeviceAuthorityError, match="INVALID_DEVICE_SIGNATURE"):
        authority.verify_status(proof, owner_subject="operator")


def test_device_authority_rejects_non_status_action(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    proof["action"] = "task.submit"

    with pytest.raises(DeviceAuthorityError, match="INVALID_REQUEST"):
        authority.verify_status(proof, owner_subject="operator")


def test_device_authority_rejects_expired_timestamp(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(
        private_key, device_id, challenge["nonce"], timestamp=int(time.time()) - 120
    )

    with pytest.raises(DeviceAuthorityError, match="DEVICE_TIMESTAMP_EXPIRED"):
        authority.verify_status(proof, owner_subject="operator")



def _signed_request(private_key, device_id, nonce, method, path, request_digest):
    timestamp = int(time.time())
    signed_text = "\n".join(
        [method, path, str(timestamp), nonce, request_digest]
    ).encode("utf-8")
    signature = private_key.sign(signed_text, ec.ECDSA(hashes.SHA256()))
    return {
        "device_id": device_id,
        "nonce": nonce,
        "timestamp": timestamp,
        "request_digest": request_digest,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def test_signed_request_is_bound_to_method_path_and_exact_digest(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    digest = hashlib.sha256(b'{"capability":"knowledge.search","input":{"query":"x"}}').hexdigest()
    proof = _signed_request(
        private_key, device_id, challenge["nonce"], "POST", "/v1/tasks", digest
    )

    assert authority.verify_request(
        proof, method="POST", path="/v1/tasks", request_digest=digest, owner_subject="operator"
    ) == {"authority": "DEVICE_REQUEST_VERIFIED"}

    with pytest.raises(DeviceAuthorityError, match="INVALID_REQUEST"):
        authority.verify_request(
            proof, method="POST", path="/v1/tasks", request_digest="0" * 64, owner_subject="operator"
        )


@pytest.mark.parametrize(
    ("method", "path", "digest"),
    [
        ("PUT", "/v1/tasks", hashlib.sha256(b"body").hexdigest()),
        ("POST", "/v1/other", hashlib.sha256(b"body").hexdigest()),
        ("POST", "/v1/tasks", hashlib.sha256(b"changed").hexdigest()),
    ],
)
def test_signed_request_rejects_method_path_or_body_substitution(
    tmp_path, method, path, digest
):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    original_digest = hashlib.sha256(b"body").hexdigest()
    proof = _signed_request(
        private_key, device_id, challenge["nonce"], "POST", "/v1/tasks",
        original_digest,
    )

    substituted = {**proof, "request_digest": digest}
    with pytest.raises(DeviceAuthorityError, match="INVALID_DEVICE_SIGNATURE"):
        authority.verify_request(
            substituted, method=method, path=path, request_digest=digest, owner_subject="operator"
        )


def test_signed_request_rejects_digest_field_mismatch_and_replay(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    digest = hashlib.sha256(b"body").hexdigest()
    proof = _signed_request(
        private_key, device_id, challenge["nonce"], "POST", "/v1/tasks", digest
    )
    altered = {**proof, "request_digest": "0" * 64}
    with pytest.raises(DeviceAuthorityError, match="INVALID_REQUEST"):
        authority.verify_request(
            altered, method="POST", path="/v1/tasks", request_digest=digest, owner_subject="operator"
        )
    authority.verify_request(
        proof, method="POST", path="/v1/tasks", request_digest=digest, owner_subject="operator"
    )
    with pytest.raises(DeviceAuthorityError, match="CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_request(
            proof, method="POST", path="/v1/tasks", request_digest=digest, owner_subject="operator"
        )


def test_device_proofs_are_bound_to_the_enrolling_operator(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)

    with pytest.raises(DeviceAuthorityError, match="DEVICE_OWNER_MISMATCH"):
        authority.challenge(device_id, owner_subject="different-operator")

    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    with pytest.raises(DeviceAuthorityError, match="DEVICE_OWNER_MISMATCH"):
        authority.verify_status(proof, owner_subject="different-operator")

    digest = hashlib.sha256(b"{}").hexdigest()
    request_challenge = authority.challenge(device_id, owner_subject="operator")
    request_proof = _signed_request(
        private_key, device_id, request_challenge["nonce"],
        "POST", "/v1/tasks", digest,
    )
    with pytest.raises(DeviceAuthorityError, match="DEVICE_OWNER_MISMATCH"):
        authority.verify_request(
            request_proof, method="POST", path="/v1/tasks",
            request_digest=digest, owner_subject="different-operator",
        )


def test_operator_owner_binding_is_atomic_and_rejects_old_owner(tmp_path):
    authority, _, _ = _enrolled_authority(tmp_path)
    with authority._database() as db:
        pem = db.execute(
            "SELECT public_key_pem FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()["public_key_pem"]

    with pytest.raises(RuntimeError):
        with authority.bind_active_key_to_operator(
            pem, owner_subject="operator:" + "a" * 32
        ):
            raise RuntimeError("force rollback")

    assert authority.verify_registered_public_key(
        pem, owner_subject="operator"
    )
    with authority.bind_active_key_to_operator(
        pem, owner_subject="operator:" + "a" * 32
    ):
        assert authority.verify_active_public_key(pem)

    assert authority.verify_registered_public_key(
        pem, owner_subject="operator:" + "a" * 32
    )
    with pytest.raises(DeviceAuthorityError, match="DEVICE_KEY_NOT_ENROLLED_FOR_OWNER"):
        authority.verify_registered_public_key(pem, owner_subject="operator")


def test_recovery_replaces_only_same_operator_device_and_invalidates_pending_proofs(tmp_path):
    owner = "operator:" + "a" * 32
    code = "recovery-enrollment-secret-" + "e" * 40
    authority = DeviceAuthority(
        tmp_path / "recovery-device.sqlite3", enrollment_code=code
    )
    old_private = ec.generate_private_key(ec.SECP256R1())
    old_public = old_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    enrolled = authority.enroll(code, old_public, owner_subject="pre-login-owner")
    challenge = authority.challenge(enrolled["device_id"], owner_subject=owner)

    new_public_key = ec.generate_private_key(ec.SECP256R1())
    new_public = new_public_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    result = authority.replace_active_device_for_recovery(
        new_public, owner_subject=owner,
        expected_old_public_key_pem=old_public,
    )
    assert result["device_id"] != enrolled["device_id"]
    assert authority.verify_registered_public_key(new_public, owner_subject=owner)
    pending_retry = authority.challenge(result["device_id"], owner_subject=owner)
    retried = authority.replace_active_device_for_recovery(
        new_public, owner_subject=owner,
        expected_old_public_key_pem=old_public,
    )
    assert retried["device_id"] == result["device_id"]
    with authority._database() as db:
        assert db.execute(
            "SELECT 1 FROM device_challenges WHERE nonce=?",
            (pending_retry["nonce"],),
        ).fetchone() is None
    with pytest.raises(DeviceAuthorityError, match="DEVICE_KEY_NOT_ACTIVE"):
        authority.verify_active_public_key(old_public)
    with authority._database() as db:
        assert db.execute(
            "SELECT 1 FROM device_challenges WHERE nonce=?",
            (challenge["nonce"],),
        ).fetchone() is None


def test_recovery_cannot_replace_an_unrelated_active_device(tmp_path):
    authority, _, device_id = _enrolled_authority(tmp_path)
    with authority._database() as db:
        original_public = db.execute(
            "SELECT public_key_pem FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()["public_key_pem"]
    new_private = ec.generate_private_key(ec.SECP256R1())
    new_public = new_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    with pytest.raises(DeviceAuthorityError, match="UNRELATED_ACTIVE_DEVICE_BLOCKS_RECOVERY"):
        authority.replace_active_device_for_recovery(
            new_public, owner_subject="operator:" + "b" * 32,
        )
    assert authority.verify_active_public_key(original_public)


def test_recovery_never_reactivates_a_previously_revoked_device_key(tmp_path):
    owner = "operator:" + "c" * 32
    code = "revoked-device-recovery-code-" + "r" * 40
    authority = DeviceAuthority(
        tmp_path / "revoked-recovery-device.sqlite3", enrollment_code=code
    )
    old_private = ec.generate_private_key(ec.SECP256R1())
    old_public = old_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    authority.enroll(code, old_public, owner_subject=owner)
    with authority.revoke_active_key(old_public):
        pass
    with pytest.raises(DeviceAuthorityError, match="DEVICE_KEY_PREVIOUSLY_ENROLLED"):
        authority.replace_active_device_for_recovery(
            old_public, owner_subject=owner,
        )
