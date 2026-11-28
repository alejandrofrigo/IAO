"""Cryptographic proof and replay tests for primary-device read-only authority."""
import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.device_authority import DeviceAuthority, DeviceAuthorityError


def test_device_authority_refuses_corrupt_sqlite_before_initialization(tmp_path):
    database = tmp_path / "corrupt.sqlite3"
    database.write_bytes(b"not a valid sqlite database")
    with pytest.raises(RuntimeError, match="DEVICE_AUTHORITY_DATABASE_INTEGRITY_FAILED"):
        DeviceAuthority(database, enrollment_code="")


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



def test_device_request_nonce_is_single_use_across_independent_authorities(tmp_path):
    """Independent API workers cannot accept the same signed device proof twice."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    body = b'{"capability":"knowledge.search","input":{"query":"race"}}'
    digest = hashlib.sha256(body).hexdigest()
    proof = _signed_request(
        private_key, device_id, challenge["nonce"], "POST", "/v1/tasks", digest,
    )
    workers = [
        authority,
        DeviceAuthority(
            tmp_path / "device-authority.sqlite3", enrollment_code="",
        ),
    ]
    gate = Barrier(2)

    def attempt(worker):
        gate.wait(timeout=10)
        try:
            result = worker.verify_request(
                proof, method="POST", path="/v1/tasks",
                request_digest=digest, owner_subject="operator",
            )
            return ("accepted", result["authority"])
        except DeviceAuthorityError as exc:
            return ("rejected", exc.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, workers))

    assert sorted(outcomes) == [
        ("accepted", "DEVICE_REQUEST_VERIFIED"),
        ("rejected", "CHALLENGE_EXPIRED_OR_REPLAYED"),
    ]
    with authority._database() as db:
        row = db.execute(
            "SELECT consumed_at FROM device_challenges WHERE nonce=?",
            (challenge["nonce"],),
        ).fetchone()
    assert row is not None and row["consumed_at"] is not None



def test_device_proof_racing_recovery_cannot_survive_primary_key_replacement(tmp_path):
    """A concurrent proof is either consumed before recovery or rejected after it."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    owner = "operator:" + "d" * 32
    code = "device-proof-recovery-race-" + "r" * 40
    db_path = tmp_path / "device-proof-recovery-race.sqlite3"
    authority = DeviceAuthority(db_path, enrollment_code=code)
    old_private = ec.generate_private_key(ec.SECP256R1())
    old_public = old_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    enrolled = authority.enroll(code, old_public, owner_subject=owner)
    challenge = authority.challenge(enrolled["device_id"], owner_subject=owner)
    body = b'{"capability":"knowledge.search","input":{"query":"race"}}'
    digest = hashlib.sha256(body).hexdigest()
    proof = _signed_request(
        old_private, enrolled["device_id"], challenge["nonce"],
        "POST", "/v1/tasks", digest,
    )
    new_private = ec.generate_private_key(ec.SECP256R1())
    new_public = new_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    workers = [
        authority,
        DeviceAuthority(db_path, enrollment_code=""),
    ]
    gate = Barrier(2)

    def verify():
        gate.wait(timeout=10)
        try:
            workers[0].verify_request(
                proof, method="POST", path="/v1/tasks",
                request_digest=digest, owner_subject=owner,
            )
            return "accepted"
        except DeviceAuthorityError as exc:
            return exc.code

    def recover():
        gate.wait(timeout=10)
        workers[1].replace_active_device_for_recovery(
            new_public, owner_subject=owner,
            expected_old_public_key_pem=old_public,
        )
        return "replaced"

    with ThreadPoolExecutor(max_workers=2) as pool:
        verify_future = pool.submit(verify)
        recover_future = pool.submit(recover)
        verify_outcome = verify_future.result()
        assert recover_future.result() == "replaced"

    assert verify_outcome in {"accepted", "DEVICE_OR_CHALLENGE_NOT_FOUND"}
    assert authority.verify_registered_public_key(new_public, owner_subject=owner)
    with pytest.raises(DeviceAuthorityError, match="DEVICE_KEY_NOT_ACTIVE"):
        authority.verify_active_public_key(old_public)
    with authority._database() as db:
        old_row = db.execute(
            "SELECT active FROM devices WHERE device_id=?",
            (enrolled["device_id"],),
        ).fetchone()
        stale_challenge = db.execute(
            "SELECT 1 FROM device_challenges WHERE device_id=? AND nonce=?",
            (enrolled["device_id"], challenge["nonce"]),
        ).fetchone()
    assert old_row["active"] == 0
    assert stale_challenge is None


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
    authority, _, device_id = _enrolled_authority(tmp_path)
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
    enrolled = authority.enroll(code, old_public, owner_subject=owner)
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


def _noncanonical_b64url_pad_bits(value):
    """Change only unused final Base64URL pad bits, preserving decoded bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    remainder = len(value) % 4
    if remainder not in (2, 3):
        raise AssertionError("signature must have unused Base64URL pad bits")
    index = alphabet.index(value[-1])
    altered = value[:-1] + alphabet[index | 1]
    assert altered != value
    assert base64.urlsafe_b64decode(altered + "=" * (-len(altered) % 4)) == base64.urlsafe_b64decode(
        value + "=" * (-len(value) % 4)
    )
    return altered


def test_signed_request_rejects_noncanonical_base64url_pad_bits(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    digest = hashlib.sha256(b"canonical-device-proof").hexdigest()
    proof = None
    for _ in range(20):
        candidate = _signed_request(
            private_key, device_id, challenge["nonce"], "POST", "/v1/tasks", digest
        )
        if len(candidate["signature"]) % 4 in (2, 3):
            proof = candidate
            break
    assert proof is not None, "could not generate a signature with unused Base64URL pad bits"
    proof["signature"] = _noncanonical_b64url_pad_bits(proof["signature"])

    with pytest.raises(DeviceAuthorityError, match="INVALID_SIGNATURE"):
        authority.verify_request(
            proof, method="POST", path="/v1/tasks",
            request_digest=digest, owner_subject="operator",
        )


def test_signed_status_rejects_noncanonical_base64url_pad_bits(tmp_path):
    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = None
    for _ in range(20):
        candidate = _signed_status(private_key, device_id, challenge["nonce"])
        if len(candidate["signature"]) % 4 in (2, 3):
            proof = candidate
            break
    assert proof is not None, "could not generate a signature with unused Base64URL pad bits"
    proof["signature"] = _noncanonical_b64url_pad_bits(proof["signature"])

    with pytest.raises(DeviceAuthorityError, match="INVALID_SIGNATURE"):
        authority.verify_status(proof, owner_subject="operator")


def test_device_status_challenge_expires_at_exact_deadline(tmp_path, monkeypatch):
    import omega.device_authority as device_authority_module

    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    proof = _signed_status(private_key, device_id, challenge["nonce"])
    fixed_now = int(time.time())
    with authority._database() as db:
        db.execute(
            "UPDATE device_challenges SET expires_at=? WHERE nonce=?",
            (fixed_now, challenge["nonce"]),
        )
    monkeypatch.setattr(device_authority_module.time, "time", lambda: fixed_now)

    with pytest.raises(DeviceAuthorityError, match="CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_status(proof, owner_subject="operator")


def test_device_request_challenge_expires_at_exact_deadline(tmp_path, monkeypatch):
    import omega.device_authority as device_authority_module

    authority, private_key, device_id = _enrolled_authority(tmp_path)
    challenge = authority.challenge(device_id, owner_subject="operator")
    digest = hashlib.sha256(b"deadline-bound-request").hexdigest()
    proof = _signed_request(
        private_key, device_id, challenge["nonce"], "POST", "/v1/tasks", digest
    )
    fixed_now = int(time.time())
    with authority._database() as db:
        db.execute(
            "UPDATE device_challenges SET expires_at=? WHERE nonce=?",
            (fixed_now, challenge["nonce"]),
        )
    monkeypatch.setattr(device_authority_module.time, "time", lambda: fixed_now)

    with pytest.raises(DeviceAuthorityError, match="CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_request(
            proof, method="POST", path="/v1/tasks",
            request_digest=digest, owner_subject="operator",
        )
