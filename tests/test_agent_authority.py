import json
import sqlite3
import time
import threading
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.agent_authority import AgentAuthority, AgentAuthorityError, DOMAIN
from omega.operator_identity import ROOT_SIGNATURE_DOMAIN


def _pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class FakeOperatorIdentity:
    def __init__(self, database):
        self.database = database
        self.root = ec.generate_private_key(ec.SECP256R1())
        self.primary = ec.generate_private_key(ec.SECP256R1())
        self.lock = threading.RLock()
        primary_pem = _pem(self.primary)
        primary_der = self.primary.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        primary_id = hashlib.sha256(primary_der).hexdigest()
        with sqlite3.connect(self.database) as db:
            db.executescript(
                "CREATE TABLE operator_identities(identity_id TEXT PRIMARY KEY,key_version INTEGER,status TEXT);"
                "CREATE TABLE primary_device_bindings(identity_id TEXT PRIMARY KEY,key_version INTEGER,device_id TEXT,device_public_key_pem TEXT);"
            )
            db.execute("INSERT INTO operator_identities VALUES(?,?,?)", ("a" * 32, 3, "ACTIVE"))
            db.execute(
                "INSERT INTO primary_device_bindings VALUES(?,?,?,?)",
                ("a" * 32, 3, primary_id, primary_pem),
            )

    def primary_device_public_key(self):
        return _pem(self.primary)

    def verify_primary_device(self, identity_id, public_key_pem):
        assert identity_id == "a" * 32
        assert public_key_pem == _pem(self.primary)
        return True

    def verify_root_signature(self, identity_id, payload, signature, *, expected_key_version):
        assert identity_id == "a" * 32
        assert expected_key_version == 3
        self.root.public_key().verify(
            signature, ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
        )
        return True


def _setup(tmp_path):
    operator = FakeOperatorIdentity(tmp_path / "operator.sqlite3")
    authority = AgentAuthority(tmp_path / "agents.sqlite3", operator)
    agent = ec.generate_private_key(ec.SECP256R1())
    return authority, operator, agent


def _grant(authority, operator, agent, *, scopes=None, expires_at=None):
    identity_id = "a" * 32
    challenge = authority.issue_challenge(identity_id, 3)
    _, _, fingerprint = authority._public_key(_pem(agent))
    expiry = int(time.time()) + 300 if expires_at is None else expires_at
    payload = authority._grant_payload(
        identity_id, 3, challenge["nonce"], fingerprint,
        ["agent.status.read"] if scopes is None else scopes, expiry,
    )
    root_sig = operator.root.sign(
        ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    primary_sig = operator.primary.sign(
        DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    result = authority.create_delegation(
        identity_id=identity_id, key_version=3, nonce=challenge["nonce"],
        agent_public_key_pem=_pem(agent),
        scopes=["agent.status.read"] if scopes is None else scopes,
        expires_at=expiry, root_signature=root_sig,
        primary_signature=primary_sig,
    )
    return result, challenge, payload


def test_dual_signature_creates_read_only_agent_and_status(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    result, _, _ = _grant(authority, operator, agent)
    assert result["authority"] == "DELEGATED_READ_ONLY"
    assert result["scopes"] == ["agent.status.read"]
    status = authority.status("a" * 32)
    assert status["agents"][0]["active"] is True
    assert status["agents"][0]["fingerprint"] == result["fingerprint"]


def test_challenge_is_single_use(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    _, challenge, payload = _grant(authority, operator, agent)
    _, _, fingerprint = authority._public_key(_pem(agent))
    expiry = json.loads(payload.decode("ascii"))["expires_at"]
    payload = authority._grant_payload(
        "a" * 32, 3, challenge["nonce"], fingerprint,
        ["agent.status.read"], expiry,
    )
    root_sig = operator.root.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    device_sig = operator.primary.sign(DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(AgentAuthorityError, match="AGENT_CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.create_delegation(
            identity_id="a" * 32, key_version=3, nonce=challenge["nonce"],
            agent_public_key_pem=_pem(agent), scopes=["agent.status.read"],
            expires_at=expiry, root_signature=root_sig,
            primary_signature=device_sig,
        )


def test_unauthorized_scope_rejected(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    with pytest.raises(AgentAuthorityError, match="AGENT_SCOPE_NOT_ALLOWED"):
        _grant(authority, operator, agent, scopes=["shell.execute"])


def test_invalid_root_or_primary_signature_rejected(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    challenge = authority.issue_challenge("a" * 32, 3)
    _, _, fingerprint = authority._public_key(_pem(agent))
    expiry = int(time.time()) + 300
    payload = authority._grant_payload("a" * 32, 3, challenge["nonce"], fingerprint, ["agent.status.read"], expiry)
    bad = b"\x00" * 70
    with pytest.raises(Exception):
        authority.create_delegation(
            identity_id="a" * 32, key_version=3, nonce=challenge["nonce"],
            agent_public_key_pem=_pem(agent), scopes=["agent.status.read"],
            expires_at=expiry, root_signature=bad, primary_signature=bad,
        )


def test_expired_grant_rejected(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    with pytest.raises(AgentAuthorityError, match="INVALID_AGENT_GRANT_EXPIRY"):
        _grant(authority, operator, agent, expires_at=int(time.time()) - 1)


def test_revocation_requires_both_signatures_and_marks_inactive(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    result, _, _ = _grant(authority, operator, agent)
    payload = authority.canonical({
        "agent_id": result["agent_id"], "identity_id": "a" * 32,
        "key_version": 3, "protocol": "IAO-AGENT-DELEGATION-V1",
        "purpose": "REVOKE",
    })
    root_sig = operator.root.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    primary_sig = operator.primary.sign(DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    assert authority.revoke(
        identity_id="a" * 32, key_version=3, agent_id=result["agent_id"],
        root_signature=root_sig, primary_signature=primary_sig,
    )["revoked"] is True
    assert authority.status("a" * 32)["agents"][0]["active"] is False


def test_duplicate_active_agent_key_rejected(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    _grant(authority, operator, agent)
    with pytest.raises(AgentAuthorityError, match="AGENT_ALREADY_ENROLLED"):
        _grant(authority, operator, agent)


def test_root_rotation_invalidates_existing_delegation(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    _grant(authority, operator, agent)
    with sqlite3.connect(operator.database) as db:
        db.execute("UPDATE operator_identities SET key_version=4")
        db.execute("UPDATE primary_device_bindings SET key_version=4")
    status = authority.status("a" * 32)
    assert status["agents"][0]["active"] is False
    with pytest.raises(AgentAuthorityError, match="OPERATOR_ROOT_KEY_VERSION_MISMATCH"):
        authority.issue_challenge("a" * 32, 3)


def test_root_rotation_between_challenge_and_grant_commit_is_rejected(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    challenge = authority.issue_challenge("a" * 32, 3)
    _, _, fingerprint = authority._public_key(_pem(agent))
    expiry = int(time.time()) + 300
    payload = authority._grant_payload(
        "a" * 32, 3, challenge["nonce"], fingerprint,
        ["agent.status.read"], expiry,
    )
    root_sig = operator.root.sign(
        ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    primary_sig = operator.primary.sign(
        DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    with sqlite3.connect(operator.database) as db:
        db.execute("UPDATE operator_identities SET key_version=4")
        db.execute("UPDATE primary_device_bindings SET key_version=4")
    with pytest.raises(AgentAuthorityError, match="OPERATOR_OR_PRIMARY_DEVICE_CHANGED"):
        authority.create_delegation(
            identity_id="a" * 32, key_version=3, nonce=challenge["nonce"],
            agent_public_key_pem=_pem(agent), scopes=["agent.status.read"],
            expires_at=expiry, root_signature=root_sig,
            primary_signature=primary_sig,
        )


def test_primary_device_replacement_invalidates_old_challenge_signature(tmp_path):
    authority, operator, agent = _setup(tmp_path)
    challenge = authority.issue_challenge("a" * 32, 3)
    _, _, fingerprint = authority._public_key(_pem(agent))
    expiry = int(time.time()) + 300
    payload = authority._grant_payload(
        "a" * 32, 3, challenge["nonce"], fingerprint,
        ["agent.status.read"], expiry,
    )
    root_sig = operator.root.sign(
        ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    old_primary_sig = operator.primary.sign(
        DOMAIN + payload, ec.ECDSA(hashes.SHA256())
    )
    operator.primary = ec.generate_private_key(ec.SECP256R1())
    new_primary_pem = _pem(operator.primary)
    new_der = operator.primary.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    new_id = hashlib.sha256(new_der).hexdigest()
    with sqlite3.connect(operator.database) as db:
        db.execute(
            "UPDATE primary_device_bindings SET device_id=?,device_public_key_pem=?",
            (new_id, new_primary_pem),
        )
    with pytest.raises(AgentAuthorityError, match="INVALID_PRIMARY_DEVICE_SIGNATURE"):
        authority.create_delegation(
            identity_id="a" * 32, key_version=3, nonce=challenge["nonce"],
            agent_public_key_pem=_pem(agent), scopes=["agent.status.read"],
            expires_at=expiry, root_signature=root_sig,
            primary_signature=old_primary_sig,
        )
