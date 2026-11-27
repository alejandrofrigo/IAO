import json
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega.agent_authority import AgentAuthority, AgentAuthorityError
from tools.iao_termux_agent import AgentClientError, _origin, init_key


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


class Identity:
    def __init__(self, path):
        self.database = path
        with sqlite3.connect(path) as db:
            db.executescript("CREATE TABLE operator_identities(identity_id TEXT PRIMARY KEY,key_version INTEGER,status TEXT); CREATE TABLE primary_device_bindings(identity_id TEXT PRIMARY KEY,key_version INTEGER);")
            db.execute("INSERT INTO operator_identities VALUES('" + "a" * 32 + "',1,'ACTIVE')")
            db.execute("INSERT INTO primary_device_bindings VALUES('" + "a" * 32 + "',1)")
    def primary_device_public_key(self):
        return "unused"
    def verify_primary_device(self, identity_id, public_key_pem):
        return True


def _agent(tmp_path):
    identity = Identity(tmp_path / "identity.sqlite3")
    authority = AgentAuthority(tmp_path / "agent.sqlite3", identity)
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    agent_id = "b" * 32
    with authority._db() as db:
        db.execute("INSERT INTO delegated_agents(agent_id,identity_id,key_version,primary_device_id,public_key_pem,scopes_json,created_at,expires_at,grant_digest) VALUES(?,?,?,?,?,?,?,?,?)", (agent_id,"a"*32,1,"c"*64,public,json.dumps(["agent.status.read"]),time.time(),time.time()+600,"d"*64))
    return authority, key, agent_id


def _signed_request(authority, key, agent_id, nonce, *, path="/v1/agent/status", body=b""):
    timestamp = int(time.time())
    payload = authority.canonical({"body_sha256": __import__("hashlib").sha256(body).hexdigest(), "method":"GET", "nonce":nonce, "path":path, "protocol":"IAO-AGENT-REQUEST-V1", "timestamp":timestamp})
    signature = key.sign(b"IAO-AGENT-REQUEST-V1\x00" + payload, ec.ECDSA(hashes.SHA256()))
    return timestamp, signature


def test_agent_challenge_and_signed_status_are_single_use(tmp_path):
    authority, key, agent_id = _agent(tmp_path)
    challenge = authority.issue_agent_challenge(agent_id)
    timestamp, signature = _signed_request(authority, key, agent_id, challenge["nonce"])
    result = authority.verify_agent_request(agent_id=agent_id, nonce=challenge["nonce"], timestamp=timestamp, signature=signature, method="GET", path="/v1/agent/status", body=b"")
    assert result["authority"] == "READ_ONLY"
    assert authority.status_for_agent(agent_id)["active"] is True
    with pytest.raises(AgentAuthorityError, match="AGENT_CHALLENGE_EXPIRED_OR_REPLAYED"):
        authority.verify_agent_request(agent_id=agent_id, nonce=challenge["nonce"], timestamp=timestamp, signature=signature, method="GET", path="/v1/agent/status", body=b"")


def test_agent_signature_cannot_be_replayed_for_other_path(tmp_path):
    authority, key, agent_id = _agent(tmp_path)
    challenge = authority.issue_agent_challenge(agent_id)
    timestamp, signature = _signed_request(authority, key, agent_id, challenge["nonce"])
    with pytest.raises(AgentAuthorityError, match="AGENT_REQUEST_SCOPE_DENIED"):
        authority.verify_agent_request(agent_id=agent_id, nonce=challenge["nonce"], timestamp=timestamp, signature=signature, method="GET", path="/v1/tasks", body=b"")


def test_agent_request_rejects_tampered_body_digest(tmp_path):
    authority, key, agent_id = _agent(tmp_path)
    challenge = authority.issue_agent_challenge(agent_id)
    timestamp, signature = _signed_request(authority, key, agent_id, challenge["nonce"])
    with pytest.raises(AgentAuthorityError, match="INVALID_AGENT_SIGNATURE"):
        authority.verify_agent_request(agent_id=agent_id, nonce=challenge["nonce"], timestamp=timestamp, signature=signature, method="GET", path="/v1/agent/status", body=b"tampered")


def test_revoked_agent_cannot_obtain_challenge(tmp_path):
    authority, key, agent_id = _agent(tmp_path)
    with authority._db() as db:
        db.execute("UPDATE delegated_agents SET revoked_at=? WHERE agent_id=?", (time.time(), agent_id))
    with pytest.raises(AgentAuthorityError, match="AGENT_NOT_ACTIVE"):
        authority.issue_agent_challenge(agent_id)


def test_agent_key_init_is_private_and_non_overwriting(tmp_path):
    state = tmp_path / "state"
    result = init_key(state)
    assert (state / "agent-ecdsa-p256.key").stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o700
    assert "BEGIN PUBLIC KEY" in result["public_key_pem"]
    with pytest.raises(AgentClientError, match="AGENT_KEY_ALREADY_EXISTS"):
        init_key(state)


@pytest.mark.parametrize("value", ["http://example.org", "https://user:pass@example.org", "https://example.org/path", "https://example.org/?q=1", "https://example.org:8443"])
def test_origin_rejects_non_fixed_https_origin(value):
    with pytest.raises(AgentClientError):
        _origin(value)


def test_origin_accepts_https_host():
    assert _origin("https://api.example.org/") == "https://api.example.org"