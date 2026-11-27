"""Device-bound, read-only delegated-agent authority.

The agent receives no bearer token and no command-execution capability. The
primary root and primary device must both sign the exact canonical grant.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PROTOCOL = "IAO-AGENT-DELEGATION-V1"
DOMAIN = b"IAO-AGENT-DELEGATION-V1\x00"
CHALLENGE_TTL = 90
MAX_GRANT_TTL = 3600
ALLOWED_SCOPES = frozenset({"agent.status.read"})


class AgentAuthorityError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code, self.status = code, status


class AgentAuthority:
    def __init__(self, database: str | Path, operator_identity: Any) -> None:
        self.database = Path(database)
        self.operator_identity = operator_identity
        self.lock = threading.RLock()
        parent = self.database.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or self.database.is_symlink():
            raise RuntimeError("AGENT_AUTHORITY_SYMLINK_REFUSED")
        if self.database.exists() and not self.database.is_file():
            raise RuntimeError("AGENT_AUTHORITY_PATH_NOT_REGULAR_FILE")
        os.chmod(parent, 0o700)
        fd = os.open(str(self.database), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("AGENT_AUTHORITY_PATH_NOT_REGULAR_FILE")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS agent_challenges(
                    nonce TEXT PRIMARY KEY, identity_id TEXT NOT NULL,
                    key_version INTEGER NOT NULL, expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS agent_challenge_expiry
                    ON agent_challenges(expires_at);
                CREATE TABLE IF NOT EXISTS delegated_agents(
                    agent_id TEXT PRIMARY KEY, identity_id TEXT NOT NULL,
                    key_version INTEGER NOT NULL, primary_device_id TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL, scopes_json TEXT NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    revoked_at REAL, grant_digest TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS delegated_agents_owner
                    ON delegated_agents(identity_id, revoked_at, expires_at);
                CREATE TABLE IF NOT EXISTS agent_request_challenges(
                    nonce TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                    expires_at REAL NOT NULL, consumed_at REAL
                );
                CREATE INDEX IF NOT EXISTS agent_request_challenge_expiry ON agent_request_challenges(expires_at);
            """)
        os.chmod(self.database, 0o600)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    def _current_parent_key_version(self, identity_id: str) -> int:
        identity_db = getattr(self.operator_identity, "database", None)
        if identity_db is None:
            raise AgentAuthorityError("OPERATOR_IDENTITY_UNAVAILABLE", 503)
        try:
            with sqlite3.connect(str(identity_db), timeout=5) as db:
                row = db.execute(
                    "SELECT i.key_version,i.status,b.key_version FROM operator_identities i JOIN primary_device_bindings b ON b.identity_id=i.identity_id WHERE i.identity_id=?",
                    (identity_id,),
                ).fetchone()
        except sqlite3.Error:
            raise AgentAuthorityError("OPERATOR_IDENTITY_UNAVAILABLE", 503) from None
        if row is None or row[1] != "ACTIVE" or row[0] != row[2]:
            raise AgentAuthorityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403)
        return int(row[0])

    @staticmethod
    def _public_key(value: Any) -> tuple[Any, str, str]:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise AgentAuthorityError("INVALID_AGENT_PUBLIC_KEY")
        try:
            key = serialization.load_pem_public_key(value.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise AgentAuthorityError("INVALID_AGENT_PUBLIC_KEY") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise AgentAuthorityError("UNSUPPORTED_AGENT_PUBLIC_KEY")
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        return key, pem, hashlib.sha256(der).hexdigest()

    @staticmethod
    def canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @staticmethod
    def _verify_device_signature(public_key_pem: str, payload: bytes, signature: bytes) -> None:
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise AgentAuthorityError("INVALID_PRIMARY_DEVICE_SIGNATURE", 401)
        try:
            key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            key.verify(signature, DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError):
            raise AgentAuthorityError("INVALID_PRIMARY_DEVICE_SIGNATURE", 401) from None

    def issue_challenge(self, identity_id: str, key_version: int) -> dict[str, Any]:
        if not isinstance(identity_id, str) or len(identity_id) != 32 or isinstance(key_version, bool) or not isinstance(key_version, int) or key_version < 1:
            raise AgentAuthorityError("INVALID_OPERATOR_BINDING", 403)
        try:
            if self._current_parent_key_version(identity_id) != key_version:
                raise AgentAuthorityError("OPERATOR_ROOT_KEY_VERSION_MISMATCH", 409)
            primary_pem = self.operator_identity.primary_device_public_key()
            self.operator_identity.verify_primary_device(identity_id, primary_pem)
        except AgentAuthorityError:
            raise
        except Exception:
            raise AgentAuthorityError("PRIMARY_DEVICE_NOT_AUTHORIZED", 403) from None
        now = time.time()
        nonce = secrets.token_hex(32)
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM agent_challenges WHERE expires_at<=?", (now,))
            count = db.execute("SELECT COUNT(*) FROM agent_challenges WHERE identity_id=? AND consumed_at IS NULL AND expires_at>?", (identity_id, now)).fetchone()[0]
            if count >= 5:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_CHALLENGE_LIMIT", 429)
            db.execute("INSERT INTO agent_challenges(nonce,identity_id,key_version,expires_at) VALUES(?,?,?,?)", (nonce, identity_id, key_version, now + CHALLENGE_TTL))
            db.execute("COMMIT")
        return {"nonce": nonce, "expires_in": CHALLENGE_TTL, "protocol": PROTOCOL}

    def create_delegation(self, *, identity_id: str, key_version: int, nonce: str,
                          agent_public_key_pem: str, scopes: Any, expires_at: Any,
                          root_signature: bytes, primary_signature: bytes) -> dict[str, Any]:
        if not isinstance(identity_id, str) or len(identity_id) != 32:
            raise AgentAuthorityError("INVALID_OPERATOR_BINDING", 403)
        if isinstance(key_version, bool) or not isinstance(key_version, int) or key_version < 1:
            raise AgentAuthorityError("INVALID_ROOT_KEY_VERSION")
        if not isinstance(nonce, str) or len(nonce) != 64:
            raise AgentAuthorityError("INVALID_AGENT_CHALLENGE")
        if not isinstance(scopes, list) or not scopes or len(scopes) > len(ALLOWED_SCOPES) or any(not isinstance(x, str) for x in scopes) or len(set(scopes)) != len(scopes) or not set(scopes).issubset(ALLOWED_SCOPES):
            raise AgentAuthorityError("AGENT_SCOPE_NOT_ALLOWED", 403)
        now = time.time()
        if isinstance(expires_at, bool) or not isinstance(expires_at, int) or not now < expires_at <= now + MAX_GRANT_TTL:
            raise AgentAuthorityError("INVALID_AGENT_GRANT_EXPIRY")
        _, canonical_pem, fingerprint = self._public_key(agent_public_key_pem)
        try:
            primary_pem = self.operator_identity.primary_device_public_key()
            self.operator_identity.verify_primary_device(identity_id, primary_pem)
            self.operator_identity.verify_root_signature(identity_id, self._grant_payload(
                identity_id, key_version, nonce, fingerprint, sorted(scopes), expires_at
            ), root_signature, expected_key_version=key_version)
        except AgentAuthorityError:
            raise
        except Exception:
            raise AgentAuthorityError("PRIMARY_OR_ROOT_AUTHORITY_INVALID", 403) from None
        payload = self._grant_payload(identity_id, key_version, nonce, fingerprint, sorted(scopes), expires_at)
        self._verify_device_signature(primary_pem, payload, primary_signature)
        agent_id = secrets.token_hex(16)
        digest = hashlib.sha256(payload).hexdigest()
        primary_device_id = hashlib.sha256(serialization.load_pem_public_key(primary_pem.encode("ascii")).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            challenge = db.execute("SELECT * FROM agent_challenges WHERE nonce=?", (nonce,)).fetchone()
            if challenge is None or challenge["identity_id"] != identity_id or challenge["key_version"] != key_version or challenge["consumed_at"] is not None or challenge["expires_at"] <= now:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_CHALLENGE_EXPIRED_OR_REPLAYED", 409)
            if db.execute("SELECT 1 FROM delegated_agents WHERE identity_id=? AND revoked_at IS NULL AND expires_at>? AND public_key_pem=?", (identity_id, now, canonical_pem)).fetchone():
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_ALREADY_ENROLLED", 409)
            db.execute("UPDATE agent_challenges SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL", (now, nonce))
            db.execute("""INSERT INTO delegated_agents
                (agent_id,identity_id,key_version,primary_device_id,public_key_pem,scopes_json,created_at,expires_at,grant_digest)
                VALUES(?,?,?,?,?,?,?,?,?)""", (agent_id, identity_id, key_version, primary_device_id, canonical_pem, json.dumps(sorted(scopes)), now, expires_at, digest))
            db.execute("COMMIT")
        return {"agent_id": agent_id, "fingerprint": fingerprint, "scopes": sorted(scopes), "expires_at": expires_at, "authority": "DELEGATED_READ_ONLY"}

    @staticmethod
    def _grant_payload(identity_id: str, key_version: int, nonce: str, fingerprint: str, scopes: list[str], expires_at: int) -> bytes:
        return AgentAuthority.canonical({
            "agent_public_key_sha256": fingerprint, "expires_at": expires_at,
            "identity_id": identity_id, "key_version": key_version, "nonce": nonce,
            "primary_device_role": "PRIMARY", "protocol": PROTOCOL, "scopes": scopes,
        })

    def status(self, identity_id: str) -> dict[str, Any]:
        now = time.time()
        try:
            current_key_version = self._current_parent_key_version(identity_id)
            primary_pem = self.operator_identity.primary_device_public_key()
            self.operator_identity.verify_primary_device(identity_id, primary_pem)
        except Exception:
            return {"agents": [], "authority": "PRIMARY_DEVICE_NOT_AUTHORIZED"}
        with self._db() as db:
            rows = db.execute("SELECT agent_id,public_key_pem,scopes_json,created_at,expires_at,revoked_at,key_version FROM delegated_agents WHERE identity_id=? ORDER BY created_at DESC LIMIT 20", (identity_id,)).fetchall()
        agents = []
        for row in rows:
            _, _, fingerprint = self._public_key(row["public_key_pem"])
            agents.append({"agent_id": row["agent_id"], "fingerprint": fingerprint, "scopes": json.loads(row["scopes_json"]), "created_at": int(row["created_at"]), "expires_at": int(row["expires_at"]), "revoked": row["revoked_at"] is not None, "active": row["revoked_at"] is None and row["expires_at"] > now and row["key_version"] == current_key_version})
        return {"agents": agents, "authority": "READ_ONLY"}

    def issue_agent_challenge(self, agent_id: Any) -> dict[str, Any]:
        if not isinstance(agent_id, str) or len(agent_id) != 32:
            raise AgentAuthorityError("INVALID_AGENT_ID", 400)
        now = time.time()
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT identity_id,key_version,expires_at,revoked_at FROM delegated_agents WHERE agent_id=?", (agent_id,)).fetchone()
            if row is None or row[3] is not None or row[2] <= now:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_NOT_ACTIVE", 403)
            try:
                current_version = self._current_parent_key_version(row[0])
            except AgentAuthorityError:
                db.execute("ROLLBACK")
                raise
            if row[1] != current_version:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_NOT_ACTIVE", 403)
            db.execute("DELETE FROM agent_request_challenges WHERE expires_at<=?", (now,))
            active = db.execute("SELECT COUNT(*) FROM agent_request_challenges WHERE agent_id=? AND consumed_at IS NULL AND expires_at>?", (agent_id, now)).fetchone()[0]
            if active >= 5:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_CHALLENGE_LIMIT", 429)
            nonce = secrets.token_hex(32)
            db.execute("INSERT INTO agent_request_challenges(nonce,agent_id,expires_at) VALUES(?,?,?)", (nonce, agent_id, now + 60))
            db.execute("COMMIT")
        return {"nonce": nonce, "expires_in": 60, "protocol": "IAO-AGENT-REQUEST-V1"}

    def verify_agent_request(self, *, agent_id: Any, nonce: Any, timestamp: Any, signature: bytes, method: str, path: str, body: bytes) -> dict[str, str]:
        if not isinstance(agent_id, str) or len(agent_id) != 32 or not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise AgentAuthorityError("INVALID_AGENT_REQUEST_IDENTITY", 401)
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or abs(time.time() - timestamp) > 60:
            raise AgentAuthorityError("AGENT_REQUEST_EXPIRED", 401)
        if method != "GET" or path != "/v1/agent/status" or body:
            raise AgentAuthorityError("AGENT_REQUEST_SCOPE_DENIED", 403)
        if not isinstance(signature, bytes) or not 64 <= len(signature) <= 80:
            raise AgentAuthorityError("INVALID_AGENT_SIGNATURE", 401)
        now = time.time()
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT a.identity_id,a.key_version,a.public_key_pem,a.scopes_json,a.expires_at,a.revoked_at,c.expires_at,c.consumed_at FROM delegated_agents a JOIN agent_request_challenges c ON c.agent_id=a.agent_id WHERE a.agent_id=? AND c.nonce=?", (agent_id, nonce)).fetchone()
            if row is None or row[5] is not None or row[4] <= now or row[6] <= now or row[7] is not None:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_CHALLENGE_EXPIRED_OR_REPLAYED", 401)
            try:
                current_version = self._current_parent_key_version(row[0])
            except AgentAuthorityError:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_NOT_ACTIVE", 403) from None
            if row[1] != current_version:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_NOT_ACTIVE", 403)
            if "agent.status.read" not in json.loads(row[3]):
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_SCOPE_NOT_ALLOWED", 403)
            payload = self.canonical({"body_sha256": hashlib.sha256(body).hexdigest(), "method": method, "nonce": nonce, "path": path, "protocol": "IAO-AGENT-REQUEST-V1", "timestamp": timestamp})
            try:
                key = serialization.load_pem_public_key(row[2].encode("ascii"))
                key.verify(signature, b"IAO-AGENT-REQUEST-V1\x00" + payload, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError, TypeError):
                db.execute("ROLLBACK")
                raise AgentAuthorityError("INVALID_AGENT_SIGNATURE", 401) from None
            changed = db.execute("UPDATE agent_request_challenges SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL", (now, nonce)).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_CHALLENGE_EXPIRED_OR_REPLAYED", 401)
            db.execute("COMMIT")
        return {"agent_id": agent_id, "identity_id": row[0], "authority": "READ_ONLY"}

    def status_for_agent(self, agent_id: str) -> dict[str, Any]:
        now = time.time()
        with self._db() as db:
            row = db.execute("SELECT agent_id,scopes_json,created_at,expires_at,revoked_at,key_version,identity_id FROM delegated_agents WHERE agent_id=?", (agent_id,)).fetchone()
        if row is None:
            raise AgentAuthorityError("AGENT_NOT_FOUND", 404)
        try:
            current_version = self._current_parent_key_version(row[6])
        except AgentAuthorityError:
            current_version = -1
        active = bool(current_version == row[5] and row[4] is None and row[3] > now)
        return {"agent_id": row[0], "scopes": json.loads(row[1]), "created_at": int(row[2]), "expires_at": int(row[3]), "revoked": row[4] is not None, "active": active, "authority": "READ_ONLY"}
    def revoke(self, *, identity_id: str, key_version: int, agent_id: str,
               root_signature: bytes, primary_signature: bytes) -> dict[str, str]:
        if not isinstance(agent_id, str) or len(agent_id) != 32:
            raise AgentAuthorityError("INVALID_AGENT_ID")
        try:
            primary_pem = self.operator_identity.primary_device_public_key()
            self.operator_identity.verify_primary_device(identity_id, primary_pem)
            payload = self.canonical({"agent_id": agent_id, "identity_id": identity_id, "key_version": key_version, "protocol": PROTOCOL, "purpose": "REVOKE"})
            self.operator_identity.verify_root_signature(identity_id, payload, root_signature, expected_key_version=key_version)
            self._verify_device_signature(primary_pem, payload, primary_signature)
        except AgentAuthorityError:
            raise
        except Exception:
            raise AgentAuthorityError("PRIMARY_OR_ROOT_AUTHORITY_INVALID", 403) from None
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE delegated_agents SET revoked_at=? WHERE agent_id=? AND identity_id=? AND key_version=? AND revoked_at IS NULL", (time.time(), agent_id, identity_id, key_version)).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                raise AgentAuthorityError("AGENT_NOT_ACTIVE", 404)
            db.execute("COMMIT")
        return {"revoked": True, "authority": "READ_ONLY"}
