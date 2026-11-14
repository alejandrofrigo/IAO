"""Signed, operator-reviewed federation proposals. No automatic enrollment."""
import base64
import json
import math
import os
import tempfile
import time
import fcntl
from pathlib import Path
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from omega.audit import canonical_json
from omega.federation import node_id_of

PROTOCOL = "iao-federation-proposal"
VERSION = 1
MAX_PROPOSAL_BYTES = 32 * 1024
MAX_TTL_SECONDS = 900
MAX_LEASE_SECONDS = 86400
MAX_PENDING = 500


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _fail(code: str) -> dict[str, Any]:
    return {"ok": False, "error": code}


def _valid_endpoint(endpoint: Any) -> bool:
    if endpoint is None:
        return True
    if not isinstance(endpoint, str) or not 1 <= len(endpoint) <= 2048:
        return False
    try:
        u = urlsplit(endpoint)
        return bool(
            u.scheme == "https" and u.hostname
            and not u.username and not u.password
            and (u.port is None or u.port == 443)
            and u.path == "/fed/v1/message"
            and not u.query and not u.fragment
        )
    except ValueError:
        return False


def create_proposal(
    key: Ed25519PrivateKey,
    capabilities: list[str],
    *,
    lease_seconds: int = 3600,
    rate_limit_per_min: int = 30,
    endpoint: str | None = None,
    now: float | None = None,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create a signed proposal; this does not enroll or grant anything."""
    now = time.time() if now is None else now
    if (isinstance(now, bool) or not isinstance(now, (int, float))
            or not math.isfinite(float(now))):
        raise ValueError("INVALID_TIME")
    if (not isinstance(capabilities, list) or not capabilities
            or any(not isinstance(x, str) or not x for x in capabilities)
            or len(capabilities) != len(set(capabilities))):
        raise ValueError("INVALID_CAPABILITIES")
    if (isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int)
            or not 1 <= lease_seconds <= MAX_LEASE_SECONDS):
        raise ValueError("INVALID_LEASE")
    if (isinstance(rate_limit_per_min, bool)
            or not isinstance(rate_limit_per_min, int)
            or not 1 <= rate_limit_per_min <= 300):
        raise ValueError("INVALID_RATE_LIMIT")
    if (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_TTL_SECONDS):
        raise ValueError("INVALID_PROPOSAL_TTL")
    if not _valid_endpoint(endpoint):
        raise ValueError("INVALID_ENDPOINT")

    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    contract = {
        "peer_id": node_id_of(pub),
        "pubkey": base64.b64encode(pub).decode("ascii"),
        "capabilities": list(capabilities),
        "lease_expires_at": float(now) + lease_seconds,
        "rate_limit_per_min": rate_limit_per_min,
    }
    if endpoint is not None:
        contract["endpoint"] = endpoint

    body = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "proposal_id": __import__("secrets").token_hex(16),
        "created_at": float(now),
        "expires_at": float(now) + ttl_seconds,
        "contract": contract,
    }
    return {
        **body,
        "sig": base64.b64encode(key.sign(canonical_json(body))).decode("ascii"),
    }


def verify_proposal(
    raw: bytes | str | dict[str, Any],
    registry: Any,
    served: set[str] | frozenset[str],
    *,
    now: float | None = None,
    max_skew: float = 60.0,
) -> dict[str, Any]:
    """Verify proposal signature, identity, time, endpoint and READ_ONLY caps."""
    now = time.time() if now is None else now
    if (isinstance(now, bool) or not isinstance(now, (int, float))
            or not math.isfinite(float(now))
            or isinstance(max_skew, bool)
            or not isinstance(max_skew, (int, float))
            or not math.isfinite(float(max_skew)) or max_skew < 0):
        return _fail("INVALID_TIME_PARAMETERS")

    try:
        if isinstance(raw, bytes):
            if len(raw) > MAX_PROPOSAL_BYTES:
                return _fail("PROPOSAL_TOO_LARGE")
            doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        elif isinstance(raw, str):
            if len(raw.encode("utf-8")) > MAX_PROPOSAL_BYTES:
                return _fail("PROPOSAL_TOO_LARGE")
            doc = json.loads(raw, object_pairs_hook=_unique_object)
        elif isinstance(raw, dict):
            doc = raw
            if len(canonical_json(doc)) > MAX_PROPOSAL_BYTES:
                return _fail("PROPOSAL_TOO_LARGE")
        else:
            return _fail("INVALID_PROPOSAL")
    except Exception:
        return _fail("INVALID_PROPOSAL")

    if not isinstance(doc, dict):
        return _fail("INVALID_PROPOSAL")
    if doc.get("protocol") != PROTOCOL or doc.get("version") != VERSION:
        return _fail("UNSUPPORTED_PROPOSAL_PROTOCOL")

    proposal_id = doc.get("proposal_id")
    if (not isinstance(proposal_id, str) or len(proposal_id) != 32
            or any(c not in "0123456789abcdef" for c in proposal_id)):
        return _fail("INVALID_PROPOSAL_ID")

    created = doc.get("created_at")
    expires = doc.get("expires_at")
    if any(isinstance(x, bool) or not isinstance(x, (int, float))
           or not math.isfinite(float(x)) for x in (created, expires)):
        return _fail("INVALID_PROPOSAL_TIME")
    if abs(float(now) - float(created)) > float(max_skew):
        return _fail("PROPOSAL_CLOCK_SKEW")
    if (float(expires) <= float(now)
            or float(expires) <= float(created)
            or float(expires) - float(created) > MAX_TTL_SECONDS):
        return _fail("PROPOSAL_EXPIRED_OR_INVALID_TTL")

    contract = doc.get("contract")
    if not isinstance(contract, dict):
        return _fail("INVALID_PEER_CONTRACT")

    peer_id = contract.get("peer_id")
    encoded = contract.get("pubkey")
    try:
        pub = base64.b64decode(encoded, validate=True)
    except Exception:
        return _fail("INVALID_PUBLIC_KEY")
    if len(pub) != 32 or peer_id != node_id_of(pub):
        return _fail("NODE_ID_KEY_MISMATCH")

    signature = doc.get("sig")
    try:
        sig = base64.b64decode(signature, validate=True)
        body = {k: v for k, v in doc.items() if k != "sig"}
        Ed25519PublicKey.from_public_bytes(pub).verify(
            sig, canonical_json(body)
        )
    except Exception:
        return _fail("INVALID_PROPOSAL_SIGNATURE")

    caps = contract.get("capabilities")
    if (not isinstance(caps, list) or not caps
            or any(not isinstance(x, str) or not x for x in caps)
            or len(caps) != len(set(caps))
            or not set(caps) <= set(served)):
        return _fail("CAPABILITY_NOT_ALLOWED")

    for cap in caps:
        spec = registry.get(cap) if registry is not None else None
        if spec is None or getattr(spec, "effect_class", None) != "READ_ONLY":
            return _fail("CAPABILITY_NOT_READ_ONLY")

    lease = contract.get("lease_expires_at")
    rate = contract.get("rate_limit_per_min")
    if (isinstance(lease, bool) or not isinstance(lease, (int, float))
            or not math.isfinite(float(lease)) or float(lease) <= float(now)
            or float(lease) > float(now) + MAX_LEASE_SECONDS):
        return _fail("INVALID_PEER_LEASE")
    if (isinstance(rate, bool) or not isinstance(rate, int)
            or not 1 <= rate <= 300):
        return _fail("INVALID_PEER_RATE_LIMIT")
    if not _valid_endpoint(contract.get("endpoint")):
        return _fail("INVALID_PEER_ENDPOINT")

    clean = {
        "peer_id": peer_id,
        "pubkey": encoded,
        "capabilities": list(caps),
        "lease_expires_at": float(lease),
        "rate_limit_per_min": rate,
    }
    if contract.get("endpoint") is not None:
        clean["endpoint"] = contract["endpoint"]

    return {
        "ok": True,
        "proposal_id": proposal_id,
        "contract": clean,
        "status": "PENDING",
        "created_at": float(created),
        "expires_at": float(expires),
    }



class PendingProposalStore:
    """Verified local inbox. It never enrolls peers or grants capabilities."""

    def __init__(
        self, path: Path, registry: Any,
        served: set[str] | frozenset[str], *,
        now: float | None = None,
    ):
        self.path = Path(path)
        self.registry = registry
        self.served = frozenset(served)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.items: dict[str, dict[str, Any]] = {}
        with self._locked():
            self.items = self._read_items(now=now)

    @contextmanager
    def _locked(self):
        lock_path = self.path.with_name(self.path.name + ".lock")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _read_items(self, *, now=None):
        if self.path.is_symlink():
            raise RuntimeError("PROPOSAL_STORE_SYMLINK_REFUSED")
        if not self.path.exists():
            return {}
        if not self.path.is_file():
            raise RuntimeError("PROPOSAL_STORE_PATH_REFUSED")

        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("STORE_TOO_LARGE")
            data = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
            )
            if (not isinstance(data, dict)
                    or data.get("version") != 2
                    or not isinstance(data.get("proposals"), list)
                    or len(data["proposals"]) > MAX_PENDING):
                raise ValueError("INVALID_STORE")

            restored = {}
            for entry in data["proposals"]:
                if not isinstance(entry, dict):
                    raise ValueError("INVALID_ITEM")
                raw = entry.get("raw_proposal")
                received = entry.get("received_at")
                if (isinstance(received, bool)
                        or not isinstance(received, (int, float))
                        or not math.isfinite(float(received))):
                    raise ValueError("INVALID_RECEIVED_AT")

                verified = verify_proposal(
                    raw, self.registry, self.served, now=now
                )
                if not verified.get("ok"):
                    raise ValueError("SAVED_PROPOSAL_REJECTED")
                pid = verified["proposal_id"]
                if pid in restored:
                    raise ValueError("DUPLICATE_PROPOSAL")
                restored[pid] = {
                    **verified,
                    "received_at": float(received),
                    "raw_proposal": raw,
                }
            return restored
        except Exception as exc:
            raise RuntimeError(
                "PROPOSAL_STORE_INVALID_FAIL_CLOSED"
            ) from exc

    def submit(
        self, raw: bytes | str | dict[str, Any], registry: Any = None,
        served: set[str] | frozenset[str] | None = None, *,
        now: float | None = None,
    ) -> dict[str, Any]:
        active_registry = self.registry if registry is None else registry
        active_served = self.served if served is None else frozenset(served)

        result = verify_proposal(
            raw, active_registry, active_served, now=now
        )
        if not result["ok"]:
            return result

        try:
            if isinstance(raw, dict):
                raw_doc = json.loads(
                    canonical_json(raw), object_pairs_hook=_unique_object
                )
            elif isinstance(raw, bytes):
                raw_doc = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=_unique_object
                )
            else:
                raw_doc = json.loads(
                    raw, object_pairs_hook=_unique_object
                )
        except Exception:
            return _fail("INVALID_PROPOSAL")

        current_time = time.time() if now is None else float(now)
        pid = result["proposal_id"]

        with self._locked():
            # Re-read under the inter-process lock to avoid lost updates.
            current = self._read_items(now=now)
            if pid in current:
                self.items = current
                return _fail("DUPLICATE_PROPOSAL")
            if len(current) >= MAX_PENDING:
                self.items = current
                return _fail("PENDING_STORE_FULL")

            item = {
                **result,
                "received_at": current_time,
                "raw_proposal": raw_doc,
            }
            updated = {**current, pid: item}
            self._save(updated)
            self.items = updated
            return dict(item)

    def _save(self, items: dict[str, dict[str, Any]]) -> None:
        if self.path.is_symlink():
            raise RuntimeError("PROPOSAL_STORE_SYMLINK_REFUSED")

        payload = {
            "version": 2,
            "proposals": [
                {
                    "raw_proposal": items[k]["raw_proposal"],
                    "received_at": items[k]["received_at"],
                }
                for k in sorted(items)
            ],
        }
        fd, temp_name = tempfile.mkstemp(
            prefix=".iao-proposals-", dir=str(self.path.parent)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(
                    payload, stream, sort_keys=True, separators=(",", ":")
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            os.chmod(self.path, 0o600)
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

