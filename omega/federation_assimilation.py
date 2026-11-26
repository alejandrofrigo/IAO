"""IAO: persistent, fail-closed candidate lifecycle for federated nodes.

Discovery never grants trust. Enrollment requires an explicit authorization
record from an operator-controlled process.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any
import ipaddress
from urllib.parse import urlsplit

VERSION = 1
MAX_CANDIDATES = 1000
MAX_SOURCE_LENGTH = 160
MAX_REASON_LENGTH = 300

ACTIVE_STATES = {
    "DISCOVERED", "PRECHECKED", "TLS_VERIFIED", "PROTOCOL_VERIFIED",
    "IDENTITY_VERIFIED", "AUTHORIZATION_PENDING",
    "ENROLLED", "ACTIVE",
}
TERMINAL_STATES = {"REJECTED", "EXPIRED", "REVOKED"}
ALL_STATES = ACTIVE_STATES | {"QUARANTINED"} | TERMINAL_STATES

TRANSITIONS = {
    "DISCOVERED": {"PRECHECKED", "QUARANTINED", "REJECTED"},
    "PRECHECKED": {"TLS_VERIFIED", "QUARANTINED", "REJECTED"},
    "TLS_VERIFIED": {"PROTOCOL_VERIFIED", "QUARANTINED", "REJECTED"},
    "PROTOCOL_VERIFIED": {"IDENTITY_VERIFIED", "QUARANTINED", "REJECTED"},
    "IDENTITY_VERIFIED": {
        "AUTHORIZATION_PENDING", "QUARANTINED", "REJECTED"
    },
    "AUTHORIZATION_PENDING": {"ENROLLED", "QUARANTINED", "REJECTED"},
    "ENROLLED": {"ACTIVE", "QUARANTINED", "EXPIRED", "REVOKED"},
    "ACTIVE": {"QUARANTINED", "EXPIRED", "REVOKED"},
    "QUARANTINED": {"PRECHECKED", "REJECTED", "REVOKED"},
    "EXPIRED": {"PRECHECKED", "REVOKED"},
    "REJECTED": set(),
    "REVOKED": set(),
}

_ENDPOINT_PATH = "/fed/v1/message"
_ID_RE = re.compile(r"^[0-9a-f]{16}$")


class AssimilationError(Exception):
    """Safe, expected error from candidate lifecycle operations."""


def validate_endpoint(endpoint: Any) -> str:
    if not isinstance(endpoint, str) or not 1 <= len(endpoint) <= 2048:
        raise AssimilationError("INVALID_ENDPOINT")
    try:
        u = urlsplit(endpoint)
        host = u.hostname
        port = u.port
        hostname = (host or "").rstrip(".").lower()
        local_name = (
            hostname == "localhost"
            or hostname.endswith(".localhost")
            or hostname.endswith(".local")
            or hostname.endswith(".internal")
        )
        non_public_ip = False
        try:
            address = ipaddress.ip_address(hostname)
            non_public_ip = not address.is_global
        except ValueError:
            pass

        valid = (
            u.scheme == "https"
            and bool(hostname)
            and not local_name
            and not non_public_ip
            and not u.username
            and not u.password
            and (port is None or port == 443)
            and u.path == _ENDPOINT_PATH
            and not u.query
            and not u.fragment
            and not any(ord(ch) < 33 or ord(ch) == 127 for ch in endpoint)
        )
    except ValueError:
        valid = False
    if not valid:
        raise AssimilationError("HTTPS_FEDERATION_ENDPOINT_REQUIRED")
    return endpoint


def candidate_id(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:24]


class CandidateRegistry:
    """Atomic JSON registry. It stores no private keys, tokens or credentials."""

    def __init__(self, path: str | Path, *, max_candidates: int = MAX_CANDIDATES):
        self.path = Path(path)
        self.max_candidates = max_candidates
        if not 1 <= max_candidates <= MAX_CANDIDATES:
            raise ValueError("INVALID_MAX_CANDIDATES")
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise AssimilationError("REGISTRY_SYMLINK_REFUSED")
        if self.path.exists():
            self._load()

    def _empty(self) -> dict[str, Any]:
        return {"version": VERSION, "candidates": []}

    def _load(self) -> dict[str, Any]:
        if self.path.is_symlink() or not self.path.is_file():
            raise AssimilationError("REGISTRY_PATH_REFUSED")
        try:
            raw = self.path.read_text(encoding="utf-8")
            if len(raw) > 2_000_000:
                raise ValueError("TOO_LARGE")
            data = json.loads(raw)
            if (
                not isinstance(data, dict)
                or data.get("version") != VERSION
                or not isinstance(data.get("candidates"), list)
                or len(data["candidates"]) > self.max_candidates
            ):
                raise ValueError("BAD_SCHEMA")
            seen = set()
            for item in data["candidates"]:
                if not isinstance(item, dict):
                    raise ValueError("BAD_RECORD")
                endpoint = validate_endpoint(item.get("endpoint"))
                cid = candidate_id(endpoint)
                if item.get("candidate_id") != cid or cid in seen:
                    raise ValueError("BAD_OR_DUPLICATE_ID")
                if item.get("status") not in ALL_STATES:
                    raise ValueError("BAD_STATUS")
                if not isinstance(item.get("history"), list):
                    raise ValueError("BAD_HISTORY")
                if not isinstance(item.get("authorized"), bool):
                    raise ValueError("BAD_AUTHORIZATION_FLAG")
                seen.add(cid)
            return data
        except AssimilationError:
            raise
        except Exception as exc:
            raise AssimilationError("REGISTRY_INVALID_FAIL_CLOSED") from exc

    def _save(self, data: dict[str, Any]) -> None:
        if self.path.is_symlink():
            raise AssimilationError("REGISTRY_SYMLINK_REFUSED")
        fd, temp_name = tempfile.mkstemp(
            prefix=".iao-candidates-", dir=str(self.path.parent)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            os.chmod(self.path, 0o600)
            try:
                dfd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _safe_source(source: Any) -> str:
        if not isinstance(source, str) or not source.strip():
            raise AssimilationError("INVALID_DISCOVERY_SOURCE")
        source = source.strip()
        if len(source) > MAX_SOURCE_LENGTH or any(ord(c) < 32 for c in source):
            raise AssimilationError("INVALID_DISCOVERY_SOURCE")
        return source

    def discover(self, endpoint: str, source: str) -> dict[str, Any]:
        endpoint = validate_endpoint(endpoint)
        source = self._safe_source(source)
        cid = candidate_id(endpoint)
        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            for item in data["candidates"]:
                if item["candidate_id"] == cid:
                    return {"created": False, "candidate": dict(item)}
            if len(data["candidates"]) >= self.max_candidates:
                raise AssimilationError("CANDIDATE_CAP_REACHED")
            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
            item = {
                "candidate_id": cid,
                "endpoint": endpoint,
                "status": "DISCOVERED",
                "source": source,
                "authorized": False,
                "authorized_by": None,
                "node_id": None,
                "reason": None,
                "created_at": now,
                "updated_at": now,
                "history": [{"status": "DISCOVERED", "at": now}],
            }
            data["candidates"].append(item)
            self._save(data)
            return {"created": True, "candidate": dict(item)}

    def get(self, cid: str) -> dict[str, Any] | None:
        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            for item in data["candidates"]:
                if item["candidate_id"] == cid:
                    return dict(item)
            return None

    def list_candidates(self) -> list[dict[str, Any]]:
        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            return [dict(item) for item in data["candidates"]]

    def transition(
        self,
        cid: str,
        new_status: str,
        *,
        reason: str | None = None,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        if new_status not in ALL_STATES:
            raise AssimilationError("UNKNOWN_STATE")

        # No se permite declarar pruebas criptográficas mediante una
        # transición administrativa. Se habilitarán con el verificador real.
        evidence_states = {
            "TLS_VERIFIED",
            "PROTOCOL_VERIFIED",
            "IDENTITY_VERIFIED",
            "AUTHORIZATION_PENDING",
            "ENROLLED",
            "ACTIVE",
        }
        if new_status in evidence_states:
            raise AssimilationError("CRYPTOGRAPHIC_VERIFIER_NOT_INTEGRATED")
        if reason is not None:
            if not isinstance(reason, str) or len(reason) > MAX_REASON_LENGTH:
                raise AssimilationError("INVALID_REASON")
        if node_id is not None and (
            not isinstance(node_id, str) or not _ID_RE.fullmatch(node_id)
        ):
            raise AssimilationError("INVALID_NODE_ID")

        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            item = next(
                (x for x in data["candidates"] if x["candidate_id"] == cid),
                None,
            )
            if item is None:
                raise AssimilationError("CANDIDATE_NOT_FOUND")
            old = item["status"]
            if new_status not in TRANSITIONS[old]:
                raise AssimilationError("ILLEGAL_STATE_TRANSITION")
            if new_status == "ENROLLED" and not item["authorized"]:
                raise AssimilationError("EXPLICIT_AUTHORIZATION_REQUIRED")
            if new_status in {"IDENTITY_VERIFIED", "AUTHORIZATION_PENDING", "ENROLLED", "ACTIVE"}:
                if node_id is None and not item.get("node_id"):
                    raise AssimilationError("VERIFIED_NODE_ID_REQUIRED")
            if node_id is not None:
                item["node_id"] = node_id
            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
            item["status"] = new_status
            item["reason"] = reason
            item["updated_at"] = now
            item["history"].append({"status": new_status, "at": now, "reason": reason})
            self._save(data)
            return dict(item)


    def record_verified_identity(
        self,
        cid: str,
        *,
        expected_node_id: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Fail closed until evidence is bound to a trusted live TLS transport."""
        raise AssimilationError("TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED")

    def authorize(self, cid: str, operator_id: str | None = None) -> dict[str, Any]:
        """Keep all enrollment paths closed until trusted transport is integrated."""
        if operator_id is not None and (
            not isinstance(operator_id, str)
            or not operator_id.strip()
            or len(operator_id) > 120
            or any(ord(char) < 32 for char in operator_id)
        ):
            raise AssimilationError("INVALID_OPERATOR_ID")

        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            item = next(
                (candidate for candidate in data["candidates"]
                 if candidate["candidate_id"] == cid),
                None,
            )
            if item is None:
                raise AssimilationError("CANDIDATE_NOT_FOUND")
            if item["status"] != "AUTHORIZATION_PENDING":
                raise AssimilationError("AUTHORIZATION_NOT_PENDING")
            if not item.get("node_id"):
                raise AssimilationError("VERIFIED_NODE_ID_REQUIRED")

            # Manual approval cannot bypass the missing transport attestation.
            raise AssimilationError("TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED")
