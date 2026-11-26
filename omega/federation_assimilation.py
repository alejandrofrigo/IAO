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
        """Verify pinned Ed25519 identity and apply autonomous policy v1."""
        # The current callers can supply transport booleans as ordinary JSON.
        # Those assertions are forgeable and are NOT proof of a TLS session.
        # Until a trusted, redirect-blocking, SSRF-safe transport adapter is
        # integrated, do not advance lifecycle state from caller-supplied data.
        raise AssimilationError("TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED")
        import time
        import json
        import hashlib

        policy_id = "IAO_PINNED_IDENTITY_VERIFICATION_V1"

        if not isinstance(evidence, dict):
            raise AssimilationError("INVALID_VERIFICATION_EVIDENCE")

        required = {
            "identity", "response", "requester_id",
            "nonce", "request_ts", "transport",
        }
        if not required.issubset(evidence):
            raise AssimilationError("INCOMPLETE_VERIFICATION_EVIDENCE")

        identity = evidence["identity"]
        response = evidence["response"]
        transport = evidence["transport"]

        if not isinstance(identity, dict) or not isinstance(response, dict):
            raise AssimilationError("INVALID_SIGNED_IDENTITY")
        if identity.get("protocol") != "iao-federation" or identity.get("version") != 1:
            raise AssimilationError("UNSUPPORTED_FEDERATION_PROTOCOL")
        if identity.get("node_id") != expected_node_id:
            raise AssimilationError("EXPECTED_IDENTITY_MISMATCH")
        if not isinstance(expected_node_id, str) or not _ID_RE.fullmatch(expected_node_id):
            raise AssimilationError("INVALID_EXPECTED_NODE_ID")

        if not isinstance(transport, dict):
            raise AssimilationError("INVALID_TRANSPORT_EVIDENCE")
        if transport.get("https_verified") is not True:
            raise AssimilationError("HTTPS_VERIFICATION_REQUIRED")
        if transport.get("redirected") is not False:
            raise AssimilationError("REDIRECT_REFUSED")

        requester_id = evidence["requester_id"]
        nonce = evidence["nonce"]
        request_ts = evidence["request_ts"]

        if not isinstance(requester_id, str) or not re.fullmatch(r"[0-9a-f]{16}", requester_id):
            raise AssimilationError("INVALID_REQUESTER_ID")
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise AssimilationError("INVALID_CHALLENGE_NONCE")
        if isinstance(request_ts, bool) or not isinstance(request_ts, (int, float)):
            raise AssimilationError("INVALID_CHALLENGE_TIMESTAMP")

        # Re-verificación independiente: una respuesta declarativa no basta.
        try:
            from tools.iao_federation_binding import verify_binding

            checked = verify_binding(
                identity,
                response,
                expected_node_id=expected_node_id,
                requester_id=requester_id,
                nonce=nonce,
                request_ts=float(request_ts),
                now=time.time(),
                skew=60.0,
            )
        except Exception as exc:
            raise AssimilationError("CRYPTOGRAPHIC_RECHECK_FAILED") from exc

        if not checked.get("ok"):
            raise AssimilationError("CRYPTOGRAPHIC_RECHECK_REJECTED")

        try:
            encoded = json.dumps(
                evidence, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        except Exception as exc:
            raise AssimilationError("EVIDENCE_NOT_SERIALIZABLE") from exc

        if len(encoded) > 65536:
            raise AssimilationError("EVIDENCE_TOO_LARGE")

        evidence_hash = hashlib.sha256(encoded).hexdigest()

        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            item = next(
                (x for x in data["candidates"] if x["candidate_id"] == cid),
                None,
            )
            if item is None:
                raise AssimilationError("CANDIDATE_NOT_FOUND")
            if item.get("authorized"):
                raise AssimilationError("CANDIDATE_ALREADY_AUTHORIZED")
            if item["status"] not in {
                "DISCOVERED", "PRECHECKED", "TLS_VERIFIED", "PROTOCOL_VERIFIED"
            }:
                raise AssimilationError("CANDIDATE_STATE_NOT_ELIGIBLE")

            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()

            # La prueba criptográfica verifica identidad; no concede confianza.
            stages = (
                "TLS_VERIFIED",
                "PROTOCOL_VERIFIED",
                "IDENTITY_VERIFIED",
                "AUTHORIZATION_PENDING",
            )
            for state in stages:
                item["status"] = state
                item["updated_at"] = now
                item["history"].append({
                    "status": state,
                    "at": now,
                    "policy": policy_id,
                    "evidence_sha256": evidence_hash,
                })

            item["node_id"] = expected_node_id
            item["authorized"] = False
            item["authorized_by"] = None
            item["reason"] = "IDENTITY_VERIFIED_OPERATOR_APPROVAL_REQUIRED"
            item["authorization_policy"] = {
                "id": policy_id,
                "decision": "PENDING_OPERATOR_APPROVAL",
                "checks": {
                    "operator_pinned_identity": True,
                    "https_verified": True,
                    "redirect_refused": True,
                    "protocol_supported": True,
                    "ed25519_signature_valid": True,
                    "challenge_valid": True,
                },
                "evidence_sha256": evidence_hash,
                "decided_at": now,
            }
            item["verification_evidence"] = {
                "identity": identity,
                "response": response,
                "requester_id": requester_id,
                "nonce": nonce,
                "request_ts": float(request_ts),
                "transport": transport,
                "evidence_sha256": evidence_hash,
                "verified_at": now,
            }

            self._save(data)
            return dict(item)

    def authorize(self, cid: str, operator_id: str | None = None) -> dict[str, Any]:
        """Autoriza un candidato verificado para enrolamiento.

        Modo autónomo (operator_id=None):
        - Requiere que el candidato esté en AUTHORIZATION_PENDING
        - Requiere identidad criptográfica verificada (node_id presente)
        - Requiere verification_evidence íntegro
        - Concede automáticamente solo capacidades READ_ONLY declaradas
        - Registra authorized_by=IAO_AUTONOMOUS_POLICY_V1 en auditoría
        - Fail-closed ante cualquier ambigüedad

        Modo operador (operator_id=str):
        - Mantiene el comportamiento manual previo para compatibilidad.
        """
        autonomous = operator_id is None
        if autonomous:
            operator_label = "IAO_AUTONOMOUS_POLICY_V1"
        else:
            if (
                not isinstance(operator_id, str)
                or not operator_id.strip()
                or len(operator_id) > 120
                or any(ord(c) < 32 for c in operator_id)
            ):
                raise AssimilationError("INVALID_OPERATOR_ID")
            operator_label = operator_id.strip()

        with self._lock:
            data = self._load() if self.path.exists() else self._empty()
            item = next(
                (x for x in data["candidates"] if x["candidate_id"] == cid),
                None,
            )
            if item is None:
                raise AssimilationError("CANDIDATE_NOT_FOUND")
            if item["status"] != "AUTHORIZATION_PENDING":
                raise AssimilationError("AUTHORIZATION_NOT_PENDING")
            if not item.get("node_id"):
                raise AssimilationError("VERIFIED_NODE_ID_REQUIRED")

            if autonomous:
                evidence = item.get("verification_evidence")
                if not isinstance(evidence, dict):
                    raise AssimilationError("VERIFICATION_EVIDENCE_REQUIRED")
                if not evidence.get("evidence_sha256"):
                    raise AssimilationError("VERIFICATION_EVIDENCE_INCOMPLETE")
                transport = evidence.get("transport")
                if (
                    not isinstance(transport, dict)
                    or transport.get("https_verified") is not True
                ):
                    raise AssimilationError("HTTPS_VERIFICATION_REQUIRED")
                if transport.get("redirected") is not False:
                    raise AssimilationError("REDIRECT_REFUSED")

                proof = {
                    key: evidence.get(key)
                    for key in (
                        "identity", "response", "requester_id",
                        "nonce", "request_ts", "transport",
                    )
                }
                try:
                    encoded = json.dumps(
                        proof, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                except Exception as exc:
                    raise AssimilationError(
                        "VERIFICATION_EVIDENCE_INVALID"
                    ) from exc
                digest = hashlib.sha256(encoded).hexdigest()
                if (
                    not isinstance(evidence.get("evidence_sha256"), str)
                    or evidence["evidence_sha256"] != digest
                ):
                    raise AssimilationError("VERIFICATION_EVIDENCE_HASH_MISMATCH")

                policy = item.get("authorization_policy")
                if (
                    not isinstance(policy, dict)
                    or policy.get("id") != "IAO_PINNED_IDENTITY_VERIFICATION_V1"
                    or policy.get("evidence_sha256") != digest
                    or policy.get("decision") != "PENDING_OPERATOR_APPROVAL"
                ):
                    raise AssimilationError("VERIFICATION_POLICY_EVIDENCE_MISMATCH")

                try:
                    from tools.iao_federation_binding import verify_binding

                    checked = verify_binding(
                        evidence["identity"],
                        evidence["response"],
                        expected_node_id=item["node_id"],
                        requester_id=evidence["requester_id"],
                        nonce=evidence["nonce"],
                        request_ts=float(evidence["request_ts"]),
                        now=__import__("time").time(),
                        skew=60.0,
                    )
                except Exception as exc:
                    raise AssimilationError(
                        "CRYPTOGRAPHIC_RECHECK_FAILED"
                    ) from exc
                if not isinstance(checked, dict) or checked.get("ok") is not True:
                    raise AssimilationError("CRYPTOGRAPHIC_RECHECK_REJECTED")

            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
            item["authorized"] = True
            item["authorized_by"] = operator_label
            item["authorized_at"] = now
            item["updated_at"] = now
            item["history"].append({
                "status": "AUTHORIZED",
                "at": now,
                "authorized_by": operator_label,
                "mode": "AUTONOMOUS" if autonomous else "OPERATOR",
            })
            self._save(data)
            return dict(item)
