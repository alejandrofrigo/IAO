"""Persistent, explicit trust registry for IAO federation peers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any


NODE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class FederationTrustError(Exception):
    pass


class FederationTrustStore:
    def __init__(
        self,
        path: Path | str = Path(".state/federation/trusted-peers.json"),
        clock=time.time,
    ):
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    @staticmethod
    def _validate_identity(node_id: str, public_key: str) -> str:
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            raise FederationTrustError("INVALID_NODE_ID")
        if not isinstance(public_key, str):
            raise FederationTrustError("INVALID_PUBLIC_KEY")
        key = public_key.strip()
        if not key or len(key) > 16384:
            raise FederationTrustError("INVALID_PUBLIC_KEY")
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "peers": {}}
        if self.path.is_symlink() or not self.path.is_file():
            raise FederationTrustError("UNSAFE_REGISTRY_PATH")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise FederationTrustError("REGISTRY_READ_FAILED") from exc
        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or not isinstance(data.get("peers"), dict)
        ):
            raise FederationTrustError("INVALID_REGISTRY_FORMAT")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                stream.write(payload + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def approve(
        self,
        node_id: str,
        public_key: str,
        approved_by: str,
    ) -> dict[str, Any]:
        fingerprint = self._validate_identity(node_id, public_key)
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise FederationTrustError("EXPLICIT_APPROVER_REQUIRED")

        data = self._read()
        peers = data["peers"]
        previous = peers.get(node_id)

        if previous and previous.get("fingerprint") != fingerprint:
            raise FederationTrustError("KEY_CHANGE_REQUIRES_REVIEW")

        peers[node_id] = {
            "fingerprint": fingerprint,
            "status": "TRUSTED",
            "approved_by": approved_by.strip()[:128],
            "approved_at": self.clock(),
        }
        self._write(data)
        return {
            "node_id": node_id,
            "fingerprint": fingerprint,
            "status": "TRUSTED",
            "authorization_granted": True,
        }

    def verify(self, node_id: str, public_key: str) -> dict[str, Any]:
        fingerprint = self._validate_identity(node_id, public_key)
        data = self._read()
        peer = data["peers"].get(node_id)

        if not peer:
            return {
                "node_id": node_id,
                "trusted": False,
                "reason": "UNKNOWN_PEER",
                "authorization_granted": False,
            }

        if peer.get("status") != "TRUSTED":
            return {
                "node_id": node_id,
                "trusted": False,
                "reason": "PEER_REVOKED",
                "authorization_granted": False,
            }

        if peer.get("fingerprint") != fingerprint:
            return {
                "node_id": node_id,
                "trusted": False,
                "reason": "PUBLIC_KEY_MISMATCH",
                "authorization_granted": False,
            }

        return {
            "node_id": node_id,
            "trusted": True,
            "reason": "IDENTITY_MATCH",
            "authorization_granted": True,
        }

    def revoke(self, node_id: str, revoked_by: str) -> dict[str, Any]:
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            raise FederationTrustError("INVALID_NODE_ID")
        if not isinstance(revoked_by, str) or not revoked_by.strip():
            raise FederationTrustError("EXPLICIT_REVOKER_REQUIRED")

        data = self._read()
        peer = data["peers"].get(node_id)
        if not peer:
            raise FederationTrustError("UNKNOWN_PEER")

        peer["status"] = "REVOKED"
        peer["revoked_by"] = revoked_by.strip()[:128]
        peer["revoked_at"] = self.clock()
        self._write(data)
        return {
            "node_id": node_id,
            "status": "REVOKED",
            "authorization_granted": False,
        }

    def list_peers(self) -> list[dict[str, Any]]:
        data = self._read()
        return [
            {"node_id": node_id, **peer}
            for node_id, peer in sorted(data["peers"].items())
        ]
