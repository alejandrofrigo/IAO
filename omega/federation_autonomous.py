"""Automatic federation of explicitly consenting public HTTPS IAO peers.

Discovery is only a lead. Enrollment requires a signed publication, an
explicit remote consent flag, a nonce-bound Ed25519 challenge, a matching
identity and contract, bounded HTTPS transport, and locally served
READ_ONLY capabilities. No inbound permissions are granted automatically.
"""
from __future__ import annotations

import json
import os
import ipaddress
import secrets
import time
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_PEERS_PER_CYCLE = 20
MAX_LEASE_SECONDS = 24 * 60 * 60


def _write_registry(path: Path, data: dict[str, Any]) -> None:
    """Atomically persist the candidate registry without following symlinks."""
    path = Path(path)
    parent = path.parent
    if path.is_symlink():
        raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_SYMLINK_REFUSED")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    absolute_parent = parent.absolute()
    if not parent.is_dir() or any(
        component.is_symlink()
        for component in (absolute_parent, *absolute_parent.parents)
    ):
        raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_PARENT_REFUSED")
    fd, temporary_name = tempfile.mkstemp(
        prefix=".iao-federation-registry-", dir=str(parent)
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(data, sort_keys=True, ensure_ascii=False) + "\\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_SYMLINK_REFUSED")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        try:
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _origin(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("INVALID_DISCOVERED_ORIGIN")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password
            or parsed.port not in (None, 443)
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("INVALID_DISCOVERED_ORIGIN")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        if not address.is_global:
            raise ValueError("NON_PUBLIC_DISCOVERED_ADDRESS")
    except ValueError as exc:
        if str(exc) == "NON_PUBLIC_DISCOVERED_ADDRESS":
            raise
    return "https://" + parsed.netloc


def _enroll_one(fed_node, candidate: dict[str, Any]) -> dict[str, Any]:
    from omega.federation import verify_identity_challenge
    from omega.federation_transport import fetch_public_json, post_public_json

    origin = _origin(candidate.get("origin"))
    expected_id = candidate.get("node_id")
    if (not isinstance(expected_id, str) or len(expected_id) != 16
            or any(ch not in "0123456789abcdef" for ch in expected_id)):
        raise ValueError("DISCOVERY_NODE_ID_INVALID")

    publication = fetch_public_json(
        origin + "/fed/v1/publication", timeout=8, max_bytes=16_384
    )
    if not isinstance(publication, dict) or not fed_node.verify_publication(publication):
        raise ValueError("PUBLICATION_SIGNATURE_INVALID")
    if publication.get("consent") is not True:
        raise ValueError("REMOTE_PEERING_CONSENT_MISSING")
    if publication.get("node_id") != expected_id:
        raise ValueError("PUBLICATION_NODE_ID_MISMATCH")
    endpoint = origin + "/fed/v1/message"
    if publication.get("endpoint") != endpoint:
        raise ValueError("PUBLICATION_ENDPOINT_MISMATCH")
    now = float(fed_node.clock())
    issued = publication.get("issued_at")
    expires = publication.get("lease_expires_at")
    if (isinstance(issued, bool) or not isinstance(issued, (int, float))
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not 0 < float(expires) - now <= MAX_LEASE_SECONDS
            or abs(now - float(issued)) > 300):
        raise ValueError("PUBLICATION_LEASE_INVALID")

    identity = fetch_public_json(
        origin + "/fed/v1/identity", timeout=8, max_bytes=4096
    )
    if (not isinstance(identity, dict)
            or identity.get("node_id") != expected_id
            or identity.get("public_key") != publication.get("public_key")):
        raise ValueError("IDENTITY_PUBLICATION_MISMATCH")

    nonce = secrets.token_hex(32)
    request_ts = now
    challenge = {
        "v": 1, "from": fed_node.node_id, "to": expected_id,
        "nonce": nonce, "ts": request_ts,
    }
    status, response = post_public_json(
        origin + "/fed/v1/handshake", challenge,
        timeout=8, max_bytes=4096,
    )
    if status != 200 or not isinstance(response, dict):
        raise ValueError("IDENTITY_CHALLENGE_HTTP_FAILED")
    verified = verify_identity_challenge(
        identity, response, requester_id=fed_node.node_id,
        nonce=nonce, request_ts=request_ts,
        now=float(fed_node.clock()), skew=60.0,
    )
    if not verified.get("ok") or verified.get("peer_id") != expected_id:
        raise ValueError("IDENTITY_CHALLENGE_REJECTED")

    contract = fetch_public_json(
        origin + "/fed/v1/contract", timeout=8, max_bytes=16_384
    )
    if not isinstance(contract, dict) or contract.get("peer_id") != expected_id:
        raise ValueError("PARTICIPATION_CONTRACT_ID_MISMATCH")
    if contract.get("pubkey") != __import__("base64").b64encode(
        bytes.fromhex(publication["public_key"])
    ).decode():
        raise ValueError("PARTICIPATION_CONTRACT_KEY_MISMATCH")

    published_caps = publication.get("capabilities", [])
    contract_caps = contract.get("capabilities", [])
    if not isinstance(published_caps, list) or not isinstance(contract_caps, list):
        raise ValueError("CAPABILITY_DOCUMENT_INVALID")
    capabilities = sorted(
        set(x for x in published_caps if isinstance(x, str))
        & set(x for x in contract_caps if isinstance(x, str))
        & set(fed_node.served)
    )
    if not capabilities:
        raise ValueError("NO_MUTUALLY_SUPPORTED_READ_ONLY_CAPABILITIES")
    contract["capabilities"] = capabilities
    contract["endpoint"] = endpoint
    contract["lease_expires_at"] = min(
        float(contract.get("lease_expires_at", 0)), float(expires)
    )
    fed_node._validate_peer_contract(contract)
    existing = fed_node.peers.get(expected_id)
    if existing is not None and existing.get("revoked"):
        raise ValueError("PEER_REVOKED_LOCALLY")
    if existing is not None:
        old_pub = existing.get("pub")
        new_pub = __import__("base64").b64decode(contract["pubkey"], validate=True)
        if old_pub != new_pub:
            raise ValueError("ENROLLED_PEER_KEY_CHANGED")
        if existing.get("endpoint") != endpoint:
            raise ValueError("ENROLLED_PEER_ENDPOINT_CHANGED")
        return {"status": "ALREADY_ENROLLED", "peer_id": expected_id}
    fed_node.enroll(contract, granted_capabilities=[])
    if expected_id not in fed_node.peers:
        raise RuntimeError("FEDERATION_ENROLLMENT_NOT_PERSISTED")
    return {
        "status": "ENROLLED", "peer_id": expected_id,
        "capabilities": capabilities, "granted_inbound_capabilities": [],
    }


def run_discovered_cycle(fed_node, state_dir: Path, registry_path: Path) -> dict[str, Any]:
    """Automatically verify and enroll only discovered peers explicitly offering federation."""
    if registry_path.is_symlink():
        raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_SYMLINK_REFUSED")
    if not registry_path.is_file():
        return {"status": "NO_INVENTORY", "checked": 0, "enrolled": 0}
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or data.get("schema") != 1
            or not isinstance(data.get("candidates"), dict)):
        raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_INVALID")
    candidates = [
        item for item in data["candidates"].values()
        if isinstance(item, dict)
        and item.get("status") in {"DISCOVERED_UNVERIFIED", "STALE_UNVERIFIED"}
        and item.get("identity_verified") is not True
    ][:MAX_PEERS_PER_CYCLE]
    checked = enrolled = failed = 0
    for item in candidates:
        checked += 1
        try:
            result = _enroll_one(fed_node, item)
            item["status"] = "ENROLLED" if result["status"] in {
                "ENROLLED", "ALREADY_ENROLLED"
            } else item.get("status", "DISCOVERED_UNVERIFIED")
            item["identity_verified"] = True
            item["enrolled"] = True
            item["verified_at"] = time.time()
            item["granted_capabilities"] = []
            item["remote_code_execution"] = False
            item["private_data_access"] = False
            item["federation_capabilities"] = result.get("capabilities", [])
            enrolled += result["status"] == "ENROLLED"
        except Exception as exc:
            item["last_federation_error"] = type(exc).__name__
            failed += 1
    _write_registry(registry_path, data)
    summary = {
        "status": "COMPLETED", "checked": checked,
        "enrolled": enrolled, "failed": failed,
        "inbound_capabilities_granted": 0,
    }
    audit_path = state_dir / "federation-autonomous.jsonl"
    state_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(audit_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (json.dumps({
            "timestamp": time.time(),
            "event": "FEDERATION_AUTOJOIN_CYCLE",
            **summary,
        }, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return summary
