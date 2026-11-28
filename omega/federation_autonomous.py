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
    absolute_parent = parent.absolute()
    # Inspect existing ancestors BEFORE mkdir: mkdir(parents=True) would
    # otherwise follow a symlink and could create directories outside state.
    if any(
        component.is_symlink()
        for component in (absolute_parent, *absolute_parent.parents)
    ):
        raise RuntimeError("EXTERNAL_NETWORK_REGISTRY_PARENT_REFUSED")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
        payload = (json.dumps(data, sort_keys=True, ensure_ascii=False) + "\n").encode()
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
    """Fail closed until a connection-bound mutual-TLS verifier is integrated.

    Ed25519 proves key possession and the pinned HTTPS client protects the
    transport to this client. Neither proves that the remote server required
    and validated this client's certificate. Optional client-certificate
    configuration is not remote mTLS attestation, so no remote handshake,
    contract fetch, or peer enrollment is allowed here.
    """
    raise RuntimeError("TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED")


def _append_cycle_audit(state_dir: Path, summary: dict[str, Any]) -> None:
    """Append a private audit record without following symlinked paths."""
    import stat

    state_dir = Path(state_dir)
    absolute_dir = state_dir.absolute()
    # Check ancestors before creating anything, so a symlinked parent cannot
    # redirect mkdir(parents=True) into an unrelated directory.
    if any(
        component.is_symlink()
        for component in (absolute_dir, *absolute_dir.parents)
    ):
        raise RuntimeError("FEDERATION_AUDIT_DIRECTORY_REFUSED")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not state_dir.is_dir() or any(
        component.is_symlink()
        for component in (absolute_dir, *absolute_dir.parents)
    ):
        raise RuntimeError("FEDERATION_AUDIT_DIRECTORY_REFUSED")
    audit_path = state_dir / "federation-autonomous.jsonl"
    if audit_path.is_symlink():
        raise RuntimeError("FEDERATION_AUDIT_FILE_REFUSED")
    flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(audit_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError("FEDERATION_AUDIT_FILE_REFUSED")
        os.fchmod(fd, 0o600)
        record = {
            "timestamp": time.time(),
            "event": "FEDERATION_AUTOJOIN_CYCLE",
            **summary,
        }
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


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
    _append_cycle_audit(state_dir, summary)
    return summary
