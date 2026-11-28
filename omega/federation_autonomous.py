"""Federation candidate auditing with remote enrollment disabled by default.

Discovery is only a lead. Ed25519 identity proofs and pinned HTTPS do not
attest that the remote server required and validated client mTLS on the same
connection. Remote enrollment therefore fails closed until a connection-bound
trusted-transport verifier is implemented and independently tested.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ipaddress
import time
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_PEERS_PER_CYCLE = 20


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


def _is_tor_v3_hostname(host: str) -> bool:
    """Validate the v3 onion address checksum and version, not just its alphabet."""
    label = host[:-6] if host.endswith(".onion") else ""
    if len(label) != 56 or any(ch not in "abcdefghijklmnopqrstuvwxyz234567" for ch in label):
        return False
    try:
        decoded = base64.b32decode(label.upper())
    except (ValueError, base64.binascii.Error):
        return False
    if len(decoded) != 35 or decoded[34] != 3:
        return False
    expected = hashlib.sha3_256(
        b".onion checksum" + decoded[:32] + b"\\x03"
    ).digest()[:2]
    return decoded[32:34] == expected


def _origin(value: Any) -> str:
    """Validate a public HTTPS origin or a Tor v3 onion HTTP origin."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("INVALID_DISCOVERED_ORIGIN")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("INVALID_DISCOVERED_ORIGIN") from exc
    if (not host or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("INVALID_DISCOVERED_ORIGIN")
    host = host.lower()
    if host.endswith(".onion"):
        if (parsed.scheme != "http" or not _is_tor_v3_hostname(host)
                or port not in (None, 80)):
            raise ValueError("INVALID_DISCOVERED_ONION_ORIGIN")
        return "http://" + host
    if parsed.scheme != "https" or port not in (None, 443):
        raise ValueError("INVALID_DISCOVERED_ORIGIN")
    try:
        address = ipaddress.ip_address(host)
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
    """Audit discovered candidates; remote enrollment stays fail-closed until mTLS attestation exists."""
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
    checked = enrolled = failed = blocked = 0
    for item in candidates:
        checked += 1
        # Candidate evaluation is intentionally metadata-only. Do not call
        # _enroll_one: its hard failure is a final safety barrier, not a
        # per-candidate operation. This avoids repeated fake failures and
        # guarantees that discovery never initiates remote handshakes.
        item["enrollment_status"] = (
            "BLOCKED_TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED"
        )
        item["identity_verification"] = "NOT_PERFORMED"
        item["enrolled"] = False
        item["identity_verified"] = False
        item["granted_capabilities"] = []
        item["remote_code_execution"] = False
        item["private_data_access"] = False
        blocked += 1
    _write_registry(registry_path, data)
    summary = {
        "status": "COMPLETED", "checked": checked,
        "enrolled": enrolled, "failed": failed, "blocked": blocked,
        "inbound_capabilities_granted": 0,
    }
    _append_cycle_audit(state_dir, summary)
    return summary
