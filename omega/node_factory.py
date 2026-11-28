"""Create isolated IAO node workspaces without enrolling or trusting them.

Private Ed25519 keys are generated and retained on the machine running the
factory. GitHub Actions only tests this code; it never creates or stores node
private keys. A generated workspace is an identity/bootstrap artifact, not a
running server and not an enrolled federation peer.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omega.federation_identity import load_or_create_key, public_identity

MAX_NODES_PER_BATCH = 10
VALID_ROLES = frozenset({"worker", "observer", "indexer"})


class NodeFactoryError(RuntimeError):
    """Safe, expected node-factory failure."""


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinks in every existing path component, not only the leaf."""
    absolute = path.absolute()
    for component in reversed((absolute, *absolute.parents)):
        if component.is_symlink():
            raise NodeFactoryError("NODE_FACTORY_SYMLINK_REFUSED")


def _write_json_private(path: Path, payload: dict[str, Any]) -> None:
    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise NodeFactoryError("NODE_FACTORY_SYMLINK_REFUSED")
    fd, temp_name = tempfile.mkstemp(prefix=".iao-node-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _safe_output_dir(value: str | Path) -> Path:
    output = Path(value).expanduser()
    _reject_symlink_components(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink() or not output.is_dir():
        raise NodeFactoryError("NODE_FACTORY_OUTPUT_PATH_REFUSED")
    try:
        os.chmod(output, 0o700)
    except OSError:
        pass
    return output


def create_nodes(
    count: int = 1,
    *,
    output_dir: str | Path = ".state/node-factory",
    role: str = "worker",
) -> list[dict[str, str]]:
    """Create count fresh, un-enrolled node identities in a private directory.

    The returned records contain public metadata and filesystem paths only.
    No private key bytes, credentials, endpoint, trust grant, or execution
    authority are returned or written to the public manifest.
    """
    if isinstance(count, bool) or not isinstance(count, int):
        raise NodeFactoryError("INVALID_NODE_COUNT")
    if not 1 <= count <= MAX_NODES_PER_BATCH:
        raise NodeFactoryError("NODE_COUNT_OUT_OF_RANGE")
    if not isinstance(role, str) or role not in VALID_ROLES:
        raise NodeFactoryError("INVALID_NODE_ROLE")

    root = _safe_output_dir(output_dir)
    created: list[dict[str, str]] = []
    created_paths: list[Path] = []
    try:
        for _ in range(count):
            nonce = secrets.token_hex(4)
            staging = root / (".staging-" + nonce)
            staging.mkdir(mode=0o700)
            try:
                identity_dir = staging / "identity"
                identity_dir.mkdir(mode=0o700)
                key_path = identity_dir / "private.key"
                key = load_or_create_key(key_path)
                node_id, public_key_hex = public_identity(key)
                node_dir = root / f"node-{node_id}"
                if node_dir.exists() or node_dir.is_symlink():
                    raise NodeFactoryError("NODE_DIRECTORY_ALREADY_EXISTS")

                identity = {
                    "protocol": "iao-federation",
                    "version": 1,
                    "node_id": node_id,
                    "public_key": public_key_hex,
                }
                manifest = {
                    "schema": 1,
                    "protocol": "iao-federation",
                    "node_id": node_id,
                    "role": role,
                    "status": "CREATED_UNENROLLED",
                    "authority": "NONE",
                    "capabilities": [],
                    "endpoint": None,
                    "enrollment": "NOT_REQUESTED",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                _write_json_private(staging / "identity" / "public.json", identity)
                _write_json_private(staging / "manifest.json", manifest)
                readme = (
                    "# IAO node workspace\n\n"
                    f"- Node ID: `{node_id}`\n"
                    f"- Role: `{role}`\n"
                    "- State: `CREATED_UNENROLLED`\n"
                    "- Authority: `NONE`\n"
                    "- Capabilities: none\n\n"
                    "This workspace is not a running server and is not trusted or "
                    "enrolled. Deploy only on infrastructure you control. Configure "
                    "a real authenticated transport and complete the federation "
                    "verification/enrollment protocol before granting even read-only "
                    "capabilities. Never commit identity/private.key.\n"
                )
                (staging / "README.md").write_text(readme, encoding="utf-8")
                os.chmod(staging / "README.md", 0o600)
                os.replace(staging, node_dir)
                created_paths.append(node_dir)
                try:
                    os.chmod(node_dir, 0o700)
                except OSError:
                    pass
                created.append({
                    "node_id": node_id,
                    "role": role,
                    "status": "CREATED_UNENROLLED",
                    "directory": str(node_dir),
                })
            except Exception:
                if staging.exists() and not staging.is_symlink():
                    import shutil
                    shutil.rmtree(staging, ignore_errors=True)
                raise
    except Exception as exc:
        import shutil
        rollback_failed = False
        for node_dir in reversed(created_paths):
            if node_dir.is_symlink():
                rollback_failed = True
                continue
            if node_dir.exists():
                try:
                    shutil.rmtree(node_dir)
                except OSError:
                    rollback_failed = True
        if rollback_failed:
            raise NodeFactoryError("NODE_BATCH_ROLLBACK_INCOMPLETE") from exc
        raise
    return created


def inspect_nodes(output_dir: str | Path = ".state/node-factory") -> list[dict[str, str]]:
    """Return validated public manifest summaries; never reads private keys."""
    root = Path(output_dir).expanduser()
    _reject_symlink_components(root)
    if not root.exists():
        return []
    if not root.is_dir():
        raise NodeFactoryError("NODE_FACTORY_OUTPUT_PATH_REFUSED")

    results: list[dict[str, str]] = []
    for node_dir in sorted(root.glob("node-*")):
        if node_dir.is_symlink() or not node_dir.is_dir():
            continue
        identity_dir = node_dir / "identity"
        manifest_path = node_dir / "manifest.json"
        public_path = identity_dir / "public.json"
        if (
            identity_dir.is_symlink()
            or manifest_path.is_symlink()
            or public_path.is_symlink()
        ):
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            identity = json.loads(public_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # Valid JSON is not necessarily a valid object. Treat null, arrays and
        # scalar documents as corrupt inventory entries rather than crashing
        # the whole inspection cycle.
        if not isinstance(manifest, dict) or not isinstance(identity, dict):
            continue
        public_key_hex = identity.get("public_key")
        node_id = identity.get("node_id")
        if (
            (type(manifest.get("schema")) is not int or manifest.get("schema") != 1)
            or manifest.get("status") != "CREATED_UNENROLLED"
            or manifest.get("authority") != "NONE"
            or manifest.get("capabilities") != []
            or not isinstance(manifest.get("role"), str)
            or manifest.get("role") not in VALID_ROLES
            or identity.get("protocol") != "iao-federation"
            or (type(identity.get("version")) is not int or identity.get("version") != 1)
            or not isinstance(node_id, str)
            or len(node_id) != 16
            or not isinstance(public_key_hex, str)
            or len(public_key_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in public_key_hex)
            or identity.get("node_id") != manifest.get("node_id")
        ):
            continue
        # Recompute the node fingerprint from the actual public key. Matching
        # two attacker-edited node_id fields is not proof of key consistency.
        import hashlib
        try:
            public_key = bytes.fromhex(public_key_hex)
        except ValueError:
            continue
        if hashlib.sha256(public_key).hexdigest()[:16] != node_id:
            continue
        results.append({
            "node_id": str(manifest["node_id"]),
            "role": str(manifest["role"]),
            "status": str(manifest["status"]),
            "directory": str(node_dir),
        })
    return results
