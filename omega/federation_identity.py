"""Persistent local Ed25519 identity for IAO federation."""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_PATH = Path(".state/federation-node-ed25519.key")


def load_or_create_key(path: Path = KEY_PATH) -> Ed25519PrivateKey:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    if path.is_symlink():
        raise RuntimeError("IDENTITY_PATH_MUST_NOT_BE_SYMLINK")

    if path.exists():
        if not path.is_file():
            raise RuntimeError("IDENTITY_PATH_NOT_REGULAR_FILE")
        os.chmod(path, 0o600)
        raw = path.read_bytes()
        if len(raw) != 32:
            raise RuntimeError("IDENTITY_KEY_INVALID_LENGTH")
        return Ed25519PrivateKey.from_private_bytes(raw)

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        # Another process created the identity first; load that identity.
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("IDENTITY_PATH_NOT_REGULAR_FILE")
        os.chmod(path, 0o600)
        existing = path.read_bytes()
        if len(existing) != 32:
            raise RuntimeError("IDENTITY_KEY_INVALID_LENGTH")
        return Ed25519PrivateKey.from_private_bytes(existing)

    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise

    os.chmod(path, 0o600)
    return key


def public_identity(key: Ed25519PrivateKey) -> tuple[str, str]:
    import hashlib

    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_raw).hexdigest()[:16], public_raw.hex()
