"""
Authorization utilities for federated participants.

Provides a thread‑safe in‑memory registry of Ed25519 public keys that are
allowed to participate in federation operations (e.g., proposal submission,
candidate assimilation). The registry can be persisted to a JSON file
specified by the environment variable `FEDERATION_AUTH_FILE` or defaults
to `omega/authorized_keys.json`.

The module deliberately does not perform any network calls or automatic
registration of external participants; it only offers a safe API for the
operator to manage the whitelist.
"""

import json
import os
import threading
from typing import Set

__all__ = [
    "AuthorizationError",
    "is_authorized",
    "authorize_key",
    "revoke_key",
    "load_authorized_keys",
    "save_authorized_keys",
]

_lock = threading.RLock()
_authorized_keys: Set[str] = set()


class AuthorizationError(RuntimeError):
    """Raised when an operation is attempted with an unauthorized key."""
    pass


def _default_auth_file() -> str:
    """Return the default path for persisting authorized keys."""
    base_dir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_dir, "authorized_keys.json")


def load_authorized_keys(path: str | None = None) -> None:
    """Load the set of authorized public keys from *path*.

    The file format is a JSON array of hex‑encoded Ed25519 public keys.
    Missing or malformed files are ignored (the registry remains empty).
    """
    global _authorized_keys
    file_path = path or os.getenv("FEDERATION_AUTH_FILE", _default_auth_file())
    if not os.path.isfile(file_path):
        return
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            with _lock:
                _authorized_keys = {str(k) for k in data}
    except Exception:
        # Preserve current set on error; do not raise to avoid breaking startup.
        pass


def save_authorized_keys(path: str | None = None) -> None:
    """Persist the current authorized key set to *path* atomically."""
    file_path = path or os.getenv("FEDERATION_AUTH_FILE", _default_auth_file())
    temp_path = f"{file_path}.tmp"
    with _lock:
        data = list(_authorized_keys)
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(temp_path, file_path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def is_authorized(pub_key_hex: str) -> bool:
    """Return ``True`` if *pub_key_hex* is in the authorized set."""
    with _lock:
        return pub_key_hex in _authorized_keys


def authorize_key(pub_key_hex: str) -> None:
    """Add *pub_key_hex* to the authorized set and persist the change."""
    with _lock:
        _authorized_keys.add(pub_key_hex)
    save_authorized_keys()


def revoke_key(pub_key_hex: str) -> None:
    """Remove *pub_key_hex* from the authorized set and persist the change."""
    with _lock:
        if pub_key_hex in _authorized_keys:
            _authorized_keys.remove(pub_key_hex)
        else:
            raise AuthorizationError(f"Key not authorized: {pub_key_hex}")
    save_authorized_keys()
