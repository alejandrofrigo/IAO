"""Independent, verifiable append-only audit ledger for IAO federation."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class FederationLedgerError(RuntimeError):
    pass


class FederationLedger:
    def __init__(self, path: str | Path, key_path: str | Path):
        self.path = Path(path)
        self.key_path = Path(key_path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self.key = self._load_key()
        if self.path.is_symlink():
            raise FederationLedgerError("LEDGER_SYMLINK_REFUSED")
        if self.path.exists() and not self.path.is_file():
            raise FederationLedgerError("LEDGER_NOT_REGULAR_FILE")
        self.path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.path, 0o600)
        self.verify()

    def _load_key(self) -> bytes:
        p = self.key_path
        if p.is_symlink():
            raise FederationLedgerError("LEDGER_KEY_SYMLINK_REFUSED")
        if p.exists():
            if not p.is_file():
                raise FederationLedgerError("LEDGER_KEY_NOT_REGULAR_FILE")
            raw = p.read_bytes()
            if len(raw) != 32:
                raise FederationLedgerError("LEDGER_KEY_INVALID")
            os.chmod(p, 0o600)
            return raw
        raw = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(p), flags, 0o600)
        except FileExistsError:
            if p.is_symlink() or not p.is_file():
                raise FederationLedgerError("LEDGER_KEY_RACE_REFUSED")
            existing = p.read_bytes()
            if len(existing) != 32:
                raise FederationLedgerError("LEDGER_KEY_INVALID")
            return existing
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(p, 0o600)
        return raw

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    def verify(self) -> tuple[bool, int | None]:
        with self._lock:
            if self.path.is_symlink() or not self.path.is_file():
                raise FederationLedgerError("LEDGER_PATH_REFUSED")
            previous = GENESIS
            expected_seq = 1
            try:
                with self.path.open("rb") as stream:
                    for line_no, raw in enumerate(stream, 1):
                        if len(raw) > 65536 or not raw.endswith(b"\n"):
                            return False, line_no
                        item = json.loads(raw)
                        if not isinstance(item, dict):
                            return False, line_no
                        digest = item.pop("hash", None)
                        if item.get("seq") != expected_seq:
                            return False, line_no
                        if item.get("previous_hash") != previous:
                            return False, line_no
                        expected = hmac.new(
                            self.key, self._canonical(item), hashlib.sha256
                        ).hexdigest()
                        if not isinstance(digest, str) or not hmac.compare_digest(
                            digest, expected
                        ):
                            return False, line_no
                        previous = digest
                        expected_seq += 1
            except Exception:
                return False, expected_seq
            return True, None

    def append(self, actor: str, event_type: str, subject: str, **details: Any):
        if not all(isinstance(x, str) and 1 <= len(x) <= 200
                   and not any(ord(c) < 32 for c in x)
                   for x in (actor, event_type, subject)):
            raise FederationLedgerError("INVALID_AUDIT_FIELDS")
        with self._lock:
            if self.path.is_symlink() or self.key_path.is_symlink():
                raise FederationLedgerError("LEDGER_PATH_REFUSED")
            fd = os.open(str(self.path), os.O_RDWR | os.O_APPEND)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                valid, bad = self.verify()
                if not valid:
                    raise FederationLedgerError(
                        "LEDGER_CHAIN_INVALID_AT_" + str(bad)
                    )
                previous = GENESIS
                seq = 1
                with os.fdopen(os.dup(fd), "rb") as stream:
                    for raw in stream:
                        item = json.loads(raw)
                        previous = item["hash"]
                        seq += 1
                payload = {
                    "seq": seq,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": actor,
                    "event_type": event_type,
                    "subject": subject,
                    "details": details,
                    "previous_hash": previous,
                }
                digest = hmac.new(
                    self.key, self._canonical(payload), hashlib.sha256
                ).hexdigest()
                record = dict(payload, hash=digest)
                data = self._canonical(record) + b"\n"
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
                return record
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
