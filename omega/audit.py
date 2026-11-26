import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def event_hash(event: dict[str, Any], previous_hash: str, key: bytes | None = None) -> str:
    payload = previous_hash.encode() + b"\n" + canonical_json(event)
    if key is not None:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def make_event(
    event_type: str,
    subject: str,
    details: dict[str, Any],
    previous_hash: str,
    key: bytes | None = None,
) -> dict[str, Any]:
    body = {
        "event_type": event_type,
        "subject": subject,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return {**body, "previous_hash": previous_hash, "event_hash": event_hash(body, previous_hash, key)}


def verify_chain(events: list[dict[str, Any]], key: bytes | None = None) -> tuple[bool, int | None]:
    """Return (ok, index_of_first_inconsistency). Detects edit, delete, reorder (AUD-01)."""
    prev = GENESIS_HASH
    for i, ev in enumerate(events):
        if ev.get("previous_hash") != prev:
            return False, i
        body = {k: v for k, v in ev.items() if k not in ("previous_hash", "event_hash")}
        if ev.get("event_hash") != event_hash(body, prev, key):
            return False, i
        prev = ev["event_hash"]
    return True, None
