"""DEV-ONLY signed bearer tokens (HMAC-SHA256).

These tokens authenticate a principal and carry bounded capability labels.
They do not establish operator identity: operator sessions must additionally
be bound to the durable root identity authority. This is not OIDC.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any

MAX_TOKEN_LENGTH = 16_384
MAX_SUBJECT_LENGTH = 256
MAX_SCOPES = 64
MAX_SCOPE_LENGTH = 128
MAX_TOKEN_TTL_SECONDS = 86_400
_SCOPE_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value):
        raise ValueError("invalid_base64url")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
    )
    if _b64(decoded) != value:
        raise ValueError("noncanonical_base64url")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_claim")
        result[key] = value
    return result


def _valid_subject(subject: Any) -> bool:
    return (
        isinstance(subject, str)
        and 1 <= len(subject) <= MAX_SUBJECT_LENGTH
        and all(ord(char) >= 0x21 and ord(char) != 0x7F for char in subject)
    )


def _valid_scopes(scopes: Any) -> bool:
    return (
        isinstance(scopes, list)
        and len(scopes) <= MAX_SCOPES
        and all(
            isinstance(scope, str)
            and len(scope) <= MAX_SCOPE_LENGTH
            and _SCOPE_RE.fullmatch(scope) is not None
            for scope in scopes
        )
        and len(set(scopes)) == len(scopes)
    )


def issue_token(
    key: str, subject: str, scopes: list[str],
    ttl: int = 3600, now: float | None = None,
) -> str:
    """Issue a bounded development bearer token with a strict claim schema."""
    if not isinstance(key, str) or not key:
        raise ValueError("invalid_signing_key")
    if not _valid_subject(subject):
        raise ValueError("invalid_subject")
    if not _valid_scopes(scopes):
        raise ValueError("invalid_scopes")
    if (
        isinstance(ttl, bool) or not isinstance(ttl, int)
        or not 1 <= ttl <= MAX_TOKEN_TTL_SECONDS
    ):
        raise ValueError("invalid_ttl")
    timestamp = time.time() if now is None else now
    if (
        isinstance(timestamp, bool) or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
    ):
        raise ValueError("invalid_timestamp")
    payload = _b64(json.dumps(
        {"sub": subject, "scopes": sorted(scopes), "exp": int(timestamp) + ttl},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii"))
    signature = _b64(
        hmac.new(key.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def verify_token(
    key: str, token: str, now: float | None = None,
) -> Principal | None:
    """Verify signature, canonical encoding, expiry and every claim type."""
    try:
        if (
            not isinstance(key, str) or not key
            or not isinstance(token, str)
            or len(token) > MAX_TOKEN_LENGTH
            or token.count(".") != 1
        ):
            return None
        payload, signature = token.split(".", 1)
        if not _B64URL_RE.fullmatch(signature):
            return None
        expected = _b64(hmac.new(
            key.encode("utf-8"), payload.encode("ascii"), hashlib.sha256,
        ).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        raw = _unb64(payload)
        data = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) != {"sub", "scopes", "exp"}:
            return None
        if not _valid_subject(data["sub"]) or not _valid_scopes(data["scopes"]):
            return None
        expiry = data["exp"]
        if isinstance(expiry, bool) or not isinstance(expiry, int):
            return None
        timestamp = time.time() if now is None else now
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
            or expiry <= timestamp
        ):
            return None
        return Principal(data["sub"], frozenset(data["scopes"]))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return None
