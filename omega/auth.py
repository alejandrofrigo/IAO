"""DEV-ONLY signed bearer tokens (HMAC-SHA256). Not a substitute for OIDC (REQ-01 remains
BLOCKED_EXTERNAL until an OIDC issuer is configured). Tokens are short-lived and scoped."""
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")


def issue_token(key: str, subject: str, scopes: list[str], ttl: int = 3600, now: float | None = None) -> str:
    t = time.time() if now is None else now
    payload = _b64(json.dumps({"sub": subject, "scopes": sorted(scopes), "exp": int(t) + ttl}, sort_keys=True).encode())
    sig = _b64(hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def _reject_duplicate_claims(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate token claim")
        result[name] = value
    return result


def verify_token(key: str, token: str, now: float | None = None) -> Principal | None:
    try:
        if not isinstance(key, str) or not key or not isinstance(token, str) or len(token) > 8192:
            return None
        payload, sig = token.split(".")
        expected = _b64(hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload), object_pairs_hook=_reject_duplicate_claims)
        if not isinstance(data, dict) or set(data) != {"sub", "scopes", "exp"}:
            return None
        exp = data["exp"]
        sub = data["sub"]
        scopes = data["scopes"]
        # Reject bool/string coercion: expiry must be a JSON integer and is exclusive.
        if isinstance(exp, bool) or not isinstance(exp, int):
            return None
        if exp <= (time.time() if now is None else now):
            return None
        if not isinstance(sub, str) or not sub or len(sub) > 256:
            return None
        if (
            not isinstance(scopes, list)
            or len(scopes) > 64
            or any(not isinstance(scope, str) or not scope or len(scope) > 128 for scope in scopes)
        ):
            return None
        return Principal(sub, frozenset(scopes))
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        return None
