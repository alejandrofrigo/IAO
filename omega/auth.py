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


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_token(key: str, subject: str, scopes: list[str], ttl: int = 3600, now: float | None = None) -> str:
    t = time.time() if now is None else now
    payload = _b64(json.dumps({"sub": subject, "scopes": sorted(scopes), "exp": int(t) + ttl}, sort_keys=True).encode())
    sig = _b64(hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_token(key: str, token: str, now: float | None = None) -> Principal | None:
    try:
        payload, sig = token.split(".", 1)
        expected = _b64(hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload))
        if int(data["exp"]) < (time.time() if now is None else now):
            return None
        sub = data["sub"]
        if not isinstance(sub, str) or not sub:
            return None
        return Principal(sub, frozenset(str(s) for s in data["scopes"]))
    except Exception:
        return None
