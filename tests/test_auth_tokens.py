"""Strict bearer-token schema and capability-claim tests."""
import base64
import hashlib
import hmac
import json

import pytest

from omega.auth import issue_token, verify_token


KEY = "auth-token-test-key-" + "k" * 40


def _signed(raw: bytes) -> str:
    payload = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    signature = base64.urlsafe_b64encode(
        hmac.new(KEY.encode(), payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    return payload + "." + signature


def test_issue_and_verify_round_trip_with_scopes():
    token = issue_token(KEY, "guest:abc123", ["memory.read", "knowledge.search"], ttl=60, now=100)
    principal = verify_token(KEY, token, now=101)
    assert principal is not None
    assert principal.subject == "guest:abc123"
    assert principal.scopes == frozenset({"memory.read", "knowledge.search"})


@pytest.mark.parametrize("ttl", [0, -1, 86401, True, 1.5, "60"])
def test_issue_rejects_invalid_ttl(ttl):
    with pytest.raises(ValueError, match="invalid_ttl"):
        issue_token(KEY, "guest:test", [], ttl=ttl)


@pytest.mark.parametrize("scopes", ["memory.read", [""], ["Memory.Read"], ["x" * 129], ["memory.read"] * 2, [f"scope{i}" for i in range(65)]])
def test_issue_rejects_invalid_scopes(scopes):
    with pytest.raises(ValueError, match="invalid_scopes"):
        issue_token(KEY, "guest:test", scopes)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"sub":"guest:x","scopes":"memory.read","exp":999}',
        b'{"sub":"guest:x","scopes":[1],"exp":999}',
        b'{"sub":"guest:x","scopes":[],"exp":true}',
        b'{"sub":"guest:x","scopes":[],"exp":999,"admin":true}',
        b'{"sub":"guest:x","sub":"operator:x","scopes":[],"exp":999}',
        b'{"sub":"","scopes":[],"exp":999}',
        b'{"sub":"guest:x\\nforged","scopes":[],"exp":999}',
    ],
)
def test_verify_rejects_signed_malformed_claims(raw):
    assert verify_token(KEY, _signed(raw), now=100) is None


def test_expiry_is_exclusive_at_exact_boundary():
    token = issue_token(KEY, "guest:test", [], ttl=60, now=100)
    assert verify_token(KEY, token, now=159.999) is not None
    assert verify_token(KEY, token, now=160) is None


def test_verify_rejects_noncanonical_or_tampered_token():
    token = issue_token(KEY, "guest:test", [], ttl=60, now=100)
    payload, signature = token.split(".")
    assert verify_token(KEY, payload + "." + signature + "=", now=101) is None
    assert verify_token(KEY, token + ".extra", now=101) is None
    assert verify_token(KEY, "!" + token, now=101) is None
    assert verify_token(KEY, token, now=101) is not None


def test_verify_rejects_oversized_token():
    assert verify_token(KEY, "a" * 17000, now=100) is None
