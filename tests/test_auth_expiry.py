import base64
import hashlib
import hmac
import json
import string

from omega.auth import issue_token, verify_token


def _signed_payload(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.new(("k" * 32).encode(), encoded.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return encoded + "." + signature


def test_token_is_rejected_at_exact_expiry_boundary():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=1, now=100)
    assert verify_token("k" * 32, token, now=100.999) is not None
    assert verify_token("k" * 32, token, now=101) is None


def test_token_is_rejected_after_expiry():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=1, now=100)
    assert verify_token("k" * 32, token, now=102) is None


def test_token_is_rejected_with_wrong_key():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=60, now=100)
    assert verify_token("x" * 32, token, now=101) is None


def test_verifier_rejects_non_integer_expiry_and_boolean_expiry():
    for expiry in ("200", True, 200.0):
        token = _signed_payload({"sub": "operator:test", "scopes": ["chat.read"], "exp": expiry})
        assert verify_token("k" * 32, token, now=100) is None


def test_verifier_rejects_duplicate_claims():
    encoded = base64.urlsafe_b64encode(
        b'{"sub":"operator:test","sub":"operator:other","scopes":[],"exp":200}'
    ).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.new(("k" * 32).encode(), encoded.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert verify_token("k" * 32, encoded + "." + signature, now=100) is None


def test_verifier_rejects_unknown_claims_and_malformed_scopes():
    assert verify_token(
        "k" * 32,
        _signed_payload({"sub": "operator:test", "scopes": [], "exp": 200, "admin": True}),
        now=100,
    ) is None
    assert verify_token(
        "k" * 32,
        _signed_payload({"sub": "operator:test", "scopes": [1], "exp": 200}),
        now=100,
    ) is None


def test_verifier_rejects_noncanonical_or_invalid_base64url_even_with_valid_hmac():
    key = "k" * 32
    for payload in ("***", "eyJzdWJpOiJ4In0=", "eyJzdWJpOiJ4In0"):
        signature = base64.urlsafe_b64encode(
            hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        assert verify_token(key, payload + "." + signature, now=100) is None


def test_verifier_rejects_nonzero_base64url_pad_bits_with_valid_hmac():
    key = "k" * 32
    canonical = _signed_payload(
        {"sub": "operator:test", "scopes": ["chat.read"], "exp": 200}
    ).split(".", 1)[0]
    alphabet = string.ascii_letters + string.digits + "-_"
    original = base64.urlsafe_b64decode(canonical + "=" * (-len(canonical) % 4))
    alternate = None
    for char in alphabet:
        candidate = canonical[:-1] + char
        if candidate != canonical:
            decoded = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
            if decoded == original:
                alternate = candidate
                break
    assert alternate is not None
    signature = base64.urlsafe_b64encode(
        hmac.new(key.encode(), alternate.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert verify_token(key, alternate + "." + signature, now=100) is None
