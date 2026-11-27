"""Regression tests for the closed, bounded IAO command envelope."""
import base64
import copy
import json
import uuid

import pytest

from omega.command_protocol import (
    CommandEnvelopeError,
    canonical_command_bytes,
    command_digest,
    parse_command_envelope,
    validate_command_envelope,
)


def envelope(now=1_800_000_000):
    signature = base64.urlsafe_b64encode(b"x" * 70).decode().rstrip("=")
    return {
        "schema": "iao.command.v1",
        "audience": "iao-command-ingress",
        "command_id": str(uuid.UUID(int=1)),
        "issuer": "operator",
        "device_id": "a" * 64,
        "issued_at": now,
        "expires_at": now + 60,
        "nonce": "A" * 32,
        "command": "status.read",
        "capabilities": ["status.read"],
        "body": {"scope": "self"},
        "signature": signature,
    }


def test_command_envelope_is_closed_and_canonical():
    value = envelope()
    assert validate_command_envelope(value, now=1_800_000_010) is value
    assert canonical_command_bytes(value, now=1_800_000_010).startswith(b"IAO-COMMAND-V1\x00")
    assert command_digest(value, now=1_800_000_010).startswith("sha256:")


@pytest.mark.parametrize("field", ["schema", "audience", "issuer", "device_id", "nonce", "command"])
def test_command_envelope_rejects_invalid_identity_fields(field):
    value = envelope()
    value[field] = "invalid"
    with pytest.raises(CommandEnvelopeError):
        validate_command_envelope(value, now=1_800_000_010)


def test_command_envelope_rejects_unknown_and_missing_fields():
    value = envelope()
    value["admin"] = True
    with pytest.raises(CommandEnvelopeError, match="FIELDS_INVALID"):
        validate_command_envelope(value, now=1_800_000_010)
    value = envelope()
    del value["signature"]
    with pytest.raises(CommandEnvelopeError, match="FIELDS_INVALID"):
        validate_command_envelope(value, now=1_800_000_010)


def test_command_envelope_rejects_bool_timestamp_and_expired_order():
    value = envelope()
    value["issued_at"] = True
    with pytest.raises(CommandEnvelopeError, match="TIME_INVALID"):
        validate_command_envelope(value, now=1_800_000_010)
    value = envelope()
    with pytest.raises(CommandEnvelopeError, match="EXPIRED"):
        validate_command_envelope(value, now=1_800_000_061)


def test_command_envelope_rejects_duplicate_or_unsorted_capabilities():
    value = envelope()
    value["capabilities"] = ["status.read", "status.read"]
    with pytest.raises(CommandEnvelopeError, match="CAPABILITIES_INVALID"):
        validate_command_envelope(value, now=1_800_000_010)
    value["capabilities"] = ["task.enqueue", "status.read"]
    with pytest.raises(CommandEnvelopeError, match="NOT_CANONICAL"):
        validate_command_envelope(value, now=1_800_000_010)


def test_command_json_rejects_duplicate_members_and_nonfinite_numbers():
    raw = json.dumps(envelope()).replace('"issuer": "operator"', '"issuer": "operator", "issuer": "operator"')
    with pytest.raises(CommandEnvelopeError, match="DUPLICATE_JSON_MEMBER"):
        parse_command_envelope(raw)
    raw = json.dumps(envelope()).replace('"scope": "self"', '"scope": NaN')
    with pytest.raises(CommandEnvelopeError, match="NONFINITE_JSON_NUMBER"):
        parse_command_envelope(raw)


def test_command_body_is_bounded_and_object_only():
    value = envelope()
    value["body"] = {"payload": "x" * 17_000}
    with pytest.raises(CommandEnvelopeError, match="TOO_LARGE"):
        validate_command_envelope(value, now=1_800_000_010)
    value = envelope()
    value["body"] = ["not", "an", "object"]
    with pytest.raises(CommandEnvelopeError, match="BODY_MUST_BE_OBJECT"):
        validate_command_envelope(value, now=1_800_000_010)


def test_signature_must_use_canonical_base64url_encoding():
    value = envelope()
    value["signature"] += "="
    with pytest.raises(CommandEnvelopeError, match="SIGNATURE_ENCODING_INVALID"):
        validate_command_envelope(value, now=1_800_000_010)


def test_command_canonical_bytes_ignore_signature_value():
    first = envelope()
    second = copy.deepcopy(first)
    second["signature"] = base64.urlsafe_b64encode(b"y" * 70).decode().rstrip("=")
    assert canonical_command_bytes(first, now=1_800_000_010) == canonical_command_bytes(
        second, now=1_800_000_010
    )
