"""Versioned, closed schema and canonical bytes for signed IAO commands.

This module validates command data only. A valid envelope is not authorization;
the ingress must still verify device identity, signature, nonce, policy and session.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import uuid
from typing import Any

SCHEMA = "iao.command.v1"
AUDIENCE = "iao-command-ingress"
MAX_ENVELOPE_BYTES = 24 * 1024
MAX_BODY_BYTES = 16 * 1024
MAX_COMMAND_TTL_SECONDS = 120
MAX_CLOCK_SKEW_SECONDS = 30
MAX_CAPABILITIES = 16

_FIELDS = {
    "schema", "audience", "command_id", "issuer", "device_id",
    "issued_at", "expires_at", "nonce", "command", "capabilities",
    "body", "signature",
}
_TOKEN = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{80,128}$")


class CommandEnvelopeError(ValueError):
    """Stable, non-sensitive command envelope validation failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CommandEnvelopeError("DUPLICATE_JSON_MEMBER")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise CommandEnvelopeError("NONFINITE_JSON_NUMBER")


def _json_bytes(value: Any, *, limit: int) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise CommandEnvelopeError("INVALID_JSON_VALUE") from None
    if len(encoded) > limit:
        raise CommandEnvelopeError("COMMAND_ENVELOPE_TOO_LARGE")
    return encoded


def parse_command_envelope(raw: bytes | bytearray | str) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON while rejecting duplicate members and NaN/Infinity."""
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeEncodeError:
            raise CommandEnvelopeError("INVALID_UTF8") from None
    elif isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
    else:
        raise CommandEnvelopeError("INVALID_ENVELOPE_TYPE")
    if not data or len(data) > MAX_ENVELOPE_BYTES:
        raise CommandEnvelopeError("COMMAND_ENVELOPE_TOO_LARGE")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except CommandEnvelopeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise CommandEnvelopeError("INVALID_COMMAND_JSON") from None
    if not isinstance(value, dict):
        raise CommandEnvelopeError("COMMAND_ENVELOPE_MUST_BE_OBJECT")
    validate_command_envelope(value)
    return value


def validate_command_envelope(
    envelope: dict[str, Any], *, now: int | None = None,
) -> dict[str, Any]:
    """Validate schema, bounded fields and time window without granting authority."""
    if not isinstance(envelope, dict):
        raise CommandEnvelopeError("COMMAND_ENVELOPE_MUST_BE_OBJECT")
    if set(envelope) != _FIELDS:
        raise CommandEnvelopeError("COMMAND_ENVELOPE_FIELDS_INVALID")
    if envelope["schema"] != SCHEMA or envelope["audience"] != AUDIENCE:
        raise CommandEnvelopeError("COMMAND_ENVELOPE_VERSION_OR_AUDIENCE_INVALID")
    if envelope["issuer"] != "operator":
        raise CommandEnvelopeError("COMMAND_ISSUER_INVALID")
    try:
        command_id = str(uuid.UUID(envelope["command_id"]))
    except (ValueError, TypeError, AttributeError):
        raise CommandEnvelopeError("COMMAND_ID_INVALID") from None
    if command_id != envelope["command_id"]:
        raise CommandEnvelopeError("COMMAND_ID_NOT_CANONICAL")
    if not isinstance(envelope["device_id"], str) or not _HEX_256.fullmatch(envelope["device_id"]):
        raise CommandEnvelopeError("DEVICE_ID_INVALID")
    issued = envelope["issued_at"]
    expires = envelope["expires_at"]
    if (
        isinstance(issued, bool) or not isinstance(issued, int)
        or isinstance(expires, bool) or not isinstance(expires, int)
    ):
        raise CommandEnvelopeError("COMMAND_TIME_INVALID")
    current = int(time.time()) if now is None else now
    if issued > current + MAX_CLOCK_SKEW_SECONDS:
        raise CommandEnvelopeError("COMMAND_ISSUED_IN_FUTURE")
    if expires < current:
        raise CommandEnvelopeError("COMMAND_EXPIRED")
    if expires <= issued or expires - issued > MAX_COMMAND_TTL_SECONDS:
        raise CommandEnvelopeError("COMMAND_TTL_INVALID")
    if not isinstance(envelope["nonce"], str) or not _NONCE.fullmatch(envelope["nonce"]):
        raise CommandEnvelopeError("COMMAND_NONCE_INVALID")
    if not isinstance(envelope["command"], str) or not _TOKEN.fullmatch(envelope["command"]):
        raise CommandEnvelopeError("COMMAND_TYPE_INVALID")
    caps = envelope["capabilities"]
    if (
        not isinstance(caps, list) or not 1 <= len(caps) <= MAX_CAPABILITIES
        or any(not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in caps)
        or len(set(caps)) != len(caps)
    ):
        raise CommandEnvelopeError("COMMAND_CAPABILITIES_INVALID")
    if caps != sorted(caps):
        raise CommandEnvelopeError("COMMAND_CAPABILITIES_NOT_CANONICAL")
    body = envelope["body"]
    if not isinstance(body, dict):
        raise CommandEnvelopeError("COMMAND_BODY_MUST_BE_OBJECT")
    _json_bytes(body, limit=MAX_BODY_BYTES)
    signature = envelope["signature"]
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        raise CommandEnvelopeError("COMMAND_SIGNATURE_ENCODING_INVALID")
    try:
        decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, binascii.Error):
        raise CommandEnvelopeError("COMMAND_SIGNATURE_ENCODING_INVALID") from None
    canonical_signature = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical_signature != signature or not 64 <= len(decoded) <= 80:
        raise CommandEnvelopeError("COMMAND_SIGNATURE_ENCODING_INVALID")
    return envelope


def canonical_command_bytes(envelope: dict[str, Any], *, now: int | None = None) -> bytes:
    """Return stable signing bytes; signature itself is deliberately excluded."""
    validate_command_envelope(envelope, now=now)
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return b"IAO-COMMAND-V1\\x00" + _json_bytes(unsigned, limit=MAX_ENVELOPE_BYTES)


def command_digest(envelope: dict[str, Any], *, now: int | None = None) -> str:
    """Return a content digest suitable for audit correlation, not authentication."""
    return "sha256:" + hashlib.sha256(canonical_command_bytes(envelope, now=now)).hexdigest()
