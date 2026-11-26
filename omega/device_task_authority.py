"""Cryptographic verification for explicit IAO device task requests."""
import base64
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TASK_ACTION = "enqueue_task"
TASK_PATH = "/v1/device/task"
ALLOWED_TASK_KINDS = frozenset({
    "self_check",
    "capability_scan",
    "improvement_plan",
})
MAX_PAYLOAD_BYTES = 8192
CLOCK_SKEW_SECONDS = 60


class DeviceTaskError(ValueError):
    pass


def _fail(code):
    raise DeviceTaskError(code)


def _strict_b64url(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        _fail("INVALID_SIGNATURE_ENCODING")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        _fail("INVALID_SIGNATURE_ENCODING")
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if canonical != value:
        _fail("INVALID_SIGNATURE_ENCODING")
    return raw


def _validate_json_value(value):
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            _fail("INVALID_TASK_PAYLOAD")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            _fail("INVALID_TASK_PAYLOAD")
        for item in value.values():
            _validate_json_value(item)
        return
    _fail("INVALID_TASK_PAYLOAD")


def validate_task_request(request, now=None):
    if not isinstance(request, dict):
        _fail("INVALID_TASK_REQUEST")

    required = {
        "device_id", "action", "kind", "payload",
        "idempotency_key", "timestamp", "nonce", "signature",
    }
    if set(request) != required:
        _fail("INVALID_TASK_SCHEMA")

    device_id = request["device_id"]
    if not isinstance(device_id, str) or not device_id or len(device_id) > 128:
        _fail("INVALID_DEVICE_ID")

    if request["action"] != TASK_ACTION:
        _fail("INVALID_TASK_ACTION")

    kind = request["kind"]
    if not isinstance(kind, str) or kind not in ALLOWED_TASK_KINDS:
        _fail("TASK_KIND_NOT_ALLOWED")

    payload = request["payload"]
    if not isinstance(payload, dict):
        _fail("INVALID_TASK_PAYLOAD")
    _validate_json_value(payload)

    try:
        encoded_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail("INVALID_TASK_PAYLOAD")

    if len(encoded_payload) > MAX_PAYLOAD_BYTES:
        _fail("TASK_PAYLOAD_TOO_LARGE")

    idem = request["idempotency_key"]
    if not isinstance(idem, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idem):
        _fail("INVALID_IDEMPOTENCY_KEY")

    timestamp = request["timestamp"]
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        _fail("INVALID_TIMESTAMP")

    current = int(time.time()) if now is None else int(now)
    if abs(current - timestamp) > CLOCK_SKEW_SECONDS:
        _fail("TIMESTAMP_OUT_OF_RANGE")

    nonce = request["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        _fail("INVALID_NONCE")

    _strict_b64url(request["signature"])

    return {
        "device_id": device_id,
        "action": TASK_ACTION,
        "kind": kind,
        "payload": payload,
        "idempotency_key": idem,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": request["signature"],
    }


def canonical_task_bytes(request):
    fields = {
        key: request[key]
        for key in (
            "device_id", "action", "kind", "payload",
            "idempotency_key", "timestamp",
        )
    }
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def signature_message(request):
    digest = hashlib.sha256(canonical_task_bytes(request)).hexdigest()
    return (
        "POST\n" + TASK_PATH + "\n"
        + str(request["timestamp"]) + "\n"
        + request["nonce"] + "\n" + digest
    ).encode("utf-8")


def verify_task_signature(public_key_pem, request, now=None):
    """Verify signature only; this does not authorize or enqueue a task."""
    validated = validate_task_request(request, now=now)

    try:
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode("ascii")
        if not isinstance(public_key_pem, bytes):
            _fail("INVALID_DEVICE_PUBLIC_KEY")
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception:
        _fail("INVALID_DEVICE_PUBLIC_KEY")

    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
    ):
        _fail("INVALID_DEVICE_PUBLIC_KEY")

    signature = _strict_b64url(validated["signature"])
    try:
        public_key.verify(
            signature,
            signature_message(validated),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        _fail("INVALID_TASK_SIGNATURE")
    except Exception:
        _fail("INVALID_TASK_SIGNATURE")

    return {
        "device_id": validated["device_id"],
        "action": validated["action"],
        "kind": validated["kind"],
        "payload": validated["payload"],
        "idempotency_key": validated["idempotency_key"],
        "timestamp": validated["timestamp"],
        "nonce": validated["nonce"],
        "signature_valid": True,
    }
