"""Versioned, strict task-intent contract for IAO execution.

Models and clients may propose intent data; only the service validates and
persists this bounded contract. This module has no execution or authority.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Any


CONTRACT_VERSION = "1.0"
_MAX_INPUT_BYTES = 48 * 1024
_MAX_DEPTH = 12
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class TaskContractError(ValueError):
    """Raised when a persisted task intent violates its versioned contract."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > _MAX_DEPTH:
        raise TaskContractError("TASK_INPUT_TOO_DEEP")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TaskContractError("TASK_INPUT_INVALID")
            _json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _json_depth(item, depth + 1)
    elif value is None or isinstance(value, (str, bool, int)):
        return depth
    elif isinstance(value, float) and math.isfinite(value):
        return depth
    else:
        raise TaskContractError("TASK_INPUT_INVALID")
    return depth


def validate_task_intent_v1(intent: Any) -> dict[str, Any]:
    """Validate and return a JSON-safe copy of the canonical v1 task intent."""
    if not isinstance(intent, dict):
        raise TaskContractError("TASK_INTENT_INVALID")
    required = {
        "contract_version", "goal", "allowed_capabilities", "authorized_scopes",
        "input", "request_digest", "operator_session_digest", "operator_device_id",
        "risk_class", "budget", "termination_condition", "policy_version", "expires_at",
    }
    if set(intent) != required:
        raise TaskContractError("TASK_INTENT_FIELDS_INVALID")
    if intent["contract_version"] != CONTRACT_VERSION:
        raise TaskContractError("TASK_CONTRACT_VERSION_UNSUPPORTED")
    goal = intent["goal"]
    if goal is not None and (not isinstance(goal, str) or not 1 <= len(goal) <= 4000):
        raise TaskContractError("TASK_GOAL_INVALID")
    capabilities = intent["allowed_capabilities"]
    scopes = intent["authorized_scopes"]
    if (
        not isinstance(capabilities, list) or len(capabilities) > 1
        or any(not isinstance(v, str) or not v or len(v) > 128 for v in capabilities)
        or len(set(capabilities)) != len(capabilities)
    ):
        raise TaskContractError("TASK_CAPABILITIES_INVALID")
    if (
        not isinstance(scopes, list) or len(scopes) > 64
        or any(not isinstance(v, str) or not v or len(v) > 128 for v in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        raise TaskContractError("TASK_SCOPES_INVALID")
    payload = intent["input"]
    if not isinstance(payload, dict):
        raise TaskContractError("TASK_INPUT_INVALID")
    _json_depth(payload)
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TaskContractError("TASK_INPUT_INVALID") from None
    if len(encoded) > _MAX_INPUT_BYTES:
        raise TaskContractError("TASK_INPUT_TOO_LARGE")
    if not isinstance(intent["request_digest"], str) or not _DIGEST_RE.fullmatch(intent["request_digest"]):
        raise TaskContractError("TASK_REQUEST_DIGEST_INVALID")
    for field in ("operator_session_digest", "operator_device_id"):
        value = intent[field]
        if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 256):
            raise TaskContractError("TASK_OPERATOR_BINDING_INVALID")
    if intent["risk_class"] != "R0":
        raise TaskContractError("TASK_RISK_CLASS_UNSUPPORTED")
    budget = intent["budget"]
    if not isinstance(budget, dict) or set(budget) != {"max_model_calls", "timeout_seconds"}:
        raise TaskContractError("TASK_BUDGET_INVALID")
    calls, timeout = budget["max_model_calls"], budget["timeout_seconds"]
    if isinstance(calls, bool) or not isinstance(calls, int) or not 0 <= calls <= 100:
        raise TaskContractError("TASK_BUDGET_INVALID")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or not 0 < timeout <= 300:
        raise TaskContractError("TASK_BUDGET_INVALID")
    if not isinstance(intent["termination_condition"], str) or not 1 <= len(intent["termination_condition"]) <= 256:
        raise TaskContractError("TASK_TERMINATION_INVALID")
    if not isinstance(intent["policy_version"], str) or not 1 <= len(intent["policy_version"]) <= 128:
        raise TaskContractError("TASK_POLICY_VERSION_INVALID")
    if not isinstance(intent["expires_at"], str):
        raise TaskContractError("TASK_EXPIRY_INVALID")
    try:
        expires = datetime.fromisoformat(intent["expires_at"])
    except ValueError:
        raise TaskContractError("TASK_EXPIRY_INVALID") from None
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise TaskContractError("TASK_EXPIRY_INVALID")
    # Canonical JSON round-trip also detaches caller-owned nested containers.
    try:
        return json.loads(json.dumps(intent, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TaskContractError("TASK_INTENT_INVALID") from None
