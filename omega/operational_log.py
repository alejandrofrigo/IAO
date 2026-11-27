"""Private, redacted operational JSONL logging."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

_REDACTED_FIELDS = {
    "backup", "command", "content", "input", "message", "output",
    "prompt", "query", "source", "stderr", "stdout", "traceback",
    "working_changes",
}
_PATH_FIELDS = {"file", "path"}
_COUNT_FIELDS = {"files", "paths"}
_SAFE_STRING_FIELDS = {
    "time", "timestamp", "event", "component", "phase", "status", "state",
    "method", "route_group", "cid", "decision", "policy_version",
    "authority", "identity_verification", "enrollment", "motor", "engine",
}
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:+-]{1,128}\Z")
_SAFE_CAPABILITY_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_SAFE_REASON_CODES = {
    "TIMEOUT",
    "NONZERO_EXIT",
    "INVALID_REPORT",
    "PADGE_EXIT_NONZERO",
    "PADGE_CYCLE_REJECTED",
    "NO_NEW_REPORT_OR_CYCLE_RESULT",
    "PROMOTION_NOT_VERIFIED",
    "NO_PYTHON_FILES_IN_CANDIDATE",
    "PREFLIGHT_COMPONENT_MISSING",
    "RATE_LIMITED",
}


def _digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        encoded = str(type(value).__name__)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def sanitize_log_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact free-form content and filesystem paths while retaining safe metrics."""
    safe: dict[str, Any] = {}
    for key, value in data.items():
        normalized = str(key).lower()
        if normalized in _REDACTED_FIELDS:
            safe[f"{normalized}_digest"] = _digest(value) if normalized in {
                "content", "input", "message", "prompt", "query",
            } else "[REDACTED]"
        elif normalized in _PATH_FIELDS:
            safe[f"{normalized}_redacted"] = True
        elif normalized in _COUNT_FIELDS:
            safe[f"{normalized}_count"] = len(value) if isinstance(value, (list, tuple, set)) else 0
        elif normalized == "goal":
            safe["goal_digest"] = _digest(value)
        elif normalized == "reason":
            if isinstance(value, str) and value in _SAFE_REASON_CODES:
                safe["reason"] = value
            else:
                safe["reason_digest"] = _digest(value)
        elif normalized == "error":
            if isinstance(value, BaseException):
                error_type = type(value).__name__
            elif isinstance(value, str):
                match = re.match(r"([A-Za-z_][A-Za-z0-9_.]*)", value)
                error_type = match.group(1) if match else "REDACTED"
            else:
                error_type = type(value).__name__
            safe["error_type"] = error_type
        elif isinstance(value, dict):
            safe[normalized] = sanitize_log_data(value)
        elif isinstance(value, (list, tuple)):
            if (
                normalized == "capabilities"
                and all(
                    isinstance(item, str) and _SAFE_CAPABILITY_RE.fullmatch(item)
                    for item in value
                )
            ):
                safe[normalized] = list(value)
            elif all(isinstance(item, dict) for item in value):
                safe[normalized] = [sanitize_log_data(item) for item in value]
            else:
                safe[f"{normalized}_digest"] = _digest(value)
        elif isinstance(value, str):
            if (
                normalized in _SAFE_STRING_FIELDS
                and _SAFE_TOKEN_RE.fullmatch(value)
            ):
                safe[normalized] = value
            else:
                safe[f"{normalized}_digest"] = _digest(value)
        else:
            safe[normalized] = value
    return safe


def append_private_jsonl(path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    """Append one sanitized event to a private directory/file, refusing symlinks."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            safe_entry = sanitize_log_data(entry)
            stream.write(json.dumps(safe_entry, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return safe_entry
