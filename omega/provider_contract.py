"""Strict provider and chat protocol contract for OpenAI-compatible gateways."""
from __future__ import annotations

import json
import math
import re
from typing import Any
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 2_000_000
MAX_MESSAGE_BYTES = 256_000
MAX_MESSAGES = 128
MAX_TIMEOUT_SECONDS = 120.0

_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MODEL = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")


class ProviderContractError(ValueError):
    """A provider config, request, or response violates the bounded protocol."""


def validate_provider_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderContractError("PROVIDER_CONFIG_INVALID")
    ident = value.get("id")
    url = value.get("url")
    model = value.get("model")
    if not isinstance(ident, str) or not _ID.fullmatch(ident):
        raise ProviderContractError("PROVIDER_ID_INVALID")
    if not isinstance(url, str) or len(url) > 2048:
        raise ProviderContractError("PROVIDER_URL_INVALID")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ProviderContractError("PROVIDER_URL_INVALID") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or any(ord(ch) < 32 for ch in url)
    ):
        raise ProviderContractError("PROVIDER_URL_INVALID")
    if not isinstance(model, str) or not _MODEL.fullmatch(model.strip()):
        raise ProviderContractError("PROVIDER_MODEL_INVALID")
    key_env = value.get("key_env", "")
    if key_env and (not isinstance(key_env, str) or not _ENV.fullmatch(key_env)):
        raise ProviderContractError("PROVIDER_SECRET_REFERENCE_INVALID")
    for field in ("capabilities", "modalities"):
        items = value.get(field)
        if items is not None and (
            not isinstance(items, list)
            or any(not isinstance(item, str) or not _CAPABILITY.fullmatch(item) for item in items)
            or len(items) != len(set(items))
        ):
            raise ProviderContractError("PROVIDER_CAPABILITIES_INVALID")
    cost = value.get("cost_per_1k_tokens")
    if cost is not None and (
        isinstance(cost, bool)
        or not isinstance(cost, (int, float))
        or not math.isfinite(float(cost))
        or cost < 0
    ):
        raise ProviderContractError("PROVIDER_COST_INVALID")
    timeout = value.get("timeout_seconds")
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0 < timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise ProviderContractError("PROVIDER_TIMEOUT_INVALID")
    priority = value.get("priority", 100)
    if isinstance(priority, bool) or not isinstance(priority, int) or not -1000 <= priority <= 1000:
        raise ProviderContractError("PROVIDER_PRIORITY_INVALID")
    return dict(value)


def validate_chat_messages(messages: Any) -> list[dict[str, str]]:
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ProviderContractError("PROVIDER_REQUEST_INVALID")
    normalized: list[dict[str, str]] = []
    total = 0
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ProviderContractError("PROVIDER_REQUEST_INVALID")
        role, content = message["role"], message["content"]
        if role not in {"system", "user", "assistant"} or not isinstance(content, str):
            raise ProviderContractError("PROVIDER_REQUEST_INVALID")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise ProviderContractError("PROVIDER_MESSAGE_TOO_LARGE")
        total += len(encoded)
        normalized.append({"role": role, "content": content})
    if total > MAX_REQUEST_BYTES:
        raise ProviderContractError("PROVIDER_REQUEST_TOO_LARGE")
    return normalized


def parse_chat_response(raw: bytes) -> tuple[str, str | None]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID") from exc
    if not isinstance(payload, dict):
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID")
    answer = message.get("content")
    if not isinstance(answer, str) or not answer.strip():
        raise ProviderContractError("PROVIDER_RESPONSE_INVALID")
    if len(answer.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ProviderContractError("PROVIDER_RESPONSE_TOO_LARGE")
    model = payload.get("model")
    if model is not None and (
        not isinstance(model, str) or not _MODEL.fullmatch(model.strip())
    ):
        model = None
    return answer.strip(), model.strip()[:120] if isinstance(model, str) else None
