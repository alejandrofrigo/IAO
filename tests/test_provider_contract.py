from __future__ import annotations

import json

import pytest

from omega.provider_contract import (
    MAX_RESPONSE_BYTES,
    ProviderContractError,
    parse_chat_response,
    validate_chat_messages,
    validate_provider_config,
)


def valid_provider():
    return {
        "id": "primary",
        "url": "https://gateway.example/v1",
        "model": "test-model",
        "key_env": "MODEL_API_KEY",
        "capabilities": ["chat.completion"],
        "modalities": ["text"],
        "timeout_seconds": 20,
        "cost_per_1k_tokens": 0.25,
        "priority": 10,
    }


def test_valid_provider_config_is_accepted_without_resolving_secret():
    assert validate_provider_config(valid_provider())["key_env"] == "MODEL_API_KEY"


@pytest.mark.parametrize("patch,code", [
    ({"url": "http://gateway.example"}, "PROVIDER_URL_INVALID"),
    ({"url": "https://user:pass@gateway.example"}, "PROVIDER_URL_INVALID"),
    ({"id": "invalid id"}, "PROVIDER_ID_INVALID"),
    ({"key_env": "bad-name"}, "PROVIDER_SECRET_REFERENCE_INVALID"),
    ({"timeout_seconds": 121}, "PROVIDER_TIMEOUT_INVALID"),
    ({"cost_per_1k_tokens": float("nan")}, "PROVIDER_COST_INVALID"),
    ({"priority": True}, "PROVIDER_PRIORITY_INVALID"),
])
def test_provider_config_rejects_invalid_values(patch, code):
    value = valid_provider()
    value.update(patch)
    with pytest.raises(ProviderContractError, match=code):
        validate_provider_config(value)


def test_messages_are_bounded_and_have_exact_role_content_shape():
    valid = validate_chat_messages([{"role": "user", "content": "hello"}])
    assert valid == [{"role": "user", "content": "hello"}]
    with pytest.raises(ProviderContractError, match="PROVIDER_REQUEST_INVALID"):
        validate_chat_messages([{"role": "tool", "content": "not allowed"}])
    with pytest.raises(ProviderContractError, match="PROVIDER_MESSAGE_TOO_LARGE"):
        validate_chat_messages([{"role": "user", "content": "x" * 300_000}])


def test_provider_response_contract_accepts_only_bounded_text():
    raw = json.dumps({
        "model": "upstream-model",
        "choices": [{"message": {"content": "safe answer"}}],
    }).encode()
    assert parse_chat_response(raw) == ("safe answer", "upstream-model")
    with pytest.raises(ProviderContractError, match="PROVIDER_RESPONSE_INVALID"):
        parse_chat_response(b'{"choices":[]}')
    with pytest.raises(ProviderContractError, match="PROVIDER_RESPONSE_INVALID"):
        parse_chat_response(b'not-json')
    with pytest.raises(ProviderContractError, match="PROVIDER_RESPONSE_INVALID"):
        parse_chat_response(b"x" * (MAX_RESPONSE_BYTES + 1))
