from unittest.mock import patch

import pytest

from tools.iao_federation_agent import request_json


@patch("tools.iao_federation_agent.fetch_public_json")
def test_identity_get_uses_pinned_public_https_transport(fetch):
    fetch.return_value = {"node_id": "0123456789abcdef"}
    assert request_json("https://peer.example/fed/v1/identity") == {
        "node_id": "0123456789abcdef"
    }
    fetch.assert_called_once_with(
        "https://peer.example/fed/v1/identity",
        timeout=8.0,
        max_bytes=65536,
    )


@patch("tools.iao_federation_agent.post_public_json")
def test_handshake_post_uses_pinned_public_https_transport(post):
    challenge = {"v": 1, "nonce": "a" * 64}
    response = {"sig": "signed"}
    post.return_value = (200, response)
    assert request_json(
        "https://peer.example/fed/v1/handshake", "POST", challenge
    ) == response
    post.assert_called_once_with(
        "https://peer.example/fed/v1/handshake",
        challenge,
        timeout=8.0,
        max_bytes=65536,
    )


@patch("tools.iao_federation_agent.post_public_json")
def test_handshake_rejects_non_success_status(post):
    post.return_value = (302, {"location": "https://other.example"})
    with pytest.raises(ValueError, match="FEDERATION_HTTP_STATUS_302"):
        request_json("https://peer.example/fed/v1/handshake", "POST", {})


@patch("tools.iao_federation_agent.fetch_public_json")
def test_identity_get_rejects_non_object_json(fetch):
    fetch.return_value = ["not", "an", "object"]
    with pytest.raises(ValueError, match="INVALID_JSON_OBJECT"):
        request_json("https://peer.example/fed/v1/identity")


def test_request_json_rejects_unsupported_method():
    with pytest.raises(ValueError, match="FEDERATION_METHOD_NOT_ALLOWED"):
        request_json("https://peer.example/fed/v1/identity", "DELETE")


def test_load_nodes_preserves_authorization_for_filtered_nodes(tmp_path, monkeypatch):
    import json
    from tools import iao_federation_agent as agent

    config = tmp_path / "nodes.json"
    config.write_text(json.dumps({
        "nodes": [
            {"authorized": True, "id": "0123456789abcdef",
             "url": "https://peer.example"},
            {"authorized": False, "id": "fedcba9876543210",
             "url": "https://ignored.example"},
        ]
    }), encoding="utf-8")
    monkeypatch.setattr(agent, "NODES", config)

    loaded = agent.load_nodes()
    assert loaded["status"] == "VALID"
    assert len(loaded["nodes"]) == 1
    assert loaded["nodes"][0]["authorized"] is True
    assert loaded["nodes"][0]["precheck"] == "URL_ACCEPTED"
    assert loaded["ignored"] == 1
