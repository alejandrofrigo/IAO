import json
from tools import iao_federation_agent as agent


def test_authorized_https_node_keeps_authorization(monkeypatch, tmp_path):
    config = tmp_path / "nodes.json"
    config.write_text(json.dumps({
        "nodes": [
            {
                "authorized": True,
                "id": "9db367aad0b70421",
                "url": "https://peer.example/fed/v1/message",
            },
            {
                "authorized": False,
                "id": "27c866ccff9c380e",
                "url": "https://untrusted.example",
            },
        ]
    }), encoding="utf-8")

    monkeypatch.setattr(agent, "NODES", config)
    result = agent.load_nodes()

    assert result["status"] == "VALID"
    assert result["ignored"] == 1
    assert len(result["nodes"]) == 1

    node = result["nodes"][0]
    assert node["authorized"] is True
    assert node["id"] == "9db367aad0b70421"
    assert node["url"] == "https://peer.example"
    assert node["precheck"] == "URL_ACCEPTED"


def test_authorized_node_with_invalid_url_remains_rejected(monkeypatch, tmp_path):
    config = tmp_path / "nodes.json"
    config.write_text(json.dumps({
        "nodes": [{
            "authorized": True,
            "id": "9db367aad0b70421",
            "url": "http://peer.example",
        }]
    }), encoding="utf-8")

    monkeypatch.setattr(agent, "NODES", config)
    result = agent.load_nodes()

    assert len(result["nodes"]) == 1
    node = result["nodes"][0]
    assert node["authorized"] is True
    assert node["precheck"] == "URL_REJECTED"
