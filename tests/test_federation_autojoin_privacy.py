"""Federation autojoin events must not persist exception messages."""
import json

from omega import federation_autojoin as autojoin


def test_autojoin_failure_logs_exception_class_only(tmp_path, monkeypatch):
    from tools import iao_federation_agent

    node_record = {
        "authorized": True,
        "node_id": "peer-identity-12345678",
        "origin": "https://peer.example",
    }
    monkeypatch.setattr(
        iao_federation_agent, "load_nodes",
        lambda: {"status": "VALID", "nodes": [node_record]},
    )
    monkeypatch.setattr(
        autojoin, "_verified",
        lambda _node, _verify: (True, "peer-identity-12345678"),
    )
    monkeypatch.setattr(autojoin, "_origin", lambda _node: "https://peer.example")
    monkeypatch.setattr(
        autojoin, "_get_contract",
        lambda _origin: {
            "peer_id": "peer-identity-12345678",
            "pubkey": "public-key-placeholder",
            "capabilities": ["knowledge.search"],
        },
    )

    class FailingNode:
        peers = {}

        def _validate_peer_contract(self, _contract):
            return None

        def enroll(self, _contract, granted_capabilities):
            assert granted_capabilities == []
            raise RuntimeError("private-autojoin-exception-marker")

    result = autojoin.run_cycle(FailingNode(), tmp_path)
    assert result["failed"] == 1
    log_path = tmp_path / "federation-autojoin.jsonl"
    log = log_path.read_text(encoding="utf-8")
    assert "RuntimeError" in log
    assert "private-autojoin-exception-marker" not in log
    event = json.loads(log.splitlines()[0])
    assert event["error_type"] == "RuntimeError"
