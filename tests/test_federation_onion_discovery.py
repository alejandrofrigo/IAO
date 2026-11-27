from __future__ import annotations

import json

from tools import iao_federation_autonomous as federation


ONION_A = "a" * 56 + ".onion"
ONION_B = "b" * 56 + ".onion"


def test_onion_feed_keeps_external_peers_unverified(monkeypatch, tmp_path):
    payload = {
        "peers": [
            {"id": "external-peer-1", "url": f"http://{ONION_A}/federation.json"},
            {"id": "external-peer-2", "url": f"http://{ONION_B}/directory"},
            {"id": "bad", "url": "https://example.org/fed"},
            {"id": "bad", "url": f"http://user:pass@{ONION_A}/feed"},
        ]
    }
    calls = []
    monkeypatch.setattr(
        federation, "fetch_onion_json",
        lambda url, **kwargs: calls.append((url, kwargs)) or payload,
    )
    monkeypatch.setattr(federation, "STATE", tmp_path)
    monkeypatch.setattr(federation, "AUDIT", tmp_path / "audit" / "events.jsonl")

    found = federation.discover_onion_feed(
        f"http://{ONION_A}/public-directory.json"
    )
    assert len(found) == 2
    assert all(item["status"] == "DISCOVERED_UNVERIFIED" for item in found)
    assert all(item["granted_capabilities"] == [] for item in found)

    added = federation.merge_onion_candidates(found)
    registry = json.loads((tmp_path / "iao-onion-candidates.json").read_text())
    assert added == 2
    assert len(registry["candidates"]) == 2
    assert all(not item["identity_verified"] for item in registry["candidates"].values())
    assert all(not item["enrolled"] for item in registry["candidates"].values())
    assert all(item["granted_capabilities"] == [] for item in registry["candidates"].values())
    assert calls[0][1]["max_bytes"] == 500_000


def test_onion_candidate_merge_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(federation, "STATE", tmp_path)
    candidate = {
        "url": f"http://{ONION_A}/api",
        "id": "peer-a",
        "source": "onion_feed",
    }
    assert federation.merge_onion_candidates([candidate]) == 1
    assert federation.merge_onion_candidates([candidate]) == 0
    data = json.loads((tmp_path / "iao-onion-candidates.json").read_text())
    assert len(data["candidates"]) == 1


def test_onion_url_validator_rejects_non_v3_and_unsafe_urls():
    valid = f"http://{ONION_A}/feed"
    assert federation._validate_onion_peer_url(valid)
    for value in (
        "https://" + ONION_A + "/feed",
        "http://short.onion/feed",
        f"http://{ONION_A}:8080/feed",
        f"http://{ONION_A}/feed?target=internal",
        f"http://user:pass@{ONION_A}/feed",
        "http://127.0.0.1/feed",
    ):
        assert not federation._validate_onion_peer_url(value)

def test_public_iao_candidates_use_signed_pinned_autojoin_not_legacy_probe(
    monkeypatch, tmp_path
):
    from omega import federation_autonomous as trusted

    monkeypatch.setattr(federation, "STATE", tmp_path)
    monkeypatch.setattr(federation, "NODES", tmp_path / "nodes.json")
    monkeypatch.setattr(federation, "POLICY", tmp_path / "policy.json")
    monkeypatch.setattr(federation, "REPORT", tmp_path / "report.json")
    monkeypatch.setattr(federation, "AUDIT", tmp_path / "audit" / "events.jsonl")
    federation.NODES.write_text(json.dumps({
        "nodes": [{
            "url": "https://public-peer.example.org",
            "id": "0123456789abcdef",
            "source": "public_feed",
            "authorized": False,
            "capabilities": ["knowledge.search"],
        }]
    }))
    federation.POLICY.write_text(json.dumps({
        "enabled": True,
        "allowed_capabilities": ["knowledge.search"],
    }))
    monkeypatch.setattr(federation, "make_node", lambda policy: object())
    calls = []

    def fake_trusted_cycle(node, state_dir, registry_path):
        data = json.loads(registry_path.read_text())
        candidate = next(iter(data["candidates"].values()))
        calls.append((node, state_dir, candidate))
        assert candidate["origin"] == "https://public-peer.example.org"
        assert candidate["node_id"] == "0123456789abcdef"
        assert candidate["status"] == "DISCOVERED_UNVERIFIED"
        assert candidate["granted_capabilities"] == []
        return {
            "status": "COMPLETED",
            "checked": 1,
            "enrolled": 1,
            "failed": 0,
            "inbound_capabilities_granted": 0,
        }

    monkeypatch.setattr(trusted, "run_discovered_cycle", fake_trusted_cycle)
    monkeypatch.setattr(
        federation, "probe_and_verify",
        lambda *_: (_ for _ in ()).throw(AssertionError("legacy probe must not run")),
    )

    report = federation.run_cycle(dry_run=False, discover=False)
    assert len(calls) == 1
    assert report["discovery"]["trusted_public_federation"]["enrolled"] == 1
    assert report["summary"]["enrolled"] == 1
    assert report["summary"]["failed"] == 0

