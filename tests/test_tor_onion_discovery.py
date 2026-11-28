from __future__ import annotations

import json
import stat

from omega import federation_transport, onion_discovery
from tools import iao_federation_autonomous as federation


def onion(label: str) -> str:
    return label * 56 + ".onion"


def test_onion_feed_discovers_only_valid_v3_onion_endpoints(monkeypatch):
    feed = f"http://{onion('a')}:8443/fed/v1/directory"
    valid = f"http://{onion('b')}:8443/fed/v1/identity"
    invalid = f"http://{onion('c')}:8080/fed/v1/identity"
    calls = []

    def fake_fetch(url, *, timeout, max_bytes):
        calls.append((url, timeout, max_bytes))
        return {"peers": [
            {"peer_id": "Q" * 40, "url": valid, "capabilities": ["admin"],
             "cids": ["Qm" + "1" * 44, "../bad-cid"]},
            {"peer_id": "R" * 40, "url": invalid},
            {"peer_id": "short", "url": valid},
            {"peer_id": "S" * 40, "url": "https://example.org/"},
        ]}

    monkeypatch.setattr(onion_discovery, "fetch_onion_json", fake_fetch)
    found = federation.discover_onion_feed(feed)
    assert len(found) == 2
    assert found[0]["service_url"] == valid
    assert found[0]["peer_id"] == "Q" * 40
    assert found[0]["identity_state"] == "UNVERIFIED"
    assert found[0]["participation_state"] == "CANDIDATE_ONLY"
    assert found[0]["content_cids"] == ["Qm" + "1" * 44]
    assert found[0]["capabilities"] == []
    assert found[0]["granted_capabilities"] == []
    assert found[0]["remote_code_execution"] is False
    assert found[1]["peer_id"] is None
    assert calls == [(feed, 15, 500_000)]


def test_onion_feed_failure_is_fail_closed(monkeypatch):
    def fail(*args, **kwargs):
        raise federation_transport.FederationTransportError("TOR_ONION_REQUEST_FAILED")
    monkeypatch.setattr(onion_discovery, "fetch_onion_json", fail)
    assert federation.discover_onion_feed(
        f"http://{onion('d')}/directory.json"
    ) == []


def test_onion_candidate_inventory_is_separate_private_and_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(federation, "STATE", tmp_path)
    endpoint = f"http://{onion('e')}:8443/fed/v1/identity"
    item = {
        "service_url": endpoint,
        "peer_id": "P" * 40,
        "source": "tor_onion_feed",
        "content_cids": ["Qm" + "1" * 44, "../bad"],
    }
    first = federation.merge_onion_candidates([item])
    second = federation.merge_onion_candidates([item])
    path = tmp_path / "iao-onion-candidates.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    record = next(iter(saved["services"].values()))
    assert first == {"new": 1, "observed": 1, "total": 1}
    assert second == {"new": 0, "observed": 1, "total": 1}
    assert record["service_url"] == endpoint
    assert record["content_cids"] == ["Qm" + "1" * 44]
    assert record["virtual_port"] == 8443
    assert record["discovery_state"] == "FEED_ADVERTISED_UNPROBED"
    assert record["identity_state"] == "UNVERIFIED"
    assert record["participation_state"] == "CANDIDATE_ONLY"
    assert record["capabilities"] == []
    assert record["granted_capabilities"] == []
    assert record["remote_code_execution"] is False
    assert record["control_authority"] is False
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_onion_candidate_registry_refuses_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(federation, "STATE", tmp_path)
    target = tmp_path / "outside.json"
    target.write_text('{"schema":1,"services":{}}', encoding="utf-8")
    (tmp_path / "iao-onion-candidates.json").symlink_to(target)
    try:
        federation.merge_onion_candidates([])
    except RuntimeError as exc:
        assert "SYMLINK" in str(exc)
    else:
        raise AssertionError("symlink registry accepted")
    assert target.read_text(encoding="utf-8") == '{"schema":1,"services":{}}'


def test_run_discovery_integrates_configured_onion_feeds(tmp_path, monkeypatch):
    feed = f"http://{onion('f')}/directory.json"
    monkeypatch.setattr(federation, "SOURCES", tmp_path / "sources.json")
    (tmp_path / "sources.json").write_text(
        json.dumps({"onion_feeds": [feed]}), encoding="utf-8"
    )
    monkeypatch.setattr(
        federation, "discover_onion_feed",
        lambda url: [{"service_url": url, "peer_id": None, "source": "tor_onion_feed"}],
    )
    candidates = federation.run_discovery()
    assert len(candidates) == 1
    assert candidates[0]["source"] == "tor_onion_feed"
