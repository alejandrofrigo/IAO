from omega.federation_protocols import nostr_bridge


def test_nostr_relay_is_not_a_federated_compute_node():
    adapter = nostr_bridge.NostrBridge()
    assert adapter.probe("wss://relay.example.org")["kind"] == "relay"
    assert adapter.to_participation_contract({
        "nostr_event": {
            "pubkey": "a" * 64,
            "content": nostr_bridge.AUTHORIZE_MARKER + "b" * 64,
        }
    }) is None


def test_authorization_filter_requires_signed_exact_prefix_and_tag(monkeypatch):
    bridge_key = "b" * 64
    monkeypatch.setattr(nostr_bridge, "bridge_pubkey_hex", lambda: bridge_key)
    monkeypatch.setattr(nostr_bridge, "verify_nostr_event", lambda event: event.get("valid") is True)

    valid = {
        "kind": 1,
        "content": nostr_bridge.AUTHORIZE_MARKER + bridge_key,
        "tags": [["t", "iao-federation"]],
        "valid": True,
    }
    wrong_recipient = {**valid, "content": nostr_bridge.AUTHORIZE_MARKER + ("c" * 64)}
    marker_in_middle = {**valid, "content": "prefix " + valid["content"]}
    missing_tag = {**valid, "tags": [["t", "other"]]}
    invalid_signature = {**valid, "valid": False}

    accepted = nostr_bridge._filter_authorizations([
        valid, wrong_recipient, marker_in_middle, missing_tag, invalid_signature
    ])
    assert accepted == [valid]


def test_nostr_event_candidates_are_discovery_only():
    event = {
        "pubkey": "a" * 64,
        "content": nostr_bridge.AUTHORIZE_MARKER + "b" * 64,
    }
    candidates = nostr_bridge.build_candidates_from_events([event], ["wss://relay.example.org"])
    assert len(candidates) == 1
    assert candidates[0]["authorized"] is False
    assert candidates[0]["source"] == "nostr_bridge"
    assert candidates[0]["nostr_event"] == event



def test_nostr_bridge_key_uses_private_persistent_state(monkeypatch, tmp_path):
    import stat
    from pathlib import Path

    directory = tmp_path / "state" / "federation-bridges" / "nostr"
    monkeypatch.setattr(nostr_bridge, "BRIDGE_DIR", directory)
    monkeypatch.setattr(nostr_bridge, "BRIDGE_KEY", directory / "bridge.pem")
    first = nostr_bridge._ensure_bridge_key()
    second = nostr_bridge._ensure_bridge_key()
    assert first.private_bytes_raw() == second.private_bytes_raw()
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "bridge.pem").stat().st_mode) == 0o600


def test_nostr_bridge_refuses_symlinked_key(monkeypatch, tmp_path):
    import pytest
    directory = tmp_path / "bridge"
    directory.mkdir()
    target = tmp_path / "outside.pem"
    target.write_text("not a key")
    key_path = directory / "bridge.pem"
    key_path.symlink_to(target)
    monkeypatch.setattr(nostr_bridge, "BRIDGE_DIR", directory)
    monkeypatch.setattr(nostr_bridge, "BRIDGE_KEY", key_path)
    with pytest.raises(RuntimeError, match="NOSTR_BRIDGE_KEY_SYMLINK_REFUSED"):
        nostr_bridge._ensure_bridge_key()
