import json
from pathlib import Path

import tools.iao_federation_autonomous as auto


def test_mtls_required_without_client_cert_blocks_before_network(monkeypatch):
    monkeypatch.setattr(
        auto, "probe_any",
        lambda addr: (
            "iao-federation",
            {
                "endpoint": "https://peer.example",
                "identity_doc": {"node_id": "remote-node"}
            }
        )
    )
    monkeypatch.setattr(
        auto, "load",
        lambda path, default=None: {
            "enabled": True,
            "require_mutual_tls": True
        }
    )
    monkeypatch.setattr(auto, "audit", lambda *a, **k: None)

    for name in (
        "IAO_FEDERATION_MTLS_CERT",
        "IAO_FEDERATION_MTLS_KEY",
        "IAO_FEDERATION_MTLS_CA"
    ):
        monkeypatch.delenv(name, raising=False)

    def forbidden_network(*args, **kwargs):
        raise AssertionError("No debe iniciarse el handshake sin certificado")

    monkeypatch.setattr(auto.urllib.request, "urlopen", forbidden_network)

    result = auto.probe_and_verify("https://peer.example")

    assert result[2]["ok"] is False
    assert result[2]["error"] == "MTLS_CLIENT_CERTIFICATE_NOT_CONFIGURED"


def test_nostr_consent_never_enrolls_a_federation_peer(monkeypatch):
    from omega.federation_protocols.nostr_bridge import NostrBridge

    item = {
        "url": "nostr://example-pubkey",
        "source": "nostr_bridge",
        "nostr_event": {"id": "signed-event"},
        "authorized": True
    }
    policy = {
        "enabled": True,
        "padge_mode": "SAFE"
    }

    def fake_load(path, default=None):
        if Path(path) == Path(auto.POLICY):
            return policy
        if Path(path) == Path(auto.NODES):
            return {"nodes": [item]}
        return default

    class FakeNode:
        def enroll(self, *args, **kwargs):
            raise AssertionError("Nostr no debe invocar Node.enroll")

    monkeypatch.setattr(auto, "load", fake_load)
    monkeypatch.setattr(auto, "make_node", lambda p: FakeNode())
    monkeypatch.setattr(auto, "save", lambda *a, **k: None)
    monkeypatch.setattr(auto, "audit", lambda *a, **k: None)
    monkeypatch.setattr(
        NostrBridge,
        "to_participation_contract",
        lambda self, candidate: {
            "peer_id": "bridge-identity",
            "endpoint": "https://nostr.bridge.local/fed/v1/message"
        }
    )

    report = auto.run_cycle(dry_run=False, discover=False)

    assert report["summary"]["enrolled"] == 0
    assert len(report["results"]) == 1
    result = report["results"][0]
    assert result["status"] == "NOSTR_CONSENT_RECORDED_NOT_FEDERATED"
    assert result["consent_verified"] is True
    assert result["federation_enrolled"] is False
    assert result["peer_id"] is None


def test_nostr_dry_run_does_not_claim_a_handshake(monkeypatch):
    from omega.federation_protocols.nostr_bridge import NostrBridge

    item = {
        "url": "nostr://example-pubkey",
        "source": "nostr_bridge",
        "nostr_event": {"id": "signed-event"},
        "authorized": True
    }

    def fake_load(path, default=None):
        if Path(path) == Path(auto.POLICY):
            return {"enabled": True}
        if Path(path) == Path(auto.NODES):
            return {"nodes": [item]}
        return default

    monkeypatch.setattr(auto, "load", fake_load)
    monkeypatch.setattr(
        NostrBridge, "to_participation_contract",
        lambda self, candidate: {"peer_id": "bridge-identity"}
    )

    report = auto.run_cycle(dry_run=True, discover=False)
    result = report["results"][0]

    assert result["status"] == "NOSTR_CONSENT_VALIDATED_NOT_FEDERATED"
    assert result["consent_verified"] is True
    assert result["federation_enrolled"] is False
    assert "handshake_ok" not in result
