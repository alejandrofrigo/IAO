import pytest

from omega.federation_trust_store import (
    FederationTrustError,
    FederationTrustStore,
)


def test_unknown_peer_is_not_authorized(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    result = store.verify("peer-1", "public-key-A")
    assert result["trusted"] is False
    assert result["authorization_granted"] is False
    assert result["reason"] == "UNKNOWN_PEER"


def test_approved_peer_survives_restart(tmp_path):
    path = tmp_path / "trust.json"
    store = FederationTrustStore(path, clock=lambda: 100.0)
    store.approve("peer-1", "public-key-A", "local-operator")

    reopened = FederationTrustStore(path)
    result = reopened.verify("peer-1", "public-key-A")
    assert result["trusted"] is True
    assert result["authorization_granted"] is True


def test_key_substitution_is_rejected(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    store.approve("peer-1", "public-key-A", "local-operator")

    result = store.verify("peer-1", "attacker-key")
    assert result["trusted"] is False
    assert result["reason"] == "PUBLIC_KEY_MISMATCH"
    assert result["authorization_granted"] is False


def test_reapproval_with_changed_key_requires_review(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    store.approve("peer-1", "public-key-A", "local-operator")

    with pytest.raises(FederationTrustError, match="KEY_CHANGE_REQUIRES_REVIEW"):
        store.approve("peer-1", "public-key-B", "local-operator")


def test_revoked_peer_is_not_authorized(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    store.approve("peer-1", "public-key-A", "operator")
    store.revoke("peer-1", "operator")

    result = store.verify("peer-1", "public-key-A")
    assert result["trusted"] is False
    assert result["reason"] == "PEER_REVOKED"
    assert result["authorization_granted"] is False


def test_approval_requires_operator(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    with pytest.raises(FederationTrustError):
        store.approve("peer-1", "public-key-A", "")


def test_invalid_node_id_is_rejected(tmp_path):
    store = FederationTrustStore(tmp_path / "trust.json")
    with pytest.raises(FederationTrustError):
        store.approve("../peer", "public-key-A", "operator")
