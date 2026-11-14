import json

import pytest

from omega.federation_public_node import PeerRegistry, valid_base_url


def test_https_peer_url_is_accepted():
    assert valid_base_url("https://node.example.org")


def test_plain_public_http_is_rejected():
    assert not valid_base_url("http://node.example.org")


def test_local_http_is_rejected():
    assert not valid_base_url("http://127.0.0.1:8765")


@pytest.mark.parametrize("url", [
    "https://localhost",
    "https://127.0.0.1",
    "https://10.0.0.8",
    "https://192.168.1.20",
    "https://172.16.0.5",
    "https://169.254.1.2",
    "https://[::1]",
    "https://node.local",
    "https://node.internal",
    "https://node.lan",
    "https://user:pass@node.example.org",
    "https://node.example.org/path",
    "https://node.example.org?token=x",
    "https://node.example.org/#fragment",
    "http://node.example.org",
    "https://node.example.org:99999",
])
def test_unsafe_peer_urls_are_rejected(url):
    assert not valid_base_url(url)


def test_https_public_dns_name_is_accepted():
    assert valid_base_url("https://node.example.org")


def test_https_public_ip_is_accepted():
    assert valid_base_url("https://8.8.8.8")


def test_registry_registers_and_persists_peer(tmp_path):
    path = tmp_path / "peers.json"
    registry = PeerRegistry(path, "iao-local-node")
    peer = registry.register("iao-remote-node", "https://node.example.org")
    assert peer["status"] == "REGISTERED_UNVERIFIED"
    assert registry.list_peers()[0]["node_id"] == "iao-remote-node"
    assert json.loads(path.read_text())["peers"]["iao-remote-node"]


def test_registry_rejects_self(tmp_path):
    registry = PeerRegistry(tmp_path / "peers.json", "iao-local-node")
    with pytest.raises(ValueError):
        registry.register("iao-local-node", "https://node.example.org")


def test_registry_rejects_public_http(tmp_path):
    registry = PeerRegistry(tmp_path / "peers.json", "iao-local-node")
    with pytest.raises(ValueError):
        registry.register("iao-remote-node", "http://node.example.org")


def test_registry_rejects_invalid_node_id(tmp_path):
    registry = PeerRegistry(tmp_path / "peers.json", "iao-local-node")
    with pytest.raises(ValueError):
        registry.register("../bad", "https://node.example.org")
