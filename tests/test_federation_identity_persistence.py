import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.federation import Node, node_id_of


class DummyStore:
    def audit(self, *args, **kwargs):
        return {}


class DummyRegistry:
    def get(self, name):
        return None


def write_identity(tmp_path, version=2):
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "private.pem").write_bytes(private)
    (tmp_path / "public.pem").write_bytes(public)
    raw_hash = hashlib.sha256(raw).hexdigest()
    manifest = {
        "public_key_algorithm": "Ed25519",
        "identity_contract_version": version,
        "node_id": raw_hash if version == 2 else hashlib.sha256(der).hexdigest(),
    }
    if version == 2:
        manifest.update({
            "operational_node_id": node_id_of(raw),
            "public_key_sha256": raw_hash,
        })
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return key, raw_hash


def test_loads_migrated_v2_identity_and_uses_identity_peer_store(tmp_path):
    _, raw_hash = write_identity(tmp_path, version=2)
    node = Node.from_persistent_identity(
        DummyStore(), DummyRegistry(), identity_dir=tmp_path
    )
    assert node.identity_contract_version == 2
    assert node.identity_fingerprint == raw_hash
    assert node.node_id == raw_hash[:16]
    assert node.peer_store_path == tmp_path / "peers.json"


def test_loads_legacy_v1_der_fingerprint(tmp_path):
    write_identity(tmp_path, version=1)
    node = Node.from_persistent_identity(
        DummyStore(), DummyRegistry(), identity_dir=tmp_path
    )
    assert node.identity_contract_version == 1
    assert node.node_id


def test_rejects_v2_manifest_with_wrong_operational_id(tmp_path):
    write_identity(tmp_path, version=2)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["operational_node_id"] = "0000000000000000"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="PERSISTENT_IDENTITY_V2_FINGERPRINT_MISMATCH"):
        Node.from_persistent_identity(
            DummyStore(), DummyRegistry(), identity_dir=tmp_path
        )
