"""Real mutual-TLS federation integration tests with generated local certificates."""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from omega.federation import (
    FedServer,
    Node,
    create_federation_server_ssl_context,
)
from omega.store import Store
from omega.tools.registry import ToolRegistry, ToolSpec


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)


def _issue_certificate(
    root: Path,
    name: str,
    key,
    ca_key,
    ca_cert,
    *,
    node_id: str | None = None,
    server: bool = False,
) -> tuple[Path, Path]:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost" if server else name)
    ])
    now = datetime.now(timezone.utc)
    sans = []
    if server:
        sans.append(x509.DNSName("localhost"))
    if node_id is not None:
        sans.append(x509.UniformResourceIdentifier(f"urn:iao:node:{node_id}"))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_path, key_path = root / f"{name}.crt", root / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    return cert_path, key_path


class FederationMTLSIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_env = {
            key: os.environ.get(key)
            for key in (
                "IAO_TLS_CA_FILE",
                "IAO_TLS_CLIENT_CERT_FILE",
                "IAO_TLS_CLIENT_KEY_FILE",
                "IAO_TLS_REQUIRE_CLIENT_CERT",
                "IAO_ALLOW_LOOPBACK_HTTP",
            )
        }
        self.clock = lambda: 1_000_000.0

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IAO test CA")])
        now = datetime.now(timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_key = ca_key
        self.ca_file = self.root / "ca.crt"
        self.ca_file.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self.store_a = Store(self.root / "a.db", audit_key=b"a" * 32)
        self.store_b = Store(self.root / "b.db", audit_key=b"b" * 32)
        self.registry_a = ToolRegistry()
        self.registry_b = ToolRegistry()
        spec = ToolSpec(
            "knowledge.search", "1.0.0", "knowledge.search", "READ_ONLY", 5.0,
            lambda value: value, lambda value: {"echo": value},
            lambda value: "PASS",
        )
        self.registry_a.register(spec)
        self.registry_b.register(spec)
        self.key_a = ed25519.Ed25519PrivateKey.generate()
        self.key_b = ed25519.Ed25519PrivateKey.generate()
        self.a = Node(
            self.store_a, self.registry_a, key=self.key_a,
            clock=self.clock, served=frozenset({"knowledge.search"}),
        )
        self.b = Node(
            self.store_b, self.registry_b, key=self.key_b,
            clock=self.clock, served=frozenset({"knowledge.search"}),
        )
        self.a.enroll(self.b.contract_for_self(["knowledge.search"]))
        self.b.enroll(
            self.a.contract_for_self(["knowledge.search"]),
            granted_capabilities=["knowledge.search"],
        )

        self.server_cert, self.server_key = _issue_certificate(
            self.root, "server", rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ), self.ca_key, self.ca_cert, node_id=self.b.node_id, server=True,
        )
        self.client_cert, self.client_key = _issue_certificate(
            self.root, "client", rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ), self.ca_key, self.ca_cert, node_id=self.a.node_id,
        )
        os.environ["IAO_TLS_CA_FILE"] = str(self.ca_file)
        os.environ["IAO_TLS_CLIENT_CERT_FILE"] = str(self.client_cert)
        os.environ["IAO_TLS_CLIENT_KEY_FILE"] = str(self.client_key)
        os.environ["IAO_TLS_REQUIRE_CLIENT_CERT"] = "1"
        os.environ["IAO_ALLOW_LOOPBACK_HTTP"] = "1"

        context = create_federation_server_ssl_context(
            self.server_cert, self.server_key, self.ca_file
        )
        self.server = FedServer(self.b, host="127.0.0.1", ssl_context=context).start()
        self.addCleanup(self._cleanup_server)
        endpoint = f"https://localhost:{self.server.port}/fed/v1/message"
        self.a.bind_peer_endpoint(self.b.node_id, endpoint)

    def _cleanup_server(self) -> None:
        try:
            self.server.stop()
        except Exception:
            pass

    def tearDown(self) -> None:
        self.store_a.close()
        self.store_b.close()
        self.temp.cleanup()
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_mutual_tls_round_trip_binds_both_node_identities(self) -> None:
        # The public-address resolver is replaced only to route this local TLS
        # integration server; certificate verification remains fully enabled.
        with patch(
            "omega.federation_transport.resolve_public_addresses",
            return_value=["127.0.0.1"],
        ):
            result = self.a.send(
                self.b.node_id,
                self.a.peers[self.b.node_id]["endpoint"],
                "knowledge.search",
                {"query": "mTLS integration"},
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"], {"echo": {"query": "mTLS integration"}})
        self.assertTrue(result["untrusted"])

    def test_missing_client_certificate_fails_closed(self) -> None:
        os.environ.pop("IAO_TLS_CLIENT_CERT_FILE", None)
        os.environ.pop("IAO_TLS_CLIENT_KEY_FILE", None)
        with patch(
            "omega.federation_transport.resolve_public_addresses",
            return_value=["127.0.0.1"],
        ):
            result = self.a.send(
                self.b.node_id,
                self.a.peers[self.b.node_id]["endpoint"],
                "knowledge.search",
                {"query": "must not connect"},
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "TRANSPORT_BLOCKED")


if __name__ == "__main__":
    unittest.main()
