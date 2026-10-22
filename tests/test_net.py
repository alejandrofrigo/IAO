import datetime
import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from omega.net import probe_https


def make_cert(d: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    c, k = d / "c.pem", d / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return c, k


class NetProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.cert, key = make_cert(d)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(self.cert, key)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.stop = False

        def serve() -> None:
            self.srv.settimeout(0.2)
            while not self.stop:
                try:
                    c, _ = self.srv.accept()
                except OSError:
                    continue
                try:
                    with sctx.wrap_socket(c, server_side=True) as t:
                        t.recv(1024)
                        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                except (ssl.SSLError, OSError):
                    pass

        self.th = threading.Thread(target=serve, daemon=True)
        self.th.start()

    def tearDown(self) -> None:
        self.stop = True
        self.th.join(2)
        self.srv.close()
        self.tmp.cleanup()

    def test_validated_tls_on_loopback_is_not_internet(self) -> None:
        r = probe_https("localhost", self.port, cafile=str(self.cert))
        self.assertEqual(r["http_status"], 200)
        self.assertTrue(r["tls"]["verified"])
        self.assertEqual(r["scope"], "loopback")
        self.assertEqual(r["verdict"], "LOCAL_TLS_OK")  # never DIRECT_INTERNET_CONNECTED

    def test_untrusted_cert_is_rejected(self) -> None:
        r = probe_https("localhost", self.port)
        self.assertEqual(r["error_class"], "TLS_VERIFY_FAILED")
        self.assertEqual(r["verdict"], "BLOCKED_NETWORK")

    def test_dns_failure_classified(self) -> None:
        r = probe_https("nonexistent.invalid", 443, timeout=3)
        self.assertEqual(r["error_class"], "DNS_FAILURE")
        self.assertEqual(r["verdict"], "BLOCKED_NETWORK")

    def test_connection_refused_classified(self) -> None:
        s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
        r = probe_https("localhost", p, timeout=2, cafile=str(self.cert))
        self.assertEqual(r["error_class"], "CONNECT_FAILED")
