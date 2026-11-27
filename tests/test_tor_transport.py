import socket
import threading
import unittest

from omega.tor_transport import (
    TorTransportError, open_tor_socket, validate_onion_endpoint,
)


class TorTransportTests(unittest.TestCase):
    def fake_proxy(self, reply=b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        captured = {}

        def serve():
            conn, _ = listener.accept()
            with conn:
                captured["greeting"] = conn.recv(3)
                conn.sendall(b"\x05\x00")
                head = conn.recv(5)
                length = head[4]
                host = conn.recv(length)
                port = conn.recv(2)
                captured["request"] = head + host + port
                conn.sendall(reply)
                try:
                    conn.recv(1)
                except OSError:
                    pass
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return listener.getsockname()[1], captured, thread

    def test_socks5_uses_domain_name_remote_dns(self):
        port, captured, thread = self.fake_proxy()
        sock = open_tor_socket(
            "exampleonionservice.onion", 80,
            proxy_port=port, timeout=2,
        )
        sock.close()
        thread.join(2)
        self.assertEqual(captured["greeting"], b"\x05\x01\x00")
        self.assertEqual(captured["request"][:4], b"\x05\x01\x00\x03")
        self.assertEqual(
            captured["request"][5:-2], b"exampleonionservice.onion"
        )

    def test_proxy_refusal_fails_without_fallback(self):
        port, _, thread = self.fake_proxy(
            b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x50"
        )
        with self.assertRaisesRegex(TorTransportError, "CONNECT_FAILED"):
            open_tor_socket("exampleonionservice.onion", 80, proxy_port=port, timeout=2)
        thread.join(2)

    def test_onion_endpoint_validation(self):
        host = "a" * 56 + ".onion"
        self.assertEqual(
            validate_onion_endpoint(f"http://{host}/fed/v1/message"),
            (host, 80),
        )
        for endpoint in (
            "https://example.org/fed/v1/message",
            "http://example.org/fed/v1/message",
            f"http://{host}/wrong",
            f"http://user@{host}/fed/v1/message",
            f"http://{'a' * 55}.onion/fed/v1/message",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    validate_onion_endpoint(endpoint)

    def test_ip_literal_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HOSTNAME"):
            open_tor_socket("1.1.1.1", 80)


if __name__ == "__main__":
    unittest.main()
