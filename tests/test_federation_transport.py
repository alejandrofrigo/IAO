import socket

import pytest

import omega.federation_transport as transport


def _answer(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return (family, socket.SOCK_STREAM, 6, "", address)


def test_private_dns_address_is_rejected():
    with pytest.raises(transport.TransportError, match="PRIVATE_ADDRESS"):
        transport._resolve(
            "peer.example",
            443,
            resolver=lambda *a, **k: [_answer("127.0.0.1")],
        )


def test_mixed_public_and_private_dns_is_rejected():
    with pytest.raises(transport.TransportError, match="PRIVATE_ADDRESS"):
        transport._resolve(
            "peer.example",
            443,
            resolver=lambda *a, **k: [
                _answer("93.184.216.34"),
                _answer("10.0.0.5"),
            ],
        )


def test_dns_failure_is_rejected():
    def broken(*args, **kwargs):
        raise OSError("DNS unavailable")

    with pytest.raises(transport.TransportError, match="DNS_FAILURE"):
        transport._resolve("peer.example", 443, resolver=broken)


def test_loopback_requires_explicit_permission():
    with pytest.raises(transport.TransportError):
        transport._parse_target("http://127.0.0.1:8765", allow_loopback=False)

    parsed = transport._parse_target(
        "http://127.0.0.1:8765",
        allow_loopback=True,
    )
    assert parsed[0] == "http"
    assert parsed[2] == 8765


def test_https_private_literal_is_rejected():
    with pytest.raises(transport.TransportError):
        transport._resolve("127.0.0.1", 443)


def test_redirect_is_never_followed(monkeypatch):
    calls = []

    class FakeResponse:
        status = 302

        def getheader(self, name):
            return "https://internal.example/" if name == "Location" else None

    class FakeConnection:
        sock = None

        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            calls.append("request")

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(transport, "_PinnedConnection", FakeConnection)

    with pytest.raises(transport.TransportError, match="REDIRECT_NOT_ALLOWED"):
        transport.request_json(
            "https://peer.example/fed/v1/identity",
            resolver=lambda *a, **k: [_answer("93.184.216.34")],
        )

    assert calls == ["request"]


def test_only_expected_https_ports_are_allowed():
    with pytest.raises(transport.TransportError, match="PORT_NOT_ALLOWED"):
        transport._parse_target("https://peer.example:8443/")

    parsed = transport._parse_target(
        "https://sample.trycloudflare.com:8443/"
    )
    assert parsed[2] == 8443


def test_credentials_and_fragments_are_rejected():
    with pytest.raises(transport.TransportError):
        transport._parse_target("https://user:pass@peer.example/")

    with pytest.raises(transport.TransportError):
        transport._parse_target("https://peer.example/#fragment")
