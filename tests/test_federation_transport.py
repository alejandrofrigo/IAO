import pytest

from omega import federation_transport as transport


class FakeResponse:
    def __init__(self, status=200, body=b'{"peers": []}', headers=None):
        self.status = status
        self._body = body
        self._headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }

    def getheader(self, name):
        return self._headers.get(name)

    def read(self, size=-1):
        return self._body[:size]


class FakeConnection:
    response = FakeResponse()

    def __init__(self, hostname, address, *, port=443, timeout, context):
        self.hostname = hostname
        self.address = address
        self.port = port
        self.timeout = timeout
        self.context = context
        self.request_args = None
        self.closed = False

    def request(self, method, target, body=None, headers=None):
        self.request_args = (method, target, headers or {}, body)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def test_discovery_url_requires_https_public_default_port_and_no_userinfo():
    assert transport.validate_discovery_url(
        "https://directory.example.org/path?channel=public"
    ) == (
        "directory.example.org",
        "directory.example.org",
        443,
        "/path?channel=public",
    )
    for url in (
        "http://directory.example.org/peers",
        "https://user:pass@directory.example.org/peers",
        "https://directory.example.org:8443/peers",
        "https://directory.example.org/peers#fragment",
        "https:///missing-host",
    ):
        with pytest.raises(transport.FederationTransportError):
            transport.validate_discovery_url(url)


def test_dns_resolution_rejects_private_and_mixed_public_private(monkeypatch):
    def answer(address):
        return (2, 1, 6, "", (address, 443))
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [answer("8.8.8.8"), answer("127.0.0.1")],
    )
    with pytest.raises(
        transport.FederationTransportError,
        match="DNS_RESOLVED_NON_PUBLIC_ADDRESS",
    ):
        transport.resolve_public_addresses("directory.example.org")


def test_fetch_public_json_pins_ip_and_parses_json(monkeypatch):
    created = []

    def factory(hostname, address, *, timeout, context):
        conn = FakeConnection(hostname, address, timeout=timeout, context=context)
        created.append(conn)
        return conn

    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(transport, "_PinnedHTTPSConnection", factory)
    FakeConnection.response = FakeResponse(body=b'{"peers":[{"id":"p1"}]}')
    result = transport.fetch_public_json("https://directory.example.org/peers")
    assert result == {"peers": [{"id": "p1"}]}
    assert created[0].hostname == "directory.example.org"
    assert created[0].address == "8.8.8.8"
    assert created[0].request_args[0:2] == ("GET", "/peers")
    assert created[0].request_args[2]["Host"] == "directory.example.org"
    assert created[0].request_args[3] is None
    assert created[0].closed


def test_fetch_public_json_rejects_redirect(monkeypatch):
    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(
        transport,
        "_PinnedHTTPSConnection",
        lambda *args, **kwargs: FakeConnection(
            *args, **kwargs
        ),
    )
    FakeConnection.response = FakeResponse(
        status=302,
        body=b'{"url":"https://internal.example/"}',
        headers={"Location": "https://internal.example/"},
    )
    with pytest.raises(transport.FederationTransportError, match="REDIRECT_REFUSED"):
        transport.fetch_public_json("https://directory.example.org/peers")


def test_fetch_public_json_enforces_body_limit(monkeypatch):
    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(
        transport,
        "_PinnedHTTPSConnection",
        lambda *args, **kwargs: FakeConnection(*args, **kwargs),
    )
    FakeConnection.response = FakeResponse(body=b'{"long":"123456789"}')
    with pytest.raises(transport.FederationTransportError, match="RESPONSE_TOO_LARGE"):
        transport.fetch_public_json(
            "https://directory.example.org/peers", max_bytes=8
        )


def test_fetch_public_json_requires_json_content_type(monkeypatch):
    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(
        transport,
        "_PinnedHTTPSConnection",
        lambda *args, **kwargs: FakeConnection(*args, **kwargs),
    )
    FakeConnection.response = FakeResponse(
        headers={"Content-Type": "text/html"}
    )
    with pytest.raises(
        transport.FederationTransportError,
        match="JSON_CONTENT_TYPE_REQUIRED",
    ):
        transport.fetch_public_json("https://directory.example.org/peers")


def test_discover_feed_uses_bounded_verified_transport(monkeypatch):
    from tools import iao_federation_autonomous as federation

    calls = []

    def fake_fetch(url, *, timeout, max_bytes):
        calls.append((url, timeout, max_bytes))
        return {
            "peers": [
                {"id": "peer-1", "url": "https://peer.example.org/fed/v1/message",
                 "capabilities": ["knowledge.search"]},
                {"id": "bad-scheme", "url": "http://peer.example.org/fed/v1/message"},
                {"id": "bad-shape", "url": 123},
            ]
        }

    monkeypatch.setattr(federation, "fetch_public_json", fake_fetch)
    peers = federation.discover_feed("https://directory.example.org/feed")
    assert len(peers) == 1
    assert peers[0]["id"] == "peer-1"
    assert peers[0]["source"] == "public_feed"
    assert calls == [
        ("https://directory.example.org/feed", 10, 500_000)
    ]


def test_discover_feed_fails_closed_on_transport_error(monkeypatch):
    from tools import iao_federation_autonomous as federation

    def fail(*args, **kwargs):
        from omega.federation_transport import FederationTransportError
        raise FederationTransportError("REDIRECT_REFUSED")

    monkeypatch.setattr(federation, "fetch_public_json", fail)
    assert federation.discover_feed("https://directory.example.org/feed") == []


def test_mtls_required_configuration_fails_closed_without_client_identity(monkeypatch):
    monkeypatch.setenv("IAO_TLS_REQUIRE_CLIENT_CERT", "true")
    monkeypatch.delenv("IAO_TLS_CLIENT_CERT_FILE", raising=False)
    monkeypatch.delenv("IAO_TLS_CLIENT_KEY_FILE", raising=False)
    with pytest.raises(
        transport.FederationTransportError, match="CLIENT_CERT_REQUIRED"
    ):
        transport._client_tls_context()


def test_mtls_client_private_key_permissions_are_enforced(tmp_path, monkeypatch):
    import os

    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_text("test-certificate", encoding="utf-8")
    key.write_text("test-private-key", encoding="utf-8")
    os.chmod(key, 0o644)
    monkeypatch.setenv("IAO_TLS_CLIENT_CERT_FILE", str(cert))
    monkeypatch.setenv("IAO_TLS_CLIENT_KEY_FILE", str(key))
    with pytest.raises(
        transport.FederationTransportError,
        match="CLIENT_KEY_PERMISSIONS_TOO_OPEN",
    ):
        transport._client_tls_context()
