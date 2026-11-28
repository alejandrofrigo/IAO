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


def test_loopback_message_endpoint_requires_valid_port():
    assert transport.validate_message_endpoint(
        "http://127.0.0.1:8080/fed/v1/message"
    )[0] == "http"
    with pytest.raises(
        transport.FederationTransportError, match="PUBLIC_HTTPS_REQUIRED"
    ):
        transport.validate_message_endpoint(
            "http://127.0.0.1:0/fed/v1/message"
        )


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

    def factory(hostname, address, *, port=443, timeout, context):
        conn = FakeConnection(
            hostname, address, port=port, timeout=timeout, context=context
        )
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


def test_onion_transport_accepts_only_v3_onion_http():
    host = "a" * 56 + ".onion"
    assert transport._parse_onion_url(f"http://{host}/directory.json") == (
        host, 80, "/directory.json"
    )
    for url in (
        "https://"+host+"/directory.json",
        "http://short.onion/feed",
        "http://"+host+":8080/feed",
        "http://"+host+"/feed?target=internal",
        "http://127.0.0.1/feed",
        "http://user:pass@"+host+"/feed",
    ):
        with pytest.raises(transport.FederationTransportError):
            transport._parse_onion_url(url)


def test_tor_proxy_must_be_loopback(monkeypatch):
    monkeypatch.setenv("IAO_TOR_SOCKS_HOST", "192.0.2.10")
    with pytest.raises(
        transport.FederationTransportError, match="TOR_SOCKS_PROXY_MUST_BE_LOOPBACK"
    ):
        transport._tor_proxy()


def test_fetch_onion_json_uses_configured_socks_and_bounds_response(monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(SOCKS5=2))
    monkeypatch.setenv("IAO_TOR_SOCKS_HOST", "127.0.0.1")
    monkeypatch.setenv("IAO_TOR_SOCKS_PORT", "9050")
    calls = []

    class Response:
        status = 200
        def getheader(self, name):
            return {"Content-Type": "application/json", "Content-Length": "12"}.get(name)
        def read(self, size=-1):
            return b'{"peers": []}'

    class Connection:
        def __init__(self, hostname, *, timeout, proxy_host, proxy_port):
            calls.append((hostname, timeout, proxy_host, proxy_port))
        def request(self, method, target, headers=None):
            calls.append((method, target, headers["Host"]))
        def getresponse(self):
            return Response()
        def close(self):
            calls.append(("closed",))

    monkeypatch.setattr(transport, "_TorOnionHTTPConnection", Connection)
    host = "b" * 56 + ".onion"
    assert transport.fetch_onion_json(f"http://{host}/feed") == {"peers": []}
    assert calls[0] == (host, 15.0, "127.0.0.1", 9050)
    assert calls[1][0:2] == ("GET", "/feed")
    assert calls[-1] == ("closed",)


def test_fetch_onion_json_rejects_redirect(monkeypatch):
    import sys
    from types import SimpleNamespace
    monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(SOCKS5=2))
    class Response:
        status = 302
        def getheader(self, name):
            return "application/json"
        def read(self, size=-1):
            return b'{}'
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(transport, "_TorOnionHTTPConnection", Connection)
    with pytest.raises(transport.FederationTransportError, match="REDIRECT_REFUSED"):
        transport.fetch_onion_json("http://" + "c"*56 + ".onion/feed")


def test_post_public_json_uses_pinned_public_https_and_no_redirect(monkeypatch):
    calls = []
    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    def factory(hostname, address, *, port=443, timeout, context):
        conn = FakeConnection(hostname, address, port=port, timeout=timeout, context=context)
        calls.append(conn)
        return conn
    monkeypatch.setattr(transport, "_PinnedHTTPSConnection", factory)
    FakeConnection.response = FakeResponse(body=b'{"ok":true}')
    status, payload = transport.post_public_json(
        "https://peer.example.org/fed/v1/handshake", {"nonce": "a" * 64}
    )
    assert status == 200
    assert payload == {"ok": True}
    assert calls[0].request_args[0:2] == ("POST", "/fed/v1/handshake")
    assert calls[0].closed


def test_post_public_json_rejects_redirect(monkeypatch):
    monkeypatch.setattr(transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(
        transport, "_PinnedHTTPSConnection",
        lambda *args, **kwargs: FakeConnection(*args, **kwargs),
    )
    FakeConnection.response = FakeResponse(status=307, headers={"Location": "https://other.example/"})
    with pytest.raises(transport.FederationTransportError, match="REDIRECT_REFUSED"):
        transport.post_public_json("https://peer.example.org/fed/v1/handshake", {"x": 1})



def test_validate_message_endpoint_accepts_only_v3_onion_federation_path():
    host = "d" * 56 + ".onion"
    assert transport.validate_message_endpoint(
        f"http://{host}/fed/v1/message"
    ) == ("onion", host, 80, "/fed/v1/message", host)
    for url in (
        f"http://{host}/admin",
        f"http://{host}:8080/fed/v1/message",
        f"http://short.onion/fed/v1/message",
        f"https://{host}/fed/v1/message",
        f"http://{host}/fed/v1/message?x=1",
    ):
        with pytest.raises(transport.FederationTransportError):
            transport.validate_message_endpoint(url)


def test_post_federation_json_routes_onion_through_tor_socks(monkeypatch):
    import sys
    from types import SimpleNamespace
    monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(SOCKS5=2))
    monkeypatch.setenv("IAO_TOR_SOCKS_HOST", "127.0.0.1")
    monkeypatch.setenv("IAO_TOR_SOCKS_PORT", "9050")
    calls = []

    class Response:
        status = 200
        def getheader(self, name):
            return {"Content-Type": "application/json", "Content-Length": "11"}.get(name)
        def read(self, size=-1):
            return b'{"ok":true}'

    class Connection:
        def __init__(self, hostname, *, timeout, proxy_host, proxy_port):
            calls.append(("init", hostname, timeout, proxy_host, proxy_port))
        def request(self, method, target, body=None, headers=None):
            calls.append((method, target, headers["Host"], body))
        def getresponse(self):
            return Response()
        def close(self):
            calls.append(("closed",))

    monkeypatch.setattr(transport, "_TorOnionHTTPConnection", Connection)
    host = "e" * 56 + ".onion"
    status, payload = transport.post_federation_json(
        f"http://{host}/fed/v1/message", {"signed": True}
    )
    assert status == 200
    assert payload == {"ok": True}
    assert calls[0] == ("init", host, 5.0, "127.0.0.1", 9050)
    assert calls[1][0:3] == ("POST", "/fed/v1/message", host)
    assert calls[-1] == ("closed",)



def test_public_federation_origin_accepts_https_and_v3_onion_only():
    onion = "http://" + "g" * 56 + ".onion"
    assert transport.validate_public_federation_origin(
        "https://node.example.org"
    ) == "https://node.example.org"
    assert transport.validate_public_federation_origin(onion) == onion
    for origin in (
        "http://node.example.org",
        "http://short.onion",
        "https://node.example.org:8443",
        "https://user@node.example.org",
        "https://node.example.org/path",
    ):
        with pytest.raises(transport.FederationTransportError):
            transport.validate_public_federation_origin(origin)


def test_outbound_https_federation_requires_client_certificate(monkeypatch):
    monkeypatch.delenv("IAO_TLS_REQUIRE_CLIENT_CERT", raising=False)
    monkeypatch.delenv("IAO_TLS_CLIENT_CERT_FILE", raising=False)
    monkeypatch.delenv("IAO_TLS_CLIENT_KEY_FILE", raising=False)
    monkeypatch.setattr(
        transport, "resolve_public_addresses", lambda *_: ["8.8.8.8"]
    )
    with pytest.raises(
        transport.FederationTransportError, match="CLIENT_CERT_REQUIRED"
    ):
        transport.post_federation_json(
            "https://peer.example.org/fed/v1/message", {"signed": True}
        )


def test_tls_peer_certificate_node_id_requires_single_valid_uri_san():
    node_id = "0123456789abcdef"
    assert transport._certificate_node_id({
        "subjectAltName": (("URI", f"urn:iao:node:{node_id}"),)
    }) == node_id
    assert transport._certificate_node_id({
        "subjectAltName": (
            ("URI", f"urn:iao:node:{node_id}"),
            ("URI", f"urn:iao:node:{node_id}"),
        )
    }) is None
    assert transport._certificate_node_id({
        "subjectAltName": (("DNS", f"urn:iao:node:{node_id}"),)
    }) is None
    assert transport._certificate_node_id(None) is None
