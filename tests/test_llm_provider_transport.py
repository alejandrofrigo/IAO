"""Security tests for the pinned HTTPS provider transport."""
import json

import pytest

from omega import llm_provider_transport as transport


class FakeResponse:
    status = 200

    def __init__(self, body=b'{"choices": []}', headers=None):
        self.body = body
        self.headers = headers or {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, limit):
        return self.body[:limit]


class FakeConnection:
    response = FakeResponse()

    def __init__(self, host, port, ip, timeout):
        self.args = (host, port, ip, timeout)
        self.request_args = None
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.request_args = (method, path, body, headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def setup_transport(monkeypatch, response):
    FakeConnection.response = response

    def resolve(host, port, policy):
        if host == "127.0.0.1":
            raise transport.EgressDenied("PRIVATE_ADDRESS")
        return "93.184.216.34"

    monkeypatch.setattr(transport, "_resolve", resolve)
    monkeypatch.setattr(transport, "_SConn", FakeConnection)


def _dns_result(*addresses):
    return [
        (2, 1, 6, "", (address, 443))
        for address in addresses
    ]


def test_real_egress_resolver_rejects_loopback_and_private_dns(monkeypatch):
    from omega.egress import EgressDenied, EgressPolicy

    policy = EgressPolicy(
        allow_hosts=frozenset({"gateway.example"}),
        resolver=lambda host, port, type: _dns_result("127.0.0.1"),
    )
    with pytest.raises(EgressDenied, match="PRIVATE_ADDRESS"):
        transport._resolve("gateway.example", 443, policy)


def test_real_egress_resolver_rejects_mixed_public_and_private_dns(monkeypatch):
    from omega.egress import EgressDenied, EgressPolicy

    policy = EgressPolicy(
        allow_hosts=frozenset({"gateway.example"}),
        resolver=lambda host, port, type: _dns_result("93.184.216.34", "10.0.0.8"),
    )
    with pytest.raises(EgressDenied, match="PRIVATE_ADDRESS"):
        transport._resolve("gateway.example", 443, policy)


def test_real_egress_resolver_accepts_public_dns_and_pins_one_ip():
    from omega.egress import EgressPolicy

    policy = EgressPolicy(
        allow_hosts=frozenset({"gateway.example"}),
        resolver=lambda host, port, type: _dns_result("93.184.216.34"),
    )
    assert transport._resolve("gateway.example", 443, policy) == "93.184.216.34"


def test_post_json_uses_pinned_https_and_posts_payload(monkeypatch):
    body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
    setup_transport(monkeypatch, FakeResponse(body))
    result = transport.post_json(
        "https://gateway.example/v1/chat/completions",
        {"model": "test", "messages": []},
        headers={"Authorization": "Bearer synthetic"},
    )
    assert result["choices"][0]["message"]["content"] == "ok"


@pytest.mark.parametrize("url", [
    "http://gateway.example/v1",
    "https://127.0.0.1/v1",
    "https://user:pass@gateway.example/v1",
    "https://gateway.example:8443/v1",
])
def test_post_json_rejects_unsafe_url(monkeypatch, url):
    setup_transport(monkeypatch, FakeResponse())
    with pytest.raises(transport.ProviderTransportError):
        transport.post_json(url, {})


def test_post_json_rejects_redirects_without_following(monkeypatch):
    setup_transport(monkeypatch, FakeResponse(
        b'{}', {"Content-Type": "application/json", "Location": "https://other.example/x"}
    ))
    FakeConnection.response.status = 302
    with pytest.raises(transport.ProviderTransportError):
        transport.post_json("https://gateway.example/v1", {})
    FakeConnection.response.status = 200


def test_post_json_rejects_oversized_response(monkeypatch):
    setup_transport(monkeypatch, FakeResponse(
        b'{"oversized": true}', {"Content-Type": "application/json", "Content-Length": "100"}
    ))
    with pytest.raises(transport.ProviderTransportError):
        transport.post_json("https://gateway.example/v1", {}, max_response_bytes=10)


def test_post_json_rejects_non_json_and_invalid_json(monkeypatch):
    setup_transport(monkeypatch, FakeResponse(b"not-json", {"Content-Type": "text/plain"}))
    with pytest.raises(transport.ProviderTransportError):
        transport.post_json("https://gateway.example/v1", {})
    setup_transport(monkeypatch, FakeResponse(b"not-json"))
    with pytest.raises(transport.ProviderTransportError):
        transport.post_json("https://gateway.example/v1", {})
