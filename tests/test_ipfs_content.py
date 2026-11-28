from __future__ import annotations

import pytest

from omega import ipfs_content


class FakeResponse:
    def __init__(self, status=200, body=b"public artifact"):
        self.status = status
        self.body = body

    def getheader(self, name):
        if name == "Content-Length":
            return str(len(self.body))
        return None

    def read(self, size=-1):
        return self.body[:size]


def test_cid_validator_accepts_cidv0_and_base32_cidv1():
    cid_v0 = "Qm" + "1" * 44
    cid_v1 = "b" + "a" * 58
    assert ipfs_content.validate_cid(cid_v0) == cid_v0
    assert ipfs_content.validate_cid(cid_v1) == cid_v1
    for invalid in ("", "https://example.org", "../etc/passwd", "Qm" + "0" * 44):
        assert ipfs_content.validate_cid(invalid) is None


def test_local_kubo_api_requires_literal_loopback():
    assert ipfs_content._local_api("http://127.0.0.1:5001") == ("127.0.0.1", 5001)
    assert ipfs_content._local_api("http://[::1]:5001") == ("::1", 5001)
    for url in (
        "https://127.0.0.1:5001",
        "http://localhost:5001",
        "http://8.8.8.8:5001",
        "http://127.0.0.1:5001/api/v0",
        "http://user:pass@127.0.0.1:5001",
    ):
        with pytest.raises(ipfs_content.IPFSContentError):
            ipfs_content._local_api(url)


def test_fetch_cid_uses_only_local_kubo_api_and_bounds_response(monkeypatch):
    calls = []

    class Connection:
        def __init__(self, host, port, *, timeout):
            calls.append(("connect", host, port, timeout))
        def request(self, method, target, body=None, headers=None):
            calls.append(("request", method, target, body, headers))
        def getresponse(self):
            return FakeResponse()
        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(ipfs_content.http.client, "HTTPConnection", Connection)
    cid = "Qm" + "1" * 44
    body = ipfs_content.fetch_public_cid(cid)
    assert body == b"public artifact"
    assert calls[0] == ("connect", "127.0.0.1", 5001, 15.0)
    assert calls[1][0:3] == (
        "request", "POST", "/api/v0/cat?arg=" + cid
    )
    assert calls[-1] == ("close",)


def test_fetch_cid_rejects_oversized_content_and_redirects(monkeypatch):
    class Connection:
        response = FakeResponse()
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return self.response
        def close(self): pass

    monkeypatch.setattr(ipfs_content.http.client, "HTTPConnection", Connection)
    cid = "Qm" + "1" * 44
    Connection.response = FakeResponse(body=b"0123456789")
    with pytest.raises(ipfs_content.IPFSContentError, match="CONTENT_TOO_LARGE"):
        ipfs_content.fetch_public_cid(cid, max_bytes=5)
    Connection.response = FakeResponse(status=302, body=b"")
    with pytest.raises(ipfs_content.IPFSContentError, match="REDIRECT_REFUSED"):
        ipfs_content.fetch_public_cid(cid)


def test_fetch_cid_rejects_invalid_cid_before_connecting(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("local API must not be contacted for an invalid CID")
    monkeypatch.setattr(ipfs_content.http.client, "HTTPConnection", forbidden)
    with pytest.raises(ipfs_content.IPFSContentError, match="INVALID_CID"):
        ipfs_content.fetch_public_cid("../not-a-cid")
