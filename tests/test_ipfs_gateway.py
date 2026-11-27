from __future__ import annotations

import base64
import hashlib

import pytest

from omega.tools.ipfs_gateway import _cid_digest, make_ipfs_fetch


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _cid(body: bytes) -> str:
    raw = b"".join((
        _varint(1), _varint(0x0129), _varint(0x12), _varint(32),
        hashlib.sha256(body).digest(),
    ))
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def test_cid_parser_accepts_only_v1_dag_json_sha256():
    body = b'{"hello":"iao"}'
    cid = _cid(body)
    assert _cid_digest(cid) == hashlib.sha256(body).digest()
    with pytest.raises(ValueError):
        _cid_digest("Qm" + "a" * 44)


def test_gateway_configuration_rejects_urls_and_private_authority():
    with pytest.raises(ValueError):
        make_ipfs_fetch(["http://gateway.example"])
    with pytest.raises(ValueError):
        make_ipfs_fetch(["gateway.example/path"])
    with pytest.raises(ValueError):
        make_ipfs_fetch([])


def test_fetch_verifies_content_against_cid(monkeypatch):
    body = b'{"hello":"iao"}'
    cid = _cid(body)
    calls = []

    def fake_fetch(url, policy):
        calls.append(url)
        return {
            "status": 200,
            "content_type": "application/vnd.ipld.dag-json",
            "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "body": body.decode(),
            "untrusted": True,
        }

    monkeypatch.setattr("omega.egress.fetch", fake_fetch)
    tool = make_ipfs_fetch(["ipfs.example"])
    validated = tool.validate({"cid": cid})
    result = tool.run(validated)
    assert result["status"] == "SUCCEEDED"
    assert result["gateway"] == "ipfs.example"
    assert tool.verify(result) == "PASS"
    assert calls == [f"https://ipfs.example/ipfs/{cid}?format=dag-json"]


def test_fetch_rejects_cid_content_mismatch(monkeypatch):
    cid = _cid(b'{"expected":true}')

    def fake_fetch(url, policy):
        return {
            "status": 200,
            "content_type": "application/vnd.ipld.dag-json",
            "sha256": "sha256:" + hashlib.sha256(b'{"attacker":true}').hexdigest(),
            "body": '{"attacker":true}',
            "untrusted": True,
        }

    monkeypatch.setattr("omega.egress.fetch", fake_fetch)
    tool = make_ipfs_fetch(["ipfs.example"])
    result = tool.run(tool.validate({"cid": cid}))
    assert result["status"] == "DENIED"
    assert result["error"] == "CID_MISMATCH"
    assert tool.verify(result) == "PASS"


def test_input_rejects_extra_fields():
    tool = make_ipfs_fetch(["ipfs.example"])
    with pytest.raises(ValueError):
        tool.validate({"cid": _cid(b"{}"), "url": "https://evil.example"})
