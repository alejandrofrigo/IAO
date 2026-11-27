"""Both HTTP adapters must enforce the same signed federation-message boundary."""
import json
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from threading import Thread
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from apps.api import main
from omega.federation import Node, _sign
from omega.server import make_handler
from tests.test_production_api import configured_client


def _forged_message(node):
    enrolled_peer = Node(node.store, node.registry)
    node.enroll(
        enrolled_peer.contract_for_self(["knowledge.search"]),
        granted_capabilities=["knowledge.search"],
    )
    envelope = {
        "v": 1,
        "from": enrolled_peer.node_id,
        "to": node.node_id,
        "ts": time.time(),
        "nonce": "federation-forged-signature-0001",
        "capability": "knowledge.search",
        "body": {"query": "audit chain"},
    }
    attacker_key = Ed25519PrivateKey.generate()
    return json.dumps(_sign(attacker_key, envelope)).encode("utf-8")


def _duplicate_message(node):
    enrolled_peer = Node(node.store, node.registry)
    node.enroll(
        enrolled_peer.contract_for_self(["knowledge.search"]),
        granted_capabilities=["knowledge.search"],
    )
    envelope = {
        "v": 1,
        "from": enrolled_peer.node_id,
        "to": node.node_id,
        "ts": time.time(),
        "nonce": "federation-duplicate-member-0001",
        "capability": "knowledge.search",
        "body": {"query": "audit chain"},
    }
    signed = json.dumps(_sign(enrolled_peer.key, envelope), separators=(",", ":"))
    return (signed[:-1] + ',"nonce":"federation-duplicate-member-0002"}').encode("utf-8")

def test_fastapi_federation_message_rejects_forged_enrolled_peer(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)
    service = main._get_service()
    node = Node(service.store, service.registry)
    monkeypatch.setattr(main, "_get_federation_node", lambda: node)
    raw = _forged_message(node)
    try:
        response = client.post(
            "/fed/v1/message",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 403
        assert response.json()["error"] == "BAD_SIGNATURE"
        duplicate_response = client.post(
            "/fed/v1/message", content=_duplicate_message(node),
            headers={"Content-Type": "application/json"},
        )
        assert duplicate_response.status_code == 400
        assert duplicate_response.json()["error"] == "MALFORMED"
        assert any(
            event["event_type"] == "FED_REQUEST"
            and event["details"].get("reason") == "BAD_SIGNATURE"
            for event in service.store._all_events()
        )
    finally:
        service.store.close()
        main._service = None
        main._federation_node = None


def test_stdlib_federation_message_rejects_forged_enrolled_peer(tmp_path, monkeypatch):
    from omega.server import build_service

    monkeypatch.setenv("AUDIT_HMAC_KEY", "federation-test-audit-key-" + "y" * 40)
    service = build_service(
        tmp_path / "state",
        "federation-test-token-key-" + "x" * 32,
        Path(__file__).resolve().parents[1] / "docs" / "corpus",
        identity_rollback_anchor_enabled=False,
    )
    node = Node(service.store, service.registry)
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(service, node),
    )
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    raw = _forged_message(node)
    request = urllib.request.Request(
        f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/message",
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        try:
            urllib.request.urlopen(request, timeout=3)
            raise AssertionError("forged federation signature was accepted")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 403
            assert payload["error"] == "BAD_SIGNATURE"
        duplicate_request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/message",
            data=_duplicate_message(node), method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(duplicate_request, timeout=3)
            raise AssertionError("duplicate federation members were accepted")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 400
            assert payload["error"] == "MALFORMED"
        assert any(
            event["event_type"] == "FED_REQUEST"
            and event["details"].get("reason") == "BAD_SIGNATURE"
            for event in service.store._all_events()
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
        service.store.close()
