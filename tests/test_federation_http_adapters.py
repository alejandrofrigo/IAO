"""Both HTTP adapters must enforce the same signed federation-message boundary."""
import asyncio
import json
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from threading import Thread

from starlette.requests import Request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from apps.api import main
from omega.federation import MAX_MSG, Node, _sign
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

def _duplicate_challenge(node):
    challenge = {
        "v": 1, "from": node.node_id, "to": node.node_id,
        "nonce": "a" * 64, "ts": time.time(),
    }
    raw = json.dumps(challenge, separators=(",", ":"))
    return (raw[:-1] + ',"ts":' + str(time.time()) + '}').encode("utf-8")

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
        challenge_response = client.post(
            "/fed/v1/handshake", content=_duplicate_challenge(node),
            headers={"Content-Type": "application/json"},
        )
        assert challenge_response.status_code == 400
        assert challenge_response.json()["error"] == "INVALID_CHALLENGE"
        for path, allowed in (
            ("/fed/v1/contract", "GET"),
            ("/fed/v1/publication", "GET"),
            ("/fed/v1/identity", "GET"),
            ("/fed/v1/handshake", "POST"),
            ("/fed/v1/message", "POST"),
        ):
            wrong_method = "POST" if allowed == "GET" else "GET"
            method_response = client.request(
                wrong_method, path, content=b"{}" if wrong_method == "POST" else None,
            )
            method_payload = method_response.json()
            assert method_response.status_code == 405
            assert method_payload["error"] == "METHOD_NOT_ALLOWED"
            assert method_response.headers["allow"] == allowed
            assert method_response.headers["x-correlation-id"] == method_payload["correlation_id"]
            assert len(method_payload["correlation_id"]) == 32
            assert method_response.headers["cache-control"] == "no-store"
            assert method_response.headers["x-content-type-options"] == "nosniff"
        device_patch = client.patch("/v1/device/enroll")
        assert device_patch.status_code == 405
        assert device_patch.json()["error"] == "METHOD_NOT_ALLOWED"
        assert device_patch.headers["allow"] == "POST"
        assert device_patch.headers["x-correlation-id"] == device_patch.json()["correlation_id"]
        unknown_response = client.get("/fed/v1/not-a-route")
        assert unknown_response.status_code == 404
        assert unknown_response.json()["error"] == "NOT_FOUND"
        assert len(unknown_response.json()["correlation_id"]) == 32
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
        challenge_request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/handshake",
            data=_duplicate_challenge(node), method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(challenge_request, timeout=3)
            raise AssertionError("duplicate federation challenge members were accepted")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 400
            assert payload["error"] == "INVALID_CHALLENGE"
        for path, allowed in (
            ("/fed/v1/contract", "GET"),
            ("/fed/v1/publication", "GET"),
            ("/fed/v1/identity", "GET"),
            ("/fed/v1/handshake", "POST"),
            ("/fed/v1/message", "POST"),
        ):
            wrong_method = "POST" if allowed == "GET" else "GET"
            method_request = urllib.request.Request(
                f"http://127.0.0.1:{httpd.server_address[1]}{path}",
                data=b"{}" if wrong_method == "POST" else None,
                method=wrong_method,
            )
            try:
                urllib.request.urlopen(method_request, timeout=3)
                raise AssertionError("invalid federation method was accepted")
            except urllib.error.HTTPError as response:
                payload = json.loads(response.read())
                assert response.code == 405
                assert payload["error"] == "METHOD_NOT_ALLOWED"
                assert response.headers["Allow"] == allowed
                assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
                assert response.headers["Cache-Control"] == "no-store"
                assert response.headers["X-Content-Type-Options"] == "nosniff"
        patch_request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/device/enroll",
            data=b"", method="PATCH",
        )
        try:
            urllib.request.urlopen(patch_request, timeout=3)
            raise AssertionError("unsupported PATCH method was accepted")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 405
            assert payload["error"] == "METHOD_NOT_ALLOWED"
            assert response.headers["Allow"] == "POST"
            assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
        unknown_request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/not-a-route",
            method="GET",
        )
        try:
            urllib.request.urlopen(unknown_request, timeout=3)
            raise AssertionError("unknown federation route was accepted")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 404
            assert payload["error"] == "NOT_FOUND"
            assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
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


def test_fastapi_federation_runtime_exception_is_non_disclosing(monkeypatch, tmp_path):
    client = configured_client(monkeypatch, tmp_path)

    def fail_node():
        raise RuntimeError("private-federation-runtime-marker")

    monkeypatch.setattr(main, "_get_federation_node", fail_node)
    response = client.get("/fed/v1/contract")
    payload = response.json()
    assert response.status_code == 503
    assert payload["error"] == "FEDERATION_UNAVAILABLE"
    assert len(payload["correlation_id"]) == 32
    assert response.headers["x-correlation-id"] == payload["correlation_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "private-federation-runtime-marker" not in response.text


def test_stdlib_federation_runtime_exception_is_non_disclosing():
    class BrokenNode:
        served = {"knowledge.search"}

        def contract_for_self(self, _capabilities):
            raise RuntimeError("private-federation-runtime-marker")

    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(object(), BrokenNode()),
    )
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/contract",
        method="GET",
    )
    try:
        try:
            urllib.request.urlopen(request, timeout=3)
            raise AssertionError("federation exception must return 503")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == 503
            assert payload["error"] == "FEDERATION_UNAVAILABLE"
            assert len(payload["correlation_id"]) == 32
            assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert "private-federation-runtime-marker" not in json.dumps(payload)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


def test_publication_runtime_failure_has_matching_safe_error(monkeypatch, tmp_path):
    class BrokenPublicationNode:
        served = {"knowledge.search"}

        def identity_publication(self, *_args, **_kwargs):
            raise RuntimeError("private-publication-runtime-marker")

    monkeypatch.setenv("IAO_FEDERATION_PUBLIC_PEERING", "true")
    monkeypatch.setenv("IAO_FEDERATION_PUBLIC_ORIGIN", "https://peer.example")

    client = configured_client(monkeypatch, tmp_path)
    monkeypatch.setattr(
        main, "_get_federation_node", lambda: BrokenPublicationNode(),
    )
    fastapi_response = client.get("/fed/v1/publication")
    assert fastapi_response.status_code == 503
    assert fastapi_response.json()["error"] == "FEDERATION_UNAVAILABLE"
    assert "private-publication-runtime-marker" not in fastapi_response.text

    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(object(), BrokenPublicationNode()),
    )
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/publication",
        method="GET",
    )
    try:
        try:
            urllib.request.urlopen(request, timeout=3)
            raise AssertionError("publication exception must return 503")
        except urllib.error.HTTPError as response:
            payload = json.loads(response.read())
            assert response.code == fastapi_response.status_code
            assert payload["error"] == fastapi_response.json()["error"]
            assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert "private-publication-runtime-marker" not in json.dumps(payload)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


def test_both_adapters_replace_invalid_federation_correlation_id(monkeypatch, tmp_path):
    class CorrelationNode:
        served = {"knowledge.search"}

        def contract_for_self(self, _capabilities):
            return {"ok": True, "correlation_id": "g" * 32}

    client = configured_client(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_get_federation_node", lambda: CorrelationNode())
    fastapi_response = client.get("/fed/v1/contract")
    assert fastapi_response.status_code == 200
    fastapi_id = fastapi_response.json()["correlation_id"]
    assert len(fastapi_id) == 32
    assert all(char in "0123456789abcdef" for char in fastapi_id)
    assert fastapi_response.headers["x-correlation-id"] == fastapi_id

    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(object(), CorrelationNode()),
    )
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/contract",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read())
            stdlib_id = payload["correlation_id"]
            assert response.status == 200
            assert len(stdlib_id) == 32
            assert all(char in "0123456789abcdef" for char in stdlib_id)
            assert response.headers["X-Correlation-ID"] == stdlib_id
            assert stdlib_id != "g" * 32
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


def test_fastapi_federation_body_enforces_streamed_size_limit():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/fed/v1/message",
        "headers": [(b"content-length", b"1")],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("test", 123),
        "scheme": "http",
        "http_version": "1.1",
        "root_path": "",
    }

    async def receive():
        return {
            "type": "http.request",
            "body": b"x" * (MAX_MSG + 1),
            "more_body": False,
        }

    request = Request(scope, receive)
    body, error = asyncio.run(main._federation_body(request))
    assert body is None
    assert error.status_code == 413
    payload = json.loads(error.body.decode("utf-8"))
    assert payload["error"] == "PAYLOAD_TOO_LARGE"
    assert error.headers["x-correlation-id"] == payload["correlation_id"]
    assert error.headers["cache-control"] == "no-store"
    assert error.headers["x-content-type-options"] == "nosniff"
