"""F5 controlled federation. Known peers only (ParticipationContract), Ed25519 signed envelopes,
replay/skew protection, leases, revocation, per-peer rate limits, READ_ONLY capabilities only.
Peers are untrusted for results: responses are signature-checked and treated as data."""
import base64
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from omega.audit import canonical_json
from omega.store import Store
from omega.tools.registry import ToolRegistry

MAX_MSG = 32 * 1024
_EXEC = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fed")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def node_id_of(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def _sign(key: Ed25519PrivateKey, env: dict[str, Any]) -> dict[str, Any]:
    return {**env, "sig": _b64(key.sign(canonical_json(env)))}


def _verify(pub_raw: bytes, env: dict[str, Any]) -> bool:
    try:
        sig = base64.b64decode(env["sig"], validate=True)
        body = {k: v for k, v in env.items() if k != "sig"}
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, canonical_json(body))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


class FedDenied(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status, self.code = status, code


class Node:
    def __init__(self, store: Store, registry: ToolRegistry, key: Ed25519PrivateKey | None = None, *,
                 clock: Callable[[], float] = time.time, skew: float = 60.0, rate_limit_per_min: int = 30,
                 served: frozenset[str] = frozenset({"knowledge.search"})) -> None:
        self.store, self.registry, self.clock, self.skew, self.rate, self.served = store, registry, clock, skew, rate_limit_per_min, served
        self.key = key or Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.node_id = node_id_of(self.pub)
        self.peers: dict[str, dict[str, Any]] = {}
        self._seen: dict[tuple[str, str], float] = {}
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    # ---- enrolment (explicit operator action) ----
    def contract_for_self(self, capabilities: list[str], lease_seconds: int = 3600, rate: int = 30) -> dict[str, Any]:
        return {"peer_id": self.node_id, "pubkey": _b64(self.pub), "capabilities": capabilities,
                "lease_expires_at": self.clock() + lease_seconds, "rate_limit_per_min": rate}

    def enroll(self, c: dict[str, Any]) -> None:
        pub = base64.b64decode(c["pubkey"], validate=True)
        if node_id_of(pub) != c["peer_id"]:
            raise ValueError("PEER_ID_DOES_NOT_MATCH_KEY")  # id is bound to the key
        if not isinstance(c["capabilities"], list) or not set(c["capabilities"]) <= self.served:
            raise ValueError("CAPABILITY_NOT_FEDERABLE")
        self.peers[c["peer_id"]] = {**c, "pub": pub, "revoked": False}
        self.store.audit("operator", "PEER_ENROLLED", c["peer_id"], capabilities=sorted(c["capabilities"]))

    def revoke(self, peer_id: str) -> None:
        if peer_id in self.peers:
            self.peers[peer_id]["revoked"] = True
        self.store.audit("operator", "PEER_REVOKED", peer_id)

    # ---- inbound ----
    def handle(self, raw: bytes) -> tuple[int, dict[str, Any]]:
        peer = "unknown"
        try:
            if len(raw) > MAX_MSG:
                raise FedDenied(413, "PAYLOAD_TOO_LARGE")
            try:
                env = json.loads(raw)
                peer = str(env["from"])
                if not isinstance(env, dict) or env.get("v") != 1:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise FedDenied(400, "MALFORMED") from None
            if env.get("to") != self.node_id:
                raise FedDenied(403, "WRONG_RECIPIENT")          # a message captured for node X is useless at node Y
            c = self.peers.get(peer)
            if c is None:
                raise FedDenied(403, "UNKNOWN_PEER")
            if not _verify(c["pub"], env):
                raise FedDenied(403, "BAD_SIGNATURE")
            now = self.clock()
            if abs(now - float(env.get("ts", 0))) > self.skew:
                raise FedDenied(403, "CLOCK_SKEW")
            nonce = str(env.get("nonce", ""))
            if len(nonce) < 16:
                raise FedDenied(400, "MALFORMED")
            with self._lock:
                self._seen = {k: t for k, t in self._seen.items() if now - t <= 2 * self.skew}
                if (peer, nonce) in self._seen:
                    raise FedDenied(409, "REPLAY")
                self._seen[(peer, nonce)] = now                    # only after the signature verified
                q = self._hits[peer]
                while q and q[0] < now - 60:
                    q.popleft()
                if len(q) >= min(self.rate, int(c["rate_limit_per_min"])):
                    raise FedDenied(429, "RATE_LIMITED")
                q.append(now)
            if c["revoked"]:
                raise FedDenied(403, "PEER_REVOKED")
            if now > float(c["lease_expires_at"]):
                raise FedDenied(403, "LEASE_EXPIRED")
            cap = env.get("capability")
            spec = self.registry.get(cap) if isinstance(cap, str) else None
            if (not isinstance(cap, str) or cap not in c["capabilities"] or cap not in self.served
                    or spec is None or spec.effect_class != "READ_ONLY"):
                raise FedDenied(403, "CAPABILITY_NOT_GRANTED")
            try:
                inp = spec.validate_input(env.get("body"))
            except ValueError:
                raise FedDenied(422, "INVALID_INPUT") from None
            fut = _EXEC.submit(spec.run, inp)
            try:
                out = fut.result(timeout=spec.timeout_seconds)
            except FutureTimeout:
                raise FedDenied(504, "TIMED_OUT") from None
            except Exception:
                raise FedDenied(500, "TOOL_ERROR") from None
            verdict = spec.verify(out)
            self.store.audit(peer, "FED_REQUEST", cap, decision="ALLOW", verification=verdict, nonce=nonce[:8])
            reply = {"v": 1, "from": self.node_id, "to": peer, "ts": self.clock(), "in_reply_to": nonce,
                     "capability": cap, "result": out, "verification": verdict}
            return 200, _sign(self.key, reply)
        except FedDenied as e:
            self.store.audit(peer, "FED_REQUEST", "denied", decision="DENY", reason=e.code)
            return e.status, {"error": e.code}

    # ---- outbound ----
    def send(self, peer_id: str, url: str, capability: str, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
        c = self.peers.get(peer_id)
        if c is None or c["revoked"]:
            return {"ok": False, "error": "UNKNOWN_PEER"}
        nonce = os.urandom(16).hex()
        env = _sign(self.key, {"v": 1, "from": self.node_id, "to": peer_id, "ts": self.clock(), "nonce": nonce,
                               "capability": capability, "body": body})
        return self._post(c, url, env, nonce, timeout)

    def _post(self, c: dict[str, Any], url: str, env: dict[str, Any], nonce: str, timeout: float) -> dict[str, Any]:
        req = urllib.request.Request(url, method="POST", data=json.dumps(env).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(MAX_MSG * 8)
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read(4096)).get("error", "HTTP_ERROR")
            except ValueError:
                err = "HTTP_ERROR"
            return {"ok": False, "status": e.code, "error": err}
        except (urllib.error.URLError, OSError, TimeoutError):
            return {"ok": False, "error": "PEER_UNREACHABLE"}   # partition: no state change, safe to retry
        try:
            resp = json.loads(data)
        except ValueError:
            return {"ok": False, "error": "BAD_RESPONSE"}
        if not _verify(c["pub"], resp):
            return {"ok": False, "error": "BAD_RESPONSE_SIGNATURE"}
        if resp.get("to") != self.node_id or resp.get("from") != c["peer_id"] or resp.get("in_reply_to") != nonce:
            return {"ok": False, "error": "REPLAYED_OR_MISROUTED_RESPONSE"}
        if abs(self.clock() - float(resp.get("ts", 0))) > self.skew:
            return {"ok": False, "error": "CLOCK_SKEW"}
        return {"ok": True, "verification": resp.get("verification"), "result": resp["result"], "untrusted": True}


class FedServer:
    def __init__(self, node: Node, host: str = "127.0.0.1", port: int = 0) -> None:
        outer = node

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: object) -> None:
                pass

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(min(n, MAX_MSG + 1)) if self.path == "/fed/v1/message" else b""
                status, payload = outer.handle(raw) if self.path == "/fed/v1/message" else (404, {"error": "NOT_FOUND"})
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer((host, port), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://{host}:{self.port}/fed/v1/message"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "FedServer":
        self._t.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
