"""F5 controlled federation. Known peers only (ParticipationContract), Ed25519 signed envelopes,
replay/skew protection, leases, revocation, per-peer rate limits, READ_ONLY capabilities only.
Peers are untrusted for results: responses are signature-checked and treated as data."""
import ssl
import base64
import hashlib
import json
import os
import threading
import time
import math
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
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
import omega.federation_transport as federation_transport
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


def verify_identity_challenge(
    identity: dict[str, Any],
    response: dict[str, Any],
    *,
    requester_id: str,
    nonce: str,
    request_ts: float,
    now: float,
    skew: float = 60.0,
) -> dict[str, Any]:
    """Verify a public identity and its signed, nonce-bound challenge response."""
    def fail(code: str) -> dict[str, Any]:
        return {"ok": False, "error": code}

    if not isinstance(identity, dict) or not isinstance(response, dict):
        return fail("INVALID_DOCUMENT")
    if identity.get("protocol") != "iao-federation" or identity.get("version") != 1:
        return fail("UNSUPPORTED_IDENTITY_PROTOCOL")

    peer_id = identity.get("node_id")
    public_hex = identity.get("public_key")
    if (not isinstance(peer_id, str) or len(peer_id) != 16
            or any(ch not in "0123456789abcdef" for ch in peer_id)
            or not isinstance(public_hex, str) or len(public_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in public_hex)):
        return fail("INVALID_PUBLIC_IDENTITY")

    try:
        public_raw = bytes.fromhex(public_hex)
    except ValueError:
        return fail("INVALID_PUBLIC_IDENTITY")
    if len(public_raw) != 32 or node_id_of(public_raw) != peer_id:
        return fail("NODE_ID_KEY_MISMATCH")

    if (not isinstance(requester_id, str) or len(requester_id) != 16
            or any(ch not in "0123456789abcdef" for ch in requester_id)
            or not isinstance(nonce, str) or len(nonce) != 64
            or any(ch not in "0123456789abcdef" for ch in nonce)):
        return fail("INVALID_EXPECTED_CHALLENGE")

    numeric = (request_ts, now, skew)
    if any(isinstance(x, bool) or not isinstance(x, (int, float))
           or not math.isfinite(float(x)) for x in numeric) or skew < 0:
        return fail("INVALID_TIME_PARAMETERS")

    if not _verify(public_raw, response):
        return fail("BAD_CHALLENGE_SIGNATURE")

    if (response.get("v") != 1
            or response.get("protocol") != "iao-federation"
            or response.get("from") != peer_id
            or response.get("to") != requester_id
            or response.get("nonce") != nonce
            or response.get("request_ts") != float(request_ts)):
        return fail("CHALLENGE_BINDING_MISMATCH")

    response_ts = response.get("ts")
    if (isinstance(response_ts, bool)
            or not isinstance(response_ts, (int, float))
            or not math.isfinite(float(response_ts))):
        return fail("INVALID_RESPONSE_TIMESTAMP")
    if abs(float(now) - float(response_ts)) > float(skew):
        return fail("RESPONSE_CLOCK_SKEW")
    if abs(float(now) - float(request_ts)) > float(skew):
        return fail("REQUEST_CLOCK_SKEW")

    return {"ok": True, "peer_id": peer_id, "verified": True}


class FedDenied(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status, self.code = status, code


class Node:
    def __init__(self, store: Store, registry: ToolRegistry, key: Ed25519PrivateKey | None = None, *,
                 clock: Callable[[], float] = time.time, skew: float = 60.0, rate_limit_per_min: int = 30,
                 served: frozenset[str] = frozenset({"knowledge.search"}),
                 peer_store_path: Path | None = None,
                 audit_fn: Callable[..., Any] | None = None) -> None:
        self.store, self.registry, self.clock, self.skew, self.rate, self.served = store, registry, clock, skew, rate_limit_per_min, served
        self.audit_fn = audit_fn or store.audit
        self.key = key or Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.node_id = node_id_of(self.pub)
        self.peer_store_path = Path(peer_store_path) if peer_store_path is not None else None
        self.peers: dict[str, dict[str, Any]] = {}
        self._seen: dict[tuple[str, str], float] = {}
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()
        if self.peer_store_path is not None:
            self._load_persistent_peers()

    def _validate_peer_contract(
        self, c: dict[str, Any], *, allow_expired: bool = False
    ) -> tuple[bytes, dict[str, Any]]:
        if not isinstance(c, dict):
            raise ValueError("INVALID_PEER_CONTRACT")
        peer_id = c.get("peer_id")
        encoded = c.get("pubkey")
        caps = c.get("capabilities")
        lease = c.get("lease_expires_at")
        rate = c.get("rate_limit_per_min")
        if not isinstance(peer_id, str) or len(peer_id) != 16:
            raise ValueError("INVALID_PEER_ID")
        if not isinstance(encoded, str):
            raise ValueError("INVALID_PUBLIC_KEY")
        try:
            pub = base64.b64decode(encoded, validate=True)
        except Exception:
            raise ValueError("INVALID_PUBLIC_KEY") from None
        if len(pub) != 32 or node_id_of(pub) != peer_id:
            raise ValueError("PEER_ID_DOES_NOT_MATCH_KEY")
        if (not isinstance(caps, list) or not caps or
                any(not isinstance(x, str) or not x for x in caps) or
                len(caps) != len(set(caps)) or not set(caps) <= self.served):
            raise ValueError("CAPABILITY_NOT_FEDERABLE")
        if (isinstance(lease, bool) or not isinstance(lease, (int, float))
                or not math.isfinite(float(lease))
                or (not allow_expired and float(lease) <= self.clock())):
            raise ValueError("INVALID_PEER_LEASE")
        if isinstance(rate, bool) or not isinstance(rate, int) or not 1 <= rate <= 300:
            raise ValueError("INVALID_PEER_RATE_LIMIT")

        clean = {
            "peer_id": peer_id,
            "pubkey": encoded,
            "capabilities": list(caps),
            "lease_expires_at": float(lease),
            "rate_limit_per_min": rate,
        }
        endpoint = c.get("endpoint")
        if endpoint is not None:
            if not isinstance(endpoint, str) or len(endpoint) > 2048:
                raise ValueError("INVALID_PEER_ENDPOINT")
            try:
                u = urlsplit(endpoint)
                # Validación estricta (producción): HTTPS, puerto 443 o vacío,
                # path exacto /fed/v1/message, sin credenciales ni query.
                tls_test_mode = bool(os.environ.get("IAO_TLS_CA_FILE"))
                # Permitir puerto no-443 en hosts de túnel reconocidos.
                # En producción con dominio propio se mantiene la regla 443.
                _TUNNEL_HOSTS = {"bore.pub", "loca.lt"}
                _TUNNEL_SUFFIXES = (
                    ".ngrok-free.app", ".ngrok.io",
                    ".trycloudflare.com", ".loca.lt",
                )
                _host = (u.hostname or "").lower()
                is_tunnel_host = (
                    _host in _TUNNEL_HOSTS
                    or any(_host.endswith(_sfx) for _sfx in _TUNNEL_SUFFIXES)
                )
                strict_valid = (
                    u.scheme == "https" and bool(u.hostname)
                    and not u.username and not u.password
                    and (u.port is None or u.port == 443 or tls_test_mode or is_tunnel_host)
                    and u.path == "/fed/v1/message"
                    and not u.query and not u.fragment
                )
                # Salvaguarda de integración local (solo si el operador
                # habilita explícitamente IAO_ALLOW_LOOPBACK_HTTP=1):
                # permite HTTP en loopback y cualquier puerto, siempre que
                # el path sea el esperado y no haya credenciales. Esta ruta
                # NUNCA afecta peers externos: el host debe ser loopback.
                loopback_valid = False
                if (not strict_valid
                        and os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") == "1"
                        and u.scheme in ("http", "https")
                        and bool(u.hostname)
                        and not u.username and not u.password
                        and u.hostname.lower() in {"127.0.0.1", "::1", "localhost"}
                        and u.path == "/fed/v1/message"
                        and not u.query and not u.fragment):
                    loopback_valid = True
                valid = strict_valid or loopback_valid
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("INVALID_PEER_ENDPOINT")
            clean["endpoint"] = endpoint
        return pub, clean

    def _save_persistent_peers(self) -> None:
        path = self.peer_store_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise RuntimeError("PEER_STORE_SYMLINK_REFUSED")
        payload = {
            "version": 2,
            "node_id": self.node_id,
            "peers": [
                {
                    **{k: v for k, v in peer.items() if k != "pub"},
                    "pubkey": peer["pubkey"],
                }
                for _, peer in sorted(self.peers.items())
            ],
        }
        fd, temp_name = tempfile.mkstemp(prefix=".federation-peers-", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, sort_keys=True, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_name, path)
            os.chmod(path, 0o600)
            try:
                dfd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _load_persistent_peers(self) -> None:
        path = self.peer_store_path
        if path is None or not path.exists():
            return
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("PEER_STORE_PATH_REFUSED")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(data, dict) or data.get("version") not in (1, 2)
                    or data.get("node_id") != self.node_id
                    or not isinstance(data.get("peers"), list)):
                raise ValueError("INVALID_PEER_STORE_FORMAT")
            loaded: dict[str, dict[str, Any]] = {}
            for item in data["peers"]:
                # Conservar peers expirados; send() bloquea su utilización.
                pub, clean = self._validate_peer_contract(item, allow_expired=True)
                peer_id = clean["peer_id"]
                if peer_id in loaded or not isinstance(item.get("revoked"), bool):
                    raise ValueError("INVALID_OR_DUPLICATE_PEER")
                # V1 no tenía concesiones explícitas: migrar sin permisos entrantes.
                grants = item.get("granted_capabilities", []) if data["version"] == 2 else []
                clean["granted_capabilities"] = self._clean_grants(grants)
                loaded[peer_id] = {**clean, "pub": pub, "revoked": item["revoked"]}
            self.peers = loaded
        except Exception as exc:
            raise RuntimeError("PEER_STORE_INVALID_FAIL_CLOSED") from exc

    # ---- public identity and signed pre-enrolment challenge ----
    def identity_document(self) -> dict[str, Any]:
        """Public metadata only; never exposes private key material."""
        return {
            "protocol": "iao-federation",
            "version": 1,
            "node_id": self.node_id,
            "public_key": self.pub.hex(),
        }

    def identity_publication(self, endpoint: str, *,
                              capabilities: list[str] | None = None,
                              lease_seconds: int = 3600) -> dict[str, Any]:
        """Firmado, publicable en /.well-known/iao-federation.json.

        Incluye identidad, endpoint público, capabilities, y una firma
        Ed25519 del cuerpo canónico. El peer que lo descubre puede
        verificar la firma, y luego completar el handshake challenge
        para confirmar posesión de la clave privada.
        """
        import time as _time
        body = {
            "protocol": "iao-federation-publication",
            "version": 1,
            "node_id": self.node_id,
            "public_key": self.pub.hex(),
            "endpoint": endpoint,
            "capabilities": sorted(capabilities or sorted(self.served)),
            "lease_expires_at": float(self.clock() + lease_seconds),
            "issued_at": float(self.clock()),
        }
        return {
            **body,
            "sig": _b64(self.key.sign(canonical_json(body))),
        }

    @staticmethod
    def verify_publication(publication: dict[str, Any]) -> bool:
        """Verifica la firma Ed25519 de una publicación.

        No verifica vigencia temporal aquí; el llamador decide.
        """
        try:
            if publication.get("protocol") != "iao-federation-publication":
                return False
            if publication.get("version") != 1:
                return False
            pub = bytes.fromhex(publication["public_key"])
            if len(pub) != 32:
                return False
            sig = base64.b64decode(publication["sig"], validate=True)
            body = {k: v for k, v in publication.items() if k != "sig"}
            Ed25519PublicKey.from_public_bytes(pub).verify(
                sig, canonical_json(body)
            )
            return True
        except Exception:
            return False

    def answer_challenge(self, raw: bytes) -> tuple[int, dict[str, Any]]:
        """Sign a fresh caller challenge without enrolling or trusting its sender."""
        if not isinstance(raw, bytes) or len(raw) > MAX_MSG:
            return 413, {"error": "PAYLOAD_TOO_LARGE"}
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "INVALID_CHALLENGE"}
        if not isinstance(request, dict):
            return 400, {"error": "INVALID_CHALLENGE"}

        requester = request.get("from")
        recipient = request.get("to")
        nonce = request.get("nonce")
        ts = request.get("ts")
        if (request.get("v") != 1
                or not isinstance(requester, str)
                or len(requester) != 16
                or any(ch not in "0123456789abcdef" for ch in requester)
                or recipient != self.node_id
                or not isinstance(nonce, str)
                or len(nonce) != 64
                or any(ch not in "0123456789abcdef" for ch in nonce)
                or isinstance(ts, bool)
                or not isinstance(ts, (int, float))
                or not math.isfinite(float(ts))):
            return 400, {"error": "INVALID_CHALLENGE"}
        if abs(self.clock() - float(ts)) > self.skew:
            return 400, {"error": "CHALLENGE_CLOCK_SKEW"}

        proof = {
            "v": 1,
            "protocol": "iao-federation",
            "from": self.node_id,
            "to": requester,
            "nonce": nonce,
            "request_ts": float(ts),
            "ts": self.clock(),
        }
        return 200, _sign(self.key, proof)

    # ---- enrolment (explicit operator action) ----
    def _clean_grants(self, grants: Any) -> list[str]:
        """Valida permisos de entrada concedidos localmente al peer."""
        if not isinstance(grants, list):
            raise ValueError("INVALID_GRANTED_CAPABILITIES")
        if any(not isinstance(cap, str) for cap in grants):
            raise ValueError("INVALID_GRANTED_CAPABILITIES")
        if len(grants) != len(set(grants)):
            raise ValueError("INVALID_GRANTED_CAPABILITIES")
        for cap in grants:
            spec = self.registry.get(cap)
            if cap not in self.served or spec is None or spec.effect_class != "READ_ONLY":
                raise ValueError("INVALID_GRANTED_CAPABILITIES")
        return sorted(grants)

    def contract_for_self(self, capabilities: list[str], lease_seconds: int = 3600, rate: int = 30) -> dict[str, Any]:
        return {"peer_id": self.node_id, "pubkey": _b64(self.pub), "capabilities": capabilities,
                "lease_expires_at": self.clock() + lease_seconds, "rate_limit_per_min": rate}

    def enroll(self, c: dict[str, Any], *, granted_capabilities: list[str] | None = None) -> None:
        pub, clean = self._validate_peer_contract(c)
        # El contrato remoto declara lo que el peer ofrece.
        # Los permisos que IAO le concede se configuran por separado.
        grants = self._clean_grants(granted_capabilities if granted_capabilities is not None else [])
        clean["granted_capabilities"] = grants
        peer_id = clean["peer_id"]
        with self._lock:
            previous = self.peers.get(peer_id)
            if previous is not None and previous.get("revoked"):
                raise ValueError("PEER_REVOKED_REENROLLMENT_REQUIRES_REVIEW")
            self.peers[peer_id] = {**clean, "pub": pub, "revoked": False}
            try:
                self._save_persistent_peers()
                self.audit_fn("operator", "PEER_ENROLLED", peer_id,
                                 capabilities=sorted(clean["capabilities"]), granted_capabilities=grants)
            except Exception:
                if previous is None:
                    self.peers.pop(peer_id, None)
                else:
                    self.peers[peer_id] = previous
                try:
                    self._save_persistent_peers()
                except Exception:
                    pass
                raise

    def revoke(self, peer_id: str) -> None:
        with self._lock:
            previous = self.peers.get(peer_id)
            if previous is not None:
                self.peers[peer_id] = {**previous, "revoked": True}
            try:
                self._save_persistent_peers()
                self.audit_fn("operator", "PEER_REVOKED", peer_id)
            except Exception:
                if previous is not None:
                    self.peers[peer_id] = previous
                try:
                    self._save_persistent_peers()
                except Exception:
                    pass
                raise

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
            if (not isinstance(cap, str) or cap not in c.get("granted_capabilities", [])
                    or cap not in self.served or spec is None
                    or spec.effect_class != "READ_ONLY"):
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
            self.audit_fn(peer, "FED_REQUEST", cap, decision="ALLOW", verification=verdict, nonce=nonce[:8])
            reply = {"v": 1, "from": self.node_id, "to": peer, "ts": self.clock(), "in_reply_to": nonce,
                     "capability": cap, "result": out, "verification": verdict}
            return 200, _sign(self.key, reply)
        except FedDenied as e:
            self.audit_fn(peer, "FED_REQUEST", "denied", decision="DENY", reason=e.code)
            return e.status, {"error": e.code}

    def handshake(self, endpoint: str, timeout: float = 5.0) -> dict[str, Any]:
        """Verifica identidad y posesión de clave de un peer sin enrolarlo."""
        if not isinstance(endpoint, str) or not isinstance(timeout, (int, float)):
            return {"ok": False, "error": "INVALID_ENDPOINT"}
        if isinstance(timeout, bool) or not math.isfinite(float(timeout)) or timeout <= 0:
            return {"ok": False, "error": "INVALID_TIMEOUT"}
        try:
            u = urlsplit(endpoint)
            host = (u.hostname or "").lower()
            loopback = host in {"127.0.0.1", "::1", "localhost"}
            if (u.scheme not in ({"https", "http"} if loopback else {"https"})
                    or not host or u.username or u.password
                    or u.path not in ("", "/") or u.query or u.fragment):
                return {"ok": False, "error": "INVALID_ENDPOINT"}
            if u.port not in (None, 443) and not loopback:
                # Quick tunnels and other HTTPS origins may use nonstandard ports
                # only when the peer contract validator recognizes that host.
                suffixes = (".trycloudflare.com", ".ngrok-free.app", ".ngrok.io", ".loca.lt")
                if not any(host.endswith(s) for s in suffixes):
                    return {"ok": False, "error": "INVALID_ENDPOINT"}

            base = endpoint.rstrip("/")
            ctx = self._ssl_context()

            def request_json(url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
                return federation_transport.request_json(
                    url,
                    method="GET" if payload is None else "POST",
                    payload=payload,
                    timeout=float(timeout),
                    max_bytes=MAX_MSG,
                    ssl_context=ctx,
                    allow_loopback=(
                        loopback
                        and os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") == "1"
                    ),
                )

            identity = request_json(base + "/fed/v1/identity")
            peer_id = identity.get("node_id")
            if peer_id == self.node_id:
                return {"ok": False, "error": "SELF_CONNECTION"}

            nonce = os.urandom(32).hex()
            request_ts = float(self.clock())
            challenge = {
                "v": 1,
                "from": self.node_id,
                "to": peer_id,
                "nonce": nonce,
                "ts": request_ts,
            }
            proof = request_json(base + "/fed/v1/handshake", challenge)
            result = verify_identity_challenge(
                identity, proof,
                requester_id=self.node_id,
                nonce=nonce,
                request_ts=request_ts,
                now=float(self.clock()),
                skew=self.skew,
            )
            if not result.get("ok"):
                return result
            return {
                "ok": True,
                "verified": True,
                "peer_id": result["peer_id"],
                "identity": identity,
                "verification": "ED25519_NONCE_CHALLENGE",
                "enrolled": False,
            }
        except urllib.error.HTTPError as exc:
            return {"ok": False, "status": exc.code, "error": "HTTP_ERROR"}
        except (urllib.error.URLError, OSError, TimeoutError):
            return {"ok": False, "error": "PEER_UNREACHABLE"}
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            return {"ok": False, "error": "INVALID_HANDSHAKE_RESPONSE"}

    # ---- outbound ----

    def connect_peer(
        self,
        publication: dict[str, Any],
        *,
        granted_capabilities: list[str],
        timeout: float = 5.0,
        rate_limit_per_min: int = 30,
    ) -> dict[str, Any]:
        """Verifica publicación y challenge antes de enrolar un peer."""
        try:
            if not isinstance(publication, dict):
                return {"ok": False, "error": "INVALID_PUBLICATION"}

            if (publication.get("protocol") != "iao-federation-publication"
                    or publication.get("version") != 1):
                return {"ok": False, "error": "UNSUPPORTED_PUBLICATION"}

            peer_id = publication.get("node_id")
            public_hex = publication.get("public_key")
            endpoint = publication.get("endpoint")
            caps = publication.get("capabilities")
            lease = publication.get("lease_expires_at")
            issued = publication.get("issued_at")

            if (not isinstance(peer_id, str) or len(peer_id) != 16
                    or any(c not in "0123456789abcdef" for c in peer_id)
                    or not isinstance(public_hex, str) or len(public_hex) != 64
                    or any(c not in "0123456789abcdef" for c in public_hex)):
                return {"ok": False, "error": "INVALID_PUBLIC_IDENTITY"}

            public_raw = bytes.fromhex(public_hex)
            if node_id_of(public_raw) != peer_id:
                return {"ok": False, "error": "NODE_ID_KEY_MISMATCH"}

            if not _verify(public_raw, publication):
                return {"ok": False, "error": "BAD_PUBLICATION_SIGNATURE"}

            if (isinstance(lease, bool) or not isinstance(lease, (int, float))
                    or not math.isfinite(float(lease))
                    or isinstance(issued, bool) or not isinstance(issued, (int, float))
                    or not math.isfinite(float(issued))):
                return {"ok": False, "error": "INVALID_PUBLICATION_TIME"}

            now = float(self.clock())
            if float(lease) <= now:
                return {"ok": False, "error": "PUBLICATION_EXPIRED"}
            if float(issued) > now + 300 or float(lease) <= float(issued):
                return {"ok": False, "error": "INVALID_PUBLICATION_TIME"}
            if float(lease) - float(issued) > 7 * 86400:
                return {"ok": False, "error": "PUBLICATION_LEASE_TOO_LONG"}

            if (not isinstance(caps, list) or not caps
                    or any(not isinstance(x, str) or not x for x in caps)
                    or len(caps) != len(set(caps))
                    or not set(caps) <= self.served):
                return {"ok": False, "error": "CAPABILITY_NOT_FEDERABLE"}

            if (isinstance(rate_limit_per_min, bool)
                    or not isinstance(rate_limit_per_min, int)
                    or not 1 <= rate_limit_per_min <= 300):
                return {"ok": False, "error": "INVALID_PEER_RATE_LIMIT"}

            if not isinstance(endpoint, str) or len(endpoint) > 2048:
                return {"ok": False, "error": "INVALID_PUBLICATION_ENDPOINT"}

            u = urlsplit(endpoint)
            host = (u.hostname or "").lower()
            loopback = host in {"127.0.0.1", "::1", "localhost"}
            try:
                port = u.port
            except ValueError:
                return {"ok": False, "error": "INVALID_PUBLICATION_ENDPOINT"}

            if (u.scheme not in ({"https", "http"} if loopback else {"https"})
                    or not host or u.username or u.password
                    or u.path not in ("", "/") or u.query or u.fragment
                    or (not loopback and port not in (None, 443))):
                return {"ok": False, "error": "INVALID_PUBLICATION_ENDPOINT"}

            if peer_id == self.node_id:
                return {"ok": False, "error": "SELF_CONNECTION"}

            # Los permisos se validan antes de establecer la conexión.
            grants = self._clean_grants(granted_capabilities)

            # Challenge firmado: verifica posesión de la clave, sin enrolar.
            challenge = self.handshake(endpoint, timeout=timeout)
            if not isinstance(challenge, dict) or not challenge.get("ok"):
                detail = challenge.get("error", "UNKNOWN") if isinstance(challenge, dict) else "INVALID_RESPONSE"
                return {"ok": False, "error": "HANDSHAKE_FAILED", "detail": detail}

            identity = challenge.get("identity")
            if (not isinstance(identity, dict)
                    or challenge.get("peer_id") != peer_id
                    or identity.get("node_id") != peer_id
                    or identity.get("public_key") != public_hex):
                return {"ok": False, "error": "PUBLICATION_IDENTITY_MISMATCH"}

            message_url = endpoint.rstrip("/") + "/fed/v1/message"
            contract = {
                "peer_id": peer_id,
                "pubkey": _b64(public_raw),
                "capabilities": list(caps),
                "lease_expires_at": float(lease),
                "rate_limit_per_min": rate_limit_per_min,
                "endpoint": message_url,
            }

            self._validate_peer_contract(contract)

            # enroll() persiste y audita; no duplicar su evento de auditoría.
            self.enroll(contract, granted_capabilities=grants)

            return {
                "ok": True,
                "peer_id": peer_id,
                "endpoint": message_url,
                "verified": True,
                "enrolled": True,
                "capabilities": sorted(caps),
                "granted_capabilities": grants,
                "verification": "ED25519_PUBLICATION_AND_NONCE_CHALLENGE",
            }

        except Exception as exc:
            return {
                "ok": False,
                "error": "PEER_ENROLLMENT_REJECTED",
                "detail": type(exc).__name__,
            }

    def send(self, peer_id: str, url: str, capability: str, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
        c = self.peers.get(peer_id)
        # Compatibilidad: desconocidos y revocados conservan el error público.
        if c is None or c["revoked"]:
            return {"ok": False, "error": "UNKNOWN_PEER"}
        if self.clock() > float(c["lease_expires_at"]):
            return {"ok": False, "error": "LEASE_EXPIRED"}
        if not isinstance(capability, str):
            return {"ok": False, "error": "CAPABILITY_NOT_GRANTED"}
        if capability not in c["capabilities"] or capability not in self.served:
            return {"ok": False, "error": "CAPABILITY_NOT_GRANTED"}
        saved_endpoint = c.get("endpoint")
        if saved_endpoint is not None and url != saved_endpoint:
            return {"ok": False, "error": "ENDPOINT_MISMATCH"}
        nonce = os.urandom(16).hex()
        env = _sign(self.key, {"v": 1, "from": self.node_id, "to": peer_id, "ts": self.clock(), "nonce": nonce,
                               "capability": capability, "body": body})
        return self._post(c, url, env, nonce, timeout)

    def _ssl_context(self) -> "ssl.SSLContext | None":
        """Contexto TLS desde IAO_TLS_CA_FILE si está definido."""
        ca_file = os.environ.get("IAO_TLS_CA_FILE")
        if not ca_file:
            return None
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _post(self, c: dict[str, Any], url: str, env: dict[str, Any], nonce: str, timeout: float) -> dict[str, Any]:
        req = urllib.request.Request(url, method="POST", data=json.dumps(env).encode(), headers={"Content-Type": "application/json"})
        try:
            ctx = self._ssl_context()
            if ctx is not None and url.startswith("https://"):
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    data = r.read(MAX_MSG * 8 + 1)
            else:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read(MAX_MSG * 8 + 1)
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read(4096))
                err = payload.get("error", "HTTP_ERROR") if isinstance(payload, dict) else "HTTP_ERROR"
            except (ValueError, UnicodeDecodeError, TypeError):
                err = "HTTP_ERROR"
            return {"ok": False, "status": e.code, "error": err}
        except (urllib.error.URLError, OSError, TimeoutError):
            return {"ok": False, "error": "PEER_UNREACHABLE"}   # partition: no state change, safe to retry
        if len(data) > MAX_MSG * 8:
            return {"ok": False, "error": "RESPONSE_TOO_LARGE"}
        try:
            resp = json.loads(data)
        except (ValueError, UnicodeDecodeError, TypeError):
            return {"ok": False, "error": "BAD_RESPONSE"}
        if not isinstance(resp, dict):
            return {"ok": False, "error": "BAD_RESPONSE"}
        if not _verify(c["pub"], resp):
            return {"ok": False, "error": "BAD_RESPONSE_SIGNATURE"}
        if resp.get("v") != 1:
            return {"ok": False, "error": "BAD_RESPONSE"}
        if (resp.get("to") != self.node_id
                or resp.get("from") != c["peer_id"]
                or resp.get("in_reply_to") != nonce):
            return {"ok": False, "error": "REPLAYED_OR_MISROUTED_RESPONSE"}
        if resp.get("capability") != env.get("capability"):
            return {"ok": False, "error": "RESPONSE_CAPABILITY_MISMATCH"}
        if "result" not in resp or "verification" not in resp:
            return {"ok": False, "error": "BAD_RESPONSE"}
        ts = resp.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            return {"ok": False, "error": "BAD_RESPONSE"}
        import math
        if not math.isfinite(ts):
            return {"ok": False, "error": "BAD_RESPONSE"}
        if abs(self.clock() - ts) > self.skew:
            return {"ok": False, "error": "CLOCK_SKEW"}
        return {
            "ok": True,
            "verification": resp["verification"],
            "result": resp["result"],
            "untrusted": True,
        }
    @classmethod
    def from_persistent_identity(cls, store, registry, *, identity_dir=None, **kwargs):
        """Load the persistent Ed25519 identity with backward-compatible manifest validation."""
        import hashlib
        import json
        from pathlib import Path
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        base = Path(identity_dir) if identity_dir else (
            Path(__file__).resolve().parent.parent / ".state" / "federation" / "identity"
        )
        private_path = base / "private.pem"
        public_path = base / "public.pem"
        manifest_path = base / "manifest.json"

        if private_path.is_symlink() or not private_path.is_file():
            raise FileNotFoundError("PERSISTENT_IDENTITY_PRIVATE_KEY_UNAVAILABLE")

        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PERSISTENT_IDENTITY_NOT_ED25519")

        public_raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        raw_fingerprint = hashlib.sha256(public_raw).hexdigest()
        der_fingerprint = hashlib.sha256(public_der).hexdigest()
        operational_id = node_id_of(public_raw)

        if public_path.is_symlink():
            raise ValueError("PERSISTENT_IDENTITY_PUBLIC_KEY_SYMLINK")
        if public_path.is_file():
            stored = serialization.load_pem_public_key(public_path.read_bytes())
            stored_raw = stored.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            if stored_raw != public_raw:
                raise ValueError("PERSISTENT_IDENTITY_PUBLIC_KEY_MISMATCH")

        identity_version = 1
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("PERSISTENT_IDENTITY_MANIFEST_UNAVAILABLE")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("public_key_algorithm") != "Ed25519":
            raise ValueError("PERSISTENT_IDENTITY_MANIFEST_INVALID")

        identity_version = manifest.get("identity_contract_version", 1)
        if identity_version == 2:
            if (manifest.get("node_id") != raw_fingerprint
                    or manifest.get("operational_node_id") != operational_id
                    or manifest.get("public_key_sha256") != raw_fingerprint):
                raise ValueError("PERSISTENT_IDENTITY_V2_FINGERPRINT_MISMATCH")
        elif identity_version == 1:
            if manifest.get("node_id") != der_fingerprint:
                raise ValueError("PERSISTENT_IDENTITY_LEGACY_FINGERPRINT_MISMATCH")
        else:
            raise ValueError("PERSISTENT_IDENTITY_CONTRACT_UNSUPPORTED")

        if "key" in kwargs:
            raise TypeError("PERSISTENT_IDENTITY_KEY_OVERRIDE_FORBIDDEN")

        kwargs.setdefault("peer_store_path", str(base / "peers.json"))
        instance = cls(store, registry, key=key, **kwargs)
        instance.identity_fingerprint = (
            raw_fingerprint if identity_version == 2 else der_fingerprint
        )
        instance.identity_source = str(private_path)
        instance.identity_contract_version = identity_version
        return instance



class FedServer:
    """Local federation HTTP origin; place behind a trusted HTTPS terminator."""

    def __init__(self, node: Node, host: str = "127.0.0.1", port: int = 0,
                 ssl_context: "ssl.SSLContext | None" = None) -> None:
        outer = node

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object) -> None:
                pass

            def _reply(self, status: int, payload: dict[str, Any]) -> None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path == "/fed/v1/identity":
                    self._reply(200, outer.identity_document())
                elif self.path == "/.well-known/iao-federation.json":
                    pub = getattr(outer, "_publication", None)
                    if isinstance(pub, dict):
                        self._reply(200, pub)
                    else:
                        self._reply(503, {"error": "PUBLICATION_NOT_READY"})
                else:
                    self._reply(404, {"error": "NOT_FOUND"})

            def do_POST(self) -> None:
                if self.path not in ("/fed/v1/handshake", "/fed/v1/message"):
                    self._reply(404, {"error": "NOT_FOUND"})
                    return
                try:
                    n = int(self.headers.get("Content-Length") or "0")
                except ValueError:
                    self._reply(400, {"error": "INVALID_CONTENT_LENGTH"})
                    return
                if n < 0 or n > MAX_MSG:
                    self._reply(413, {"error": "PAYLOAD_TOO_LARGE"})
                    return
                raw = self.rfile.read(n)
                if len(raw) != n:
                    self._reply(400, {"error": "INCOMPLETE_BODY"})
                    return
                if self.path == "/fed/v1/handshake":
                    status, payload = outer.answer_challenge(raw)
                else:
                    status, payload = outer.handle(raw)
                self._reply(status, payload)

        self.httpd = ThreadingHTTPServer((host, port), H)
        if ssl_context is not None:
            self.httpd.socket = ssl_context.wrap_socket(
                self.httpd.socket, server_side=True
            )
        self.port = self.httpd.server_address[1]
        self._node_for_publication = node
        scheme = "https" if ssl_context is not None else "http"
        self.url = f"{scheme}://{host}:{self.port}/fed/v1/message"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def set_publication(self, publication: dict[str, Any]) -> None:
        """Adjunta la publicación firmada al nodo que sirve el endpoint."""
        self.httpd.RequestHandlerClass  # touch; no-op
        outer = getattr(self, "_outer_node", None)
        if outer is None:
            outer = self._node_for_publication
        outer._publication = publication

    def start(self) -> "FedServer":
        self._t.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
