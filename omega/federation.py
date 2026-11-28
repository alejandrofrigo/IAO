"""F5 controlled federation. Known peers only (ParticipationContract), Ed25519 signed envelopes,
replay/skew protection, leases, revocation, per-peer rate limits, READ_ONLY capabilities only.
Peers are untrusted for results: responses are signature-checked and treated as data."""
import ssl
import base64
import hashlib
import ipaddress
import json
import os
import threading
import time
import math
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
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
from omega.federation_transport import (
    FederationTransportError,
    post_federation_json,
    validate_message_endpoint,
)

MAX_MSG = 32 * 1024
_EXEC = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fed")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def node_id_of(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]

def create_federation_server_ssl_context(
    certificate_file: str | Path,
    private_key_file: str | Path,
    client_ca_file: str | Path,
) -> ssl.SSLContext:
    """Build a fail-closed TLS 1.2+ server context requiring a trusted client cert."""
    paths = (
        (Path(certificate_file), False),
        (Path(private_key_file), True),
        (Path(client_ca_file), False),
    )
    for path, is_private in paths:
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("FEDERATION_TLS_FILE_REFUSED")
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            raise ValueError("FEDERATION_TLS_FILE_REFUSED") from exc
        if is_private and mode & 0o077:
            raise ValueError("FEDERATION_TLS_PRIVATE_KEY_PERMISSIONS_TOO_OPEN")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(paths[0][0]), keyfile=str(paths[1][0])
        )
        context.load_verify_locations(cafile=str(paths[2][0]))
        context.verify_mode = ssl.CERT_REQUIRED
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ValueError("FEDERATION_TLS_CONFIGURATION_INVALID") from exc
    return context


def _peer_certificate_node_id(certificate: dict[str, Any] | None) -> str | None:
    """Return the single IAO node identity asserted by a verified TLS peer cert."""
    if not isinstance(certificate, dict):
        return None
    names = certificate.get("subjectAltName")
    if not isinstance(names, tuple):
        return None
    identities = [
        value[len("urn:iao:node:"):]
        for kind, value in names
        if kind == "URI"
        and isinstance(value, str)
        and value.startswith("urn:iao:node:")
    ]
    if len(identities) != 1:
        return None
    identity = identities[0]
    if (
        len(identity) != 16
        or any(char not in "0123456789abcdef" for char in identity)
    ):
        return None
    return identity


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
                # Central transport policy accepts pinned public HTTPS, v3
                # onion over Tor SOCKS5, and explicitly enabled loopback tests.
                endpoint_scheme = validate_message_endpoint(endpoint)[0]
                valid = not (
                    endpoint_scheme == "http"
                    and os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") != "1"
                )
            except FederationTransportError:
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
                              lease_seconds: int = 3600,
                              consent: bool = False) -> dict[str, Any]:
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
            "consent": consent is True,
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

    def bind_peer_endpoint(self, peer_id: str, endpoint: str) -> None:
        """Pin the sole outbound URL for an enrolled peer; changes are audited."""
        try:
            endpoint_scheme = validate_message_endpoint(endpoint)[0]
        except FederationTransportError as exc:
            raise ValueError("INVALID_PEER_ENDPOINT") from exc
        if (
            endpoint_scheme == "http"
            and os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") != "1"
        ):
            raise ValueError("LOOPBACK_HTTP_DISABLED")
        with self._lock:
            peer = self.peers.get(peer_id)
            if peer is None or peer.get("revoked"):
                raise ValueError("UNKNOWN_PEER")
            previous = peer.get("endpoint")
            peer["endpoint"] = endpoint
            try:
                self._save_persistent_peers()
                self.audit_fn(
                    "operator",
                    "PEER_ENDPOINT_PINNED",
                    peer_id,
                    endpoint_sha256=hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
                )
            except Exception:
                if previous is None:
                    peer.pop("endpoint", None)
                else:
                    peer["endpoint"] = previous
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

    # ---- outbound ----
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
        try:
            endpoint_scheme = validate_message_endpoint(url)[0]
        except FederationTransportError:
            return {"ok": False, "error": "INVALID_ENDPOINT"}
        if (
            endpoint_scheme == "http"
            and os.environ.get("IAO_ALLOW_LOOPBACK_HTTP", "") != "1"
        ):
            return {"ok": False, "error": "LOOPBACK_HTTP_DISABLED"}
        saved_endpoint = c.get("endpoint")
        if not isinstance(saved_endpoint, str) or not saved_endpoint:
            return {"ok": False, "error": "ENDPOINT_NOT_PINNED"}
        if url != saved_endpoint:
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
        try:
            status, resp = post_federation_json(
                url, env, timeout=timeout, max_bytes=MAX_MSG * 8,
                expected_peer_id=c["peer_id"],
            )
        except FederationTransportError as exc:
            if exc.code in {
                "HTTPS_REQUEST_FAILED",
                "DNS_RESOLUTION_FAILED",
                "DNS_NO_ADDRESSES",
                "LOOPBACK_RESOLUTION_FAILED",
            }:
                return {"ok": False, "error": "PEER_UNREACHABLE"}
            return {"ok": False, "error": "TRANSPORT_BLOCKED"}

        if status != 200:
            error = resp.get("error", "HTTP_ERROR") if isinstance(resp, dict) else "HTTP_ERROR"
            return {"ok": False, "status": status, "error": error}
        if not isinstance(resp, dict):
            return {"ok": False, "error": "BAD_RESPONSE"}
        if not _verify(c["pub"], resp):
            return {"ok": False, "error": "BAD_RESPONSE_SIGNATURE"}
        if "result" not in resp:
            return {"ok": False, "error": "BAD_RESPONSE"}
        if (
            resp.get("to") != self.node_id
            or resp.get("from") != c["peer_id"]
            or resp.get("in_reply_to") != nonce
        ):
            return {"ok": False, "error": "REPLAYED_OR_MISROUTED_RESPONSE"}
        try:
            response_ts = float(resp.get("ts", 0))
        except (TypeError, ValueError):
            return {"ok": False, "error": "CLOCK_SKEW"}
        if not math.isfinite(response_ts) or abs(self.clock() - response_ts) > self.skew:
            return {"ok": False, "error": "CLOCK_SKEW"}
        return {
            "ok": True,
            "verification": resp.get("verification"),
            "result": resp["result"],
            "untrusted": True,
        }

    @classmethod
    def from_persistent_identity(cls, store, registry, *, identity_dir=None, **kwargs):
        """Crea un nodo federado con la identidad Ed25519 persistente de esta instalación."""
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

        if not private_path.is_file():
            raise FileNotFoundError(f"No existe la clave privada: {private_path}")

        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("La clave persistente no es Ed25519")

        public_raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(public_raw).hexdigest()

        if public_path.is_file():
            stored = serialization.load_pem_public_key(public_path.read_bytes())
            stored_raw = stored.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            if stored_raw != public_raw:
                raise ValueError("La clave pública no corresponde a la privada")

        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("public_key_algorithm") != "Ed25519":
                raise ValueError("Algoritmo incompatible en el manifiesto")
            if manifest.get("node_id") != fingerprint:
                raise ValueError("La huella del manifiesto no corresponde a la clave")

        if "key" in kwargs:
            raise TypeError("No se permite sustituir la identidad persistente")

        kwargs.setdefault("peer_store_path", str(base.parent / "peers.json"))
        instance = cls(store, registry, key=key, **kwargs)
        instance.identity_fingerprint = fingerprint
        instance.identity_source = str(private_path)
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
                if ssl_context is not None:
                    # TLS verified the certificate chain; additionally bind its
                    # unique URI SAN to the signed protocol sender identity.
                    certificate = self.connection.getpeercert()
                    certificate_node_id = _peer_certificate_node_id(certificate)
                    try:
                        request = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        request = None
                    sender = request.get("from") if isinstance(request, dict) else None
                    if (
                        certificate_node_id is None
                        or not isinstance(sender, str)
                        or sender != certificate_node_id
                    ):
                        self._reply(403, {"error": "TLS_NODE_ID_MISMATCH"})
                        return
                if self.path == "/fed/v1/handshake":
                    status, payload = outer.answer_challenge(raw)
                else:
                    status, payload = outer.handle(raw)
                self._reply(status, payload)

        if ssl_context is None:
            try:
                bind_address = ipaddress.ip_address(host)
            except ValueError:
                bind_address = None
            if bind_address is None or not bind_address.is_loopback:
                raise ValueError("FEDERATION_TLS_REQUIRED_FOR_NON_LOOPBACK_BIND")
        self.httpd = ThreadingHTTPServer((host, port), H)
        if ssl_context is not None:
            # A TLS listener without mandatory client certificates is not an
            # authenticated federation transport. Fail closed at construction.
            if (
                not isinstance(ssl_context, ssl.SSLContext)
                or ssl_context.protocol != ssl.PROTOCOL_TLS_SERVER
                or ssl_context.verify_mode != ssl.CERT_REQUIRED
                or ssl_context.minimum_version < ssl.TLSVersion.TLSv1_2
            ):
                self.httpd.server_close()
                raise ValueError("FEDERATION_MTLS_CLIENT_CERT_REQUIRED")
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
