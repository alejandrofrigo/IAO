"""Stdlib HTTP runtime for IAO. Refuses to start in production with dev auth."""
import hashlib
import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from omega.env_loader import load_env_files
from omega.config import load_settings
from omega.service import MAX_BODY, OmegaService
from omega.device_authority import DeviceAuthority
from omega.operator_identity import OperatorIdentityAuthority
from omega.identity_rollback_anchor import IdentityRollbackAnchor, capture_identity_state
from omega.store import Store
from omega.federation import MAX_MSG, Node
from omega.federation_identity import load_or_create_key
from omega.federation_ledger import FederationLedger
from omega.tools.knowledge_search import KnowledgeCorpus
from omega.tools.registry import ToolRegistry, ToolSpec


def build_service(state_dir: Path, token_key: str, corpus_dir: Path, **kw: object) -> OmegaService:
    state_dir.mkdir(parents=True, exist_ok=True)
    audit_key_env = os.environ.get("AUDIT_HMAC_KEY", "")
    if audit_key_env:
        audit_key = audit_key_env.encode()
    else:
        key_path = Path.home() / ".config" / "iao" / "audit-hmac-key"
        if not key_path.is_file():
            raise RuntimeError("Persistent audit key is missing")
        audit_key = key_path.read_text().strip().encode()
        if len(audit_key) < 32:
            raise RuntimeError("Persistent audit key is invalid")
    store = Store(state_dir / "omega.db", audit_key=audit_key)
    corpus = KnowledgeCorpus(corpus_dir)
    reg = ToolRegistry()
    reg.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search", "READ_ONLY", 5.0,
                          corpus.validate_input, corpus.run, corpus.verify))
    allow = {h.strip().lower() for h in os.environ.get("OMEGA_EGRESS_ALLOWLIST", "").split(",") if h.strip()}
    if allow:  # F3: web.fetch exists only when an explicit allowlist is configured (deny-by-default)
        from omega.egress import EgressPolicy
        from omega.tools.web_fetch import make_web_fetch
        reg.register(make_web_fetch(EgressPolicy(allow_hosts=frozenset(allow))))
    store.audit("system", "RUNTIME_START", "omega", docs=len(corpus.docs), tools=sorted(reg.names()))
    from omega.adapters.model import adapter_from_env
    router_enabled = os.environ.get("IAO_LLM_ROUTER", "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    # Explicit dependency injection takes precedence over environment defaults.
    if kw.get("model_adapter") is not None:
        pass
    elif router_enabled:
        from omega.llm_router import RouterModelAdapter
        kw["model_adapter"] = RouterModelAdapter()
    else:
        kw.setdefault("model_adapter", adapter_from_env(dict(os.environ)))
    kw.setdefault(
        "device_authority",
        DeviceAuthority(
            state_dir / "device-authority.sqlite3",
            enrollment_code=os.environ.get("IAO_DEVICE_ENROLLMENT_CODE", ""),
        ),
    )
    bootstrap_expiry_raw = os.environ.get(
        "IAO_OPERATOR_BOOTSTRAP_EXPIRES_AT", ""
    ).strip()
    try:
        bootstrap_expiry = float(bootstrap_expiry_raw) if bootstrap_expiry_raw else None
    except ValueError:
        bootstrap_expiry = None
    bootstrap_code = os.environ.pop("IAO_OPERATOR_BOOTSTRAP_CODE", "")
    operator_identity_authority = OperatorIdentityAuthority(
        state_dir / "operator-identity.sqlite3",
        bootstrap_code=bootstrap_code,
        bootstrap_expires_at=bootstrap_expiry,
        subject_digest_key=hashlib.sha256(
            b"IAO-OPERATOR-SUBJECT-HMAC-V1\x00" + token_key.encode("utf-8")
        ).digest(),
    )
    bootstrap_code = ""
    kw.setdefault("operator_identity_authority", operator_identity_authority)
    if kw.pop("identity_rollback_anchor_enabled", False):
        trust_dir = Path(os.environ.get(
            "IAO_IDENTITY_ROLLBACK_DIR",
            str(Path.home() / ".config" / "iao" / "identity-trust"),
        )).expanduser()
        anchor = IdentityRollbackAnchor(
            trust_dir / "identity.anchor",
            trust_dir / "identity.key",
        )
        device_authority = kw["device_authority"]
        def state_supplier():
            return capture_identity_state(
                operator_identity_authority.database,
                device_authority.database,  # type: ignore[union-attr]
            )
        current_state = state_supplier()
        anchor_file = trust_dir / "identity.anchor"
        key_file = trust_dir / "identity.key"
        if not anchor_file.exists() and not anchor_file.is_symlink() and not key_file.exists() and not key_file.is_symlink():
            empty_state = (
                current_state["active_root_count"] == 0
                and current_state["active_device_count"] == 0
                and current_state["revoked_root_count"] == 0
                and current_state["inactive_device_count"] == 0
                and current_state["root_fingerprint"] is None
                and current_state["primary_device_fingerprint"] is None
                and current_state["root_key_version"] == 0
            )
            if not empty_state:
                raise RuntimeError("IDENTITY_ROLLBACK_ANCHOR_MISSING_FOR_EXISTING_IDENTITY")
            anchor.initialize(current_state)
        else:
            anchor.verify(current_state)
        kw["identity_rollback_anchor"] = anchor
        kw["identity_state_supplier"] = state_supplier
    return OmegaService(store, reg, token_key, **kw)  # type: ignore[arg-type]


def make_handler(svc: OmegaService, fed_node: Node | None = None) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "omega"
        sys_version = ""

        def _cors_headers(self) -> None:
            origin = self.headers.get("Origin", "")
            allowed = {
                x.strip().rstrip("/")
                for x in os.environ.get(
                    "IAO_CORS_ORIGINS",
                    "https://alejandrofrigo.github.io"
                ).split(",") if x.strip()
            }
            if origin and origin.rstrip("/") in allowed:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")

        def _send_fed_json(self, status: int, payload: dict[str, object]) -> None:
            data = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _do(self) -> None:
            # Identidad publica y reto firmado; estas rutas no enrolan peers.
            route = self.path.split("?", 1)[0]
            if route == "/fed/v1/contract":
                if self.command != "GET":
                    self._send_fed_json(405, {"error": "METHOD_NOT_ALLOWED"})
                    return
                if fed_node is None:
                    self._send_fed_json(503, {"error": "FEDERATION_UNAVAILABLE"})
                    return
                self._send_fed_json(200, fed_node.contract_for_self(sorted(fed_node.served)))
                return

            if route == "/fed/v1/publication":
                if self.command != "GET":
                    self._send_fed_json(405, {"error": "METHOD_NOT_ALLOWED"})
                    return
                if fed_node is None:
                    self._send_fed_json(503, {"error": "FEDERATION_UNAVAILABLE"})
                    return
                # Public federation participation is opt-in per installation.
                # A discovery listing or reachable endpoint alone is not consent.
                origin = os.environ.get("IAO_FEDERATION_PUBLIC_ORIGIN", "").strip().rstrip("/")
                if os.environ.get("IAO_FEDERATION_PUBLIC_PEERING", "").lower() != "true" or not origin:
                    self._send_fed_json(404, {"error": "PUBLIC_PEERING_NOT_OFFERED"})
                    return
                try:
                    from urllib.parse import urlsplit
                    parsed = urlsplit(origin)
                    if (parsed.scheme != "https" or not parsed.hostname
                            or parsed.username or parsed.password
                            or parsed.port not in (None, 443)
                            or parsed.path or parsed.query or parsed.fragment):
                        raise ValueError("INVALID_PUBLIC_ORIGIN")
                    publication = fed_node.identity_publication(
                        origin + "/fed/v1/message",
                        capabilities=sorted(fed_node.served),
                        consent=True,
                    )
                except Exception:
                    self._send_fed_json(503, {"error": "PUBLIC_PEERING_CONFIG_INVALID"})
                    return
                self._send_fed_json(200, publication)
                return

            if route == "/fed/v1/identity":
                if self.command != "GET":
                    self._send_fed_json(405, {"error": "METHOD_NOT_ALLOWED"})
                    return
                if fed_node is None:
                    self._send_fed_json(503, {"error": "FEDERATION_UNAVAILABLE"})
                    return
                self._send_fed_json(200, fed_node.identity_document())
                return

            if route == "/fed/v1/handshake":
                if self.command != "POST":
                    self._send_fed_json(405, {"error": "METHOD_NOT_ALLOWED"})
                    return
                if fed_node is None:
                    self._send_fed_json(503, {"error": "FEDERATION_UNAVAILABLE"})
                    return
                if self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    self._send_fed_json(400, {"error": "INVALID_TRANSFER_ENCODING"})
                    return
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length) if raw_length is not None else -1
                except ValueError:
                    length = -1
                if length < 0:
                    self.close_connection = True
                    self._send_fed_json(411, {"error": "CONTENT_LENGTH_REQUIRED"})
                    return
                if length > MAX_MSG:
                    self.close_connection = True
                    self._send_fed_json(413, {"error": "PAYLOAD_TOO_LARGE"})
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.close_connection = True
                    self._send_fed_json(400, {"error": "INCOMPLETE_BODY"})
                    return
                status, payload = fed_node.answer_challenge(body)
                self._send_fed_json(status, payload)
                return

            # Endpoint interno de federacion: no usa CORS ni la API publica.
            if self.path.split("?", 1)[0] == "/fed/v1/message":
                if self.command != "POST":
                    self._send_fed_json(405, {"error": "METHOD_NOT_ALLOWED"})
                    return
                if fed_node is None:
                    self._send_fed_json(503, {"error": "FEDERATION_UNAVAILABLE"})
                    return
                if self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    self._send_fed_json(400, {"error": "INVALID_TRANSFER_ENCODING"})
                    return
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length) if raw_length is not None else -1
                except ValueError:
                    length = -1
                if length < 0:
                    self.close_connection = True
                    self._send_fed_json(411, {"error": "CONTENT_LENGTH_REQUIRED"})
                    return
                if length > MAX_MSG:
                    self.close_connection = True
                    self._send_fed_json(413, {"error": "PAYLOAD_TOO_LARGE"})
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.close_connection = True
                    self._send_fed_json(400, {"error": "INCOMPLETE_BODY"})
                    return
                status, payload = fed_node.handle(body)
                self._send_fed_json(status, payload)
                return

            if self.command == "OPTIONS":
                origin = self.headers.get("Origin", "")
                requested_method = self.headers.get(
                    "Access-Control-Request-Method", ""
                ).upper()
                requested_headers = {
                    x.strip().lower()
                    for x in self.headers.get(
                        "Access-Control-Request-Headers", ""
                    ).split(",") if x.strip()
                }
                allowed = {
                    x.strip().rstrip("/")
                    for x in os.environ.get(
                        "IAO_CORS_ORIGINS",
                        "https://alejandrofrigo.github.io"
                    ).split(",") if x.strip()
                }
                if (
                    origin.rstrip("/") not in allowed
                    or requested_method not in {"POST", "GET"}
                    or not requested_headers.issubset(
                        {"authorization", "content-type", "x-iao-device-proof"}
                    )
                ):
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    return
                self.send_response(204)
                self._cors_headers()
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-IAO-Device-Proof")
                self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # Serve only the fixed local chat page; API requests remain in OmegaService.
            if self.command == "GET" and self.path.split("?", 1)[0] in ("/", "/index.html"):
                page = Path(__file__).resolve().parent.parent / "web" / "index.html"
                try:
                    data = page.read_bytes()
                except OSError:
                    self.send_error(503, "WEB_INTERFACE_UNAVAILABLE")
                    return
                self.send_response(200)
                self._cors_headers()
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
                self.end_headers()
                self.wfile.write(data)
                return
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, MAX_BODY + 1)) if n else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            hdrs["x-omega-client-ip"] = self.client_address[0]
            status, payload = svc.handle(self.command, self.path, hdrs, body)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self._cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            sys.stderr.write(json.dumps({"m": self.command, "p": self.path.split("?")[0], "s": status, "cid": payload.get("correlation_id")}) + "\n")

        do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = _do

        def log_message(self, *a: object) -> None:
            pass

    return H


def main() -> None:
    project_env = Path(__file__).resolve().parent.parent / '.env'
    runtime_env = Path.home() / '.iao-runtime.env'
    load_env_files((project_env, runtime_env))
    s = load_settings()
    if s.app_env == "production":
        sys.exit("BLOCKED_EXTERNAL: dev token auth is not allowed in production; configure OIDC")
    key = os.environ.get("OMEGA_DEV_TOKEN_KEY", "")
    if len(key) < 16:
        sys.exit("OMEGA_DEV_TOKEN_KEY (>=16 chars) required")
    state = Path(os.environ.get("OMEGA_STATE_DIR", ".state"))
    svc = build_service(
        state, key, Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus")),
        rate_limit_per_min=int(os.environ.get("OMEGA_RATE_LIMIT", "120")),
        identity_rollback_anchor_enabled=True,
    )
    fed_key = load_or_create_key(state / "federation-node-ed25519.key")
    fed_ledger = FederationLedger(
        state / "federation-audit.jsonl",
        state / "federation-audit.key",
    )
    fed_node = Node(
        svc.store, svc.registry, key=fed_key,
        peer_store_path=state / "federation-peers.json",
        audit_fn=fed_ledger.append,
    )
    fed_ledger.append(
        "system", "FEDERATION_NODE_READY", fed_node.node_id,
        capabilities=["knowledge.search"]
    )
    from omega.federation_autojoin import start_federation_autojoin
    start_federation_autojoin(fed_node, state)
    from omega.federation_discovery import start_federation_discovery
    start_federation_discovery(state)
    from omega.external_network import start_external_network
    start_external_network(state / "external-network", fed_node=fed_node)
    httpd = ThreadingHTTPServer((s.host, s.port), make_handler(svc, fed_node))
    (state / "server.pid").write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=httpd.shutdown).start())
    sys.stderr.write(json.dumps({"event": "listening", "host": s.host, "port": s.port}) + "\n")
    httpd.serve_forever()
    svc.store.audit("system", "RUNTIME_STOP", "omega")
    svc.store.close()


if __name__ == "__main__":
    main()
