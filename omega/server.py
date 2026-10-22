"""Stdlib HTTP runtime for SO-OMEGA. Refuses to start in production with dev auth."""
import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from omega.config import load_settings
from omega.service import MAX_BODY, OmegaService
from omega.store import Store
from omega.tools.knowledge_search import KnowledgeCorpus
from omega.tools.registry import ToolRegistry, ToolSpec


def build_service(state_dir: Path, token_key: str, corpus_dir: Path, **kw: object) -> OmegaService:
    state_dir.mkdir(parents=True, exist_ok=True)
    audit_key = os.environ.get("AUDIT_HMAC_KEY", "").encode() or ("audit|" + token_key).encode()
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
    return OmegaService(store, reg, token_key, **kw)  # type: ignore[arg-type]


def make_handler(svc: OmegaService) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "omega"
        sys_version = ""

        def _do(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, MAX_BODY + 1)) if n else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            status, payload = svc.handle(self.command, self.path, hdrs, body)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            sys.stderr.write(json.dumps({"m": self.command, "p": self.path.split("?")[0], "s": status, "cid": payload.get("correlation_id")}) + "\n")

        do_GET = do_POST = do_PUT = do_DELETE = _do

        def log_message(self, *a: object) -> None:
            pass

    return H


def main() -> None:
    s = load_settings()
    if s.app_env == "production":
        sys.exit("BLOCKED_EXTERNAL: dev token auth is not allowed in production; configure OIDC")
    key = os.environ.get("OMEGA_DEV_TOKEN_KEY", "")
    if len(key) < 16:
        sys.exit("OMEGA_DEV_TOKEN_KEY (>=16 chars) required")
    state = Path(os.environ.get("OMEGA_STATE_DIR", ".state"))
    svc = build_service(state, key, Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus")),
                        rate_limit_per_min=int(os.environ.get("OMEGA_RATE_LIMIT", "120")))
    httpd = ThreadingHTTPServer((s.host, s.port), make_handler(svc))
    (state / "server.pid").write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=httpd.shutdown).start())
    sys.stderr.write(json.dumps({"event": "listening", "host": s.host, "port": s.port}) + "\n")
    httpd.serve_forever()
    svc.store.audit("system", "RUNTIME_STOP", "omega")
    svc.store.close()


if __name__ == "__main__":
    main()
