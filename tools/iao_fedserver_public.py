#!/usr/bin/env python3
"""Expone Node con /fed/v1/identity, /handshake, /message. NO enrola."""
import sys, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omega.store import Store
from omega.tools.registry import ToolRegistry
from omega.federation import Node
STATE = ROOT / ".state"
def make_node():
    import os
    from omega.tools.knowledge_search import KnowledgeCorpus
    from omega.tools.registry import ToolSpec
    corpus_dir = Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus"))
    corpus = KnowledgeCorpus(corpus_dir)
    r = ToolRegistry()
    r.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search",
                        "READ_ONLY", 5.0,
                        corpus.validate_input, corpus.run, corpus.verify))
    key = load_pem_private_key((STATE/"federation/identity/private.pem").read_bytes(), password=None)
    return Node(store=Store(str(STATE/"store.db")), registry=r, key=key,
                peer_store_path=STATE/"iao-node-network/peers.json",
                served=frozenset({"knowledge.search"}))
class Handler(BaseHTTPRequestHandler):
    node = None
    def _json(self, code, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path == "/fed/v1/identity": self._json(200, self.node.identity_document())
        else: self._json(404, {"error": "NOT_FOUND"})
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(min(length, 32768))
        if self.path == "/fed/v1/handshake":
            code, body = self.node.answer_challenge(raw)
        elif self.path == "/fed/v1/message":
            code, body = self.node.handle(raw)
        else:
            code, body = 404, {"error": "NOT_FOUND"}
        self._json(code, body)
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0"); ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    Handler.node = make_node()
    print(f"FedServer http://{args.host}:{args.port}/fed/v1/*  node_id={Handler.node.node_id}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
if __name__ == "__main__": main()
