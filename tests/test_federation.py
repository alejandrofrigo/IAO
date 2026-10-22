import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.federation import FedServer, Node, _sign
from omega.store import Store
from omega.tools.knowledge_search import KnowledgeCorpus
from omega.tools.registry import ToolRegistry, ToolSpec

CORPUS = Path(__file__).resolve().parent.parent / "docs" / "corpus"
Q = {"query": "audit chain restore"}


def mk(tmp: str, name: str, clock) -> Node:  # type: ignore[no-untyped-def]
    store = Store(Path(tmp) / f"{name}.db", audit_key=b"k-" + name.encode())
    c = KnowledgeCorpus(CORPUS)
    reg = ToolRegistry()
    reg.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search", "READ_ONLY", 5.0, c.validate_input, c.run, c.verify))
    reg.register(ToolSpec("danger.write", "1", "danger.write", "CHANGE_REVERSIBLE", 5.0, lambda x: x, lambda x: {"w": 1}, lambda o: "PASS"))
    return Node(store, reg, clock=clock, served=frozenset({"knowledge.search"}))


class FedBase(unittest.TestCase):
    def setUp(self) -> None:
        self.t = [1_000_000.0]
        self.clock = lambda: self.t[0]
        self.tmp = tempfile.TemporaryDirectory()
        self.a, self.b = mk(self.tmp.name, "a", self.clock), mk(self.tmp.name, "b", self.clock)
        self.a.enroll(self.b.contract_for_self(["knowledge.search"]))   # A trusts B
        self.b.enroll(self.a.contract_for_self(["knowledge.search"]))   # B trusts A
        self.sb = FedServer(self.b).start()
        self.servers = [self.sb]

    def tearDown(self) -> None:
        for s in self.servers:
            try:
                s.stop()
            except Exception:
                pass
        for n in (self.a, self.b):
            n.store.close()
        self.tmp.cleanup()

    def raw(self, env: dict, key=None) -> tuple[int, dict]:  # type: ignore[type-arg,no-untyped-def]
        return self.b.handle(json.dumps(_sign(key or self.a.key, env)).encode())

    def env(self, **kw) -> dict:  # type: ignore[no-untyped-def,type-arg]
        e = {"v": 1, "from": self.a.node_id, "to": self.b.node_id, "ts": self.clock(), "nonce": "n" * 16 + str(len(kw)),
             "capability": "knowledge.search", "body": Q}
        e.update(kw)
        return e


class HappyAndAuthTests(FedBase):
    def test_roundtrip_signed_verified_untrusted(self) -> None:
        r = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        self.assertEqual((r["ok"], r["verification"], r["untrusted"]), (True, "PASS", True))
        self.assertTrue(r["result"]["items"])

    def test_node_id_bound_to_key_at_enrolment(self) -> None:
        c = self.b.contract_for_self(["knowledge.search"]); c["peer_id"] = "deadbeefdeadbeef"
        with self.assertRaises(ValueError):
            self.a.enroll(c)

    def test_cannot_enroll_non_federable_capability(self) -> None:
        with self.assertRaises(ValueError):
            self.a.enroll(self.b.contract_for_self(["danger.write"]))

    def test_unknown_peer_rejected(self) -> None:
        evil = Ed25519PrivateKey.generate()
        s, p = self.raw(self.env(), evil)
        self.assertEqual((s, p["error"]), (403, "BAD_SIGNATURE"))
        c = mk(self.tmp.name, "c", self.clock)  # a real, un-enrolled node
        s, p = self.b.handle(json.dumps(_sign(c.key, {**self.env(), "from": c.node_id})).encode())
        self.assertEqual((s, p["error"]), (403, "UNKNOWN_PEER"))

    def test_tampered_body_breaks_signature(self) -> None:
        e = _sign(self.a.key, self.env())
        e["body"] = {"query": "something else"}
        self.assertEqual(self.b.handle(json.dumps(e).encode())[1]["error"], "BAD_SIGNATURE")

    def test_impersonation_with_another_enrolled_key(self) -> None:
        c = mk(self.tmp.name, "c", self.clock); self.b.enroll(c.contract_for_self(["knowledge.search"]))
        s, p = self.raw(self.env(), c.key)  # claims to be A, signed by C
        self.assertEqual(p["error"], "BAD_SIGNATURE")


class ReplayAndTimeTests(FedBase):
    def test_replay_rejected(self) -> None:
        raw = json.dumps(_sign(self.a.key, self.env())).encode()
        self.assertEqual(self.b.handle(raw)[0], 200)
        s, p = self.b.handle(raw)
        self.assertEqual((s, p["error"]), (409, "REPLAY"))

    def test_replayed_to_a_different_node_rejected(self) -> None:
        c = mk(self.tmp.name, "c", self.clock); c.enroll(self.a.contract_for_self(["knowledge.search"]))
        raw = json.dumps(_sign(self.a.key, self.env())).encode()  # addressed to B
        self.assertEqual(c.handle(raw)[1]["error"], "WRONG_RECIPIENT")

    def test_stale_and_future_timestamps(self) -> None:
        for ts in (self.clock() - 120, self.clock() + 120):
            s, p = self.raw(self.env(ts=ts, nonce="x" * 20))
            self.assertEqual(p["error"], "CLOCK_SKEW")

    def test_nonce_cache_expires_but_old_message_still_dead_by_skew(self) -> None:
        raw = json.dumps(_sign(self.a.key, self.env())).encode()
        self.b.handle(raw)
        self.t[0] += 500
        self.assertEqual(self.b.handle(raw)[1]["error"], "CLOCK_SKEW")  # cannot be replayed after cache pruning

    def test_failed_signature_does_not_poison_nonce_cache(self) -> None:
        evil = Ed25519PrivateKey.generate()
        self.raw(self.env(nonce="N" * 20), evil)
        s, _ = self.raw(self.env(nonce="N" * 20))
        self.assertEqual(s, 200)


class PolicyTests(FedBase):
    def test_revocation_takes_effect_immediately(self) -> None:
        self.assertTrue(self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)["ok"])
        self.b.revoke(self.a.node_id)
        r = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        self.assertEqual((r["ok"], r["error"]), (False, "PEER_REVOKED"))

    def test_lease_expiry(self) -> None:
        self.t[0] += 7200
        r = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        self.assertEqual(r["error"], "LEASE_EXPIRED")

    def test_capability_not_granted_or_not_readonly(self) -> None:
        for cap in ("danger.write", "shell.execute", "web.fetch", ""):
            s, p = self.raw(self.env(capability=cap, nonce=("c" + cap).ljust(20, "_")))
            self.assertEqual((s, p["error"]), (403, "CAPABILITY_NOT_GRANTED"), cap)

    def test_peer_granted_write_capability_still_refused(self) -> None:
        self.b.peers[self.a.node_id]["capabilities"].append("danger.write")  # even if mis-configured
        s, p = self.raw(self.env(capability="danger.write", nonce="w" * 20))
        self.assertEqual(p["error"], "CAPABILITY_NOT_GRANTED")                 # served-set + READ_ONLY are independent layers

    def test_input_validation_and_size(self) -> None:
        s, p = self.raw(self.env(body={"query": "ab", "path": "/etc/passwd"}, nonce="i" * 20))
        self.assertEqual((s, p["error"]), (422, "INVALID_INPUT"))
        self.assertEqual(self.b.handle(b"x" * 40000)[0], 413)
        self.assertEqual(self.b.handle(b"{not json")[0], 400)

    def test_rate_limit_per_peer(self) -> None:
        self.b.rate = 3
        codes = [self.raw(self.env(nonce=f"r{i}".ljust(20, "_")))[0] for i in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    def test_audit_chain_records_denials_and_stays_valid(self) -> None:
        self.raw(self.env(capability="shell.execute", nonce="a" * 20))
        self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        reasons = [e["details"].get("reason") for e in self.b.store._all_events() if e["event_type"] == "FED_REQUEST"]
        self.assertIn("CAPABILITY_NOT_GRANTED", reasons)
        self.assertTrue(self.b.store.verify_audit()[0])


class PartitionAndHostilePeerTests(FedBase):
    def test_partition_unreachable_then_recovery_without_duplicates(self) -> None:
        port = self.sb.port
        self.sb.stop()
        r = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q, timeout=1)
        self.assertEqual((r["ok"], r["error"]), (False, "PEER_UNREACHABLE"))
        before = len([e for e in self.b.store._all_events() if e["event_type"] == "FED_REQUEST"])
        self.assertEqual(before, 0)  # nothing was applied during the partition
        self.sb = FedServer(self.b, port=port).start(); self.servers.append(self.sb)
        self.assertTrue(self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)["ok"])

    def _hostile(self, build) -> FedServer:  # type: ignore[no-untyped-def]
        peer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_POST(self) -> None:
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                data = json.dumps(build(req)).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        class S:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/message"
            def stop(self_inner) -> None: httpd.shutdown(); httpd.server_close()  # noqa: E704
        s = S(); self.servers.append(s); del peer
        return s  # type: ignore[return-value]

    def test_forged_result_signed_by_attacker_rejected(self) -> None:
        evil = Ed25519PrivateKey.generate()
        s = self._hostile(lambda req: _sign(evil, {"v": 1, "from": self.b.node_id, "to": self.a.node_id, "ts": self.clock(),
                                                    "in_reply_to": req["nonce"], "result": {"items": [{"fake": 1}]}, "verification": "PASS"}))
        r = self.a.send(self.b.node_id, s.url, "knowledge.search", Q)
        self.assertEqual((r["ok"], r["error"]), (False, "BAD_RESPONSE_SIGNATURE"))

    def test_old_valid_response_replayed_by_man_in_the_middle_rejected(self) -> None:
        good = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        self.assertTrue(good["ok"])
        captured = _sign(self.b.key, {"v": 1, "from": self.b.node_id, "to": self.a.node_id, "ts": self.clock(),
                                       "in_reply_to": "old-nonce", "result": {"items": []}, "verification": "PASS"})
        s = self._hostile(lambda req: captured)
        r = self.a.send(self.b.node_id, s.url, "knowledge.search", Q)
        self.assertEqual(r["error"], "REPLAYED_OR_MISROUTED_RESPONSE")

    def test_garbage_and_oversized_responses_handled(self) -> None:
        r = self.a.send(self.b.node_id, self._hostile(lambda req: {"x": "not an envelope"}).url, "knowledge.search", Q)
        self.assertFalse(r["ok"])

    def test_cannot_send_to_unenrolled_or_revoked_peer(self) -> None:
        self.assertEqual(self.a.send("0" * 16, self.sb.url, "knowledge.search", Q)["error"], "UNKNOWN_PEER")
        self.a.revoke(self.b.node_id)
        self.assertEqual(self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)["error"], "UNKNOWN_PEER")


if __name__ == "__main__":
    unittest.main()
