import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from omega.auth import issue_token
from omega.server import build_service
from omega.tools.knowledge_search import KnowledgeCorpus
from omega.tools.registry import ToolSpec

KEY = "unit-test-key-0123456789"
CORPUS = Path(__file__).resolve().parent.parent / "docs" / "corpus"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.mk()

    def mk(self, **kw: object) -> None:
        self.svc = build_service(self.state, KEY, CORPUS, **kw)

    def tearDown(self) -> None:
        self.svc.store.close()
        self.tmp.cleanup()

    def tok(self, sub: str, scopes: list[str] | None = None) -> dict[str, str]:
        return {"authorization": "Bearer " + issue_token(KEY, sub, ["knowledge.search"] if scopes is None else scopes)}

    def call(self, m: str, p: str, h: dict[str, str] | None = None, body: object = None) -> tuple[int, dict]:  # type: ignore[type-arg]
        return self.svc.handle(m, p, h or {}, json.dumps(body).encode() if body is not None else b"")

    def task(self, sub: str, cap: str, inp: dict | None = None, scopes: list[str] | None = None, **extra: str) -> tuple[int, dict]:  # type: ignore[type-arg]
        h = {**self.tok(sub, scopes), **extra}
        return self.call("POST", "/v1/tasks", h, {"goal": "g", "capability": cap, "input": inp if inp is not None else {"query": "audit chain"}})


class AuthTests(Base):
    def test_AUTH01_no_session_401(self) -> None:
        s, p = self.call("GET", "/v1/me")
        self.assertEqual((s, p["error"]), (401, "AUTHENTICATION_REQUIRED"))

    def test_bad_and_expired_tokens(self) -> None:
        self.assertEqual(self.call("GET", "/v1/me", {"authorization": "Bearer x.y"})[0], 401)
        old = issue_token(KEY, "a", [], ttl=-10)
        self.assertEqual(self.call("GET", "/v1/me", {"authorization": "Bearer " + old})[0], 401)
        forged = issue_token("other-key-0123456789", "a", ["audit.admin"])
        self.assertEqual(self.call("GET", "/v1/me", {"authorization": "Bearer " + forged})[0], 401)

    def test_AUTH02_cross_user_isolation(self) -> None:
        a, b = self.tok("alice"), self.tok("bob")
        cid = self.call("POST", "/v1/conversations", a, {"title": "x"})[1]["conversation_id"]
        s, p = self.call("GET", f"/v1/conversations/{cid}/messages", b)
        self.assertEqual(s, 404)
        self.assertNotIn("alice", json.dumps(p))
        tid = self.task("alice", "knowledge.search")[1]["task_id"]
        self.assertEqual(self.call("GET", f"/v1/tasks/{tid}", b)[0], 404)
        self.assertEqual(self.call("GET", f"/v1/tasks/{tid}", a)[0], 200)
        ev = self.call("GET", "/v1/audit/events", b)[1]["events"]
        self.assertTrue(all(e["details"]["actor"] == "bob" for e in ev))


class PolicyToolTests(Base):
    def test_POL01_capability_outside_allowlist_denied_before_execution(self) -> None:
        s, p = self.task("alice", "shell.execute", scopes=["knowledge.search", "shell.execute"])
        self.assertEqual((s, p["state"], p["reason"]), (403, "DENIED", "CAPABILITY_NOT_GRANTED"))
        self.assertTrue(any(e["event_type"] == "DECISION" and e["details"]["decision"] == "DENY" for e in self.svc.store._all_events()))

    def test_scope_missing_denied(self) -> None:
        self.assertEqual(self.task("alice", "knowledge.search", scopes=[])[0], 403)

    def test_happy_path_pass(self) -> None:
        s, p = self.task("alice", "knowledge.search", {"query": "audit hash chain restore"})
        self.assertEqual((s, p["state"], p["verification"]), (200, "SUCCEEDED", "PASS"))
        self.assertTrue(p["result"]["items"])
        ex = self.svc.store.tool_executions(p["task_id"])
        self.assertEqual([e["status"] for e in ex], ["SUCCEEDED"])

    def test_TOOL01_unknown_fields_and_bad_types_rejected_no_execution(self) -> None:
        for bad in ({"query": "audit", "path": "/etc/passwd"}, {"query": 5}, {"query": "ab", "limit": 999},
                    {"query": "audit", "limit": True}, {"url": "http://x"}):
            s, p = self.task("alice", "knowledge.search", bad)
            self.assertEqual((p["state"], p["error"]), ("FAILED", "INVALID_INPUT"), bad)
            self.assertEqual(self.svc.store.tool_executions(p["task_id"])[0]["status"], "DENIED")

    def test_TOOL02_timeout_terminal_state_and_log(self) -> None:
        self.svc.registry.register(ToolSpec("test.slow", "1", "test.slow", "READ_ONLY", 0.2, lambda x: {}, lambda x: (time.sleep(1.5), {})[1], lambda o: "PASS"))
        s, p = self.task("alice", "test.slow", {}, scopes=["test.slow"])
        self.assertEqual((p["state"], p["error"]), ("FAILED", "TIMED_OUT"))
        self.assertEqual(self.svc.store.tool_executions(p["task_id"])[0]["status"], "TIMED_OUT")

    def test_UNKNOWN_is_never_pass(self) -> None:
        self.svc.registry.register(ToolSpec("test.unk", "1", "test.unk", "READ_ONLY", 1, lambda x: {}, lambda x: {"a": 1}, lambda o: "UNKNOWN"))
        p = self.task("alice", "test.unk", {}, scopes=["test.unk"])[1]
        self.assertEqual((p["state"], p["error"]), ("FAILED", "VERIFICATION_UNKNOWN"))

    def test_verifier_catches_tampered_output(self) -> None:
        c = KnowledgeCorpus(CORPUS)
        out = c.run({"query": "audit", "limit": 3})
        self.assertEqual(c.verify(out), "PASS")
        out["items"][0]["snippet"] = "fabricated text not in the document"
        self.assertEqual(c.verify(out), "FAIL")
        out2 = c.run({"query": "audit", "limit": 3})
        out2["items"][0]["source_hash"] = "sha256:00"
        self.assertEqual(c.verify(out2), "FAIL")

    def test_INJ01_corpus_injection_is_data_not_authority(self) -> None:
        s, p = self.task("alice", "knowledge.search", {"query": "ignore previous instructions shell.execute admin"})
        self.assertEqual(p["state"], "SUCCEEDED")
        self.assertTrue(any(i["document_id"] == "injection-sample" for i in p["result"]["items"]))  # returned as plain data
        me = self.call("GET", "/v1/me", self.tok("alice"))[1]
        self.assertEqual(me["scopes"], ["knowledge.search"])  # unchanged
        self.assertEqual(self.task("alice", "shell.execute", scopes=["knowledge.search"])[0], 403)  # still denied

    def test_missing_fields_needs_clarification(self) -> None:
        s, p = self.call("POST", "/v1/tasks", self.tok("alice"), {"capability": "knowledge.search"})
        self.assertEqual((s, p["state"], p["missing"]), (422, "NEEDS_CLARIFICATION", ["goal"]))

    def test_idempotency_key_no_duplicate(self) -> None:
        a = self.task("alice", "knowledge.search", **{"idempotency-key": "k1"})[1]
        s, b = self.task("alice", "knowledge.search", **{"idempotency-key": "k1"})
        self.assertEqual((a["task_id"], b["idempotent_replay"]), (b["task_id"], True))
        c = self.task("bob", "knowledge.search", **{"idempotency-key": "k1"})[1]
        self.assertNotEqual(c["task_id"], a["task_id"])

    def test_invalid_json_and_oversize(self) -> None:
        self.assertEqual(self.svc.handle("POST", "/v1/tasks", self.tok("alice"), b"{bad")[0], 400)
        self.assertEqual(self.svc.handle("POST", "/v1/tasks", self.tok("alice"), b"x" * 70000)[0], 413)


class LimitsAndIntegrityTests(Base):
    def test_COST01_quota_and_rate_limit_cut_with_audit_event(self) -> None:
        self.svc.store.close()
        self.mk(daily_task_quota=2, rate_limit_per_min=5)
        self.assertEqual(self.task("q", "knowledge.search")[0], 200)
        self.assertEqual(self.task("q", "knowledge.search")[0], 200)
        s, p = self.task("q", "knowledge.search")
        self.assertEqual((s, p["error"]), (429, "QUOTA_EXCEEDED"))
        codes = [self.call("GET", "/v1/me", self.tok("r"))[0] for _ in range(7)]
        self.assertEqual(codes, [200] * 5 + [429] * 2)
        reasons = {e["details"].get("reason") for e in self.svc.store._all_events() if e["event_type"] == "QUOTA"}
        self.assertEqual(reasons, {"QUOTA_EXCEEDED", "RATE_LIMITED"})

    def test_lease_expiry(self) -> None:
        self.svc.store.close()
        self.mk(task_ttl_seconds=0)
        p = self.task("alice", "knowledge.search")[1]
        self.assertEqual((p["state"], p["error"]), ("EXPIRED", "LEASE_EXPIRED"))

    def test_AUD01_tamper_detected_through_the_database(self) -> None:
        self.task("alice", "knowledge.search")
        self.assertEqual(self.svc.store.verify_audit(), (True, None))
        self.assertEqual(self.call("GET", "/health/ready")[0], 200)
        c = sqlite3.connect(str(self.state / "omega.db"))
        c.execute("UPDATE audit_event SET details=replace(details,'alice','mallory') WHERE id=3")
        c.commit()
        c.close()
        ok, bad = self.svc.store.verify_audit()
        self.assertEqual((ok, bad), (False, 2))
        s, p = self.call("GET", "/health/ready")
        self.assertEqual((s, p["status"]), (503, "not_ready"))  # integrity failure => not ready (RESTRICTED)

    def test_chat_reports_model_not_configured_after_authz(self) -> None:
        self.assertEqual(self.call("POST", "/v1/chat", {}, {"conversation_id": "x", "message": "hi"})[0], 401)
        cid = self.call("POST", "/v1/conversations", self.tok("a"), {})[1]["conversation_id"]
        # Aislar el escenario: esta prueba verifica el caso sin adaptador.
        self.svc.model = None
        s, p = self.call("POST", "/v1/chat", self.tok("a"), {"conversation_id": cid, "message": "hi"})
        self.assertEqual((s, p["error"]), (503, "MODEL_ADAPTER_NOT_CONFIGURED"))
        self.assertEqual(self.call("POST", "/v1/chat", self.tok("b"), {"conversation_id": cid, "message": "hi"})[0], 404)

    def test_persistence_survives_restart(self) -> None:
        tid = self.task("alice", "knowledge.search")[1]["task_id"]
        self.svc.store.close()
        self.mk()
        self.assertEqual(self.call("GET", f"/v1/tasks/{tid}", self.tok("alice"))[1]["state"], "SUCCEEDED")
        self.assertTrue(self.svc.store.verify_audit()[0])
