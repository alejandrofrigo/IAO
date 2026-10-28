"""Framework-agnostic API service. handle(method, path, headers, body) -> (status, payload).
The same logic can be mounted under FastAPI later; the stdlib server in omega/server.py runs it today."""
import hashlib
import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from omega.adapters.model import ModelError
from omega.audit import canonical_json
from omega.auth import Principal, issue_token, verify_token
from omega.control import transition
from omega.policy import authorize
from omega.store import Store
from omega.tools.registry import ToolRegistry

POLICY_VERSION = "policy-v1:" + hashlib.sha256((Path(__file__).parent / "policy.py").read_bytes()).hexdigest()[:12]
MAX_BODY = 64 * 1024
_EXEC = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tool")


class ApiError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj) if isinstance(obj, dict) else str(obj).encode()).hexdigest()


class OmegaService:
    def __init__(self, store: Store, registry: ToolRegistry, token_key: str, *, rate_limit_per_min: int = 120,
                 daily_task_quota: int = 1000, task_ttl_seconds: int = 300, model_adapter: Any = None,
                 clock: Any = time.time) -> None:
        self.store, self.registry, self.token_key = store, registry, token_key
        self.rate, self.quota, self.ttl, self.model, self.clock = rate_limit_per_min, daily_task_quota, task_ttl_seconds, model_adapter, clock

        # IAO_ROUTER_FALLBACK_V1
        if self.model is None:
            try:
                from omega.llm_router import RouterModelAdapter, providers
                if providers():
                    self.model = RouterModelAdapter()
            except (ImportError, OSError, ValueError):
                pass
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._public_hits: dict[str, deque[float]] = defaultdict(deque)
        self._rl = threading.Lock()

        # IAO_PATCH: la dependencia inyectada tiene prioridad sobre el router por defecto.
        if model_adapter is not None:
            self.model = model_adapter

    # ---------- entry ----------
    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        cid = uuid.uuid4().hex
        try:
            if len(body) > MAX_BODY:
                raise ApiError(413, "PAYLOAD_TOO_LARGE")
            status, payload = self._route(method.upper(), path, headers, body)
        except ApiError as e:
            status, payload = e.status, {"error": e.code}
        except Exception:  # never leak internals
            status, payload = 500, {"error": "INTERNAL_ERROR"}
        payload["correlation_id"] = cid
        return status, payload

    def _auth(self, headers: dict[str, str]) -> Principal:
        h = headers.get("authorization", "")
        p = verify_token(self.token_key, h[7:], self.clock()) if h.startswith("Bearer ") else None
        if p is None:
            self.store.audit("anonymous", "AUTH", "request", decision="DENY", reason="AUTHENTICATION_REQUIRED")
            raise ApiError(401, "AUTHENTICATION_REQUIRED")
        now = self.clock()
        with self._rl:
            q = self._hits[p.subject]
            while q and q[0] < now - 60:
                q.popleft()
            limit = min(self.rate, 20) if p.subject.startswith('guest:') else self.rate
            if len(q) >= limit:
                limited = True
            else:
                q.append(now)
                limited = False
        if limited:
            self.store.audit(p.subject, "QUOTA", "rate_limit", decision="DENY", reason="RATE_LIMITED")
            raise ApiError(429, "RATE_LIMITED")
        return p

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        try:
            d = json.loads(body or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "INVALID_JSON") from None
        if not isinstance(d, dict):
            raise ApiError(400, "INVALID_JSON")
        return d

    def _route(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        u = urlsplit(path)
        p = u.path.rstrip("/") or "/"
        if method == "GET" and p == "/health/live":
            return 200, {"status": "live"}
        if method == "GET" and p == "/health/ready":
            ok_db = self.store.ping()
            chain_ok, bad = self.store.verify_audit()
            ready = ok_db and chain_ok and bool(self.registry.names())
            return (200 if ready else 503), {"status": "ready" if ready else "not_ready",
                                             "checks": {"database": ok_db, "audit_chain": chain_ok, "tools": sorted(self.registry.names())}}
        if method == "POST" and p == "/v1/public/session":
            # The HTTP handler overwrites this header using the socket peer address.
            client = headers.get("x-omega-client-ip", "unknown")[:64]
            now = self.clock()
            with self._rl:
                q = self._public_hits[client]
                while q and q[0] < now - 60:
                    q.popleft()
                limited = len(q) >= 10
                if not limited:
                    q.append(now)
            if limited:
                self.store.audit("anonymous", "PUBLIC_SESSION_DENIED", "public_chat",
                                 decision="DENY", reason="RATE_LIMITED")
                raise ApiError(429, "RATE_LIMITED")
            subject = "guest:" + uuid.uuid4().hex
            ttl = 7200
            token = issue_token(self.token_key, subject, [], ttl=ttl, now=now)
            self.store.audit(subject, "PUBLIC_SESSION_CREATED", "public_chat", expires_in=ttl)
            return 201, {"access_token": token, "token_type": "Bearer", "expires_in": ttl}

        pr = self._auth(headers)
        if method == "GET" and p == "/v1/me":
            return 200, {"subject": pr.subject, "scopes": sorted(pr.scopes)}
        if method == "POST" and p == "/v1/conversations":
            title = self._json(body).get("title", "")
            if not isinstance(title, str) or len(title) > 200:
                raise ApiError(400, "INVALID_TITLE")
            cid = self.store.create_conversation(pr.subject, title)
            self.store.audit(pr.subject, "CONVERSATION_CREATED", cid)
            return 201, {"conversation_id": cid}
        m = re.fullmatch(r"/v1/conversations/([0-9a-f-]{36})/messages", p)
        if method == "GET" and m:
            msgs = self.store.list_messages(m.group(1), pr.subject)
            if msgs is None:
                raise ApiError(404, "NOT_FOUND")
            return 200, {"messages": msgs}
        if method == "POST" and p == "/v1/chat":
            d = self._json(body)
            cid, msg = d.get("conversation_id"), d.get("message")
            if not isinstance(cid, str) or not isinstance(msg, str) or not 1 <= len(msg) <= 20000:
                raise ApiError(400, "INVALID_REQUEST")
            if self.store.get_conversation(cid, pr.subject) is None:
                raise ApiError(404, "NOT_FOUND")
            if self.model is None:
                raise ApiError(503, "MODEL_ADAPTER_NOT_CONFIGURED")
            history = [{"role": r["role"].lower(), "content": r["content"]}
                       for r in (self.store.list_messages(cid, pr.subject) or []) if r["role"] in ("USER", "ASSISTANT")]
            history.append({"role": "user", "content": msg})
            digest = hashlib.sha256(msg.encode()).hexdigest()
            try:
                reply = self.model.chat(history)
            except ModelError as e:
                self.store.audit(pr.subject, "CHAT_MODEL_ERROR", cid, code=e.code, input_digest=digest)
                raise ApiError(e.http_status, e.code) from None
            self.store.add_message(cid, "USER", msg)
            self.store.add_message(cid, "ASSISTANT", reply)
            self.store.audit(pr.subject, "CHAT_COMPLETED", cid, input_digest=digest,
                             output_digest=hashlib.sha256(reply.encode()).hexdigest())
            return 200, {"status": "OK", "conversation_id": cid, "reply": reply,
                         "authority": "NON_AUTHORITATIVE_MODEL_OUTPUT"}
        if p == "/v1/memory" or p.startswith("/v1/memory/"):
            return self._memory(method, p, pr, body)
        if method == "POST" and p == "/v1/tasks":
            return self._create_task(pr, headers, body)
        m = re.fullmatch(r"/v1/tasks/([0-9a-f-]{36})", p)
        if method == "GET" and m:
            t = self.store.get_task(m.group(1), pr.subject)
            if t is None:
                raise ApiError(404, "NOT_FOUND")
            return 200, self._view(t)
        if method == "GET" and p == "/v1/audit/events":
            q = parse_qs(u.query)
            try:
                limit = min(100, max(1, int(q.get("limit", ["50"])[0])))
                after = int(q.get("after_id", ["0"])[0])
            except ValueError:
                raise ApiError(400, "INVALID_QUERY") from None
            actor = None if "audit.admin" in pr.scopes else pr.subject
            return 200, {"events": self.store.audit_events(actor, limit, after)}
        raise ApiError(404, "NOT_FOUND")

    # ---------- memory (REQ-05) ----------
    def _memory(self, method: str, p: str, pr: Principal, body: bytes) -> tuple[int, dict[str, Any]]:
        need = "memory.read" if method == "GET" else "memory.write"
        dec = authorize(need, authenticated=True, approved_capabilities=set(pr.scopes))
        if not dec.allowed:
            self.store.audit(pr.subject, "DECISION", "memory", decision="DENY", reason=dec.reason, capability=need)
            raise ApiError(403, dec.reason)
        now_ts = self.clock()
        now = datetime.fromtimestamp(now_ts, timezone.utc).isoformat()
        sub = p[len("/v1/memory"):].strip("/")
        if method == "GET" and sub == "":
            return 200, {"memories": self.store.memory_list(pr.subject, now)}
        if method == "GET" and sub == "export":
            items = self.store.memory_list(pr.subject, now)
            self.store.audit(pr.subject, "MEMORY_EXPORT", "memory", count=len(items))
            return 200, {"subject": pr.subject, "exported_at": now, "memories": items}
        if method == "POST" and sub == "":
            d = self._json(body)
            if d.get("consent") is not True:
                raise ApiError(422, "CONSENT_REQUIRED")  # nothing is stored without explicit consent
            val, mt, prov = d.get("value"), d.get("type"), d.get("provenance")
            ttl = d.get("ttl_days")
            if (mt not in ("PREFERENCE", "FACT") or not isinstance(val, str) or not 1 <= len(val) <= 2000
                    or not isinstance(prov, str) or not 1 <= len(prov) <= 200
                    or (ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 3650))):
                raise ApiError(400, "INVALID_REQUEST")
            exp = datetime.fromtimestamp(now_ts + ttl * 86400, timezone.utc).isoformat() if ttl else None
            mid = self.store.memory_add(pr.subject, mt, val, prov, now, exp)
            self.store.audit(pr.subject, "MEMORY_CREATED", mid, consent=True, value_digest=_digest(val))  # never the content
            return 201, {"memory_id": mid, "expires_at": exp}
        if method == "PUT" and re.fullmatch(r"[0-9a-f-]{36}", sub):
            val = self._json(body).get("value")
            if not isinstance(val, str) or not 1 <= len(val) <= 2000:
                raise ApiError(400, "INVALID_REQUEST")
            if not self.store.memory_update(pr.subject, sub, val, now):
                raise ApiError(404, "NOT_FOUND")
            self.store.audit(pr.subject, "MEMORY_UPDATED", sub, value_digest=_digest(val))
            return 200, {"memory_id": sub}
        if method == "DELETE" and (sub == "" or re.fullmatch(r"[0-9a-f-]{36}", sub)):
            n = self.store.memory_delete(pr.subject, sub or None)
            if sub and n == 0:
                raise ApiError(404, "NOT_FOUND")
            self.store.audit(pr.subject, "MEMORY_DELETED", sub or "ALL", count=n)
            return 200, {"deleted": n}
        raise ApiError(404, "NOT_FOUND")

    # ---------- tasks ----------
    def _view(self, t: dict[str, Any]) -> dict[str, Any]:
        r = json.loads(t["result_json"]) if t.get("result_json") else {}
        return {"task_id": t["id"], "state": t["state"], "capability": (json.loads(t["intent_json"]).get("allowed_capabilities") or [None])[0], **r}

    def _create_task(self, pr: Principal, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        d = self._json(body)
        idem = headers.get("idempotency-key")
        if idem is not None and not 1 <= len(idem) <= 128:
            raise ApiError(400, "INVALID_IDEMPOTENCY_KEY")
        day = datetime.fromtimestamp(self.clock(), timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        if self.store.count_tasks_since(pr.subject, day) >= self.quota:
            self.store.audit(pr.subject, "QUOTA", "daily_task_quota", decision="DENY", reason="QUOTA_EXCEEDED")
            raise ApiError(429, "QUOTA_EXCEEDED")
        goal, cap, tin = d.get("goal"), d.get("capability"), d.get("input", {})
        missing = [n for n, ok in (("goal", isinstance(goal, str) and 1 <= len(goal) <= 4000),
                                   ("capability", isinstance(cap, str) and bool(cap)),
                                   ("input", isinstance(tin, dict))) if not ok]
        expires = datetime.fromtimestamp(self.clock() + self.ttl, timezone.utc).isoformat()
        intent = {"contract_version": "1.0", "goal": goal if isinstance(goal, str) else None,
                  "allowed_capabilities": [cap] if isinstance(cap, str) and cap else [], "risk_class": "R0",
                  "budget": {"max_model_calls": 0, "timeout_seconds": 20}, "termination_condition": "result or terminal error",
                  "policy_version": POLICY_VERSION, "expires_at": expires}
        tid = str(uuid.uuid4())
        row, created = self.store.create_task(tid, pr.subject, intent, idem)
        if not created:
            return 200, {**self._view(row), "idempotent_replay": True}
        tid = row["id"]
        st = "CREATED"

        def to(new: str, **ev: Any) -> None:
            nonlocal st
            st = transition(st, new)
            self.store.set_task_state(tid, st)
            self.store.audit(pr.subject, "TASK_STATE", tid, to=st, **ev)

        to("AUTHENTICATED")
        to("COMPILED")
        to("POLICY_CHECKED")
        if missing:
            to("NEEDS_CLARIFICATION", missing=missing)
            res = {"decision": "NEEDS_CLARIFICATION", "missing": missing}
            self.store.set_task_state(tid, st, res)
            return 422, {"task_id": tid, "state": st, **res}
        assert isinstance(cap, str) and isinstance(tin, dict)
        dec = authorize(cap, authenticated=True, approved_capabilities=set(pr.scopes) & self.registry.names())
        self.store.audit(pr.subject, "DECISION", tid, decision="ALLOW" if dec.allowed else "DENY", reason=dec.reason,
                         capability=cap, policy_version=POLICY_VERSION)
        if not dec.allowed:
            to("DENIED", reason=dec.reason)
            res = {"decision": "DENY", "reason": dec.reason}
            self.store.set_task_state(tid, st, res)
            return 403, {"task_id": tid, "state": st, **res}
        to("AUTHORIZED")
        spec = self.registry.get(cap)
        assert spec is not None
        if self.ttl <= 0:
            to("EXPIRED")
            res = {"decision": "ALLOW", "error": "LEASE_EXPIRED"}
            self.store.set_task_state(tid, st, res)
            return 200, {"task_id": tid, "state": st, **res}
        to("RUNNING")
        started = datetime.now(timezone.utc).isoformat()
        try:
            clean = spec.validate_input(tin)
        except ValueError:
            self.store.add_tool_execution(tid, spec.name, spec.version, "DENIED", _digest(tin), None, "INVALID_INPUT", None, None)
            to("FAILED", error="INVALID_INPUT")
            res = {"decision": "ALLOW", "error": "INVALID_INPUT", "verification": "FAIL"}
            self.store.set_task_state(tid, st, res)
            return 200, {"task_id": tid, "state": st, **res}
        din = _digest(clean)
        t_limit = min(spec.timeout_seconds, intent["budget"]["timeout_seconds"])
        fut = _EXEC.submit(spec.run, clean)
        try:
            out = fut.result(timeout=t_limit)
        except FutureTimeout:
            fut.cancel()
            self.store.add_tool_execution(tid, spec.name, spec.version, "TIMED_OUT", din, None, "TIMED_OUT", started, datetime.now(timezone.utc).isoformat())
            to("FAILED", error="TIMED_OUT")
            res = {"decision": "ALLOW", "error": "TIMED_OUT"}
            self.store.set_task_state(tid, st, res)
            return 200, {"task_id": tid, "state": st, **res}
        except Exception:
            self.store.add_tool_execution(tid, spec.name, spec.version, "FAILED", din, None, "TOOL_ERROR", started, datetime.now(timezone.utc).isoformat())
            to("FAILED", error="TOOL_ERROR")
            res = {"decision": "ALLOW", "error": "TOOL_ERROR"}
            self.store.set_task_state(tid, st, res)
            return 200, {"task_id": tid, "state": st, **res}
        self.store.add_tool_execution(tid, spec.name, spec.version, "SUCCEEDED", din, _digest(out), None, started, datetime.now(timezone.utc).isoformat())
        to("VERIFYING")
        verdict = spec.verify(out)
        self.store.audit(pr.subject, "EVIDENCE", tid, decision=verdict, method="schema+source_hash+snippet_provenance",
                         output_digest=_digest(out))
        res = {"decision": "ALLOW", "verification": verdict, "result": out}
        if verdict == "PASS":
            to("SUCCEEDED")
            self.store.set_task_state(tid, st, res)
            return 200, {"task_id": tid, "state": st, **res}
        to("FAILED", verification=verdict)  # UNKNOWN is never presented as PASS
        res["error"] = "VERIFICATION_" + verdict
        self.store.set_task_state(tid, st, res)
        return 200, {"task_id": tid, "state": st, **res}
