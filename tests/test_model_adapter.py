"""Adapter tests use an injected FAKE transport (a test double, not a provider). They prove the gateway's
contract and safety properties; they do NOT prove that any real provider accepts the key."""
import json
import unittest

from omega.adapters.model import AdapterLimits, HttpsModelAdapter, ModelError, adapter_from_env, https_transport
from tests.test_service import Base

SECRET = "TESTKEY-not-a-real-credential-123"


def fake(status: int, payload: object, seen: list | None = None):  # type: ignore[no-untyped-def,type-arg]
    def t(url: str, headers: dict, body: bytes, timeout: float):  # type: ignore[no-untyped-def,type-arg]
        if seen is not None:
            seen.append((url, headers, json.loads(body), timeout))
        return status, payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return t


A_OK = {"content": [{"type": "text", "text": "hola"}]}
G_OK = {"candidates": [{"content": {"parts": [{"text": "hola"}]}}]}
MSG = [{"role": "user", "content": "hi"}]


class AdapterTests(unittest.TestCase):
    def test_anthropic_request_shape_fixed_host_and_limits(self) -> None:
        seen: list = []  # type: ignore[type-arg]
        a = HttpsModelAdapter("anthropic", "some-model", SECRET, AdapterLimits(timeout_seconds=7, max_output_tokens=99), fake(200, A_OK, seen))
        self.assertEqual(a.chat(MSG), "hola")
        url, h, body, to = seen[0]
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual((body["max_tokens"], to), (99, 7))
        self.assertEqual(h["x-api-key"], SECRET)

    def test_gemini_request_shape(self) -> None:
        seen: list = []  # type: ignore[type-arg]
        a = HttpsModelAdapter("gemini", "m-1", SECRET, None, fake(200, G_OK, seen))
        self.assertEqual(a.chat(MSG), "hola")
        self.assertTrue(seen[0][0].startswith("https://generativelanguage.googleapis.com/v1beta/models/m-1:"))
        self.assertNotIn(SECRET, seen[0][0])  # key in header, never in the URL

    def test_error_mapping(self) -> None:
        for st, code in ((401, "PROVIDER_AUTH_REJECTED"), (403, "PROVIDER_AUTH_REJECTED"), (429, "PROVIDER_RATE_LIMITED"), (500, "PROVIDER_ERROR")):
            with self.assertRaises(ModelError) as c:
                HttpsModelAdapter("anthropic", "m", SECRET, None, fake(st, {})).chat(MSG)
            self.assertEqual(c.exception.code, code)

    def test_malformed_and_empty_output_never_pass(self) -> None:
        for payload, code in ((b"not json", "PROVIDER_INVALID_OUTPUT"), ({"x": 1}, "PROVIDER_INVALID_OUTPUT"),
                              ({"content": [{"type": "text", "text": "  "}]}, "PROVIDER_EMPTY_OUTPUT")):
            with self.assertRaises(ModelError) as c:
                HttpsModelAdapter("anthropic", "m", SECRET, None, fake(200, payload)).chat(MSG)
            self.assertEqual(c.exception.code, code)

    def test_timeout_and_unreachable(self) -> None:
        def to(*a: object) -> tuple[int, bytes]:
            raise TimeoutError()
        def un(*a: object) -> tuple[int, bytes]:
            raise OSError("no route")
        self.assertEqual(self._code(to), "PROVIDER_TIMEOUT")
        self.assertEqual(self._code(un), "PROVIDER_UNREACHABLE")

    def _code(self, t):  # type: ignore[no-untyped-def]
        with self.assertRaises(ModelError) as c:
            HttpsModelAdapter("anthropic", "m", SECRET, None, t).chat(MSG)
        return c.exception.code

    def test_prompt_limits(self) -> None:
        a = HttpsModelAdapter("anthropic", "m", SECRET, AdapterLimits(max_prompt_chars=10), fake(200, A_OK))
        with self.assertRaises(ModelError):
            a.chat([{"role": "user", "content": "x" * 11}])
        with self.assertRaises(ModelError):
            a.chat([{"role": "assistant", "content": "x"}])  # must end with a user turn

    def test_key_never_in_repr_or_output(self) -> None:
        a = HttpsModelAdapter("anthropic", "m", SECRET, None, fake(200, {"content": [{"type": "text", "text": f"leak {SECRET}"}]}))
        self.assertNotIn(SECRET, repr(a))
        self.assertNotIn(SECRET, a.chat(MSG))

    def test_closed_provider_enum_and_validation(self) -> None:
        for args in (("evil", "m", SECRET), ("anthropic", "bad model!", SECRET), ("anthropic", "m", ""), ("anthropic", "m", "a b")):
            with self.assertRaises(ValueError):
                HttpsModelAdapter(*args)  # type: ignore[arg-type]

    def test_egress_proxy_denial_is_not_reported_as_provider_auth_failure(self) -> None:
        import io
        import urllib.error
        import urllib.request
        from email.message import Message
        from unittest import mock
        h = Message()
        h["x-deny-reason"] = "host_not_allowed"
        err = urllib.error.HTTPError("https://api.anthropic.com/v1/messages", 403, "Forbidden", h, io.BytesIO(b"Host not in allowlist"))
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=err):
            with self.assertRaises(ModelError) as c:
                https_transport("https://api.anthropic.com/v1/messages", {}, b"{}", 1)
        self.assertEqual(c.exception.code, "EGRESS_DENIED_BY_SANDBOX")

    def test_plain_http_refused(self) -> None:
        with self.assertRaises(ModelError):
            https_transport("http://api.anthropic.com/v1/messages", {}, b"{}", 1)

    def test_env_loader(self) -> None:
        self.assertIsNone(adapter_from_env({}))
        self.assertIsNone(adapter_from_env({"MODEL_PROVIDER": "disabled"}))
        a = adapter_from_env({"MODEL_PROVIDER": "gemini", "MODEL_ID": "m", "MODEL_API_KEY": SECRET})
        self.assertIsNotNone(a)
        self.assertNotIn(SECRET, repr(a))


class ChatEndpointTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.svc.store.close()
        self.mk(model_adapter=HttpsModelAdapter("anthropic", "m", SECRET, None, fake(200, A_OK)))

    def test_chat_ok_persists_audits_and_is_isolated(self) -> None:
        h = self.tok("alice")
        _, c = self.call("POST", "/v1/conversations", h, {"title": "t"})
        st, r = self.call("POST", "/v1/chat", h, {"conversation_id": c["conversation_id"], "message": "hello"})
        self.assertEqual((st, r["authority"], r["reply"]), (200, "NON_AUTHORITATIVE_MODEL_OUTPUT", "hola"))
        _, m = self.call("GET", f"/v1/conversations/{c['conversation_id']}/messages", h)
        self.assertEqual([x["role"] for x in m["messages"]], ["USER", "ASSISTANT"])
        st, _ = self.call("POST", "/v1/chat", self.tok("bob"), {"conversation_id": c["conversation_id"], "message": "x"})
        self.assertEqual(st, 404)
        _, ev = self.call("GET", "/v1/audit/events", h)
        blob = json.dumps(ev)
        self.assertIn("CHAT_COMPLETED", blob)
        self.assertNotIn("hello", blob)  # digests only, no content in audit
        self.assertNotIn(SECRET, blob)

    def test_provider_failure_is_controlled_and_stores_nothing(self) -> None:
        self.svc.store.close()
        self.mk(model_adapter=HttpsModelAdapter("anthropic", "m", SECRET, None, fake(429, {})))
        h = self.tok("alice")
        _, c = self.call("POST", "/v1/conversations", h, {})
        st, r = self.call("POST", "/v1/chat", h, {"conversation_id": c["conversation_id"], "message": "hi"})
        self.assertEqual(st, 503)
        _, m = self.call("GET", f"/v1/conversations/{c['conversation_id']}/messages", h)
        self.assertEqual(m["messages"], [])


if __name__ == "__main__":
    unittest.main()
