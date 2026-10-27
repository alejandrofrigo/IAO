import json
import threading
from http.server import ThreadingHTTPServer

from omega.egress import EgressPolicy
from omega.tools.web_fetch import make_web_fetch
from tests.test_egress import H
from tests.test_service import Base


class WebFetchToolTests(Base):
    @classmethod
    def setUpClass(cls) -> None:
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self) -> None:
        super().setUp()
        pol = EgressPolicy(allow_hosts=frozenset({"localhost"}), allow_http=True, allowed_ports=frozenset({self.port}), allow_private=True, total_timeout=2)
        self.svc.registry.register(make_web_fetch(pol))

    def fetch(self, path: str, scopes: list[str] | None = None) -> tuple[int, dict]:  # type: ignore[type-arg]
        return self.task("alice", "web.fetch", {"url": f"http://localhost:{self.port}{path}"}, scopes=scopes or ["web.fetch"])

    def test_governed_fetch_succeeds_with_pass(self) -> None:
        s, p = self.fetch("/json")
        self.assertEqual((p["state"], p["verification"], p["result"]["untrusted"]), ("SUCCEEDED", "PASS", True))

    def test_denied_without_scope(self) -> None:
        self.assertEqual(self.fetch("/ok", ["knowledge.search"])[0], 403)

    def test_ssrf_attempt_through_tool_is_a_verified_denial_not_an_execution_of_the_target(self) -> None:
        s, p = self.fetch("/to-meta")
        self.assertEqual((p["state"], p["result"]["status"], p["result"]["error"]), ("SUCCEEDED", "DENIED", "HOST_NOT_ALLOWED"))

    def test_extra_input_fields_rejected(self) -> None:
        s, p = self.task("alice", "web.fetch", {"url": "http://localhost/", "method": "POST"}, scopes=["web.fetch"])
        self.assertEqual(p["error"], "INVALID_INPUT")

    def test_injected_page_does_not_change_authority(self) -> None:
        s, p = self.fetch("/ok")
        self.assertIn("IGNORE ALL PREVIOUS INSTRUCTIONS", p["result"]["body"])  # returned as data
        self.assertEqual(self.call("GET", "/v1/me", self.tok("alice", ["web.fetch"]))[1]["scopes"], ["web.fetch"])
        self.assertEqual(self.task("alice", "shell.execute", scopes=["web.fetch"])[0], 403)
        self.assertNotIn("password", json.dumps(self.svc.store._all_events()))
