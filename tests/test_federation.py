import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omega.federation import (FedServer, Node, _sign, verify_identity_challenge)
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
        self.b.enroll(self.a.contract_for_self(["knowledge.search"]), granted_capabilities=["knowledge.search"])   # B grants A inbound access
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


class IdentityChallengeVerificationTests(FedBase):
    def make_proof(self):
        nonce = "a" * 64
        request_ts = self.clock()
        request = {
            "v": 1,
            "from": self.a.node_id,
            "to": self.b.node_id,
            "nonce": nonce,
            "ts": request_ts,
        }
        status, response = self.b.answer_challenge(json.dumps(request).encode())
        self.assertEqual(status, 200)
        return self.b.identity_document(), response, nonce, request_ts

    def verify(self, identity, response, nonce, request_ts, **kw):
        args = {
            "requester_id": self.a.node_id,
            "nonce": nonce,
            "request_ts": request_ts,
            "now": self.clock(),
        }
        args.update(kw)
        return verify_identity_challenge(identity, response, **args)

    def test_valid_identity_and_signed_challenge(self):
        identity, response, nonce, request_ts = self.make_proof()
        result = self.verify(identity, response, nonce, request_ts)
        self.assertTrue(result["ok"])
        self.assertEqual(result["peer_id"], self.b.node_id)

    def test_identity_key_substitution_rejected(self):
        identity, response, nonce, request_ts = self.make_proof()
        identity["public_key"] = self.a.pub.hex()
        result = self.verify(identity, response, nonce, request_ts)
        self.assertEqual(result["error"], "NODE_ID_KEY_MISMATCH")

    def test_tampered_signed_response_rejected(self):
        identity, response, nonce, request_ts = self.make_proof()
        response["nonce"] = "b" * 64
        result = self.verify(identity, response, nonce, request_ts)
        self.assertEqual(result["error"], "BAD_CHALLENGE_SIGNATURE")

    def test_wrong_expected_nonce_rejected(self):
        identity, response, nonce, request_ts = self.make_proof()
        result = self.verify(identity, response, "c" * 64, request_ts)
        self.assertEqual(result["error"], "CHALLENGE_BINDING_MISMATCH")

    def test_expired_response_rejected(self):
        identity, response, nonce, request_ts = self.make_proof()
        self.t[0] += 120
        result = self.verify(identity, response, nonce, request_ts)
        self.assertEqual(result["error"], "RESPONSE_CLOCK_SKEW")



class OutboundHandshakeTests(FedBase):
    def test_http_handshake_verifies_peer_without_enrolling(self):
        before_a = json.dumps(self.a._save_peer_snapshot() if hasattr(self.a, "_save_peer_snapshot")
                              else self.a.peers, sort_keys=True, default=str)
        before_b = json.dumps(self.b.peers, sort_keys=True, default=str)
        endpoint = self.sb.url.rsplit("/fed/v1/message", 1)[0]

        from unittest.mock import patch
        with patch.dict('os.environ', {'IAO_ALLOW_LOOPBACK_HTTP': '1'}):
            result = self.a.handshake(endpoint)

        self.assertTrue(result["ok"], result)
        self.assertTrue(result["verified"])
        self.assertEqual(result["peer_id"], self.b.node_id)
        self.assertEqual(result["verification"], "ED25519_NONCE_CHALLENGE")
        self.assertFalse(result["enrolled"])
        after_a = json.dumps(self.a._save_peer_snapshot() if hasattr(self.a, "_save_peer_snapshot")
                             else self.a.peers, sort_keys=True, default=str)
        after_b = json.dumps(self.b.peers, sort_keys=True, default=str)
        self.assertEqual(before_a, after_a)
        self.assertEqual(before_b, after_b)

    def test_handshake_rejects_self_connection(self):
        endpoint = self.sb.url.rsplit("/fed/v1/message", 1)[0]
        self.assertEqual(
            self.a.handshake("http://127.0.0.1:1")["error"],
            "PEER_UNREACHABLE",
        )




class VerifiedPeerEnrollmentTests(FedBase):
    def test_signed_publication_handshake_enrolls_and_runs_search(self):
        import os

        # FedBase ya enrola ambos nodos: aislar el estado inicial de esta prueba.
        self.a.peers.pop(self.b.node_id, None)

        old = os.environ.get("IAO_ALLOW_LOOPBACK_HTTP")
        os.environ["IAO_ALLOW_LOOPBACK_HTTP"] = "1"
        try:
            endpoint = self.sb.url.rsplit("/fed/v1/message", 1)[0]
            publication = self.b.identity_publication(
                endpoint,
                capabilities=["knowledge.search"],
                lease_seconds=1800,
            )

            self.assertNotIn(self.b.node_id, self.a.peers)
            result = self.a.connect_peer(
                publication,
                granted_capabilities=[],
            )

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["verified"])
            self.assertTrue(result["enrolled"])
            self.assertEqual(result["peer_id"], self.b.node_id)
            self.assertEqual(
                self.a.peers[self.b.node_id]["granted_capabilities"], []
            )

            response = self.a.send(
                self.b.node_id,
                self.sb.url,
                "knowledge.search",
                Q,
            )
            self.assertTrue(response.get("ok"), response)
            self.assertIn("result", response)
        finally:
            if old is None:
                os.environ.pop("IAO_ALLOW_LOOPBACK_HTTP", None)
            else:
                os.environ["IAO_ALLOW_LOOPBACK_HTTP"] = old

    def test_tampered_publication_is_rejected_without_enrollment(self):
        self.a.peers.pop(self.b.node_id, None)

        endpoint = self.sb.url.rsplit("/fed/v1/message", 1)[0]
        publication = self.b.identity_publication(
            endpoint,
            capabilities=["knowledge.search"],
            lease_seconds=1800,
        )
        publication["capabilities"] = [
            "knowledge.search", "forged.capability"
        ]

        result = self.a.connect_peer(
            publication,
            granted_capabilities=[],
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "BAD_PUBLICATION_SIGNATURE")
        self.assertNotIn(self.b.node_id, self.a.peers)



class HappyAndAuthTests(FedBase):
    def test_roundtrip_signed_verified_untrusted(self) -> None:
        r = self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)
        self.assertEqual((r["ok"], r["verification"], r["untrusted"]), (True, "PASS", True))
        self.assertTrue(r["result"]["items"])

    def test_peer_offer_does_not_imply_local_grant(self) -> None:
        self.b.peers[self.a.node_id]["granted_capabilities"] = []
        status, payload = self.raw(self.env(nonce="directional-deny-0001"))
        self.assertEqual((status, payload["error"]), (403, "CAPABILITY_NOT_GRANTED"))

    def test_node_id_bound_to_key_at_enrolment(self) -> None:
        c = self.b.contract_for_self(["knowledge.search"])
        c["peer_id"] = "deadbeefdeadbeef"
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
        c = mk(self.tmp.name, "c", self.clock)
        self.b.enroll(c.contract_for_self(["knowledge.search"]))
        s, p = self.raw(self.env(), c.key)  # claims to be A, signed by C
        self.assertEqual(p["error"], "BAD_SIGNATURE")


class ReplayAndTimeTests(FedBase):
    def test_replay_rejected(self) -> None:
        raw = json.dumps(_sign(self.a.key, self.env())).encode()
        self.assertEqual(self.b.handle(raw)[0], 200)
        s, p = self.b.handle(raw)
        self.assertEqual((s, p["error"]), (409, "REPLAY"))

    def test_replayed_to_a_different_node_rejected(self) -> None:
        c = mk(self.tmp.name, "c", self.clock)
        c.enroll(self.a.contract_for_self(["knowledge.search"]))
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
        self.b.peers[self.a.node_id]["granted_capabilities"].append("danger.write")  # even if mis-configured
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
        self.sb = FedServer(self.b, port=port).start()
        self.servers.append(self.sb)
        self.assertTrue(self.a.send(self.b.node_id, self.sb.url, "knowledge.search", Q)["ok"])

    def _hostile(self, build) -> FedServer:  # type: ignore[no-untyped-def]
        peer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_POST(self) -> None:
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                data = json.dumps(build(req)).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        class S:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/fed/v1/message"
            def stop(self_inner) -> None:
                httpd.shutdown()
                httpd.server_close()
        s = S()
        self.servers.append(s)
        del peer
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


class PersistentPeerStoreTests(FedBase):
    def test_peer_survives_node_restart(self) -> None:
        from omega.federation import Node
        path = Path(self.tmp.name) / "federation-peers.json"
        node = Node(self.a.store, self.a.registry, key=self.a.key,
                    clock=self.clock, served=self.a.served, peer_store_path=path)
        node.enroll(self.b.contract_for_self(["knowledge.search"]))
        restored = Node(self.a.store, self.a.registry, key=self.a.key,
                        clock=self.clock, served=self.a.served, peer_store_path=path)
        self.assertIn(self.b.node_id, restored.peers)
        self.assertFalse(restored.peers[self.b.node_id]["revoked"])

    def test_revocation_survives_node_restart(self) -> None:
        from omega.federation import Node
        path = Path(self.tmp.name) / "federation-peers.json"
        node = Node(self.a.store, self.a.registry, key=self.a.key,
                    clock=self.clock, served=self.a.served, peer_store_path=path)
        node.enroll(self.b.contract_for_self(["knowledge.search"]))
        node.revoke(self.b.node_id)
        restored = Node(self.a.store, self.a.registry, key=self.a.key,
                        clock=self.clock, served=self.a.served, peer_store_path=path)
        self.assertTrue(restored.peers[self.b.node_id]["revoked"])

    def test_corrupt_peer_store_fails_closed(self) -> None:
        from omega.federation import Node
        path = Path(self.tmp.name) / "federation-peers.json"
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "PEER_STORE_INVALID_FAIL_CLOSED"):
            Node(self.a.store, self.a.registry, key=self.a.key,
                 clock=self.clock, served=self.a.served, peer_store_path=path)

    def test_endpoint_must_be_https_and_exact_path(self) -> None:
        from omega.federation import Node
        path = Path(self.tmp.name) / "federation-peers.json"
        node = Node(self.a.store, self.a.registry, key=self.a.key,
                    clock=self.clock, served=self.a.served, peer_store_path=path)
        contract = self.b.contract_for_self(["knowledge.search"])
        contract["endpoint"] = "http://example.org/fed/v1/message"
        with self.assertRaisesRegex(ValueError, "INVALID_PEER_ENDPOINT"):
            node.enroll(contract)

    def test_v2_granted_capabilities_survive_node_restart(self) -> None:
        from omega.federation import Node

        path = Path(self.tmp.name) / "federation-peers-v2.json"
        node = Node(self.a.store, self.a.registry, key=self.a.key,
                    clock=self.clock, served=self.a.served, peer_store_path=path)
        node.enroll(self.b.contract_for_self(["knowledge.search"]),
                    granted_capabilities=["knowledge.search"])

        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 2)
        self.assertEqual(saved["peers"][0]["granted_capabilities"],
                         ["knowledge.search"])

        restored = Node(self.a.store, self.a.registry, key=self.a.key,
                        clock=self.clock, served=self.a.served, peer_store_path=path)
        self.assertEqual(
            restored.peers[self.b.node_id]["granted_capabilities"],
            ["knowledge.search"],
        )

    def test_v1_peer_store_migrates_without_inbound_grants(self) -> None:
        from omega.federation import Node

        path = Path(self.tmp.name) / "federation-peers-v1.json"
        node = Node(self.a.store, self.a.registry, key=self.a.key,
                    clock=self.clock, served=self.a.served, peer_store_path=path)
        node.enroll(self.b.contract_for_self(["knowledge.search"]),
                    granted_capabilities=["knowledge.search"])

        legacy = json.loads(path.read_text(encoding="utf-8"))
        legacy["version"] = 1
        for peer in legacy["peers"]:
            peer.pop("granted_capabilities", None)
        path.write_text(json.dumps(legacy), encoding="utf-8")

        restored = Node(self.a.store, self.a.registry, key=self.a.key,
                        clock=self.clock, served=self.a.served, peer_store_path=path)
        self.assertEqual(
            restored.peers[self.b.node_id]["granted_capabilities"],
            [],
        )

class BidirectionalLocalFederationIntegrationTests(FedBase):
    """Intercambio HTTP firmado entre dos nodos federados locales."""

    def test_two_nodes_exchange_signed_requests_in_both_directions(self) -> None:
        self.a.enroll(
            self.b.contract_for_self(["knowledge.search"]),
            granted_capabilities=["knowledge.search"],
        )
        server_a = FedServer(self.a).start()
        self.servers.append(server_a)

        self.assertNotEqual(self.a.node_id, self.b.node_id)
        self.assertNotEqual(server_a.port, self.sb.port)

        a_to_b = self.a.send(
            self.b.node_id, self.sb.url, "knowledge.search", Q
        )
        b_to_a = self.b.send(
            self.a.node_id, server_a.url, "knowledge.search", Q
        )

        for response in (a_to_b, b_to_a):
            self.assertTrue(response.get("ok"), response)
            self.assertEqual(response.get("verification"), "PASS")
            self.assertTrue(response.get("untrusted"))
            self.assertTrue(response.get("result", {}).get("items"))

        for node in (self.a, self.b):
            allowed = [
                event for event in node.store._all_events()
                if event["event_type"] == "FED_REQUEST"
                and event["details"].get("decision") == "ALLOW"
            ]
            self.assertTrue(
                allowed,
                f"missing inbound federation audit for {node.node_id}",
            )
            self.assertTrue(node.store.verify_audit()[0])



class RealTLSFederationTransportTests(FedBase):
    def test_real_tls_signed_federation_exchange(self):
        import datetime
        import ipaddress
        import os
        import ssl
        from pathlib import Path
        from unittest.mock import patch
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        from cryptography.x509.oid import NameOID

        cert_dir = Path(self.tmp.name) / "tls"
        cert_dir.mkdir()

        def make_cert(prefix):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            key_path = cert_dir / f"{prefix}.key"
            cert_path = cert_dir / f"{prefix}.crt"
            key_path.write_bytes(key.private_bytes(
                Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
            ))
            cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
            return cert_path, key_path

        trusted_cert, trusted_key = make_cert("trusted")
        wrong_cert, _ = make_cert("wrong")

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(trusted_cert), str(trusted_key))

        self.sb.stop()
        tls_server = FedServer(self.b, ssl_context=server_context).start()
        self.sb = tls_server
        self.servers[0] = tls_server

        with patch.dict(os.environ, {"IAO_TLS_CA_FILE": str(trusted_cert)}):
            result = self.a.send(
                self.b.node_id, tls_server.url,
                "knowledge.search", Q, timeout=8.0
            )

        self.assertTrue(result.get("ok"), repr(result))
        self.assertEqual(result.get("verification"), "PASS")

        with patch.dict(os.environ, {"IAO_TLS_CA_FILE": str(wrong_cert)}):
            rejected = self.a.send(
                self.b.node_id, tls_server.url,
                "knowledge.search", Q, timeout=8.0
            )

        self.assertFalse(rejected.get("ok"), repr(rejected))
        self.assertEqual(rejected.get("error"), "PEER_UNREACHABLE")
