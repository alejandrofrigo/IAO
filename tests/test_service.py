import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from pathlib import Path

from omega.auth import issue_token
from omega.server import build_service
from omega.tools.knowledge_search import KnowledgeCorpus
from omega.tools.registry import ToolSpec
from omega.task_worker import TaskWorker
from omega.service import POLICY_VERSION
from omega.device_authority import DeviceAuthority, DeviceAuthorityError
from omega.operator_identity import OperatorIdentityAuthority, ROOT_SIGNATURE_DOMAIN
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEY = "unit-test-key-0123456789"
CORPUS = Path(__file__).resolve().parent.parent / "docs" / "corpus"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._audit_env = patch.dict(
            os.environ,
            {"AUDIT_HMAC_KEY": "unit-test-audit-key-" + "a" * 48},
        )
        self._audit_env.start()
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.mk()

    def mk(self, **kw: object) -> None:
        self.svc = build_service(self.state, KEY, CORPUS, **kw)

    def tearDown(self) -> None:
        self.svc.store.close()
        self.tmp.cleanup()
        self._audit_env.stop()

    def tok(self, sub: str, scopes: list[str] | None = None) -> dict[str, str]:
        return {"authorization": "Bearer " + issue_token(KEY, sub, ["knowledge.search"] if scopes is None else scopes)}

    def call(self, m: str, p: str, h: dict[str, str] | None = None, body: object = None) -> tuple[int, dict]:  # type: ignore[type-arg]
        return self.svc.handle(m, p, h or {}, json.dumps(body).encode() if body is not None else b"")

    def task(self, sub: str, cap: str, inp: dict | None = None, scopes: list[str] | None = None, **extra: str) -> tuple[int, dict]:  # type: ignore[type-arg]
        h = {**self.tok(sub, scopes), **extra}
        return self.call("POST", "/v1/tasks", h, {"goal": "g", "capability": cap, "input": inp if inp is not None else {"query": "audit chain"}})




class AuthTests(Base):
    def test_root_signed_revocation_deactivates_device_and_session(self) -> None:
        bootstrap_code = "operator-revoke-bootstrap-" + "r" * 40
        enrollment_code = "operator-revoke-device-" + "d" * 40
        device_authority = DeviceAuthority(
            self.state / "operator-revoke-device.sqlite3",
            enrollment_code=enrollment_code,
        )
        root = ec.generate_private_key(ec.SECP256R1())
        root_public = root.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        device = ec.generate_private_key(ec.SECP256R1())
        device_public = device.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        enrolled = device_authority.enroll(
            enrollment_code, device_public, owner_subject="pre-login-owner"
        )
        identity_authority = OperatorIdentityAuthority(
            self.state / "operator-revoke-identity.sqlite3",
            bootstrap_code,
            bootstrap_expires_at=time.time() + 600,
            subject_digest_key=hashlib.sha256(b"operator-revoke-session-key").digest(),
        )
        identity = identity_authority.bootstrap(bootstrap_code, root_public)
        _, binding_payload = identity_authority.device_binding_payload(
            device_public, key_version=1
        )
        identity_authority.bind_primary_device(
            identity["identity_id"], device_public,
            root.sign(ROOT_SIGNATURE_DOMAIN + binding_payload, ec.ECDSA(hashes.SHA256())),
            expected_key_version=1,
        )
        self.svc.device_authority = device_authority
        self.svc.operator_identity_authority = identity_authority
        status, challenge = self.call("POST", "/v1/operator/login/challenge", {}, {})
        self.assertEqual(status, 200)
        payload = base64.urlsafe_b64decode(
            challenge["signing_payload"]
            + "=" * (-len(challenge["signing_payload"]) % 4)
        )
        login_result = self.call(
            "POST", "/v1/operator/login/complete", {},
            {
                "challenge": challenge["challenge"],
                "root_signature": base64.urlsafe_b64encode(
                    root.sign(ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
                ).decode().rstrip("="),
                "device_signature": base64.urlsafe_b64encode(
                    device.sign(
                        b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + payload,
                        ec.ECDSA(hashes.SHA256()),
                    )
                ).decode().rstrip("="),
            },
        )
        self.assertEqual(login_result[0], 200)
        headers = {"authorization": "Bearer " + login_result[1]["access_token"]}
        revoke_payload = b"revoke-root-v1\n" + identity["identity_id"].encode("ascii")
        signature = root.sign(
            ROOT_SIGNATURE_DOMAIN + revoke_payload, ec.ECDSA(hashes.SHA256())
        )
        status, result = self.call(
            "POST", "/v1/operator/identity/revoke", headers,
            {
                "key_version": 1,
                "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result, {
            "authority": "OPERATOR_IDENTITY_REVOKED", "device_revoked": True,
        })
        with self.assertRaisesRegex(DeviceAuthorityError, "DEVICE_KEY_NOT_ACTIVE"):
            device_authority.verify_active_public_key(device_public)
        self.assertFalse(identity_authority.verify_authenticated_session(
            "operator:" + identity["identity_id"], login_result[1]["access_token"]
        ))
        with self.assertRaisesRegex(DeviceAuthorityError, "DEVICE_KEY_NOT_ACTIVE"):
            device_authority.challenge(enrolled["device_id"], owner_subject="operator:" + identity["identity_id"])


    def test_dual_signature_operator_login_api_issues_read_only_session_once(self) -> None:
        bootstrap_code = "operator-login-api-bootstrap-" + "v" * 40
        enrollment_code = "operator-login-device-enrollment-" + "w" * 40
        device_authority = DeviceAuthority(
            self.state / "operator-login-device.sqlite3",
            enrollment_code=enrollment_code,
        )
        root = ec.generate_private_key(ec.SECP256R1())
        root_public = root.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        device = ec.generate_private_key(ec.SECP256R1())
        device_public = device.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        enrolled_device = device_authority.enroll(
            enrollment_code, device_public, owner_subject="existing-device-owner"
        )
        identity_authority = OperatorIdentityAuthority(
            self.state / "operator-login-identity.sqlite3",
            bootstrap_code,
            bootstrap_expires_at=time.time() + 600,
            subject_digest_key=hashlib.sha256(b"operator-login-api-session-key").digest(),
        )
        identity = identity_authority.bootstrap(bootstrap_code, root_public)
        _, binding_payload = identity_authority.device_binding_payload(
            device_public, key_version=1
        )
        identity_authority.bind_primary_device(
            identity["identity_id"], device_public,
            root.sign(ROOT_SIGNATURE_DOMAIN + binding_payload, ec.ECDSA(hashes.SHA256())),
            expected_key_version=1,
        )
        self.svc.device_authority = device_authority
        self.svc.operator_identity_authority = identity_authority

        status, challenge = self.call(
            "POST", "/v1/operator/login/challenge", {}, {}
        )
        self.assertEqual(status, 200)
        self.assertEqual(challenge["protocol"], "IAO-OPERATOR-LOGIN-V1")
        payload = base64.urlsafe_b64decode(
            challenge["signing_payload"]
            + "=" * (-len(challenge["signing_payload"]) % 4)
        )
        root_signature = root.sign(
            ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
        )
        device_signature = device.sign(
            b"IAO-OPERATOR-DEVICE-LOGIN-V1\x00" + payload,
            ec.ECDSA(hashes.SHA256()),
        )
        def encoded(value: bytes) -> str:
            return base64.urlsafe_b64encode(value).decode().rstrip("=")
        status, result = self.call(
            "POST", "/v1/operator/login/complete", {},
            {
                "challenge": challenge["challenge"],
                "root_signature": encoded(root_signature),
                "device_signature": encoded(device_signature),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["authority"], "OPERATOR_AUTHENTICATED_READ_ONLY")
        self.assertEqual(result["scopes"], [])
        operator_subject = "operator:" + identity["identity_id"]
        self.assertTrue(device_authority.verify_registered_public_key(
            device_public, owner_subject=operator_subject,
        ))
        with self.assertRaisesRegex(DeviceAuthorityError, "DEVICE_KEY_NOT_ENROLLED_FOR_OWNER"):
            device_authority.verify_registered_public_key(
                device_public, owner_subject="existing-device-owner",
            )
        self.assertEqual(
            device_authority.challenge(
                enrolled_device["device_id"], owner_subject=operator_subject,
            )["expires_in"],
            60,
        )
        headers = {"authorization": "Bearer " + result["access_token"]}
        self.assertEqual(self.call("GET", "/v1/me", headers)[1]["scopes"], [])
        self.assertTrue(
            self.call("GET", "/v1/operator/session/status", headers)[1]["associated"]
        )
        replay = self.call(
            "POST", "/v1/operator/login/complete", {},
            {
                "challenge": challenge["challenge"],
                "root_signature": encoded(root_signature),
                "device_signature": encoded(device_signature),
            },
        )
        self.assertEqual((replay[0], replay[1]["error"]), (409, "OPERATOR_LOGIN_REPLAYED"))
        audit = json.dumps(self.svc.store._all_events())
        self.assertNotIn(result["access_token"], audit)
        self.assertNotIn(root_public, audit)
        self.assertNotIn(device_public, audit)


    def test_operator_bootstrap_endpoint_consumes_out_of_band_capability_once(self) -> None:
        code = "out-of-band-bootstrap-" + "q" * 48
        self.svc.store.close()
        with patch.dict(os.environ, {
            "IAO_OPERATOR_BOOTSTRAP_CODE": code,
            "IAO_OPERATOR_BOOTSTRAP_EXPIRES_AT": str(time.time() + 600),
        }):
            self.mk()
            self.assertNotIn("IAO_OPERATOR_BOOTSTRAP_CODE", os.environ)
        root = ec.generate_private_key(ec.SECP256R1())
        public = root.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        status, result = self.call(
            "POST", "/v1/operator/bootstrap", {},
            {"code": code, "root_public_key_pem": public},
        )
        self.assertEqual(status, 201)
        self.assertEqual(result["status"], "ROOT_REGISTERED")
        self.assertEqual(self.svc.operator_identity_authority.bootstrap_code, "")
        self.assertNotIn("identity_id", result)
        self.assertNotIn(public, json.dumps(result))
        repeated = self.call(
            "POST", "/v1/operator/bootstrap", {},
            {"code": code, "root_public_key_pem": public},
        )
        self.assertEqual(
            (repeated[0], repeated[1]["error"]),
            (503, "OPERATOR_BOOTSTRAP_DISABLED"),
        )
        audit = json.dumps(self.svc.store._all_events())
        self.assertNotIn(code, audit)
        self.assertNotIn(public, audit)

    def test_operator_bootstrap_is_disabled_without_out_of_band_configuration(self) -> None:
        status, result = self.call(
            "POST", "/v1/operator/bootstrap", {},
            {"code": "unconfigured-bootstrap-" + "x" * 40,
             "root_public_key_pem": "not-a-public-key"},
        )
        self.assertEqual((status, result["error"]), (503, "OPERATOR_BOOTSTRAP_DISABLED"))


    def test_root_signed_session_binding_api_is_scoped_and_read_only(self) -> None:
        bootstrap_code = "session-api-bootstrap-" + "z" * 40
        authority = OperatorIdentityAuthority(
            self.state / "api-operator-identity.sqlite3",
            bootstrap_code,
            bootstrap_expires_at=time.time() + 600,
            subject_digest_key=hashlib.sha256(b"api-session-test-key").digest(),
        )
        self.svc.operator_identity_authority = authority
        root = ec.generate_private_key(ec.SECP256R1())
        public = root.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        identity = authority.bootstrap(bootstrap_code, public)
        headers_a = self.tok("authenticated-session-A")
        headers_a_alt = self.tok("authenticated-session-A", scopes=[])
        headers_b = self.tok("authenticated-session-B")

        guest = self.call("POST", "/v1/public/session", {}, {})
        guest_headers = {"authorization": "Bearer " + guest[1]["access_token"]}
        self.assertEqual(
            self.call("POST", "/v1/operator/session/challenge", guest_headers, {})[0],
            403,
        )

        status, challenge = self.call(
            "POST", "/v1/operator/session/challenge", headers_a, {}
        )
        self.assertEqual(status, 200)
        self.assertNotIn(identity["identity_id"], json.dumps(challenge))
        payload = base64.urlsafe_b64decode(
            challenge["signing_payload"]
            + "=" * (-len(challenge["signing_payload"]) % 4)
        )
        signature = root.sign(
            ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256())
        )
        encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        body = {"challenge": challenge["challenge"], "signature": encoded}

        same_subject_other_token = self.call(
            "POST", "/v1/operator/session/bind", headers_a_alt, body
        )
        self.assertEqual(
            (same_subject_other_token[0], same_subject_other_token[1]["error"]),
            (403, "OPERATOR_SESSION_MISMATCH"),
        )
        wrong_session = self.call(
            "POST", "/v1/operator/session/bind", headers_b, body
        )
        self.assertEqual(
            (wrong_session[0], wrong_session[1]["error"]),
            (403, "OPERATOR_SESSION_MISMATCH"),
        )
        bound = self.call("POST", "/v1/operator/session/bind", headers_a, body)
        self.assertEqual(bound[0], 200)
        self.assertEqual(bound[1]["authority"], "IDENTITY_BOUND_READ_ONLY")
        self.assertNotIn("identity_id", bound[1])
        self.assertEqual(
            self.call("GET", "/v1/operator/session/status", headers_a)[1]["associated"],
            True,
        )
        self.assertEqual(
            self.call("GET", "/v1/operator/session/status", headers_b)[1]["associated"],
            False,
        )
        replay = self.call("POST", "/v1/operator/session/bind", headers_a, body)
        self.assertEqual((replay[0], replay[1]["error"]), (409, "SESSION_CHALLENGE_REPLAYED"))
        self.assertEqual(bound[1]["authority"], "IDENTITY_BOUND_READ_ONLY")

        audit = json.dumps(self.svc.store._all_events())
        self.assertNotIn(identity["identity_id"], audit)
        self.assertNotIn(challenge["challenge"], audit)
        self.assertNotIn(encoded, audit)


    def test_root_associated_session_binds_only_exact_enrolled_device_key(self) -> None:
        bootstrap = "root-device-bootstrap-" + "r" * 40
        identity = OperatorIdentityAuthority(
            self.state / "root-device-identity.sqlite3", bootstrap,
            bootstrap_expires_at=time.time() + 600,
            subject_digest_key=hashlib.sha256(b"root-device-session-key").digest(),
        )
        devices = DeviceAuthority(
            self.state / "root-device-authority.sqlite3",
            enrollment_code="device-enrollment-" + "d" * 40,
        )
        self.svc.operator_identity_authority = identity
        self.svc.device_authority = devices
        root = ec.generate_private_key(ec.SECP256R1())
        root_pem = root.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        identity_record = identity.bootstrap(bootstrap, root_pem)
        device = ec.generate_private_key(ec.SECP256R1())
        device_pem = device.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        devices.enroll(
            "device-enrollment-" + "d" * 40, device_pem,
            owner_subject="root-device-operator",
        )
        headers = self.tok("root-device-operator")
        status, challenge = self.call(
            "POST", "/v1/operator/session/challenge", headers, {},
        )
        self.assertEqual(status, 200)
        payload = base64.urlsafe_b64decode(
            challenge["signing_payload"]
            + "=" * (-len(challenge["signing_payload"]) % 4)
        )
        session_signature = root.sign(
            ROOT_SIGNATURE_DOMAIN + payload, ec.ECDSA(hashes.SHA256()),
        )
        encoded_session = base64.urlsafe_b64encode(session_signature).decode().rstrip("=")
        self.assertEqual(self.call(
            "POST", "/v1/operator/session/bind", headers,
            {"challenge": challenge["challenge"], "signature": encoded_session},
        )[0], 200)

        _, binding_payload = OperatorIdentityAuthority.device_binding_payload(
            device_pem, key_version=1,
        )
        binding_signature = root.sign(
            ROOT_SIGNATURE_DOMAIN + binding_payload, ec.ECDSA(hashes.SHA256()),
        )
        encoded_device = base64.urlsafe_b64encode(binding_signature).decode().rstrip("=")
        bound = self.call(
            "POST", "/v1/operator/device/bind", headers,
            {"public_key_pem": device_pem, "signature": encoded_device},
        )
        self.assertEqual(bound[0], 200)
        self.assertEqual(bound[1]["authority"], "PRIMARY_DEVICE_BOUND_READ_ONLY")
        self.assertEqual(bound[1]["key_version"], 1)
        self.assertTrue(identity.verify_primary_device(
            identity_record["identity_id"], device_pem,
        ))

        other = ec.generate_private_key(ec.SECP256R1())
        other_pem = other.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        rejected = self.call(
            "POST", "/v1/operator/device/bind", headers,
            {"public_key_pem": other_pem, "signature": encoded_device},
        )
        self.assertEqual((rejected[0], rejected[1]["error"]),
                         (403, "DEVICE_KEY_NOT_ENROLLED_FOR_OWNER"))
        self.assertEqual(bound[1]["authority"], "PRIMARY_DEVICE_BOUND_READ_ONLY")

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

    def test_idempotency_key_cannot_switch_execution_mode(self) -> None:
        headers = {**self.tok("alice"), "idempotency-key": "mode-bound"}
        payload = {
            "goal": "g",
            "capability": "knowledge.search",
            "input": {"query": "audit"},
        }
        self.assertEqual(
            self.call("POST", "/v1/tasks", headers, payload)[0], 200
        )
        queued_retry = {**payload, "execution_mode": "queued"}
        authority = self.svc.device_authority
        authority.enrollment_code = "unit-test-mode-switch-enrollment-secret"
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        enrolled = authority.enroll(authority.enrollment_code, public_pem, owner_subject="alice")
        challenge = authority.challenge(enrolled["device_id"], owner_subject="alice")
        raw_body = json.dumps(queued_retry).encode()
        timestamp = int(time.time())
        digest = hashlib.sha256(raw_body).hexdigest()
        signed = "\n".join([
            "POST", "/v1/tasks", str(timestamp), challenge["nonce"], digest,
        ]).encode()
        signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        proof = {
            "device_id": enrolled["device_id"],
            "nonce": challenge["nonce"],
            "timestamp": timestamp,
            "request_digest": digest,
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }
        queued_headers = {
            **headers,
            "x-iao-device-proof": json.dumps(proof, separators=(",", ":")),
        }
        status, response = self.call(
            "POST", "/v1/tasks", queued_headers, queued_retry
        )
        self.assertEqual(
            (status, response["error"]),
            (409, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"),
        )

    def test_idempotency_key_rejects_different_payload(self) -> None:
        headers = {**self.tok("alice"), "idempotency-key": "same-key"}
        first = self.call("POST", "/v1/tasks", headers, {
            "goal": "first goal", "capability": "knowledge.search",
            "input": {"query": "audit"},
        })
        self.assertEqual(first[0], 200)
        changed = self.call("POST", "/v1/tasks", headers, {
            "goal": "different goal", "capability": "knowledge.search",
            "input": {"query": "audit"},
        })
        self.assertEqual(
            (changed[0], changed[1]["error"]),
            (409, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"),
        )

    def test_idempotent_replay_is_allowed_after_daily_quota_is_reached(self) -> None:
        self.svc.store.close()
        self.mk(daily_task_quota=1)
        headers = {**self.tok("alice"), "idempotency-key": "stable-task"}
        payload = {
            "goal": "g",
            "capability": "knowledge.search",
            "input": {"query": "audit chain"},
        }
        first_status, first = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual(first_status, 200)
        second_status, second = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual(second_status, 200)
        self.assertEqual(second["task_id"], first["task_id"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(self.svc.store.count_tasks_since("alice", "0000"), 1)
        self.assertTrue(any(
            event["event_type"] == "TASK_IDEMPOTENT_REPLAY"
            for event in self.svc.store._all_events()
        ))

    def test_invalid_json_and_oversize(self) -> None:
        self.assertEqual(self.svc.handle("POST", "/v1/tasks", self.tok("alice"), b"{bad")[0], 400)
        self.assertEqual(self.svc.handle("POST", "/v1/tasks", self.tok("alice"), b"x" * 70000)[0], 413)


class QueuedTaskApiTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.device_private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = self.device_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.svc.device_authority.enrollment_code = (
            "unit-test-device-enrollment-secret-long-enough"
        )
        enrolled = self.svc.device_authority.enroll(
            self.svc.device_authority.enrollment_code, public_pem,
            owner_subject="queued-user",
        )
        self.device_id = enrolled["device_id"]
        bootstrap = "queued-root-bootstrap-" + "r" * 40
        identity = OperatorIdentityAuthority(
            self.state / "queued-root-identity.sqlite3", bootstrap,
            bootstrap_expires_at=time.time() + 600,
            subject_digest_key=hashlib.sha256(b"queued-root-session-test-key").digest(),
        )
        self.svc.operator_identity_authority = identity
        self.root_private_key = ec.generate_private_key(ec.SECP256R1())
        root_pem = self.root_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        identity.bootstrap(bootstrap, root_pem)
        self.operator_token = issue_token(KEY, "queued-user", ["knowledge.search", "test.write"])
        session_challenge = identity.create_session_challenge("queued-user", self.operator_token)
        session_payload = base64.urlsafe_b64decode(
            session_challenge["signing_payload"]
            + "=" * (-len(session_challenge["signing_payload"]) % 4)
        )
        session_signature = self.root_private_key.sign(
            ROOT_SIGNATURE_DOMAIN + session_payload, ec.ECDSA(hashes.SHA256())
        )
        identity.bind_authenticated_session(
            session_challenge["challenge"], "queued-user", self.operator_token,
            session_signature,
        )
        _, device_payload = OperatorIdentityAuthority.device_binding_payload(
            public_pem, key_version=1,
        )
        device_signature = self.root_private_key.sign(
            ROOT_SIGNATURE_DOMAIN + device_payload, ec.ECDSA(hashes.SHA256())
        )
        identity.bind_primary_device_for_session(
            "queued-user", self.operator_token, public_pem, device_signature,
        )

    def queued_headers(self, payload: dict) -> dict[str, str]:
        body = json.dumps(payload).encode()
        challenge = self.svc.device_authority.challenge(self.device_id, owner_subject="queued-user")
        timestamp = int(time.time())
        digest = hashlib.sha256(body).hexdigest()
        signed = "\n".join(
            ["POST", "/v1/tasks", str(timestamp), challenge["nonce"], digest]
        ).encode()
        signature = self.device_private_key.sign(
            signed, ec.ECDSA(hashes.SHA256())
        )
        proof = {
            "device_id": self.device_id,
            "nonce": challenge["nonce"],
            "timestamp": timestamp,
            "request_digest": digest,
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }
        return {
            "authorization": "Bearer " + self.operator_token,
            "x-iao-device-proof": json.dumps(proof, separators=(",", ":")),
        }

    def test_queued_task_returns_202_and_worker_completes_it(self) -> None:
        payload = {
            "goal": "search the local knowledge corpus",
            "capability": "knowledge.search",
            "input": {"query": "audit hash chain"},
            "execution_mode": "queued",
        }
        status, accepted = self.call(
            "POST", "/v1/tasks", self.queued_headers(payload), payload
        )
        self.assertEqual(
            status, 202,
            msg=str([
                event for event in self.svc.store._all_events()
                if event["event_type"] == "API_INTERNAL_ERROR"
            ][-1:]),
        )
        self.assertEqual(accepted["state"], "QUEUED")
        self.assertTrue(accepted["status_url"].endswith(accepted["task_id"]))
        queued = self.svc.store.get_task(accepted["task_id"], "queued-user")
        intent = json.loads(queued["intent_json"])
        self.assertEqual(intent["input"], {"query": "audit hash chain"})
        self.assertIn("knowledge.search", intent["authorized_scopes"])

        worker = TaskWorker(
            self.svc.store, self.svc.registry,
            worker_id="test-worker", lease_seconds=30,
            operator_identity_authority=self.svc.operator_identity_authority,
        )
        self.assertTrue(worker.run_once())
        completed = self.svc.store.get_task(accepted["task_id"], "queued-user")
        self.assertEqual(completed["state"], "SUCCEEDED")
        self.assertIsNone(completed["lease_owner"])
        self.assertEqual(
            [item["status"] for item in self.svc.store.tool_executions(accepted["task_id"])],
            ["SUCCEEDED"],
        )
        self.assertFalse(worker.run_once())

    def test_worker_rechecks_primary_device_binding_before_execution(self) -> None:
        payload = {
            "goal": "search the local knowledge corpus",
            "capability": "knowledge.search",
            "input": {"query": "audit hash chain"},
            "execution_mode": "queued",
        }
        status, accepted = self.call(
            "POST", "/v1/tasks", self.queued_headers(payload), payload
        )
        self.assertEqual(status, 202)
        task = self.svc.store.get_task(accepted["task_id"], "queued-user")
        intent = json.loads(task["intent_json"])
        self.assertNotIn(self.operator_token, json.dumps(intent))
        self.assertRegex(intent["operator_session_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(intent["operator_device_id"], self.device_id)

        # Simulate revocation after API acceptance but before the worker claims it.
        with self.svc.operator_identity_authority._database() as db:
            db.execute("DELETE FROM primary_device_bindings")
        worker = TaskWorker(
            self.svc.store, self.svc.registry,
            worker_id="revocation-check-worker", lease_seconds=30,
            operator_identity_authority=self.svc.operator_identity_authority,
        )
        self.assertTrue(worker.run_once())
        failed = self.svc.store.get_task(accepted["task_id"], "queued-user")
        self.assertEqual(failed["state"], "FAILED")
        self.assertEqual(
            json.loads(failed["result_json"])["error"],
            "WORKER_OPERATOR_AUTHORITY_REVOKED",
        )
        self.assertEqual(self.svc.store.tool_executions(accepted["task_id"]), [])

    def test_worker_fails_closed_without_operator_identity_authority(self) -> None:
        payload = {
            "goal": "search the local knowledge corpus",
            "capability": "knowledge.search",
            "input": {"query": "audit hash chain"},
            "execution_mode": "queued",
        }
        status, accepted = self.call(
            "POST", "/v1/tasks", self.queued_headers(payload), payload
        )
        self.assertEqual(status, 202)
        worker = TaskWorker(
            self.svc.store, self.svc.registry,
            worker_id="unbound-worker", lease_seconds=30,
        )
        self.assertTrue(worker.run_once())
        failed = self.svc.store.get_task(accepted["task_id"], "queued-user")
        self.assertEqual(failed["state"], "FAILED")
        self.assertEqual(
            json.loads(failed["result_json"])["error"],
            "WORKER_OPERATOR_AUTHORITY_UNAVAILABLE",
        )
        self.assertEqual(self.svc.store.tool_executions(accepted["task_id"]), [])

    def test_queued_mode_rejects_non_read_only_capability(self) -> None:
        self.svc.registry.register(
            ToolSpec(
                "test.write", "1", "test.write", "WRITE",
                1.0, lambda value: value, lambda value: value,
                lambda output: "PASS",
            )
        )
        payload = {
            "goal": "attempt queued write",
            "capability": "test.write",
            "input": {"value": "x"},
            "execution_mode": "queued",
        }
        headers = self.queued_headers(payload)
        status, response = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual(status, 403)
        self.assertEqual(response["state"], "DENIED")
        self.assertEqual(
            response["reason"], "QUEUED_TASK_REQUIRES_READ_ONLY_CAPABILITY"
        )
        self.assertEqual(
            self.svc.store.get_task(response["task_id"], "queued-user")["state"],
            "DENIED",
        )

 
    def test_device_enrollment_and_status_api_are_gated_and_read_only(self) -> None:
        code = "one-time-api-enrollment-secret-long-enough"
        self.svc.device_authority = DeviceAuthority(
            self.state / "api-device-authority.sqlite3",
            enrollment_code=code,
        )
        with patch.dict(os.environ, {"IAO_DEVICE_ENROLLMENT_ENABLED": "0"}):
            denied = self.call(
                "POST", "/v1/device/enroll", {},
                {"code": code, "public_key_pem": "invalid"},
            )
        self.assertEqual((denied[0], denied[1]["error"]), (403, "DEVICE_ENROLLMENT_DISABLED"))

        with patch.dict(os.environ, {"IAO_DEVICE_ENROLLMENT_ENABLED": "1"}):
            unauthenticated = self.call(
                "POST", "/v1/device/enroll", {},
                {"code": code, "public_key_pem": "invalid"},
            )
        self.assertEqual(
            (unauthenticated[0], unauthenticated[1]["error"]),
            (401, "AUTHENTICATION_REQUIRED"),
        )

        guest_status, guest_session = self.call(
            "POST", "/v1/public/session", {}, {}
        )
        self.assertEqual(guest_status, 201)
        guest_headers = {"authorization": "Bearer " + guest_session["access_token"]}
        with patch.dict(os.environ, {"IAO_DEVICE_ENROLLMENT_ENABLED": "1"}):
            guest_enroll = self.call(
                "POST", "/v1/device/enroll", guest_headers,
                {"code": code, "public_key_pem": "invalid"},
            )
        self.assertEqual(
            (guest_enroll[0], guest_enroll[1]["error"]),
            (403, "OPERATOR_SESSION_REQUIRED"),
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with patch.dict(os.environ, {"IAO_DEVICE_ENROLLMENT_ENABLED": "1"}):
            status, enrolled = self.call(
                "POST", "/v1/device/enroll", self.tok("device-owner"),
                {"code": code, "public_key_pem": public_pem},
            )
        self.assertEqual(status, 201)
        self.assertEqual(enrolled["algorithm"], "ECDSA-P256-SHA256")
        self.assertNotIn("device_id", enrolled)
        device_id = hashlib.sha256(
            private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()

        guest_challenge = self.call(
            "POST", "/v1/device/challenge", guest_headers,
            {"device_id": device_id},
        )
        self.assertEqual(
            (guest_challenge[0], guest_challenge[1]["error"]),
            (403, "OPERATOR_SESSION_REQUIRED"),
        )
        status, challenge = self.call(
            "POST", "/v1/device/challenge", self.tok("device-owner"),
            {"device_id": device_id},
        )
        self.assertEqual(status, 200)
        wrong_owner_challenge = self.call(
            "POST", "/v1/device/challenge", self.tok("different-owner"),
            {"device_id": device_id},
        )
        self.assertEqual(
            (wrong_owner_challenge[0], wrong_owner_challenge[1]["error"]),
            (403, "DEVICE_OWNER_MISMATCH"),
        )
        timestamp = int(time.time())
        canonical = json.dumps(
            {"action": "status"}, separators=(",", ":"), ensure_ascii=False
        )
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        signed = "\n".join([
            "POST", "/v1/device/command", str(timestamp),
            challenge["nonce"], digest,
        ]).encode()
        signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        proof = {
            "device_id": device_id,
            "nonce": challenge["nonce"],
            "timestamp": timestamp,
            "action": "status",
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }
        unauthenticated_status, unauthenticated_result = self.call(
            "POST", "/v1/device/command", {}, proof
        )
        self.assertEqual(
            (unauthenticated_status, unauthenticated_result["error"]),
            (401, "AUTHENTICATION_REQUIRED"),
        )
        wrong_owner_status = self.call(
            "POST", "/v1/device/command", self.tok("different-owner"), proof
        )
        self.assertEqual(
            (wrong_owner_status[0], wrong_owner_status[1]["error"]),
            (403, "DEVICE_OWNER_MISMATCH"),
        )
        status, result = self.call(
            "POST", "/v1/device/command", self.tok("device-owner"), proof
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["authority"], "READ_ONLY_DEVICE_VERIFIED")
        self.assertNotIn("device_id", result)
        audit = json.dumps(self.svc.store._all_events())
        self.assertNotIn(code, audit)
        self.assertNotIn(device_id, audit)
        enrollment_events = [
            event for event in self.svc.store._all_events()
            if event["event_type"] == "DEVICE_ENROLLED"
        ]
        self.assertEqual(len(enrollment_events), 1)
        self.assertEqual(enrollment_events[0]["details"]["actor"], "device-owner")
        self.assertEqual(enrollment_events[0]["subject"], "primary_device")

    def test_queued_submission_requires_primary_device_proof(self) -> None:
        payload = {
            "goal": "search",
            "capability": "knowledge.search",
            "input": {"query": "audit"},
            "execution_mode": "queued",
        }
        status, response = self.call(
            "POST", "/v1/tasks", self.tok("queued-user"), payload
        )
        self.assertEqual((status, response["error"]), (401, "DEVICE_PROOF_REQUIRED"))
        self.assertEqual(self.svc.store.count_tasks_since("queued-user", "0000"), 0)

    def test_device_challenge_endpoint_and_proof_replay_rejected(self) -> None:
        status, challenge = self.call(
            "POST", "/v1/device/challenge", self.tok("queued-user"),
            {"device_id": self.device_id},
        )
        self.assertEqual(status, 200)
        self.assertEqual(challenge["expires_in"], 60)
        payload = {
            "goal": "search",
            "capability": "knowledge.search",
            "input": {"query": "audit"},
            "execution_mode": "queued",
        }
        headers = self.queued_headers(payload)
        first = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual(first[0], 202)
        replay = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual((replay[0], replay[1]["error"]), (401, "CHALLENGE_EXPIRED_OR_REPLAYED"))

    def test_queued_task_rejects_same_subject_with_different_bearer_session(self) -> None:
        payload = {
            "goal": "search",
            "capability": "knowledge.search",
            "input": {"query": "audit"},
            "execution_mode": "queued",
        }
        headers = self.queued_headers(payload)
        headers["authorization"] = self.tok("queued-user")["authorization"]
        status, response = self.call("POST", "/v1/tasks", headers, payload)
        self.assertEqual((status, response["error"]), (403, "PRIMARY_DEVICE_NOT_AUTHORIZED"))
        self.assertEqual(self.svc.store.count_tasks_since("queued-user", "0000"), 0)

    def test_queued_proof_cannot_be_reused_for_modified_body(self) -> None:
        payload = {
            "goal": "search",
            "capability": "knowledge.search",
            "input": {"query": "audit"},
            "execution_mode": "queued",
        }
        headers = self.queued_headers(payload)
        changed = {**payload, "goal": "different request"}
        status, response = self.call("POST", "/v1/tasks", headers, changed)
        self.assertEqual((status, response["error"]), (400, "INVALID_REQUEST"))
        self.assertEqual(self.svc.store.count_tasks_since("queued-user", "0000"), 0)

    def test_worker_independently_rejects_persisted_write_task(self) -> None:
        self.svc.registry.register(
            ToolSpec(
                "test.write", "1", "test.write", "WRITE",
                1.0, lambda value: value, lambda value: value,
                lambda output: "PASS",
            )
        )
        intent = {
            "contract_version": "1.0",
            "goal": "must not execute",
            "allowed_capabilities": ["test.write"],
            "authorized_scopes": ["test.write"],
            "input": {"value": "x"},
            "policy_version": POLICY_VERSION,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
            "budget": {"timeout_seconds": 5},
        }
        task, created = self.svc.store.create_task(
            "persisted-write-task", "queued-user", intent, None
        )
        self.assertTrue(created)
        self.svc.store.set_task_state(task["id"], "AUTHORIZED")
        self.assertTrue(self.svc.store.queue_task(task["id"]))

        worker = TaskWorker(
            self.svc.store, self.svc.registry,
            worker_id="defensive-worker", lease_seconds=30,
        )
        self.assertTrue(worker.run_once())
        result = self.svc.store.get_task(task["id"], "queued-user")
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(
            json.loads(result["result_json"])["error"],
            "WORKER_READ_ONLY_ONLY",
        )
        self.assertEqual(self.svc.store.tool_executions(task["id"]), [])

    def test_queued_mode_rejects_non_string_mode(self) -> None:
        status, payload = self.call(
            "POST", "/v1/tasks", self.tok("queued-user"),
            {
                "goal": "x",
                "capability": "knowledge.search",
                "input": {"query": "audit"},
                "execution_mode": [],
            },
        )
        self.assertEqual((status, payload["error"]), (400, "INVALID_EXECUTION_MODE"))


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
        changed = c.execute(
            "UPDATE audit_event_v2 SET details=replace(details,'alice','mallory') WHERE id=3"
        ).rowcount
        self.assertEqual(
            changed, 1,
            "AUD01 debe modificar exactamente un evento de la cadena activa"
        )
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

    def test_running_task_is_failed_closed_after_service_restart(self) -> None:
        intent = {
            "contract_version": "1.0",
            "goal": "recover interrupted work",
            "request_digest": "sha256:test",
        }
        task, created = self.svc.store.create_task(
            "interrupted-task-id", "alice", intent, None
        )
        self.assertTrue(created)
        self.svc.store.set_task_state(task["id"], "RUNNING")
        self.svc.store.close()

        self.mk()

        recovered = self.svc.store.get_task(task["id"], "alice")
        self.assertEqual(recovered["state"], "FAILED")
        self.assertEqual(
            json.loads(recovered["result_json"]),
            {"decision": "INTERRUPTED", "error": "PROCESS_INTERRUPTED"},
        )
        events = self.svc.store._all_events()
        self.assertTrue(any(
            event["event_type"] == "TASK_INTERRUPTED_ON_RESTART"
            and event["subject"] == task["id"]
            and event["details"].get("actor") == "alice"
            and event["details"].get("decision") == "FAIL_CLOSED"
            and event["details"].get("reason") == "PROCESS_INTERRUPTED"
            for event in events
        ))

    def test_persistence_survives_restart(self) -> None:
        tid = self.task("alice", "knowledge.search")[1]["task_id"]
        self.svc.store.close()
        self.mk()
        self.assertEqual(self.call("GET", f"/v1/tasks/{tid}", self.tok("alice"))[1]["state"], "SUCCEEDED")
        self.assertTrue(self.svc.store.verify_audit()[0])
