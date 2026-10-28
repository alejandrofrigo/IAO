import json
import os
import tempfile
import unittest
from pathlib import Path

from omega.release import ReleaseController, ReleaseError, evaluate_promotion, smoke_runtime

SRC = Path(__file__).resolve().parent.parent
KEY = b"release-test-key"


def promo(**kw: object) -> str:
    base = dict(critical_test="PASS", required_evidence="PASS", rollback_test="PASS", approval_required=False, approval_for_exact_diff="PASS")
    base.update(kw)
    return evaluate_promotion(**base)  # type: ignore[arg-type]


class PromotionRuleTests(unittest.TestCase):
    def test_only_all_pass_is_eligible(self) -> None:
        self.assertEqual(promo(), "ELIGIBLE_FOR_STAGING_OR_NEXT_GATE")

    def test_every_blocker_blocks(self) -> None:
        self.assertEqual(promo(critical_test="FAIL"), "BLOCKED")
        self.assertEqual(promo(required_evidence="MISSING"), "BLOCKED")
        self.assertEqual(promo(required_evidence="UNKNOWN"), "BLOCKED")
        for rb in ("FAIL", "UNKNOWN", "MISSING", ""):
            self.assertEqual(promo(rollback_test=rb), "BLOCKED")
        self.assertEqual(promo(approval_required=True, approval_for_exact_diff="UNKNOWN"), "BLOCKED")
        self.assertEqual(promo(approval_required=True, approval_for_exact_diff="PASS"), "ELIGIBLE_FOR_STAGING_OR_NEXT_GATE")


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.rc = ReleaseController(Path(self.tmp.name), KEY)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def bad_build(self, version: str) -> None:  # a release whose runtime cannot start
        self.rc.build(SRC, version)
        f = self.rc.release_dir(version) / "omega" / "service.py"
        f.write_text("this is not python (\n")
        # re-sign so the artifact is *authentic but broken* -> only the health gate can catch it
        from omega.release import tree_digest
        d = tree_digest(self.rc.release_dir(version))
        (self.rc.release_dir(version) / "manifest.json").write_text(json.dumps({"version": version, "digest": d, "signature": self.rc._sig(version, d)}))

    def test_build_is_immutable_and_verifies(self) -> None:
        self.rc.build(SRC, "v1")
        self.assertTrue(self.rc.verify("v1"))
        with self.assertRaises(ReleaseError):
            self.rc.build(SRC, "v1")

    def test_tampered_artifact_refused(self) -> None:  # supply-chain: modified after signing
        self.rc.build(SRC, "v1")
        (self.rc.release_dir("v1") / "omega" / "policy.py").write_text("def authorize(*a, **k): return True\n")
        self.assertFalse(self.rc.verify("v1"))
        with self.assertRaises(ReleaseError):
            self.rc.activate("v1")
        self.assertIsNone(self.rc.current())

    def test_wrong_key_cannot_forge_release(self) -> None:
        self.rc.build(SRC, "v1")
        self.assertFalse(ReleaseController(Path(self.tmp.name), b"other-key").verify("v1"))

    def test_REL01_good_deploys_then_bad_release_auto_rolls_back(self) -> None:
        self.rc.build(SRC, "v1")
        self.rc.build(SRC, "v2")
        self.bad_build("v3")
        self.assertEqual(self.rc.deploy_with_gate("v1", smoke_runtime)["result"], "PROMOTED")
        self.assertEqual(self.rc.deploy_with_gate("v2", smoke_runtime)["result"], "PROMOTED")
        r = self.rc.deploy_with_gate("v3", smoke_runtime)
        self.assertEqual((r["result"], r["to"]), ("ROLLED_BACK", "v2"))
        self.assertEqual(self.rc.current(), "v2")
        self.assertEqual(os.path.realpath(self.rc.current_path()), str(self.rc.release_dir("v2").resolve()))
        self.assertTrue(smoke_runtime(self.rc.current_path().resolve()))  # previous version really serves again
        self.assertEqual(self.rc.verify_log(), (True, None))

    def test_first_release_failing_gate_leaves_nothing_active(self) -> None:
        self.bad_build("v1")
        self.assertEqual(self.rc.deploy_with_gate("v1", smoke_runtime), {"version": "v1", "result": "ROLLED_BACK", "to": None})
        self.assertIsNone(self.rc.current())

    def test_NEG09_rollback_failure_goes_restricted_and_blocks_further_deploys(self) -> None:
        self.rc.build(SRC, "v1")
        self.bad_build("v2")
        self.rc.deploy_with_gate("v1", lambda p: True)
        (self.rc.release_dir("v1") / "omega" / "auth.py").write_text("# corrupted after promotion\n")  # previous version no longer verifiable
        r = self.rc.deploy_with_gate("v2", smoke_runtime)
        self.assertEqual((r["result"], r["reason"]), ("RESTRICTED", "ROLLBACK_FAILED"))
        self.assertEqual(self.rc.mode(), "RESTRICTED")
        self.rc.build(SRC, "v3")
        self.assertEqual(self.rc.deploy_with_gate("v3", lambda p: True)["result"], "BLOCKED")  # no promotion while RESTRICTED

    def test_release_log_tamper_detected(self) -> None:
        self.rc.build(SRC, "v1")
        self.rc.deploy_with_gate("v1", lambda p: True)
        self.assertTrue(self.rc.verify_log()[0])
        lines = self.rc.log_file.read_text().splitlines()
        e = json.loads(lines[0])
        e["subject"] = "v9"
        lines[0] = json.dumps(e, sort_keys=True)
        self.rc.log_file.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.rc.verify_log()[0])

    def test_NEG10_evidence_bundle_detects_alteration_and_deletion(self) -> None:
        art = Path(self.tmp.name) / "art"
        art.mkdir()
        (art / "a.txt").write_text("result: PASS")
        (art / "b.txt").write_text("x")
        out = Path(self.tmp.name) / "bundle.json"
        self.rc.make_evidence_bundle(art, out)
        self.assertEqual(self.rc.verify_evidence_bundle(art, out), (True, "OK"))
        (art / "a.txt").write_text("result: FAIL->PASS")
        self.assertEqual(self.rc.verify_evidence_bundle(art, out), (False, "ALTERED:a.txt"))
        (art / "a.txt").write_text("result: PASS")
        (art / "b.txt").unlink()
        self.assertEqual(self.rc.verify_evidence_bundle(art, out), (False, "MISSING:b.txt"))
        (art / "b.txt").write_text("x")
        b = json.loads(out.read_text())
        b["files"]["a.txt"] = "0" * 64
        out.write_text(json.dumps(b))
        self.assertEqual(self.rc.verify_evidence_bundle(art, out)[1], "BUNDLE_SIGNATURE_INVALID")


if __name__ == "__main__":
    unittest.main()
