"""End-to-end release rehearsal on the local sandbox (staging = local runtime): build -> gate -> promote,
broken release -> gate fails -> automatic rollback -> evidence bundle. Run: python3 tools/release_demo.py"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from omega.release import ReleaseController, evaluate_promotion, smoke_runtime, tree_digest  # noqa: E402

work = Path(tempfile.mkdtemp(prefix="omega-rel-"))
rc = ReleaseController(work, os.urandom(32))
out: dict = {"steps": []}  # type: ignore[type-arg]
step = lambda name, **d: (out["steps"].append({"step": name, **d}), print(name, d))  # noqa: E731

m1 = rc.build(ROOT, "1.0.0")
step("build 1.0.0", digest=m1["digest"][:16])
step("deploy 1.0.0", **rc.deploy_with_gate("1.0.0", smoke_runtime))
m2 = rc.build(ROOT, "1.1.0")
(rc.release_dir("1.1.0") / "omega" / "service.py").write_text("raise RuntimeError('defective release')\n")
d = tree_digest(rc.release_dir("1.1.0"))
(rc.release_dir("1.1.0") / "manifest.json").write_text(json.dumps({"version": "1.1.0", "digest": d, "signature": rc._sig("1.1.0", d)}))
step("deploy defective 1.1.0 (authentic but broken)", **rc.deploy_with_gate("1.1.0", smoke_runtime))
step("current after gate", current=rc.current(), still_serving=smoke_runtime(rc.current_path().resolve()))
step("promotion rule w/ UNKNOWN evidence", decision=evaluate_promotion(critical_test="PASS", required_evidence="UNKNOWN", rollback_test="PASS", approval_required=False, approval_for_exact_diff="PASS"))
step("release log chain", ok=rc.verify_log()[0])
b = rc.make_evidence_bundle(ROOT / "artifacts", work / "evidence-bundle.json")
step("evidence bundle verifies", result=rc.verify_evidence_bundle(ROOT / "artifacts", work / "evidence-bundle.json"))
shutil.copy(work / "evidence-bundle.json", ROOT / "artifacts" / "release-evidence-bundle.json")
shutil.copy(work / "release-audit.jsonl", ROOT / "artifacts" / "release-audit.jsonl")
ok = out["steps"][1]["result"] == "PROMOTED" and out["steps"][2]["result"] == "ROLLED_BACK" and out["steps"][3]["current"] == "1.0.0" and out["steps"][3]["still_serving"]
(ROOT / "artifacts" / "release-rehearsal.json").write_text(json.dumps({**out, "verdict": "PASS" if ok else "FAIL", "scope": "local sandbox staging; no external infrastructure"}, indent=2))
print("VERDICT", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
