"""F4 release controller: signed immutable artifacts, deterministic promotion rule (Annex O.10),
health-gated deploy with automatic rollback, hash-chained release log, tamper-evident evidence bundle.
Nothing here consults a model."""
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from omega.audit import GENESIS_HASH, make_event, verify_chain

INCLUDE = ("apps", "omega", "docs/corpus")


class ReleaseError(Exception):
    pass


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file() and "__pycache__" not in x.parts and x.name != "manifest.json"):
        h.update(str(p.relative_to(root)).encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def evaluate_promotion(*, critical_test: str, required_evidence: str, rollback_test: str,
                       approval_required: bool, approval_for_exact_diff: str) -> str:
    """Annex O.10 verbatim: anything but explicit PASS blocks. UNKNOWN/MISSING never promote."""
    if critical_test == "FAIL":
        return "BLOCKED"
    if required_evidence in ("MISSING", "UNKNOWN"):
        return "BLOCKED"
    if rollback_test != "PASS":
        return "BLOCKED"
    if approval_required and approval_for_exact_diff != "PASS":
        return "BLOCKED"
    return "ELIGIBLE_FOR_STAGING_OR_NEXT_GATE"


class ReleaseController:
    def __init__(self, root: Path, key: bytes) -> None:
        self.root, self.key = Path(root), key
        (self.root / "releases").mkdir(parents=True, exist_ok=True)
        self.state_file = self.root / "state.json"
        self.log_file = self.root / "release-audit.jsonl"

    # ---- signing / integrity ----
    def _sig(self, version: str, digest: str) -> str:
        return hmac.new(self.key, f"{version}|{digest}".encode(), hashlib.sha256).hexdigest()

    def release_dir(self, version: str) -> Path:
        return self.root / "releases" / version

    def build(self, src: Path, version: str) -> dict[str, Any]:
        dest = self.release_dir(version)
        if dest.exists():
            raise ReleaseError("VERSION_EXISTS")  # releases are immutable
        for rel in INCLUDE:
            shutil.copytree(Path(src) / rel, dest / rel, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        d = tree_digest(dest)
        m = {"version": version, "digest": d, "signature": self._sig(version, d)}
        (dest / "manifest.json").write_text(json.dumps(m, sort_keys=True))
        self._log("BUILD", version, digest=d)
        return m

    def verify(self, version: str) -> bool:
        try:
            d = self.release_dir(version)
            m = json.loads((d / "manifest.json").read_text())
            return (m["version"] == version and hmac.compare_digest(m["signature"], self._sig(version, tree_digest(d)))
                    and m["digest"] == tree_digest(d))
        except (OSError, ValueError, KeyError):
            return False

    # ---- state / pointer ----
    def _state(self) -> dict[str, Any]:
        return json.loads(self.state_file.read_text()) if self.state_file.exists() else {"history": [], "mode": "NORMAL"}

    def _save(self, st: dict[str, Any]) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(st))
        os.replace(tmp, self.state_file)

    def current(self) -> str | None:
        h = self._state()["history"]
        return h[-1] if h else None

    def mode(self) -> str:
        return str(self._state()["mode"])

    def current_path(self) -> Path:
        return self.root / "current"

    def activate(self, version: str) -> None:
        if not self.verify(version):
            self._log("ACTIVATE_REFUSED", version, reason="SIGNATURE_OR_DIGEST_INVALID")
            raise ReleaseError("ARTIFACT_INTEGRITY_FAILED")
        tmp = self.root / "current.tmp"
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(self.release_dir(version), tmp)
        os.replace(tmp, self.current_path())  # atomic pointer swap
        st = self._state()
        st["history"].append(version)
        self._save(st)
        self._log("ACTIVATE", version)

    def rollback(self) -> str:
        st = self._state()
        bad = st["history"].pop() if st["history"] else None
        while st["history"]:
            prev = st["history"].pop()  # activate() re-appends
            if self.verify(prev):
                self._save(st)
                self.activate(prev)
                self._log("ROLLBACK", prev, from_version=bad)
                return prev
        st["mode"] = "RESTRICTED"
        self._save(st)
        self._log("ROLLBACK_FAILED", bad or "none", mode="RESTRICTED")
        raise ReleaseError("NO_VERIFIED_PREVIOUS_VERSION")

    def deploy_with_gate(self, version: str, smoke: Callable[[Path], bool]) -> dict[str, Any]:
        """Activate, run health gate against the ACTIVE release, auto-rollback on failure."""
        if self.mode() != "NORMAL":
            return {"version": version, "result": "BLOCKED", "reason": "MODE_" + self.mode()}
        had_prev = self.current() is not None
        try:
            self.activate(version)
        except ReleaseError as e:
            return {"version": version, "result": "BLOCKED", "reason": str(e)}
        try:
            ok = bool(smoke(self.current_path().resolve()))
        except Exception:
            ok = False
        if ok:
            self._log("PROMOTED", version)
            return {"version": version, "result": "PROMOTED"}
        self._log("GATE_FAILED", version)
        if not had_prev:
            st = self._state(); st["history"].pop(); self._save(st)
            self.current_path().unlink(missing_ok=True)
            return {"version": version, "result": "ROLLED_BACK", "to": None}
        try:
            return {"version": version, "result": "ROLLED_BACK", "to": self.rollback()}
        except ReleaseError:
            return {"version": version, "result": "RESTRICTED", "reason": "ROLLBACK_FAILED"}

    # ---- hash-chained release log ----
    def _log(self, event: str, version: str, **d: Any) -> None:
        prev = GENESIS_HASH
        if self.log_file.exists():
            lines = self.log_file.read_text().splitlines()
            if lines:
                prev = json.loads(lines[-1])["event_hash"]
        ev = make_event(event, version, d, prev, self.key)
        with self.log_file.open("a") as f:
            f.write(json.dumps(ev, sort_keys=True) + "\n")

    def verify_log(self) -> tuple[bool, int | None]:
        evs = [json.loads(line) for line in self.log_file.read_text().splitlines()] if self.log_file.exists() else []
        return verify_chain(evs, self.key)

    # ---- evidence bundle ----
    def make_evidence_bundle(self, artifacts: Path, out: Path) -> dict[str, Any]:
        files = {str(p.relative_to(artifacts)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(artifacts.rglob("*")) if p.is_file() and p.resolve() != Path(out).resolve()}
        body = {"files": files, "release": self.current(), "log_head": self._head()}
        b = {**body, "signature": hmac.new(self.key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()}
        Path(out).write_text(json.dumps(b, indent=2, sort_keys=True))
        return b

    def _head(self) -> str:
        if not self.log_file.exists():
            return GENESIS_HASH
        lines = self.log_file.read_text().splitlines()
        return json.loads(lines[-1])["event_hash"] if lines else GENESIS_HASH

    def verify_evidence_bundle(self, artifacts: Path, bundle: Path) -> tuple[bool, str]:
        try:
            b = json.loads(Path(bundle).read_text())
            body = {k: v for k, v in b.items() if k != "signature"}
            if not hmac.compare_digest(b["signature"], hmac.new(self.key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()):
                return False, "BUNDLE_SIGNATURE_INVALID"
            for rel, h in b["files"].items():
                p = Path(artifacts) / rel
                if not p.is_file():
                    return False, f"MISSING:{rel}"
                if hashlib.sha256(p.read_bytes()).hexdigest() != h:
                    return False, f"ALTERED:{rel}"
            return True, "OK"
        except (OSError, ValueError, KeyError):
            return False, "BUNDLE_UNREADABLE"


def smoke_runtime(release: Path, timeout: float = 15.0) -> bool:
    """Health gate: start THE RELEASE's runtime on a free port, require ready + a verified task."""
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    from omega.auth import issue_token
    key = os.urandom(16).hex()
    state = tempfile.mkdtemp(prefix="smoke-")
    env = {**os.environ, "OMEGA_DEV_TOKEN_KEY": key, "OMEGA_STATE_DIR": state, "OMEGA_CORPUS_DIR": str(release / "docs/corpus"),
           "PORT": str(port), "HOST": "127.0.0.1", "APP_ENV": "development", "PYTHONPATH": str(release)}
    p = subprocess.Popen([sys.executable, "-m", "omega.server"], cwd=release, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        end = time.time() + timeout
        ready = False
        while time.time() < end and p.poll() is None:
            try:
                with urllib.request.urlopen(base + "/health/ready", timeout=2) as r:
                    ready = r.status == 200
                    break
            except Exception:
                time.sleep(0.2)
        if not ready:
            return False
        tok = issue_token(key, "smoke", ["knowledge.search"], 60)
        req = urllib.request.Request(base + "/v1/tasks", method="POST", headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
                                     data=json.dumps({"goal": "smoke", "capability": "knowledge.search", "input": {"query": "audit chain"}}).encode())
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
        return bool(d["state"] == "SUCCEEDED" and d["verification"] == "PASS")
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(state, ignore_errors=True)
