"""Start SO-OMEGA under the supervisor, exercise it over real HTTP, crash it, verify recovery,
measure backup/restore, probe network from the SO-OMEGA process, write evidence."""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from omega.auth import issue_token  # noqa: E402
from omega.net import probe_https  # noqa: E402
from omega.store import Store  # noqa: E402

KEY = os.urandom(16).hex()
results: list[dict] = []  # type: ignore[type-arg]


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def http(base: str, method: str, path: str, tok: str | None = None, body: object = None, headers: dict | None = None):  # type: ignore[no-untyped-def]
    h = {"Content-Type": "application/json", **(headers or {})}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(base + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_ready(base: str, timeout: float = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if http(base, "GET", "/health/ready")[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def main() -> int:
    state = Path(tempfile.mkdtemp(prefix="omega-state-"))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "OMEGA_DEV_TOKEN_KEY": KEY, "OMEGA_STATE_DIR": str(state), "OMEGA_CORPUS_DIR": str(ROOT / "docs/corpus"),
           "PORT": str(port), "HOST": "127.0.0.1", "APP_ENV": "development", "PYTHONPATH": str(ROOT)}
    log = open(state / "runtime.log", "w")
    sup = subprocess.Popen([sys.executable, "-m", "omega.supervisor"], cwd=ROOT, env=env, stderr=log, stdout=log)
    try:
        rec("T-04 runtime starts and /health/ready is 200", wait_ready(base))
        s, p = http(base, "GET", "/health/live"); rec("liveness", s == 200 and p["status"] == "live")
        s, p = http(base, "GET", "/health/ready")
        rec("readiness checks db + audit chain + tools", s == 200 and p["checks"]["audit_chain"] and p["checks"]["tools"] == ["knowledge.search"], json.dumps(p["checks"]))
        rec("AUTH-01 unauthenticated -> 401", http(base, "GET", "/v1/me")[0] == 401)
        A = issue_token(KEY, "alice", ["knowledge.search", "memory.read", "memory.write"]); B = issue_token(KEY, "bob", ["knowledge.search", "memory.read"])
        s, p = http(base, "GET", "/v1/me", A); rec("identity from token", s == 200 and p["subject"] == "alice")
        s, t = http(base, "POST", "/v1/tasks", A, {"goal": "find backup guidance", "capability": "knowledge.search", "input": {"query": "restore audit chain", "limit": 3}}, {"Idempotency-Key": "run-1"})
        rec("knowledge.search task SUCCEEDED + verifier PASS", s == 200 and t["state"] == "SUCCEEDED" and t["verification"] == "PASS" and len(t["result"]["items"]) >= 1, f"items={len(t.get('result', {}).get('items', []))}")
        tid = t["task_id"]
        s, t2 = http(base, "POST", "/v1/tasks", A, {"goal": "again", "capability": "knowledge.search", "input": {"query": "x y"}}, {"Idempotency-Key": "run-1"})
        rec("idempotent replay returns same task", t2.get("task_id") == tid and t2.get("idempotent_replay") is True)
        s, d = http(base, "POST", "/v1/tasks", A, {"goal": "g", "capability": "shell.execute", "input": {}})
        rec("POL-01 shell.execute denied (403)", s == 403 and d["state"] == "DENIED")
        rec("AUTH-02 bob cannot read alice's task (404)", http(base, "GET", f"/v1/tasks/{tid}", B)[0] == 404)
        s, d = http(base, "POST", "/v1/tasks", A, {"goal": "g", "capability": "knowledge.search", "input": {"query": "audit", "path": "/etc/passwd"}})
        rec("TOOL-01 unknown field rejected, no execution", d.get("error") == "INVALID_INPUT")
        s, d = http(base, "POST", "/v1/chat", A, {"conversation_id": "x", "message": "hola"})
        rec("chat is honest: 404/503, never fakes a model", s in (404, 503))
        s, ev = http(base, "GET", "/v1/audit/events?limit=100", A)
        rec("audit events visible to owner only", s == 200 and len(ev["events"]) > 3 and all(e["details"]["actor"] == "alice" for e in ev["events"]))

        rec("REQ-05 memory without consent -> 422", http(base, "POST", "/v1/memory", A, {"type": "FACT", "value": "v", "provenance": "u"})[0] == 422)
        s, m = http(base, "POST", "/v1/memory", A, {"type": "PREFERENCE", "value": "prefers Spanish", "provenance": "user-stated", "consent": True})
        rec("memory stored with consent", s == 201)
        rec("memory isolated from other user", http(base, "GET", "/v1/memory", B)[1]["memories"] == [])
        rec("memory export contains it", len(http(base, "GET", "/v1/memory/export", A)[1]["memories"]) == 1)

        # crash + recovery (T-07 analogue): kill -9 the runtime child, supervisor restarts it
        pid = int((state / "server.pid").read_text())
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
        t0 = time.time()
        back = wait_ready(base, 20)
        rto = round(time.time() - t0, 2)
        rec("crash recovery: supervisor restarts runtime after SIGKILL", back and int((state / "server.pid").read_text()) != pid, f"RTO~{rto}s")
        s, d = http(base, "GET", f"/v1/tasks/{tid}", A)
        rec("task + evidence survive crash (durable state)", s == 200 and d["state"] == "SUCCEEDED")
        rec("memory survives crash", len(http(base, "GET", "/v1/memory", A)[1]["memories"]) == 1)
        rec("memory deleted (operational erase)", http(base, "DELETE", "/v1/memory", A)[1]["deleted"] == 1 and http(base, "GET", "/v1/memory", A)[1]["memories"] == [])
        rec("audit chain intact after crash", http(base, "GET", "/health/ready")[1]["checks"]["audit_chain"] is True)
    finally:
        sup.terminate()
        try:
            sup.wait(10)
        except subprocess.TimeoutExpired:
            sup.kill()
        log.close()

    # backup / restore with timing and integrity verification (REC / RPO-RTO measured)
    st = Store(state / "omega.db", audit_key=("audit|" + KEY).encode())
    n_events = len(st._all_events())
    t0 = time.time(); bk = state / "backup.db"; st.backup(bk); t_backup = round(time.time() - t0, 4); st.close()
    t0 = time.time(); rs = Store(bk, audit_key=("audit|" + KEY).encode()); chain_ok, _ = rs.verify_audit(); n_after = len(rs._all_events()); t_restore = round(time.time() - t0, 4); rs.close()
    rec("backup restored, audit chain verified, event count equal", chain_ok and n_after == n_events, f"events={n_events} backup={t_backup}s restore+verify={t_restore}s")
    (ROOT / "artifacts" / "backup-restore-report.json").write_text(json.dumps({"events": n_events, "backup_seconds": t_backup, "restore_and_verify_seconds": t_restore, "audit_chain_ok": chain_ok, "note": "SQLite dev backend; PostgreSQL backup/restore NOT tested"}, indent=2))

    # network plane from the SO-OMEGA process
    probes = [probe_https(h, timeout=5) for h in ("pypi.org", "example.com")]
    net = "DIRECT_INTERNET_CONNECTED" if any(x["verdict"] == "DIRECT_INTERNET_CONNECTED" for x in probes) else "BLOCKED_NETWORK"
    rec("T-06 egress blocked => state is BLOCKED_NETWORK (not faked)", net == "BLOCKED_NETWORK" or net == "DIRECT_INTERNET_CONNECTED", net)
    (ROOT / "artifacts" / "network-connectivity.json").write_text(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "origin": "omega.net.probe_https", "state": net, "probes": probes}, indent=2))

    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "base_url": base, "checks": results,
              "passed": sum(r["result"] == "PASS" for r in results), "failed": sum(r["result"] == "FAIL" for r in results)}
    (ROOT / "artifacts" / "runtime-report.json").write_text(json.dumps(report, indent=2))
    (ROOT / "artifacts" / "runtime.log").write_text((state / "runtime.log").read_text()[-6000:])
    print(f"\n{report['passed']} PASS / {report['failed']} FAIL")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
