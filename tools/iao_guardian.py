#!/usr/bin/env python
"""IAO Guardian: snapshots verificados y restauracion con rollback."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
SNAPS = STATE / "guardian-snapshots"
REPORT = STATE / "iao-guardian-run-report.txt"
FILES = [
    "omega/__init__.py", "omega/federation.py", "omega/service.py",
    "omega/server.py", "omega/auth.py", "omega/store.py", "omega/config.py"
]

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def snapshot():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = SNAPS / (stamp + "-" + str(os.getpid()))
    dest.mkdir(parents=True, exist_ok=False)
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(),
                "files": {}, "format": "iao-guardian-snapshot-v1"}
    for rel in FILES:
        src = ROOT / rel
        if src.is_file():
            dst = dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest["files"][rel] = digest(dst)
    m = dest / "manifest.json"
    m.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                 encoding="utf-8")
    return dest

def verify_snapshot(path):
    m = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if m.get("format") != "iao-guardian-snapshot-v1":
        raise ValueError("unsupported snapshot format")
    files = m.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("empty or invalid manifest")
    for rel, expected in files.items():
        if rel not in FILES or ".." in Path(rel).parts or Path(rel).is_absolute():
            raise ValueError("unsafe manifest path")
        p = path / rel
        if not p.is_file() or digest(p) != expected:
            raise ValueError("snapshot integrity failure: " + rel)
    return files

def restore(path):
    files = verify_snapshot(path)
    # Make a fresh recovery point before changing anything.
    rollback = snapshot()
    changed = []
    try:
        for rel in files:
            src = path / rel
            dst = ROOT / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".iao-guardian-tmp")
            shutil.copy2(src, tmp)
            if digest(tmp) != files[rel]:
                raise ValueError("copy verification failed: " + rel)
            os.replace(tmp, dst)
            changed.append(rel)
        test = subprocess.run([sys.executable, "-m", "compileall", "-q", "omega"],
                              cwd=ROOT, capture_output=True, text=True, timeout=90)
        if test.returncode:
            raise RuntimeError("compileall failed after restore")
        return "RESTORE=PASS", rollback, changed
    except Exception:
        # Roll back the attempted restore from the recovery point.
        current = verify_snapshot(rollback)
        for rel, expected in current.items():
            src = rollback / rel
            dst = ROOT / rel
            tmp = dst.with_name(dst.name + ".iao-guardian-rollback")
            shutil.copy2(src, tmp)
            if digest(tmp) != expected:
                raise RuntimeError("rollback copy verification failed: " + rel)
            os.replace(tmp, dst)
        return "RESTORE=ROLLED_BACK", rollback, changed

def main():
    lines = ["IAO GUARDIAN RUN", "UTC=" + datetime.now(timezone.utc).isoformat()]
    args = sys.argv[1:]
    if args and args[0] == "--restore":
        if len(args) != 2:
            raise SystemExit("Usage: python tools/iao_guardian.py --restore SNAPSHOT_PATH")
        path = Path(args[1]).expanduser().resolve()
        status, rollback, changed = restore(path)
        lines += [status, "ROLLBACK_POINT=" + str(rollback),
                  "RESTORED_FILES=" + ",".join(changed)]
    else:
        path = snapshot()
        verify_snapshot(path)
        lines += ["SNAPSHOT=PASS", "SNAPSHOT_PATH=" + str(path),
                  "SNAPSHOT_INTEGRITY=PASS",
                  "SNAPSHOT_FILE_COUNT=" + str(len(verify_snapshot(path)))]

    test = subprocess.run([sys.executable, "-m", "compileall", "-q", "omega"],
                          cwd=ROOT, capture_output=True, text=True, timeout=90)
    lines.append("COMPILEALL=" + ("PASS" if test.returncode == 0 else "FAIL"))
    if test.returncode:
        lines.append("COMPILE_DETAIL=" + (test.stderr or test.stdout).strip()[:600])
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2) as r:
            lines.append("LOCAL_HTTP_STATUS=" + str(r.status))
    except Exception as e:
        lines.append("LOCAL_HTTP=UNAVAILABLE_" + type(e).__name__)
    lines += ["EXTERNAL_PEER_EXCHANGE=NOT_TESTED",
              "EXTERNAL_DEPLOYMENT=NOT_PERFORMED"]
    body = "\n".join(lines) + "\n"
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(body + "REPORT_SHA256=" +
                      hashlib.sha256(body.encode()).hexdigest() + "\n",
                      encoding="utf-8")
    print(body, end="")
    print("REPORT_PATH=" + str(REPORT))
    print("REPORT_FILE_SHA256=" + digest(REPORT))
    if test.returncode:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
