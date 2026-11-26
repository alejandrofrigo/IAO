#!/usr/bin/env python3
import os, json, time, subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

ROOT = Path.cwd()
STATE = ROOT / ".state"
PADGE = STATE / "padge"
REPORTS = PADGE / "reports"
AUDIT_CANDIDATES = [
    PADGE / "events.jsonl",
    PADGE / "audit.jsonl",
    STATE / "padge" / "events.jsonl",
    STATE / "iao-five-motors" / "events.jsonl",
    STATE / "iao-five-motors" / "events.json",
]
def read_json(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def tail_jsonl(p):
    rows = []
    try:
        with p.open(encoding="utf-8") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return rows

def process_list():
    try:
        r = subprocess.run(
            ["ps", "-A", "-o", "PID,ARGS"],
            capture_output=True, text=True, timeout=5
        )
        return [
            x.strip() for x in r.stdout.splitlines()
            if any(s in x.lower() for s in (
                "padge", "autonomous", "iao-five-motor"
            ))
        ]
    except Exception:
        return []

def main():
    print("========== IAO / PADGE STATUS ==========")
    print("UTC:", datetime.now(timezone.utc).isoformat())

    processes = process_list()
    print("\n[PROCESOS]")
    print("PROCESOS_RELACIONADOS:", len(processes))
    for p in processes:
        print("PROCESS:", p)

    print("\n[REPORTES PADGE]")
    files = sorted(REPORTS.glob("*")) if REPORTS.exists() else []
    print("REPORTES_ENCONTRADOS:", len(files))
    for p in files[-15:]:
        try:
            st = p.stat()
            print("REPORT:", p.name, "bytes=", st.st_size,
                  "modified=", datetime.fromtimestamp(
                      st.st_mtime, timezone.utc
                  ).isoformat())
            if p.suffix == ".json":
                doc = read_json(p)
                if isinstance(doc, dict):
                    for k in (
                        "status", "result", "decision", "reason",
                        "baseline", "candidate", "tests",
                        "promoted", "rollback", "timestamp"
                    ):
                        if k in doc:
                            print(" ", k, "=", str(doc[k])[:500])
        except Exception as e:
            print("REPORT_READ_ERROR:", p.name, str(e)[:150])

    print("\n[EVENTOS]")
    event_files = []
    for p in AUDIT_CANDIDATES:
        if p.is_file() and p not in event_files:
            event_files.append(p)
    # Incluir JSONL de auditoría bajo el directorio PADGE.
    if PADGE.exists():
        for p in PADGE.rglob("*.jsonl"):
            if p.is_file() and p not in event_files:
                event_files.append(p)

    all_events = []
    for p in event_files:
        rows = tail_jsonl(p)
        if rows:
            print("EVENT_SOURCE:", p.relative_to(ROOT), "rows=", len(rows))
            for e in rows:
                e["_source"] = str(p.relative_to(ROOT))
            all_events.extend(rows)

    print("TOTAL_EVENTOS_LEIDOS:", len(all_events))
    counts = Counter()
    for e in all_events:
        name = str(
            e.get("event") or e.get("event_type")
            or e.get("action") or e.get("type") or "UNKNOWN"
        ).lower()
        counts[name] += 1

    for name, count in counts.most_common(35):
        print("EVENT_COUNT:", name, "=", count)

    keywords = (
        "cycle", "proposal", "candidate", "patch", "edit",
        "modify", "test", "promot", "rollback", "reject",
        "error", "improv", "autoprogram", "evolution"
    )
    relevant = [
        e for e in all_events
        if any(k in str(e).lower() for k in keywords)
    ]
    print("\n[ULTIMOS EVENTOS RELEVANTES]")
    for e in relevant[-20:]:
        print(json.dumps(e, ensure_ascii=False, default=str)[:1000])

    print("\n[CAMBIOS RECIENTES EN CODIGO]")
    cutoff = time.time() - 24 * 3600
    changed = []
    for folder in ("omega", "tools"):
        base = ROOT / folder
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            try:
                if p.stat().st_mtime >= cutoff:
                    changed.append((
                        p.stat().st_mtime,
                        str(p.relative_to(ROOT)),
                        p.stat().st_size
                    ))
            except OSError:
                pass
    changed.sort(reverse=True)
    print("PYTHON_FILES_MODIFIED_LAST_24H:", len(changed))
    for ts, name, size in changed[:20]:
        print("CODE_CHANGE:",
              datetime.fromtimestamp(ts, timezone.utc).isoformat(),
              name, "bytes=", size)

    print("\n[CLASIFICACION]")
    active = any(
        "padge" in p.lower() for p in processes
    )
    print("PADGE_PROCESS_VISIBLE:", active)
    print("AUTOPROGRAMMING_EVIDENCE:",
          "YES" if any(
              any(k in str(e).lower() for k in (
                  "candidate", "patch", "promot", "code_change"
              )) for e in all_events
          ) else "NO_EVENTS_FOUND")
    print("IMPORTANT: proceso activo no demuestra autoprogramacion.")
    print("IMPORTANT: propuesta no equivale a cambio integrado.")
    print("IMPORTANT: cambio de archivo no demuestra autoria de PADGE.")
    print("========== END PADGE STATUS ==========")

if __name__ == "__main__":
    main()
