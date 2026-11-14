from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "iao-life"
QUEUE = STATE / "development-proposals.jsonl"
INDEX = STATE / "processed-cycle-ids.json"


def utc():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".iao-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_index():
    try:
        value = json.loads(INDEX.read_text(encoding="utf-8"))
        return set(value if isinstance(value, list) else [])
    except FileNotFoundError:
        return set()
    except Exception:
        return set()


def normalize_result(result):
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        return repr(result)


def extract_proposal(result):
    """
    Registra la respuesta de PADGE como evidencia.
    No interpreta texto del modelo como código ejecutable.
    """
    content = normalize_result(result).strip()
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

    keywords = {
        "self_programming": (
            "program", "código", "code", "archivo", "módulo",
            "implement", "refactor",
        ),
        "federation": (
            "feder", "nodo", "node", "peer", "contract",
        ),
        "resilience": (
            "recuper", "resilien", "backup", "rollback", "error",
        ),
        "memory": (
            "memoria", "memory", "persisten", "knowledge",
        ),
        "integration": (
            "integr", "prueba", "test", "validación", "validation",
        ),
    }

    lowered = content.lower()
    categories = [
        name for name, terms in keywords.items()
        if any(term in lowered for term in terms)
    ]

    return {
        "proposal_id": digest[:20],
        "created_at": utc(),
        "source": "PADGE",
        "content_sha256": digest,
        "categories": categories or ["unclassified"],
        "content": content[:12000],
        "status": "PENDING_REVIEW",
        "execution": "NOT_EXECUTED",
        "promotion": "NOT_PERFORMED",
        "integration": "NOT_INTEGRATED",
    }


def register_result(cycle_id, goal, result):
    STATE.mkdir(parents=True, exist_ok=True)
    processed = load_index()

    if cycle_id in processed:
        return {
            "status": "ALREADY_REGISTERED",
            "cycle_id": cycle_id,
        }

    proposal = extract_proposal(result)

    if proposal["content"].strip():
        with QUEUE.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(proposal, ensure_ascii=False) + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())

    processed.add(cycle_id)
    atomic_json(INDEX, sorted(processed)[-5000:])

    return {
        "status": "REGISTERED",
        "cycle_id": cycle_id,
        "proposal_id": proposal["proposal_id"],
        "categories": proposal["categories"],
        "execution": "NOT_EXECUTED",
    }


def pending_proposals(limit=20):
    if not QUEUE.exists():
        return []

    found = []
    with QUEUE.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
                if row.get("status") == "PENDING_REVIEW":
                    found.append(row)
            except Exception:
                continue
    return found[-max(1, int(limit)):]


def stats():
    proposals = pending_proposals(100000)
    return {
        "pending": len(proposals),
        "queue": str(QUEUE),
        "index": str(INDEX),
    }
