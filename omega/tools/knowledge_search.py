"""knowledge.search v1.0.0 - read-only search over a fixed local corpus.
No URLs, no paths, no code accepted. Output is untrusted data (provenance via source_hash)."""
import hashlib
import re
from pathlib import Path
from typing import Any

MAX_SNIPPET = 240


def _collapse(s: str) -> str:
    return " ".join(s.split())


class KnowledgeCorpus:
    def __init__(self, directory: str | Path) -> None:
        self.docs: dict[str, dict[str, str]] = {}
        for p in sorted(Path(directory).glob("*.txt")):
            text = p.read_text(encoding="utf-8")
            first = text.splitlines()[0].strip() if text.strip() else p.stem
            self.docs[p.stem] = {"title": first, "text": _collapse(text),
                                 "hash": "sha256:" + hashlib.sha256(text.encode()).hexdigest()}

    @staticmethod
    def validate_input(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) - {"query", "limit"}:
            raise ValueError("INVALID_INPUT")
        q, lim = raw.get("query"), raw.get("limit", 5)
        if not isinstance(q, str) or not 2 <= len(q) <= 500:
            raise ValueError("INVALID_INPUT")
        if isinstance(lim, bool) or not isinstance(lim, int) or not 1 <= lim <= 20:
            raise ValueError("INVALID_INPUT")
        return {"query": q, "limit": lim}

    def run(self, inp: dict[str, Any]) -> dict[str, Any]:
        tokens = set(re.findall(r"\w+", inp["query"].lower()))
        scored = []
        for doc_id, d in self.docs.items():
            words = re.findall(r"\w+", d["text"].lower())
            score = sum(words.count(t) for t in tokens)
            if score:
                scored.append((-score, doc_id))
        scored.sort()
        items = []
        for _, doc_id in scored[: inp["limit"]]:
            d = self.docs[doc_id]
            low = d["text"].lower()
            pos = min((low.find(t) for t in tokens if low.find(t) >= 0), default=0)
            start = max(0, pos - 60)
            items.append({"document_id": doc_id, "title": d["title"],
                          "snippet": d["text"][start:start + MAX_SNIPPET], "source_hash": d["hash"]})
        return {"tool": "knowledge.search", "tool_version": "1.0.0", "status": "SUCCEEDED",
                "items": items, "truncated": len(scored) > inp["limit"]}

    def verify(self, out: Any) -> str:
        """PASS / FAIL / UNKNOWN. Checks schema and that every snippet really comes from the cited document."""
        try:
            if not isinstance(out, dict) or not isinstance(out.get("items"), list) or out.get("tool") != "knowledge.search":
                return "FAIL"
            for it in out["items"]:
                d = self.docs.get(it["document_id"])
                if d is None or it["source_hash"] != d["hash"]:
                    return "FAIL"
                if len(it["snippet"]) > MAX_SNIPPET or it["snippet"] not in d["text"]:
                    return "FAIL"
            return "PASS"
        except (KeyError, TypeError):
            return "FAIL"
        except Exception:
            return "UNKNOWN"
