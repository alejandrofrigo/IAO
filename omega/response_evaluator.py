"""Deterministic, non-authoritative evaluation of model response completeness/evidence."""
from __future__ import annotations

import hashlib
import re
from typing import Any

MAX_RESPONSE_BYTES = 256_000
MAX_REQUIRED_CLAIMS = 64
_CITATION = re.compile(r"\[([A-Za-z0-9_.:-]{1,120})\]")


class ResponseEvaluationError(ValueError):
    pass


def evaluate_response(
    response: Any,
    *,
    required_claims: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    require_citations: bool = False,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Check structural completeness and reference presence, never truth or authority."""
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= MAX_RESPONSE_BYTES
    ):
        raise ResponseEvaluationError("INVALID_RESPONSE_LIMIT")
    if not isinstance(response, str):
        raise ResponseEvaluationError("RESPONSE_NOT_TEXT")
    try:
        raw = response.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ResponseEvaluationError("RESPONSE_ENCODING_INVALID") from exc
    if not raw or not response.strip():
        raise ResponseEvaluationError("RESPONSE_EMPTY")
    if len(raw) > max_bytes:
        raise ResponseEvaluationError("RESPONSE_TOO_LARGE")
    claims = [] if required_claims is None else required_claims
    refs = [] if evidence_refs is None else evidence_refs
    if (
        not isinstance(claims, list)
        or len(claims) > MAX_REQUIRED_CLAIMS
        or any(not isinstance(item, str) or not item.strip() or len(item) > 500 for item in claims)
        or len(claims) != len(set(claims))
        or not isinstance(refs, list)
        or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", item) for item in refs)
        or len(refs) != len(set(refs))
        or not isinstance(require_citations, bool)
    ):
        raise ResponseEvaluationError("INVALID_EVALUATION_REQUIREMENTS")

    normalized = response.strip()
    lowered = normalized.casefold()
    missing_claims = [claim for claim in claims if claim.casefold() not in lowered]
    citations = sorted(set(_CITATION.findall(normalized)))
    supported_refs = sorted(set(citations) & set(refs))
    unsupported_refs = sorted(set(citations) - set(refs))
    missing_citations = require_citations and not supported_refs
    if missing_claims or missing_citations or unsupported_refs:
        status = "INCOMPLETE" if missing_claims or missing_citations else "REVIEW"
    else:
        status = "STRUCTURALLY_COMPLETE"
    return {
        "status": status,
        "complete": status == "STRUCTURALLY_COMPLETE",
        "missing_claims": missing_claims,
        "citations": citations,
        "matched_evidence_refs": supported_refs,
        "unmatched_citations": unsupported_refs,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "authoritative": False,
        "truth_verified": False,
    }
