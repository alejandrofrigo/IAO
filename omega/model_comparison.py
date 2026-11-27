"""Deterministic comparison of already-produced model candidates; never executes models."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from omega.response_evaluator import evaluate_response, ResponseEvaluationError


class ModelComparisonError(ValueError):
    pass


def compare_model_candidates(
    candidates: Any,
    *,
    required_claims: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    require_citations: bool = False,
    max_candidates: int = 8,
) -> dict[str, Any]:
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= max_candidates
        or isinstance(max_candidates, bool)
        or not isinstance(max_candidates, int)
        or not 1 <= max_candidates <= 8
    ):
        raise ModelComparisonError("INVALID_CANDIDATE_SET")
    seen: set[str] = set()
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {
            "provider_id", "model_id", "response"
        }:
            raise ModelComparisonError("INVALID_CANDIDATE")
        provider = candidate["provider_id"]
        model = candidate["model_id"]
        if (
            not isinstance(provider, str) or not 1 <= len(provider) <= 64
            or not isinstance(model, str) or not 1 <= len(model) <= 120
            or provider in seen
        ):
            raise ModelComparisonError("INVALID_CANDIDATE_IDENTITY")
        seen.add(provider)
        try:
            evaluation = evaluate_response(
                candidate["response"],
                required_claims=required_claims,
                evidence_refs=evidence_refs,
                require_citations=require_citations,
            )
        except ResponseEvaluationError:
            raise ModelComparisonError("CANDIDATE_EVALUATION_FAILED") from None
        ranked.append({
            "provider_id": provider,
            "model_id": model,
            "evaluation": evaluation,
            "response": candidate["response"].strip(),
        })

    ranked.sort(key=lambda item: (
        0 if item["evaluation"]["complete"] else 1,
        len(item["evaluation"]["missing_claims"]),
        len(item["evaluation"]["unmatched_citations"]),
        item["provider_id"],
    ))
    response_hashes = {
        hashlib.sha256(item["response"].encode("utf-8")).hexdigest()
        for item in ranked
    }
    claim_sets = [
        set(required_claims or []) & set(item["response"].casefold().split())
        for item in ranked
    ]
    disagreements = []
    if len(response_hashes) > 1:
        disagreements.append("RESPONSES_DIFFER")
    if any(item["evaluation"]["status"] != "STRUCTURALLY_COMPLETE" for item in ranked):
        disagreements.append("COMPLETENESS_DIFFERS_OR_INCOMPLETE")
    return {
        "ranking": [
            {
                "provider_id": item["provider_id"],
                "model_id": item["model_id"],
                "status": item["evaluation"]["status"],
                "missing_claims": item["evaluation"]["missing_claims"],
                "matched_evidence_refs": item["evaluation"]["matched_evidence_refs"],
                "response_sha256": item["evaluation"]["response_sha256"],
            }
            for item in ranked
        ],
        "disagreements": sorted(set(disagreements)),
        "candidate_count": len(ranked),
        "selection": None,
        "authority_granted": False,
        "truth_verified": False,
        "responses": [
            {
                "provider_id": item["provider_id"],
                "model_id": item["model_id"],
                "response": item["response"],
            }
            for item in ranked
        ],
    }
