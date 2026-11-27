"""Deterministic effect-class authorization; model output never grants effects."""
from __future__ import annotations

from dataclasses import dataclass


EFFECT_CLASSES = frozenset({
    "READ_ONLY", "REVERSIBLE", "EXTERNAL", "IRREVERSIBLE",
    # Compatibility labels are treated as restrictive aliases, never implicit grants.
    "WRITE", "DESTRUCTIVE",
})


@dataclass(frozen=True)
class EffectDecision:
    allowed: bool
    reason: str


def authorize_effect(
    effect_class: str,
    *,
    approved_effects: set[str] | frozenset[str] = frozenset({"READ_ONLY"}),
    approval_bound_to_request: bool = False,
) -> EffectDecision:
    """Fail closed; non-read-only effects require an explicit request-bound grant."""
    if not isinstance(effect_class, str) or effect_class not in EFFECT_CLASSES:
        return EffectDecision(False, "UNKNOWN_EFFECT_CLASS")
    if effect_class == "READ_ONLY":
        return EffectDecision(
            effect_class in approved_effects,
            "ALLOW" if effect_class in approved_effects else "EFFECT_NOT_GRANTED",
        )
    if not approval_bound_to_request:
        return EffectDecision(False, "REQUEST_BOUND_EFFECT_APPROVAL_REQUIRED")
    if effect_class not in approved_effects:
        return EffectDecision(False, "EFFECT_NOT_GRANTED")
    return EffectDecision(True, "ALLOW")
