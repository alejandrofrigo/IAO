from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def authorize(
    capability: str, *, authenticated: bool, approved_capabilities: set[str]
) -> PolicyDecision:
    """Deterministic deny-by-default policy. Never consults a model."""
    if not authenticated:
        return PolicyDecision(False, "AUTHENTICATION_REQUIRED")
    if capability not in approved_capabilities:
        return PolicyDecision(False, "CAPABILITY_NOT_GRANTED")
    return PolicyDecision(True, "ALLOW")
