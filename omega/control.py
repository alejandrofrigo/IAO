"""Deterministic task state machine (F1.5). Transitions are a table; no model involvement."""
TRANSITIONS: dict[str, frozenset[str]] = {
    "CREATED": frozenset({"AUTHENTICATED"}),
    "AUTHENTICATED": frozenset({"COMPILED"}),
    "COMPILED": frozenset({"POLICY_CHECKED"}),
    "POLICY_CHECKED": frozenset({"AUTHORIZED", "DENIED", "NEEDS_CLARIFICATION"}),
    "AUTHORIZED": frozenset({"RUNNING", "CANCELLED", "EXPIRED"}),
    "RUNNING": frozenset({"VERIFYING", "FAILED", "CANCELLED", "EXPIRED"}),
    "VERIFYING": frozenset({"SUCCEEDED", "FAILED"}),
    "SUCCEEDED": frozenset(), "FAILED": frozenset(), "DENIED": frozenset(),
    "NEEDS_CLARIFICATION": frozenset(), "CANCELLED": frozenset(), "EXPIRED": frozenset(),
}
STATES = tuple(TRANSITIONS)


class InvalidTransition(Exception):
    pass


def transition(current: str, new: str) -> str:
    if new not in TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(f"{current} -> {new}")
    return new
