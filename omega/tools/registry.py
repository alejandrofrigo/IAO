from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


# Queue execution is deliberately narrower than the general tool registry.
# Only the deterministic local corpus lookup is approved until each additional
# tool has an isolated execution and cancellation contract.
QUEUED_TOOL_ALLOWLIST = frozenset({"knowledge.search"})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    scope: str
    effect_class: str
    timeout_seconds: float
    validate_input: Callable[[Any], dict[str, Any]]
    run: Callable[[dict[str, Any]], dict[str, Any]]
    verify: Callable[[Any], str]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register a new tool specification.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if spec.name in self._tools:
            raise ValueError(f"Tool '{spec.name}' is already registered; duplicate registration is not allowed.")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> set[str]:
        return set(self._tools)
