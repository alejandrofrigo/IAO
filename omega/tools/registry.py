from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


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
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> set[str]:
        return set(self._tools)
