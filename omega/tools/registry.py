from collections.abc import Callable
from dataclasses import dataclass, field
import json
import math
import re
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
    input_schema: dict[str, Any] = field(default_factory=dict)
    provenance: str = "internal"


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register a new tool specification.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if (
            not isinstance(spec.name, str)
            or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", spec.name)
            or not isinstance(spec.version, str)
            or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", spec.version)
            or not isinstance(spec.scope, str)
            or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", spec.scope)
            or not isinstance(spec.effect_class, str)
            or spec.effect_class not in {
                "READ_ONLY", "REVERSIBLE", "EXTERNAL", "IRREVERSIBLE",
                "WRITE", "DESTRUCTIVE",
            }
            or isinstance(spec.timeout_seconds, bool)
            or not isinstance(spec.timeout_seconds, (int, float))
            or not math.isfinite(float(spec.timeout_seconds))
            or not 0 < spec.timeout_seconds <= 300
            or not callable(spec.validate_input)
            or not callable(spec.run)
            or not callable(spec.verify)
            or not isinstance(spec.input_schema, dict)
            or not isinstance(spec.provenance, str)
            or not 1 <= len(spec.provenance) <= 128
        ):
            raise ValueError("INVALID_TOOL_MANIFEST")
        try:
            schema_json = json.dumps(spec.input_schema, allow_nan=False, sort_keys=True)
        except (TypeError, ValueError):
            raise ValueError("INVALID_TOOL_SCHEMA") from None
        if len(schema_json.encode("utf-8")) > 16_384:
            raise ValueError("TOOL_SCHEMA_TOO_LARGE")
        if spec.name in self._tools:
            raise ValueError(f"Tool '{spec.name}' is already registered; duplicate registration is not allowed.")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> set[str]:
        return set(self._tools)

    def manifest(self) -> list[dict[str, Any]]:
        """Return a stable, non-executable view of registered tool contracts."""
        return [
            {
                "capability": spec.name,
                "version": spec.version,
                "scope": spec.scope,
                "effect_class": spec.effect_class,
                "timeout_seconds": float(spec.timeout_seconds),
                "input_schema": json.loads(json.dumps(spec.input_schema, sort_keys=True)),
                "schema_status": "DECLARED" if bool(spec.input_schema) else "UNDECLARED",
                "provenance": spec.provenance,
                "executable": False,
            }
            for spec in sorted(self._tools.values(), key=lambda item: item.name)
        ]
