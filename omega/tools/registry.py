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

_SCHEMA_TYPES = {"object", "array", "string", "integer", "number", "boolean"}
_SCHEMA_KEYS = {
    "type", "properties", "required", "additionalProperties", "items",
    "enum", "minLength", "maxLength", "minimum", "maximum",
}


def _validate_schema(schema: Any, *, depth: int = 0) -> None:
    """Validate a deliberately small JSON Schema subset; reject unknown keywords."""
    if depth > 8 or not isinstance(schema, dict) or set(schema) - _SCHEMA_KEYS:
        raise ValueError("INVALID_TOOL_SCHEMA")
    kind = schema.get("type")
    if kind not in _SCHEMA_TYPES:
        raise ValueError("INVALID_TOOL_SCHEMA")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not 1 <= len(enum) <= 100:
            raise ValueError("INVALID_TOOL_SCHEMA")
        try:
            encoded = json.dumps(enum, allow_nan=False, sort_keys=True)
        except (TypeError, ValueError):
            raise ValueError("INVALID_TOOL_SCHEMA") from None
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("INVALID_TOOL_SCHEMA")
    for field in ("minLength", "maxLength"):
        if field in schema and (
            isinstance(schema[field], bool)
            or not isinstance(schema[field], int)
            or not 0 <= schema[field] <= 1_000_000
        ):
            raise ValueError("INVALID_TOOL_SCHEMA")
    if (
        "minLength" in schema and "maxLength" in schema
        and schema["minLength"] > schema["maxLength"]
    ):
        raise ValueError("INVALID_TOOL_SCHEMA")
    for field in ("minimum", "maximum"):
        value = schema.get(field)
        if field in schema and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("INVALID_TOOL_SCHEMA")
    if (
        "minimum" in schema and "maximum" in schema
        and schema["minimum"] > schema["maximum"]
    ):
        raise ValueError("INVALID_TOOL_SCHEMA")
    if kind == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)
        if (
            not isinstance(properties, dict)
            or len(properties) > 128
            or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key) for key in properties)
            or not isinstance(required, list)
            or len(required) != len(set(required))
            or any(not isinstance(key, str) or key not in properties for key in required)
            or not isinstance(additional, bool)
        ):
            raise ValueError("INVALID_TOOL_SCHEMA")
        for child in properties.values():
            _validate_schema(child, depth=depth + 1)
    elif "properties" in schema or "required" in schema or "additionalProperties" in schema:
        raise ValueError("INVALID_TOOL_SCHEMA")
    if kind == "array":
        if "items" not in schema:
            raise ValueError("INVALID_TOOL_SCHEMA")
        _validate_schema(schema["items"], depth=depth + 1)
    elif "items" in schema:
        raise ValueError("INVALID_TOOL_SCHEMA")
    if kind not in {"string"} and ({"minLength", "maxLength"} & set(schema)):
        raise ValueError("INVALID_TOOL_SCHEMA")
    if kind not in {"integer", "number"} and ({"minimum", "maximum"} & set(schema)):
        raise ValueError("INVALID_TOOL_SCHEMA")


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
                "WRITE", "DESTRUCTIVE", "CHANGE_REVERSIBLE", "CHANGE_EXTERNAL", "CHANGE_IRREVERSIBLE",
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
            if spec.input_schema:
                _validate_schema(spec.input_schema)
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
