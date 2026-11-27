"""Deterministic, non-executing task DAG compiler.

This module validates proposed step dependencies and returns a stable topological
order. It does not authorize capabilities, invoke tools, or grant execution rights.
"""
from __future__ import annotations

import json
import re
from typing import Any


PLAN_VERSION = "1.0"
_MAX_STEPS = 64
_MAX_DEPENDENCIES = 16
_STEP_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class TaskPlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def compile_task_plan(proposal: Any) -> dict[str, Any]:
    """Validate a proposed DAG and produce a deterministic topological order."""
    if not isinstance(proposal, dict) or set(proposal) != {"steps"}:
        raise TaskPlanError("PLAN_SCHEMA_INVALID")
    raw_steps = proposal["steps"]
    if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= _MAX_STEPS:
        raise TaskPlanError("PLAN_STEP_COUNT_INVALID")

    steps: dict[str, dict[str, Any]] = {}
    for raw in raw_steps:
        if not isinstance(raw, dict) or set(raw) != {
            "step_id", "capability", "input", "depends_on"
        }:
            raise TaskPlanError("PLAN_STEP_SCHEMA_INVALID")
        step_id, capability = raw["step_id"], raw["capability"]
        payload, dependencies = raw["input"], raw["depends_on"]
        if not isinstance(step_id, str) or not _STEP_ID.fullmatch(step_id):
            raise TaskPlanError("PLAN_STEP_ID_INVALID")
        if step_id in steps:
            raise TaskPlanError("PLAN_STEP_ID_DUPLICATE")
        if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
            raise TaskPlanError("PLAN_CAPABILITY_INVALID")
        if not isinstance(payload, dict) or not isinstance(dependencies, list):
            raise TaskPlanError("PLAN_STEP_INPUT_INVALID")
        if len(dependencies) > _MAX_DEPENDENCIES or any(
            not isinstance(dep, str) or not _STEP_ID.fullmatch(dep)
            for dep in dependencies
        ):
            raise TaskPlanError("PLAN_DEPENDENCIES_INVALID")
        if len(set(dependencies)) != len(dependencies) or step_id in dependencies:
            raise TaskPlanError("PLAN_DEPENDENCIES_INVALID")
        try:
            # Enforce JSON-only input and detach caller-owned containers.
            payload_copy = json.loads(json.dumps(
                payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ))
        except (TypeError, ValueError, UnicodeEncodeError):
            raise TaskPlanError("PLAN_STEP_INPUT_INVALID") from None
        steps[step_id] = {
            "step_id": step_id,
            "capability": capability,
            "input": payload_copy,
            "depends_on": sorted(dependencies),
        }

    for step in steps.values():
        if any(dep not in steps for dep in step["depends_on"]):
            raise TaskPlanError("PLAN_DEPENDENCY_NOT_FOUND")

    # Kahn's algorithm with lexical tie-breaking makes output independent of
    # proposal order, hash iteration order, and model generation order.
    remaining = {key: set(value["depends_on"]) for key, value in steps.items()}
    ordered: list[dict[str, Any]] = []
    while remaining:
        ready = sorted(key for key, deps in remaining.items() if not deps)
        if not ready:
            raise TaskPlanError("PLAN_CYCLE_DETECTED")
        for step_id in ready:
            ordered.append(steps[step_id])
            remaining.pop(step_id)
        for deps in remaining.values():
            deps.difference_update(ready)

    return {
        "plan_version": PLAN_VERSION,
        "step_count": len(ordered),
        "execution_order": [step["step_id"] for step in ordered],
        "steps": ordered,
        "authorization_required": True,
        "execution_performed": False,
    }
