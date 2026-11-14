"""Utilities to generate a comprehensive validation report for a federation candidate.

This module coordinates the existing low‑level validators (DNS validation,
HTTPS endpoint connectivity, and capability validation) and produces a
single structured dictionary that can be consumed by operators, auditors, or
automated tests.

The implementation deliberately uses the package‑level ``_safe_import``
helper so that the report generator degrades gracefully if any optional
validator is unavailable in the current deployment.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

# Import the tolerant import helper from the package root.
from . import _safe_import

# Safely obtain the concrete validator callables. If a module or attribute is
# missing the variable will be ``None`` and the corresponding step will be
# reported as "skipped".
_dns_validator = _safe_import("omega.federation_dns_validator", "validate_candidate_dns")
_https_checker = _safe_import("omega.federation_endpoint_connectivity", "verify_https_connectivity")
_capability_validator = _safe_import("omega.federation_capability_validator", "validate_candidate_capabilities")


def _run_validator(func: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Execute *func* safely and normalise its outcome.

    The returned dictionary always contains a ``status`` key with one of the
    following values:

    * ``"ok"`` – the validator executed without raising and returned a result.
    * ``"error"`` – the validator raised an exception; the error message is
      captured under the ``error`` key.
    * ``"skipped"`` – the validator function is ``None`` because the optional
      module could not be imported.
    """
    if func is None:
        return {"status": "skipped", "reason": "validator not available"}
    try:
        result = func(*args, **kwargs)
        return {"status": "ok", "result": result}
    except Exception as exc:  # pragma: no cover – defensive programming
        return {"status": "error", "error": str(exc)}


def generate_validation_report(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Run all available validation steps for *candidate* and return a report.

    The *candidate* dictionary should contain the fields expected by the
    underlying validators (e.g. ``"domains"`` for DNS validation, ``"endpoint"``
    for HTTPS checks, and ``"capabilities"`` for capability validation). Any
    missing validator is marked as ``skipped`` so the function works even in
    minimal environments.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    report: Dict[str, Any] = {
        "candidate_id": candidate.get("id"),
        "generated_at": timestamp,
        "steps": {},
    }

    # DNS validation step.
    report["steps"]["dns"] = _run_validator(_dns_validator, candidate)

    # HTTPS connectivity step.
    report["steps"]["https"] = _run_validator(_https_checker, candidate)

    # Capability validation step.
    report["steps"]["capabilities"] = _run_validator(_capability_validator, candidate)

    return report
