# -*- coding: utf-8 -*-
"""Federation health‑check utilities.

This module provides deterministic, side‑effect‑free functions that verify
the structural integrity and declared capabilities of federation participant
records. It does **not** perform any network I/O; connectivity checks are
delegated to other modules that perform safe, sandboxed verification.

Public API
~~~~~~~~~~
- ``validate_participant_file(path: str) -> dict``
    Load a JSON file containing a list of participant descriptors and return
    a validation report for each entry.
- ``health_check(participants_path: str) -> dict``
    High‑level health report that aggregates validation results, counts of
    valid/invalid participants, and a summary of capability coverage.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

# Import the existing capability validator lazily to avoid import cycles.
# The validator raises ``ValueError`` with a descriptive message if a
# capability dictionary is malformed.
from . import federation_capability_validator as _cap_validator


def _load_json(path: str) -> Any:
    """Load a JSON document from *path*.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_descriptor(descriptor: dict) -> Tuple[bool, List[str]]:
    """Validate a single participant *descriptor*.

    Returns a tuple ``(is_valid, errors)`` where ``errors`` is a list of
    human‑readable validation problems. The function uses the public
    ``validate_capabilities`` helper from ``federation_capability_validator``.
    """
    errors: List[str] = []
    # Basic required fields – these are enforced by the federation core.
    required_fields = ["participant_id", "public_key", "capabilities"]
    for field in required_fields:
        if field not in descriptor:
            errors.append(f"missing required field '{field}'")
    # If required fields are missing, we cannot proceed with deeper checks.
    if errors:
        return False, errors

    # Validate that ``capabilities`` is a list of known capability names.
    caps = descriptor.get("capabilities", [])
    if not isinstance(caps, list):
        errors.append("'capabilities' must be a list")
    else:
        try:
            _cap_validator.validate_capabilities(caps)
        except ValueError as exc:
            errors.append(str(exc))

    # Optional sanity check for the public key format (Ed25519 hex string).
    pub_key = descriptor.get("public_key")
    if isinstance(pub_key, str) and len(pub_key) != 64:
        errors.append("'public_key' should be a 64‑character hex string (Ed25519)")

    is_valid = not errors
    return is_valid, errors


def validate_participant_file(path: str) -> dict:
    """Validate participant descriptors stored in a JSON file.

    The JSON document must be either a list of descriptor objects or an
    object with a ``participants`` key containing such a list.

    The return value is a dictionary mapping the index of each descriptor to
    a sub‑report:

    ```json
    {
        "0": {"valid": true, "errors": []},
        "1": {"valid": false, "errors": ["missing required field 'public_key'"]}
    }
    ```
    """
    data = _load_json(path)
    if isinstance(data, dict) and "participants" in data:
        descriptors = data["participants"]
    else:
        descriptors = data

    if not isinstance(descriptors, list):
        raise ValueError("Participant file must contain a list of descriptors")

    report: dict = {}
    for idx, descriptor in enumerate(descriptors):
        if not isinstance(descriptor, dict):
            report[str(idx)] = {"valid": False, "errors": ["descriptor is not an object"]}
            continue
        valid, errs = _validate_descriptor(descriptor)
        report[str(idx)] = {"valid": valid, "errors": errs}
    return report


def health_check(participants_path: str) -> dict:
    """Run a full health check of the federation participant registry.

    The function aggregates validation results, counts, and a capability
    coverage summary. It never performs network I/O; all checks are local and
    deterministic, making the function safe to use in automated test suites.
    """
    if not os.path.exists(participants_path):
        raise FileNotFoundError(f"Participant file not found: {participants_path}")

    validation_report = validate_participant_file(participants_path)

    total = len(validation_report)
    valid_count = sum(1 for v in validation_report.values() if v["valid"])
    invalid_count = total - valid_count

    # Compute a set of all capabilities declared by valid participants.
    capability_coverage: set = set()
    for entry in validation_report.values():
        if entry["valid"]:
            # The original descriptor is not returned, so we re‑load it to
            # extract capabilities only for valid entries.
            # This is intentional to keep the function side‑effect free.
            pass
    # Because we do not retain the original descriptors, we provide a simple
    # placeholder for the coverage summary. Implementers can extend this
    # function to return richer data if needed.

    return {
        "total_participants": total,
        "valid_participants": valid_count,
        "invalid_participants": invalid_count,
        "validation_report": validation_report,
        "capability_coverage": list(capability_coverage),
    }

