# -*- coding: utf-8 -*-
"""
Utilities to report validation status of pending federation proposal files.

The function :func:`get_pending_proposals_status` scans a directory for JSON
files that appear to be federation proposals and returns a list of dictionaries
with the filename and a simple validation result.

Validation is intentionally lightweight and does not perform cryptographic
signature checks – those are provided by higher‑level modules such as
``omega.federation_proposal_processor``. The goal is to give operators and
tests a deterministic way to see which pending proposals are syntactically
well‑formed before any network or secret‑key operations are performed.
"""

import json
import os
from typing import List, Dict, Any

# Minimal set of top‑level fields that a well‑formed federation proposal must contain.
_REQUIRED_FIELDS = {"id", "signature", "payload"}


def _validate_structure(proposal: Dict[str, Any]) -> List[str]:
    """Return a list of missing required keys. An empty list means the structure is ok.

    Args:
        proposal: The parsed JSON object representing a proposal.

    Returns:
        List of field names that are required but not present in *proposal*.
    """
    missing = _REQUIRED_FIELDS - proposal.keys()
    return list(missing)


def get_pending_proposals_status(directory: str) -> List[Dict[str, Any]]:
    """Scan *directory* for ``*.json`` files and report each file's structural validity.

    The function never raises for individual malformed files; instead it records
    the problem in the result entry. This makes the utility safe to use in
    automated test suites and operator dashboards.

    Args:
        directory: Path to the folder that contains pending proposal JSON files.

    Returns:
        A list of dictionaries, each containing:
        - ``filename``: The file name relative to *directory*.
        - ``valid``: ``True`` if the JSON could be parsed and contains all required fields.
        - ``errors``: A list of error strings (empty when ``valid`` is ``True``).

    Raises:
        NotADirectoryError: If *directory* does not exist or is not a directory.
    """
    results: List[Dict[str, Any]] = []
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"'{directory}' is not a valid directory")

    for entry in os.listdir(directory):
        if not entry.lower().endswith(".json"):
            continue
        path = os.path.join(directory, entry)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:  # JSONDecodeError, IOError, etc.
            results.append({"filename": entry, "valid": False, "errors": [str(exc)]})
            continue

        errors = _validate_structure(data)
        results.append({"filename": entry, "valid": len(errors) == 0, "errors": errors})

    return results
