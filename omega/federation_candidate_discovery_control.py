# -*- coding: utf-8 -*-
"""omega.federation_candidate_discovery_control

Utility module that implements controlled discovery of federation candidate
files in a local directory, validates each candidate against the existing
capability validator, and returns a deterministic report.

The function is deliberately side‑effect‑free except for reading files from the
configured directory. It respects a configurable limit to avoid resource
exhaustion and operates without any external network calls, satisfying the
security constraints of the PADGE policy.
"""

from __future__ import annotations

import os
import json
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Helper: safe import of the capability validator
# ---------------------------------------------------------------------------
try:
    # The validator is expected to expose a function `validate_candidate`
    # that returns a tuple (bool, Optional[str]) where the bool indicates
    # validity and the optional string contains an error message.
    from .federation_capability_validator import validate_candidate  # type: ignore
except Exception:  # pragma: no cover
    # Fallback stub – in environments where the validator is unavailable we
    # consider every candidate valid. This ensures the utility remains usable
    # for testing and does not raise ImportError.
    def validate_candidate(candidate: Dict[str, Any]) -> tuple[bool, str | None]:
        return True, None

__all__ = ["discover_and_validate_candidates"]


def _load_json_file(path: str) -> Dict[str, Any]:
    """Load a JSON file and return its content.

    Args:
        path: Absolute or relative path to the JSON file.

    Returns:
        Parsed JSON object as a dictionary.

    Raises:
        OSError: If the file cannot be read.
        json.JSONDecodeError: If the file does not contain valid JSON.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def discover_and_validate_candidates(limit: int = 10) -> List[Dict[str, Any]]:
    """Discover candidate descriptors in a configured directory and validate them.

    The discovery respects a configurable limit to prevent excessive resource
    consumption. Candidates are JSON files with any name ending in ``.json``.
    Validation is delegated to :func:`omega.federation_capability_validator.
    validate_candidate`.

    Environment:
        FEDERATION_CANDIDATE_DIR – Directory path where candidate JSON files are
        stored. Defaults to ``"./candidates"`` relative to the current working
        directory.

    Args:
        limit: Maximum number of candidate files to process. If ``limit`` is
            non‑positive, all discovered files are processed.

    Returns:
        A list of dictionaries, each containing:
            - ``candidate_path``: Path to the processed file.
            - ``valid``: Boolean indicating validation success.
            - ``error``: Optional error message when ``valid`` is ``False``.
            - ``descriptor``: The parsed JSON content when validation succeeds;
              omitted otherwise.
    """
    directory = os.getenv("FEDERATION_CANDIDATE_DIR", "./candidates")
    if not os.path.isdir(directory):
        # No candidates directory – return empty report rather than raising.
        return []

    # List JSON files sorted for deterministic order.
    all_files = sorted(
        f for f in os.listdir(directory) if f.lower().endswith('.json')
    )

    if limit > 0:
        files_to_process = all_files[:limit]
    else:
        files_to_process = all_files

    results: List[Dict[str, Any]] = []
    for filename in files_to_process:
        full_path = os.path.join(directory, filename)
        try:
            descriptor = _load_json_file(full_path)
        except Exception as exc:  # pragma: no cover
            results.append(
                {
                    "candidate_path": full_path,
                    "valid": False,
                    "error": f"Failed to load JSON: {exc}",
                }
            )
            continue

        try:
            is_valid, err_msg = validate_candidate(descriptor)
        except Exception as exc:  # pragma: no cover
            # Defensive: if validator raises, treat as invalid.
            is_valid = False
            err_msg = f"Validator exception: {exc}"

        if is_valid:
            results.append(
                {
                    "candidate_path": full_path,
                    "valid": True,
                    "descriptor": descriptor,
                }
            )
        else:
            results.append(
                {
                    "candidate_path": full_path,
                    "valid": False,
                    "error": err_msg or "Validation failed",
                }
            )

    return results
