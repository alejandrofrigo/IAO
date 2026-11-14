"""Federation candidate discovery utilities.

This module provides a deterministic, side‑effect‑free way to obtain a list of
federation candidate specifications that can be used by the rest of the
pipeline (validation, proposal creation, assimilation, etc.).

The implementation reads a JSON file located at ``artifacts/federation_candidates.json``
relative to the repository root. The JSON file should contain an array of objects
with at least the following keys:

* ``candidate_id`` – a unique identifier for the candidate (string).
* ``endpoint`` – the HTTPS endpoint URL of the candidate (string).
* ``capabilities`` – a list or mapping describing the candidate's advertised
  capabilities (optional, any JSON‑serialisable value).

If the file is missing, unreadable, or malformed the function returns an empty
list and logs a warning. This behaviour ensures that the discovery step never
fails catastrophically and that the rest of the federation workflow can continue
with zero candidates (a valid situation for isolated testing).

The function is pure Python, uses only the standard library and the existing
logging configuration of the IAO system, and does not perform any network I/O.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Mapping, Any

_logger = logging.getLogger(__name__)

# Path to the static candidates file. It lives under the repository's ``artifacts``
# directory which is already part of the project and is included in the source
# distribution.
_CANDIDATES_FILE = Path(__file__).resolve().parents[1] / "artifacts" / "federation_candidates.json"


def _load_json_file(path: Path) -> Any:
    """Load and parse a JSON file.

    Returns the parsed JSON object, or ``None`` if the file cannot be read or the
    content is not valid JSON.
    """
    try:
        with path.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except FileNotFoundError:
        _logger.debug("Candidate discovery file not found: %s", path)
    except json.JSONDecodeError as exc:
        _logger.warning("Malformed JSON in candidate discovery file %s: %s", path, exc)
    except Exception as exc:  # pragma: no cover – unexpected I/O errors
        _logger.exception("Unexpected error reading candidate discovery file %s: %s", path, exc)
    return None


def discover_local_candidates() -> List[Mapping[str, Any]]:
    """Return a list of federation candidate specifications.

    The function looks for ``artifacts/federation_candidates.json`` relative to the
    project root. The expected JSON structure is a list of mappings, each mapping
    representing a candidate. Minimal validation is performed:

    * Each candidate must contain a ``candidate_id`` (string) and an ``endpoint``
      (string). ``capabilities`` is optional.
    * Candidates missing required keys are skipped with a debug log entry.

    The returned list is safe to mutate by callers; a shallow copy of each
    candidate mapping is provided.
    """
    raw = _load_json_file(_CANDIDATES_FILE)
    if not isinstance(raw, list):
        _logger.info("No valid candidate list found in %s; returning empty list.", _CANDIDATES_FILE)
        return []

    valid_candidates: List[Mapping[str, Any]] = []
    for idx, cand in enumerate(raw):
        if not isinstance(cand, dict):
            _logger.debug("Skipping non‑dict candidate at index %s: %r", idx, cand)
            continue
        cand_id = cand.get("candidate_id")
        endpoint = cand.get("endpoint")
        if not isinstance(cand_id, str) or not isinstance(endpoint, str):
            _logger.debug(
                "Candidate missing required fields at index %s: candidate_id=%r, endpoint=%r",
                idx,
                cand_id,
                endpoint,
            )
            continue
        # Shallow copy to prevent accidental mutation of the original data.
        valid_candidates.append(dict(cand))

    _logger.debug("Discovered %d valid federation candidates.", len(valid_candidates))
    return valid_candidates
