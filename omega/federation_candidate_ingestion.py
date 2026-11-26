"""Federation Candidate Ingestion Utilities.

This module provides a safe, deterministic way to load federation candidate
definitions from a local JSON artifact and register them in the in‑memory
candidate registry. It is deliberately side‑effect free with respect to the
network – all operations are performed on local data, making it suitable for
unit‑tests and controlled deployments.

Typical usage::

    from omega.federation_candidate_ingestion import ingest_candidates_from_file
    ingest_candidates_from_file('/path/to/candidates.json')

The JSON file must contain an array of candidate objects. Each candidate is
validated using the existing ``omega.federation_capability_validator`` module
before being registered via ``omega.federation_candidate_registry``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable, List

# Local imports – these modules are part of the federation subsystem and are
# expected to be present in the current code base.
from omega.federation_capability_validator import validate_candidate_capabilities
from omega.federation_candidate_registry import FederationCandidateRegistry

_logger = logging.getLogger(__name__)


def _load_json_file(filepath: Path) -> List[Any]:
    """Read *filepath* and return its JSON content.

    The function raises a ``ValueError`` with a clear message if the file cannot
    be read or does not contain a JSON array.
    """
    try:
        with filepath.open('r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as exc:
        raise ValueError(f"Failed to read JSON file '{filepath}': {exc}") from exc

    if not isinstance(data, list):
        raise ValueError(
            f"Candidate file '{filepath}' must contain a JSON array of candidates"
        )
    return data


def _register_candidate(candidate: Any) -> None:
    """Validate and register a single *candidate*.

    Validation is performed by ``validate_candidate_capabilities``. If validation
    fails, a ``ValueError`` is raised and the candidate is **not** registered.
    Successful candidates are stored in the singleton ``FederationCandidateRegistry``.
    """
    # Validation may raise; we let it propagate to inform the caller.
    validate_candidate_capabilities(candidate)
    registry = FederationCandidateRegistry.get_instance()
    registry.register(candidate)
    _logger.debug("Registered federation candidate: %s", candidate.get('id', '<no‑id>'))


def ingest_candidates_from_file(file_path: str | Path) -> int:
    """Ingest federation candidates from *file_path*.

    Parameters
    ----------
    file_path: str | Path
        Path to a JSON file containing an array of candidate objects.

    Returns
    -------
    int
        The number of candidates successfully registered.

    Raises
    ------
    ValueError
        If the file cannot be read, does not contain a JSON array, or any
        candidate fails validation.
    """
    path = Path(file_path)
    candidates = _load_json_file(path)
    registered = 0
    for cand in candidates:
        _register_candidate(cand)
        registered += 1
    _logger.info("Ingested %d federation candidate(s) from %s", registered, path)
    return registered


__all__ = [
    "ingest_candidates_from_file",
]
