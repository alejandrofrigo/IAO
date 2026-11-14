# -*- coding: utf-8 -*-
"""Utilities for loading and validating federation proposals from JSON files.

This module provides two high‑level helpers that combine file I/O, structural
validation and cryptographic signature verification for federation proposals.
They are deterministic, side‑effect free and can be used in tests and in
operator tooling without requiring network access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

# Local imports are lazy‑loaded via the package's safe import mechanism to
# avoid circular import issues.
from .federation_proposal_validator import validate_proposal_structure
from .federation_verify_signature import verify_proposal_signature

__all__ = ["load_proposal", "load_and_validate_proposal"]


def load_proposal(file_path: str | Path) -> Dict[str, Any]:
    """Read a federation proposal JSON file and return its decoded dictionary.

    Parameters
    ----------
    file_path: str or Path
        Path to the JSON file containing the proposal.

    Returns
    -------
    dict
        The parsed JSON content.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If the file content is not valid JSON.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Proposal file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_and_validate_proposal(
    file_path: str | Path,
    signer_public_key: bytes,
) -> Optional[Dict[str, Any]]:
    """Load a proposal, validate its structure and verify its Ed25519 signature.

    This helper performs three deterministic steps:

    1. Load the JSON representation from *file_path*.
    2. Validate that the payload conforms to the required schema using
       ``validate_proposal_structure``.
    3. Verify the attached Ed25519 signature with ``verify_proposal_signature``.

    If any step fails, ``None`` is returned; otherwise the fully‑validated
    proposal dictionary is returned.

    Parameters
    ----------
    file_path: str or Path
        Path to the proposal JSON file.
    signer_public_key: bytes
        The Ed25519 public key of the expected signer.

    Returns
    -------
    dict | None
        The validated proposal on success, or ``None`` on failure.
    """
    try:
        proposal = load_proposal(file_path)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    # Step 2: structural validation
    if not validate_proposal_structure(proposal):
        return None

    # Step 3: signature verification
    if not verify_proposal_signature(proposal, signer_public_key):
        return None

    return proposal
