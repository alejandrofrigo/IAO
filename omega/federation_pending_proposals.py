# -*- coding: utf-8 -*-
"""Utility to list pending federation proposal files.

This module provides a single deterministic function that scans a given
directory for JSON files that are expected to contain federation proposals.
It does **not** validate the content – validation is delegated to the
existing ``omega.federation_proposal_validator`` module.  The purpose of the
function is to support the discovery phase of the federation workflow and
to enable reproducible unit‑tests that can feed known proposal files to the
higher‑level processing pipeline.

The implementation is deliberately minimal and safe:
* Only regular files with a ``.json`` suffix are returned.
* Symbolic links are ignored to avoid accidental traversal outside the
  intended directory.
* Errors such as missing directories raise ``FileNotFoundError`` – they are
  not silently swallowed, allowing calling code to react appropriately.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

__all__: List[str] = ["list_pending_proposals"]


def list_pending_proposals(directory: str | os.PathLike) -> List[Path]:
    """Return a list of ``Path`` objects representing pending proposal files.

    Parameters
    ----------
    directory: str | os.PathLike
        The directory to scan. It must exist and be readable.

    Returns
    -------
    List[Path]
        A list of absolute ``Path`` objects for each ``*.json`` file found
        directly inside *directory* (non‑recursive).  The list is sorted
        alphabetically to provide deterministic ordering.

    Raises
    ------
    FileNotFoundError
        If *directory* does not exist.
    NotADirectoryError
        If *directory* exists but is not a directory.
    PermissionError
        If the process lacks permission to read the directory.
    """
    dir_path = Path(directory).expanduser().resolve()

    if not dir_path.exists():
        raise FileNotFoundError(f"Directory does not exist: {dir_path}")
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {dir_path}")

    # Gather files with .json suffix, ignore symlinks for safety.
    proposals: List[Path] = []
    for entry in dir_path.iterdir():
        if entry.is_file() and not entry.is_symlink() and entry.suffix.lower() == ".json":
            proposals.append(entry)

    # Deterministic order for reproducibility.
    proposals.sort()
    return proposals
