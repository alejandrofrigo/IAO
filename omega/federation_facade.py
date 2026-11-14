"""High‑level façade for federation operations.

This module provides a small, test‑friendly API that ties together the
building blocks introduced in previous PADGE steps:

* ``omega.federation_validation.validate_candidate`` – validates a candidate
  description.
* ``omega.federation_proposal_builder.build_signed_proposal`` – creates a
  proposal and signs it with the authority's Ed25519 key.
* ``omega.federation_manager.FederationManager`` – optional state tracking for
  proposals and candidates.

The façade deliberately **does not** perform any network communication or
automatic enrolment of external participants; it works only with in‑memory or
locally supplied data, respecting all security constraints of the system.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .federation_validation import validate_candidate
from .federation_proposal_builder import build_signed_proposal
from .federation_manager import FederationManager


class FederationError(RuntimeError):
    """Base class for errors raised by :class:`FederationFacade`."""


class FederationFacade:
    """Coordinate the basic federation workflow.

    Typical usage::

        facade = FederationFacade(state_path="state.json")
        candidates = facade.load_candidates_from_file("candidates.json")
        signed = facade.validate_and_sign_candidates(candidates)
        facade.dump_state("state.json")
    """

    def __init__(self, state_path: str | Path | None = None) -> None:
        """Create a façade.

        Parameters
        ----------
        state_path: optional
            Path where the :class:`FederationManager` will persist its state.
            If omitted, an in‑memory manager is used.
        """
        if state_path is None:
            self.manager = FederationManager()
        else:
            self.manager = FederationManager(state_path=Path(state_path))

    # ---------------------------------------------------------------------
    # Discovery helpers
    # ---------------------------------------------------------------------
    @staticmethod
    def load_candidates_from_file(file_path: str | Path) -> List[Dict[str, Any]]:
        """Load a JSON file containing a list of candidate specifications.

        The file must contain a top‑level JSON array. Each element is passed
        unchanged to the validation routine.

        Raises
        ------
        FederationError
            If the file cannot be read or does not contain a valid JSON array.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:  # pragma: no cover – defensive
            raise FederationError(
                f"Unable to read candidates from {file_path!s}: {exc}"
            ) from exc

        if not isinstance(data, list):
            raise FederationError("Candidate file must contain a JSON array")
        return data

    # ---------------------------------------------------------------------
    # Validation + proposal creation
    # ---------------------------------------------------------------------
    def validate_and_sign_candidates(
        self,
        candidates: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Validate each candidate and return a list of signed proposals.

        The function performs three steps for every candidate:

        1. Validate the candidate description using :func:`validate_candidate`.
        2. Build a signed proposal with :func:`build_signed_proposal`.
        3. Register the signed proposal in the underlying
           :class:`FederationManager` for optional state tracking.

        Parameters
        ----------
        candidates
            An iterable of candidate dictionaries.

        Returns
        -------
        list[dict]
            The signed proposal objects as produced by ``build_signed_proposal``.

        Raises
        ------
        FederationError
            If validation fails for any candidate or proposal creation raises.
        """
        signed: List[Dict[str, Any]] = []
        for cand in candidates:
            # ---- validation -------------------------------------------------
            try:
                validate_candidate(cand)
            except Exception as exc:  # pragma: no cover – defensive
                raise FederationError(f"Candidate validation failed: {exc}") from exc

            # ---- proposal construction --------------------------------------
            try:
                proposal = build_signed_proposal(cand)
            except Exception as exc:  # pragma: no cover – defensive
                raise FederationError(f"Proposal building failed: {exc}") from exc

            # ---- optional state registration --------------------------------
            try:
                # ``register_proposal`` is part of the public API introduced in
                # ``federation_manager``; if it is not present we ignore the call.
                getattr(self.manager, "register_proposal", lambda *_: None)(proposal)
            except Exception:
                # State tracking is non‑essential for the façade; failures are
                # deliberately ignored to keep the core flow robust.
                pass

            signed.append(proposal)
        return signed

    # ---------------------------------------------------------------------
    # State persistence helpers
    # ---------------------------------------------------------------------
    def dump_state(self, file_path: str | Path) -> None:
        """Serialise the internal ``FederationManager`` state to *file_path*.

        The manager already knows how to serialise its state; this method simply
        forwards the call and converts any exception into ``FederationError``.
        """
        try:
            self.manager.dump_state(Path(file_path))
        except Exception as exc:  # pragma: no cover – defensive
            raise FederationError(f"Unable to dump federation state: {exc}") from exc

    def load_state(self, file_path: str | Path) -> None:
        """Load previously stored manager state from *file_path*.

        Mirrors :meth:`dump_state` for symmetry.
        """
        try:
            self.manager.load_state(Path(file_path))
        except Exception as exc:  # pragma: no cover – defensive
            raise FederationError(f"Unable to load federation state: {exc}") from exc
