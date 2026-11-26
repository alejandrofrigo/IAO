"""High‑level façade for federation operations.

This module provides a tiny orchestrator that ties together the core federation
modules:

* creation of a proposal (omega.federation_proposals.Proposal)
* cryptographic signing (omega.federation_utils.sign_proposal)
* in‑memory persistence (omega.federation_proposal_store.ProposalStore)
* assimilation processing (omega.federation_assimilation_processor.assimilate)

All steps raise explicit exceptions when validation fails, enabling the test‑
suite to verify the complete life‑cycle without contacting external participants.
"""

from __future__ import annotations

import threading
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Lazy import helper – avoids circular imports and keeps import time low.
# ---------------------------------------------------------------------------
def _lazy_import(module_name: str):
    import importlib
    return importlib.import_module(module_name)

# ---------------------------------------------------------------------------
# Thread‑safe singleton wrapper around the in‑memory proposal store.
# ---------------------------------------------------------------------------
class _ProposalStoreSingleton:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                store_mod = _lazy_import("omega.federation_proposal_store")
                cls._instance = store_mod.ProposalStore()
            return cls._instance

# ---------------------------------------------------------------------------
# Public façade.
# ---------------------------------------------------------------------------
class FederationFacade:
    """Orchestrates creation, signing, storage and assimilation of proposals.

    The façade is deliberately lightweight: it only coordinates calls to the
    existing, well‑tested building blocks.  No network I/O or external state is
    introduced, keeping the implementation safe for the PADGE sandbox.
    """

    def __init__(self) -> None:
        # Resolve required modules lazily to prevent import‑time side effects.
        self._proposals_mod = _lazy_import("omega.federation_proposals")
        self._utils_mod = _lazy_import("omega.federation_utils")
        self._assim_mod = _lazy_import("omega.federation_assimilation_processor")
        self._store = _ProposalStoreSingleton()

    # -------------------------------------------------------------------
    # Basic building‑block operations.
    # -------------------------------------------------------------------
    def create_proposal(self, payload: Dict[str, Any]):
        """Instantiate a :class:`Proposal` from an arbitrary payload dict.

        The concrete ``Proposal`` class is provided by ``omega.federation_proposals``.
        """
        ProposalCls = getattr(self._proposals_mod, "Proposal")
        return ProposalCls(payload)

    def sign_proposal(self, proposal) -> bytes:
        """Sign *proposal* using the operator's Ed25519 key.

        The underlying implementation lives in ``omega.federation_utils``.
        """
        sign_fn = getattr(self._utils_mod, "sign_proposal")
        return sign_fn(proposal)

    def store_proposal(self, proposal, signature: bytes) -> str:
        """Persist a signed proposal and return its identifier.

        The store is a singleton in‑memory ``ProposalStore`` instance.
        """
        self._store.add(proposal, signature)
        # The proposal class is required to expose a stable ``id`` attribute.
        return getattr(proposal, "id")

    def assimilate(self, proposal_id: str) -> None:
        """Run the assimilation pipeline for a stored proposal.

        Steps:
        1. Retrieve the proposal and its signature from the store.
        2. Verify the signature using ``omega.federation_utils``.
        3. Invoke the assimilation processor.
        """
        entry = self._store.get(proposal_id)
        if entry is None:
            raise KeyError(f"Proposal {proposal_id!r} not found in store")
        proposal, signature = entry

        # Verify the Ed25519 signature before any state change.
        verify_fn = getattr(self._utils_mod, "verify_proposal_signature")
        if not verify_fn(proposal, signature):
            raise ValueError("Invalid proposal signature")

        # Execute assimilation.
        assimilate_fn = getattr(self._assim_mod, "assimilate")
        assimilate_fn(proposal)

    # -------------------------------------------------------------------
    # Convenience combined workflow.
    # -------------------------------------------------------------------
    def create_sign_store(self, payload: Dict[str, Any]) -> str:
        """Create a proposal, sign it, store it and return its identifier.

        This helper mirrors the typical path exercised by federation tests.
        """
        proposal = self.create_proposal(payload)
        signature = self.sign_proposal(proposal)
        return self.store_proposal(proposal, signature)
