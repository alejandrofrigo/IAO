"""Verified assimilation utilities for federation proposals.

This module offers a thin wrapper around the existing assimilation logic that
first verifies the Ed25519 signature of a proposal using the provided public
key. Only proposals with valid signatures are passed to the underlying
assimilation routine, ensuring that unauthenticated data cannot affect the
local federation state.

The function is deliberately small and side‑effect‑free apart from invoking
the core ``assimilate_proposal`` function, making it suitable for unit testing
and direct operator use.
"""

from typing import Any

# Import the core assimilation function. The exact signature of
# ``assimilate_proposal`` may vary; it is expected to accept at least the raw
# proposal bytes. Additional arguments (e.g., metadata) can be passed through
# via ``*args`` and ``**kwargs`` if needed.
from .federation_assimilation import assimilate_proposal

# Import the signature verification helper that was added earlier.
from .federation_proposal_verification import verify_proposal_signature


def assimilate_verified_proposal(
    proposal: bytes,
    signature: bytes,
    public_key: bytes,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Verify and assimilate a federation proposal.

    Args:
        proposal: Serialized proposal payload (bytes).
        signature: Ed25519 signature covering ``proposal``.
        public_key: Ed25519 public key of the signer.
        *args, **kwargs: Additional arguments forwarded to the underlying
            ``assimilate_proposal`` implementation.

    Returns:
        Whatever ``assimilate_proposal`` returns when the proposal is accepted.

    Raises:
        ValueError: If the signature verification fails.
    """
    if not verify_proposal_signature(proposal, signature, public_key):
        raise ValueError("Proposal signature verification failed")

    # Forward the call to the original assimilation function. The wrapper does
    # not make assumptions about the exact parameter list beyond the required
    # ``proposal`` argument; extra positional or keyword arguments are passed
    # through unchanged.
    return assimilate_proposal(proposal, *args, **kwargs)
