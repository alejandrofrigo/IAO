"""Safe assimilation utilities for federation proposals.

Provides a wrapper that verifies proposal signatures before delegating to the
core assimilation logic. This ensures that only proposals signed with a valid
Ed25519 key are processed, preventing unauthorized or tampered proposals from
being assimilated.
"""

from typing import Any, Dict

# Import the core assimilation function. It is expected to exist in the
# ``omega.federation_assimilation`` module and to accept a proposal dict.
from .federation_assimilation import assimilate_proposal

# Import the signature verification utility. It should return ``True`` when the
# proposal is correctly signed and ``False`` otherwise.
from .federation_proposal_verification import verify_proposal_signature


def safe_assimilate_proposal(proposal: Dict[str, Any]) -> bool:
    """Verify and assimilate a federation proposal.

    Args:
        proposal: The federation proposal dictionary. Expected to contain the
            fields ``payload`` (bytes or str), ``signature`` (bytes), and
            ``public_key`` (bytes) as produced by the proposal builder.

    Returns:
        True if the proposal was successfully verified and assimilated,
        False otherwise.

    Raises:
        ValueError: If verification fails.
    """
    # First, ensure the proposal's cryptographic signature is valid.
    if not verify_proposal_signature(proposal):
        raise ValueError("Proposal signature verification failed")

    # Proceed with the core assimilation logic now that the proposal is
    # authenticated.
    return assimilate_proposal(proposal)
