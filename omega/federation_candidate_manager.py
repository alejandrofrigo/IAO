'''omega/federation_candidate_manager.py

In‑memory manager for federation candidates.

The manager provides a very small public API that can be used by the test suite
or higher‑level orchestration code to:

* Discover candidates from an arbitrary source (here a simple iterable of dicts).
* Validate the structural integrity of a candidate (required fields, address
  format, Ed25519 public‑key length).
* Perform a *mock* connectivity check – in a production environment this would
  attempt an HTTPS/TCP handshake; in the test environment it simply returns
  ``True`` for addresses that look syntactically correct.
* Register a validated candidate in a module‑level registry.
* Retrieve, list and revoke candidates.

All operations are pure Python and do not perform any network I/O, making the
implementation safe for the sandboxed PADGE environment while still providing a
realistic behaviour surface for the federation workflow.
''' 

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Candidate:
    """Immutable representation of a federation candidate.

    Attributes
    ----------
    candidate_id: str
        Unique identifier for the candidate (e.g., a UUID or hash).
    address: str
        Network address (IP or hostname) where the candidate can be reached.
    ed25519_pubkey: bytes
        Ed25519 public key used for signature verification. The key must be
        exactly 32 bytes long.
    metadata: Mapping[str, str]
        Optional free‑form metadata supplied by the operator.
    """

    candidate_id: str
    address: str
    ed25519_pubkey: bytes
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # ``dataclass`` with ``frozen=True`` prevents mutation; the following
        # checks raise ``ValueError`` if the instance is malformed.
        if not self.candidate_id:
            raise ValueError("candidate_id must be a non‑empty string")
        if not isinstance(self.ed25519_pubkey, (bytes, bytearray)):
            raise ValueError("ed25519_pubkey must be bytes")
        if len(self.ed25519_pubkey) != 32:
            raise ValueError("ed25519_pubkey must be exactly 32 bytes (Ed25519 public key)")
        # ``address`` validation is performed in ``validate_candidate``; we keep
        # the constructor lightweight.

# ---------------------------------------------------------------------------
# Internal registry (thread‑safe)
# ---------------------------------------------------------------------------

_registry_lock = threading.RLock()
_registry: Dict[str, Candidate] = {}

# ---------------------------------------------------------------------------
# Public helper functions
# ---------------------------------------------------------------------------

def discover_candidates(source: Iterable[Mapping[str, object]]) -> List[Candidate]:
    """Create ``Candidate`` objects from an iterable of dict‑like structures.

    The function is deliberately permissive – it yields a ``Candidate`` for each
    entry that contains the required keys. Validation of each candidate is
    deferred to :func:`validate_candidate` so callers can decide whether to keep
    or discard malformed entries.
    """

    candidates: List[Candidate] = []
    for entry in source:
        try:
            candidate = Candidate(
                candidate_id=str(entry["candidate_id"]),
                address=str(entry["address"]),
                ed25519_pubkey=bytes(entry["ed25519_pubkey"]),
                metadata=dict(entry.get("metadata", {})),
            )
            candidates.append(candidate)
        except Exception:
            # Silently ignore entries that cannot be coerced; callers can log
            # if needed.
            continue
    return candidates


def _is_valid_ip_or_hostname(address: str) -> bool:
    """Return ``True`` if *address* looks like a valid IP or hostname.

    The check is intentionally lightweight: it accepts IPv4, IPv6 and any
    non‑empty hostname that does not contain whitespace. This mirrors the level
    of validation performed by the original (pre‑refactor) candidate modules.
    """

    if not address:
        return False
    # Try IP address first – ``ipaddress`` raises a ``ValueError`` for invalid
    # inputs.
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        pass
    # Simple hostname validation: must be non‑empty, contain no whitespace and
    # consist of printable characters.
    if any(ch.isspace() for ch in address):
        return False
    return True


def validate_candidate(candidate: Candidate) -> bool:
    """Validate the structural integrity of *candidate*.

    Checks performed:

    * ``address`` is a syntactically valid IP or hostname.
    * ``ed25519_pubkey`` length has already been enforced by ``Candidate``.
    * ``candidate_id`` is non‑empty (enforced by ``Candidate``).
    """

    return _is_valid_ip_or_hostname(candidate.address)


def check_connectivity(candidate: Candidate) -> bool:
    """Mock connectivity check.

    In a real deployment this would attempt a TLS handshake or an HTTP ``HEAD``
    request. For the sandboxed test environment we simply return ``True`` when
    the address passes basic validation; otherwise ``False``.
    """

    return validate_candidate(candidate)


def register_candidate(candidate: Candidate) -> None:
    """Register *candidate* after validation and connectivity check.

    Raises
    ------
    ValueError
        If the candidate fails validation or connectivity.
    """

    if not validate_candidate(candidate):
        raise ValueError("Candidate structural validation failed")
    if not check_connectivity(candidate):
        raise ValueError("Candidate connectivity check failed")
    with _registry_lock:
        _registry[candidate.candidate_id] = candidate


def get_candidate(candidate_id: str) -> Optional[Candidate]:
    """Retrieve a registered candidate by its identifier.

    Returns ``None`` if the candidate is not present in the registry.
    """

    with _registry_lock:
        return _registry.get(candidate_id)


def list_candidates() -> List[Candidate]:
    """Return a snapshot list of all registered candidates."""

    with _registry_lock:
        return list(_registry.values())


def revoke_candidate(candidate_id: str) -> bool:
    """Revoke (remove) a registered candidate.

    Returns ``True`` if a candidate was removed, ``False`` otherwise.
    """

    with _registry_lock:
        return _registry.pop(candidate_id, None) is not None

# ---------------------------------------------------------------------------
# Exported names for lazy loader (__all__ is generated dynamically in
# ``omega.__init__``). Explicitly define the public interface to aid static
# analysis tools.
# ---------------------------------------------------------------------------

__all__ = [
    "Candidate",
    "discover_candidates",
    "validate_candidate",
    "check_connectivity",
    "register_candidate",
    "get_candidate",
    "list_candidates",
    "revoke_candidate",
]
