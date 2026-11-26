# -*- coding: utf-8 -*-
"""Utility to verify HTTPS connectivity for a registered federation participant.

This module implements a single public function :func:`check_participant_connectivity`
that resolves a participant by its identifier, retrieves the stored endpoint URL
and performs a lightweight HTTPS reachability test. The function returns a
structured ``dict`` containing the endpoint, a boolean ``reachable`` flag and an
optional ``error`` message. All imports are performed lazily via the package's
``_safe_import`` helper to avoid import‑time failures when optional components are
missing.
"""

from __future__ import annotations

from typing import Any, Dict

# Lazy imports using the package‑level helper to keep the package importable even
# if optional modules are unavailable.
try:
    from . import _safe_import
except Exception:  # pragma: no cover
    # Fallback in case the helper is not present (should never happen in the
    # current package layout).
    def _safe_import(module_name: str, attribute: str) -> Any:  # type: ignore
        return None

# Resolve the participant registry accessor.
_get_participant = _safe_import('omega.federation_participant_registry', 'get_participant')
# Resolve the low‑level connectivity checker (expects ``endpoint`` and ``timeout``).
_check_endpoint = _safe_import('omega.federation_connectivity', 'check_endpoint')


def _require_callable(name: str, fn: Any) -> Any:
    """Validate that *fn* is a callable, otherwise raise an informative error.

    This helper centralises the error handling for missing optional imports.
    """
    if not callable(fn):
        raise ImportError(
            f"Required callable '{name}' is unavailable. Ensure the corresponding "
            f"module is present and exports the expected attribute."
        )
    return fn


def check_participant_connectivity(participant_id: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Check HTTPS reachability for the participant identified by *participant_id*.

    Parameters
    ----------
    participant_id: str
        Identifier of the participant as stored in the participant registry.
    timeout: float, optional
        Maximum number of seconds to wait for the HTTPS request. Defaults to ``5``.

    Returns
    -------
    dict
        ``{"endpoint": str, "reachable": bool, "error": Optional[str]}``
        * ``endpoint`` – the URL stored for the participant.
        * ``reachable`` – ``True`` if the endpoint responded within *timeout*,
          ``False`` otherwise.
        * ``error`` – ``None`` on success or a string describing the failure.
    """
    # Retrieve participant metadata.
    if _get_participant is None:
        raise ImportError(
            "Participant registry accessor 'get_participant' is unavailable. "
            "Ensure 'omega.federation_participant_registry' provides this function."
        )
    get_participant = _require_callable('get_participant', _get_participant)
    participant = get_participant(participant_id)
    if not participant:
        raise ValueError(f"Participant with id '{participant_id}' not found.")

    endpoint = participant.get('endpoint')
    if not endpoint:
        raise ValueError(f"Participant '{participant_id}' does not have an 'endpoint' field.")

    # Perform the connectivity test.
    if _check_endpoint is None:
        raise ImportError(
            "Connectivity checker 'check_endpoint' is unavailable. "
            "Ensure 'omega.federation_connectivity' provides this function."
        )
    check_endpoint = _require_callable('check_endpoint', _check_endpoint)
    try:
        reachable = check_endpoint(endpoint, timeout=timeout)
        error_msg: str | None = None
    except Exception as exc:  # pragma: no cover – defensive, unlikely in tests
        reachable = False
        error_msg = str(exc)

    return {
        'endpoint': endpoint,
        'reachable': reachable,
        'error': error_msg,
    }
