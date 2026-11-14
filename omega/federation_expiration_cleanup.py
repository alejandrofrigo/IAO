'''Utility to purge expired federation proposals.

This module defines a single public function ``clean_expired_proposals`` that
loads all stored federation proposals, determines which ones are expired
according to the logic provided by ``omega.federation_proposal_expiration``
and removes them from the persistent store using the API from
``omega.federation_proposal_store``.  The function returns a list of proposal
identifiers that were successfully deleted, allowing callers (e.g. a
maintenance task or an admin CLI) to report the cleanup outcome.

The implementation relies exclusively on the existing, verified components of
the federation pipeline and uses the tolerant ``_safe_import`` helper from the
package ``omega.__init__`` to avoid hard failures if optional utilities are
temporarily unavailable.
'''  # noqa: D400,D401

from __future__ import annotations

from typing import List, Any

# Import the safe import helper from the package initializer.  Using _safe_import
# ensures that the cleanup utility can be imported even in minimal environments
# where optional federation sub‑modules are missing.
try:
    from . import _safe_import  # type: ignore
except Exception:  # pragma: no cover
    # Fallback: define a minimal version that never fails.
    def _safe_import(module_path: str, attr: str | None = None) -> Any:  # type: ignore
        try:
            module = __import__(module_path, fromlist=["*"])
            return getattr(module, attr) if attr else module
        except Exception:  # noqa: BLE001
            return None

# ------------------------------------------------------------
# Lazy imports of federation utilities via the tolerant helper.
# ------------------------------------------------------------

# Store API – expected to provide ``load_all_proposals()`` and ``delete_proposal(proposal_id)``.
_store_module = _safe_import("omega.federation_proposal_store")
load_all_proposals = getattr(_store_module, "load_all_proposals", None)
delete_proposal = getattr(_store_module, "delete_proposal", None)

# Expiration checker – expected to provide ``is_expired(proposal)``.
_expiration_module = _safe_import("omega.federation_proposal_expiration")
is_expired = getattr(_expiration_module, "is_expired", None)

# Optional logger – if the package provides a logger we use it, otherwise a no‑op.
_logger = _safe_import("omega", "logger")
if _logger is None:
    class _NullLogger:
        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

    _logger = _NullLogger()


def _ensure_callable(name: str, func: Any) -> None:
    """Raise a clear error if a required callable is missing.

    The cleanup utility is only usable when the underlying federation store
    and expiration checker are present.  By failing fast with a descriptive
    exception we avoid silent data loss.
    """
    if not callable(func):
        raise RuntimeError(
            f"Required federation utility '{name}' is not available. "
            "Ensure that the corresponding module is present and implements the "
            "expected callable."
        )


def clean_expired_proposals() -> List[str]:
    """Remove all expired federation proposals from persistent storage.

    Returns
    -------
    List[str]
        A list containing the identifiers (or keys) of the proposals that were
        successfully deleted.

    Notes
    -----
    * The function is idempotent – calling it repeatedly will only delete each
      expired proposal once.
    * It operates entirely offline; no network requests are performed.
    * Errors while processing an individual proposal are logged and the
      remaining proposals are still examined.
    """
    # Verify that required utilities are present.
    _ensure_callable("load_all_proposals", load_all_proposals)
    _ensure_callable("delete_proposal", delete_proposal)
    _ensure_callable("is_expired", is_expired)

    deleted_ids: List[str] = []

    try:
        all_proposals = load_all_proposals()  # Expected to return an iterable of dicts
    except Exception as exc:  # pragma: no cover
        _logger.warning("Failed to load federation proposals: %s", exc)
        return deleted_ids

    for proposal in all_proposals:
        try:
            proposal_id = proposal.get("id") or proposal.get("proposal_id")
            if proposal_id is None:
                _logger.warning("Proposal missing identifier, skipping: %s", proposal)
                continue

            if is_expired(proposal):
                delete_proposal(proposal_id)
                deleted_ids.append(str(proposal_id))
                _logger.info("Deleted expired federation proposal %s", proposal_id)
        except Exception as exc:  # pragma: no cover
            _logger.warning(
                "Error processing proposal %s during expiration cleanup: %s",
                proposal.get("id", "<unknown>"),
                exc,
            )
            continue

    return deleted_ids

# The module's public interface is intentionally small – only the cleanup function
# is exported.  This makes it straightforward to import from maintenance scripts
# or scheduled jobs without pulling in the entire federation stack.
__all__ = ["clean_expired_proposals"]
