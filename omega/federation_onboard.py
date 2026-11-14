# -*- coding: utf-8 -*-
"""High‑level orchestrator for onboarding a federation candidate.

The function :func:`onboard_candidate` performs the complete, deterministic
pipeline required to bring a new participant into the federated network:

1. Load a candidate descriptor (JSON/YAML) from a local path.
2. Validate the descriptor's structural and capability requirements using the
   existing ``omega.federation_candidate_validation_report`` utilities.
3. Optionally verify that the declared endpoint(s) are reachable via a limited
   TCP connect test (uses ``omega.federation_endpoint_connectivity``).
4. Generate a federation proposal for the candidate (``omega.federation_proposal_generator``).
5. Sign the proposal with the provided Ed25519 private key (deterministic
   signing – the helper lives in ``omega.federation_proposal_signature``).
6. Assimilate the signed proposal into the local federation store using the
   controller ``omega.federation_assimilation_controller``.
7. Return a structured report describing each step and any errors encountered.

All operations are performed offline except for the optional connectivity test,
which is bounded by a short timeout and does not perform any data‑exfiltration.
The orchestrator is deliberately side‑effect‑free apart from the final assimilation
step, making it suitable for unit‑tests and automated pipelines.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict, Optional

# Import lazy‑loaded sub‑modules; they will be loaded only when used.
from . import (
    federation_candidate_validation_report as validation_report,
    federation_endpoint_connectivity as endpoint_conn,
    federation_proposal_generator as proposal_gen,
    federation_proposal_signature as proposal_sig,
    federation_assimilation_controller as assimilation_ctrl,
)

__all__ = ["onboard_candidate"]


def _load_descriptor(path: str) -> Dict[str, Any]:
    """Load a candidate descriptor from *path*.

    Supported formats are JSON and YAML (if ``yaml`` is available). The function
    raises ``FileNotFoundError`` or ``json.JSONDecodeError``/``yaml.YAMLError``
    for invalid input.
    """
    p = pathlib.Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Candidate descriptor not found: {path}")

    if p.suffix.lower() in {".json"}:
        return json.loads(p.read_text(encoding="utf-8"))
    # YAML support is optional; fallback to JSON if yaml package missing.
    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover
        raise ValueError("YAML descriptors require PyYAML to be installed")
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def onboard_candidate(
    descriptor_path: str,
    signing_private_key: bytes,
    *,
    check_endpoint_connectivity: bool = True,
    connectivity_timeout: float = 2.0,
) -> Dict[str, Any]:
    """Orchestrate the end‑to‑end onboarding of a federation candidate.

    Parameters
    ----------
    descriptor_path: str
        Path to the candidate descriptor file (JSON or YAML).
    signing_private_key: bytes
        Raw Ed25519 private key used to sign the generated proposal.
    check_endpoint_connectivity: bool, default ``True``
        Whether to perform a bounded TCP connectivity test for each declared
        endpoint. Set to ``False`` for pure offline validation.
    connectivity_timeout: float, default ``2.0``
        Socket timeout (seconds) for the connectivity check.

    Returns
    -------
    dict
        Structured report with keys ``descriptor``, ``validation``, ``connectivity``
        (optional), ``proposal``, ``signature`` and ``assimilation`` indicating the
        outcome of each stage.
    """
    report: Dict[str, Any] = {
        "descriptor_path": descriptor_path,
        "steps": {},
    }

    # 1. Load descriptor
    try:
        descriptor = _load_descriptor(descriptor_path)
        report["steps"]["load_descriptor"] = {"status": "ok"}
    except Exception as exc:  # pragma: no cover
        report["steps"]["load_descriptor"] = {"status": "error", "error": str(exc)}
        return report

    # 2. Structural / capability validation
    try:
        validation_result = validation_report.validate_candidate_descriptor(descriptor)
        report["steps"]["validation"] = {"status": "ok", "result": validation_result}
    except Exception as exc:  # pragma: no cover
        report["steps"]["validation"] = {"status": "error", "error": str(exc)}
        return report

    # 3. Optional endpoint connectivity check
    if check_endpoint_connectivity:
        try:
            connectivity = endpoint_conn.check_candidate_endpoints(
                descriptor, timeout=connectivity_timeout
            )
            report["steps"]["connectivity"] = {"status": "ok", "result": connectivity}
        except Exception as exc:  # pragma: no cover
            report["steps"]["connectivity"] = {"status": "error", "error": str(exc)}
            return report

    # 4. Generate proposal
    try:
        proposal = proposal_gen.generate_proposal_from_descriptor(descriptor)
        report["steps"]["proposal"] = {"status": "ok", "proposal": proposal}
    except Exception as exc:  # pragma: no cover
        report["steps"]["proposal"] = {"status": "error", "error": str(exc)}
        return report

    # 5. Sign proposal
    try:
        signed_proposal = proposal_sig.sign_proposal(proposal, signing_private_key)
        report["steps"]["signature"] = {"status": "ok", "signed_proposal": signed_proposal}
    except Exception as exc:  # pragma: no cover
        report["steps"]["signature"] = {"status": "error", "error": str(exc)}
        return report

    # 6. Assimilate proposal
    try:
        assimilation_result = assimilation_ctrl.assimilate_proposal(signed_proposal)
        report["steps"]["assimilation"] = {"status": "ok", "result": assimilation_result}
    except Exception as exc:  # pragma: no cover
        report["steps"]["assimilation"] = {"status": "error", "error": str(exc)}
        return report

    # Final aggregate status
    report["overall_status"] = "success"
    return report
