# -*- coding: utf-8 -*-
"""Orquestador de candidatos federados.

Esta pieza central coordina tres pasos críticos:
1. **Descubrimiento** de candidatos candidatos mediante ``federation_candidate_discovery``.
2. **Validación** de las capacidades declaradas de cada candidato mediante ``federation_candidate_validation_report``.
3. **Comprobación de conectividad** (DNS + HTTPS) mediante ``federation_participant_connectivity``.

El orquestador está diseñado para ser determinista, respetar límites de recursos
y permitir filtrado opcional de dominios de nivel superior (TLD). Cada candidato
procesado produce un registro estructurado con los resultados de cada fase y
cualquier error encontrado.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

# Lazy import helpers to avoid hard dependencies at import time
from . import _safe_import  # type: ignore

# ---------------------------------------------------------------------------
# Internals – wrappers around existing low‑level modules
# ---------------------------------------------------------------------------

def _discover_candidates() -> List[Dict[str, Any]]:
    discover = _safe_import("omega.federation_candidate_discovery", "discover_candidates")
    if discover is None:
        raise RuntimeError("Módulo de descubrimiento de candidatos no disponible.")
    return discover()

def _validate_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    validator = _safe_import("omega.federation_candidate_validation_report", "validate_candidate")
    if validator is None:
        raise RuntimeError("Validador de candidato no disponible.")
    return validator(candidate)

def _check_connectivity(candidate: Dict[str, Any]) -> bool:
    connectivity = _safe_import("omega.federation_participant_connectivity", "check_participant_connectivity")
    if connectivity is None:
        raise RuntimeError("Chequeo de conectividad no disponible.")
    participant_id = candidate.get("id")
    if not participant_id:
        return False
    return connectivity(participant_id)

# ---------------------------------------------------------------------------
# Public orchestrator API
# ---------------------------------------------------------------------------

def discover_and_process_candidates(
    max_candidates: int = 10,
    allowed_tlds: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Descubre, valida y verifica la conectividad de candidatos federados.

    Parameters
    ----------
    max_candidates: int
        Número máximo de candidatos a procesar. Si el descubrimiento devuelve
        más, se truncará la lista.
    allowed_tlds: Optional[Set[str]]
        Conjunto de TLDs permitidos (p.ej. {"org", "edu"}). Si se proporciona,
        los candidatos cuyo dominio no coincida serán descartados.

    Returns
    -------
    List[Dict[str, Any]]
        Lista de reportes por candidato. Cada dict contiene al menos:
        ``id``, ``domain``, ``validation`` (resultado del validador), ``connectivity``
        (bool) y ``errors`` (lista de strings).
    """
    raw_candidates = _discover_candidates()
    processed: List[Dict[str, Any]] = []
    count = 0
    for cand in raw_candidates:
        if count >= max_candidates:
            break
        # Opcional filtrado por TLD
        domain = cand.get("domain", "")
        if allowed_tlds is not None:
            m = re.search(r"\.([a-zA-Z0-9-]+)$", domain)
            tld = m.group(1).lower() if m else ""
            if tld not in allowed_tlds:
                continue
        report: Dict[str, Any] = {
            "id": cand.get("id"),
            "domain": domain,
            "validation": None,
            "connectivity": False,
            "errors": [],
        }
        # Validación de capacidades
        try:
            validation_res = _validate_candidate(cand)
            report["validation"] = validation_res
        except Exception as exc:  # pragma: no cover
            report["errors"].append(f"validation_error: {exc}")
        # Chequeo de conectividad
        try:
            report["connectivity"] = _check_connectivity(cand)
        except Exception as exc:  # pragma: no cover
            report["errors"].append(f"connectivity_error: {exc}")
        processed.append(report)
        count += 1
    return processed
