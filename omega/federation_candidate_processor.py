"""Orquestador central para el procesamiento de candidatos federados.

Este módulo combina las capacidades ya presentes en la infraestructura
federada:
- descubrimiento controlado de candidatos
- validación de capacidades requeridas
- comprobación de conectividad DNS/IP
- limitación de velocidad de operaciones
- seguimiento de estado del candidato
- expiración de propuestas firmadas

El objetivo es ofrecer una única API sencilla que pueda ser utilizada por
otros componentes o pruebas para procesar un candidato y obtener un
resultado determinístico.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

# Importar los componentes especializados. Se asume que existen y cumplen con la
# interfaz mínima descrita en sus respectivas docstrings.
from .federation_candidate_discovery import discover_candidate  # noqa: F401
from .federation_capability_validator import validate_capabilities  # noqa: F401
from .federation_dns_ip_check import check_dns_ip  # noqa: F401
from .federation_rate_limiter import RateLimiter  # noqa: F401
from .federation_state_tracker import CandidateStateTracker  # noqa: F401
from .federation_proposal_expiration import is_proposal_expired  # noqa: F401


class FederationCandidateProcessor:
    """Procesa un candidato federado aplicando todas las fases de control.

    La clase está diseñada para ser reutilizable y thread‑safe en la medida en que
    los componentes subyacentes lo permitan. El método ``process`` devuelve un
    diccionario con al menos la clave ``status`` cuyo valor será ``"accepted"``
    o ``"rejected"``. En caso de rechazo se incluye también la clave ``reason``.
    """

    def __init__(
        self,
        rate_limiter: RateLimiter | None = None,
        state_tracker: CandidateStateTracker | None = None,
    ) -> None:
        self.rate_limiter = rate_limiter or RateLimiter()
        self.state_tracker = state_tracker or CandidateStateTracker()

    def _ensure_candidate_id(self, candidate: Dict[str, Any]) -> str:
        if "id" not in candidate:
            raise ValueError("El candidato debe contener la clave 'id'.")
        return str(candidate["id"])

    def process(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta el flujo completo de procesamiento para un candidato.

        Pasos realizados:
        1. **Rate limiting** – Se verifica que el candidato no supere los
           límites configurados.
        2. **Descubrimiento** – Enriquecimiento opcional del candidato mediante
           ``discover_candidate``.
        3. **Validación de capacidades** – Comprueba que el candidato cumple con
           los requisitos de la red federada.
        4. **Comprobación DNS/IP** – Asegura que la dirección es resoluble y
           alcanzable.
        5. **Expiración de propuesta** – Si el candidato contiene una propuesta
           firmada, se verifica que no haya expirado.
        6. **Actualización de estado** – Se registra el estado final del
           candidato en el tracker.
        """
        candidate_id = self._ensure_candidate_id(candidate)

        # 1. Rate limiting
        self.rate_limiter.assert_allowed(candidate_id)

        # 2. Descubrimiento (puede modificar el diccionario)
        candidate = discover_candidate(candidate)

        # 3. Validación de capacidades
        if not validate_capabilities(candidate):
            self.state_tracker.update(candidate_id, "invalid_capabilities")
            return {"status": "rejected", "reason": "invalid_capabilities"}

        # 4. Comprobación DNS/IP
        if not check_dns_ip(candidate):
            self.state_tracker.update(candidate_id, "unreachable")
            return {"status": "rejected", "reason": "unreachable"}

        # 5. Expiración de propuesta (si existe)
        proposal = candidate.get("proposal")
        if proposal is not None and is_proposal_expired(proposal):
            self.state_tracker.update(candidate_id, "expired")
            return {"status": "rejected", "reason": "expired"}

        # 6. Todo correcto – marcar como listo
        self.state_tracker.update(candidate_id, "ready")
        return {"status": "accepted", "candidate": candidate}
