'''Thread‑safe wrapper for the in‑memory federation proposal store.

Este módulo expone `ThreadSafeProposalStore`, una capa que protege todas
las operaciones del almacén subyacente (`ProposalStore`) mediante un
`threading.RLock`.  Se preserva la API pública del almacén original para
que el resto del código (orquestadores, pruebas, servicios) pueda seguir
utilizándolo sin cambios.

Uso típico:

```python
from omega.federation_proposal_store_threadsafe import ThreadSafeProposalStore
store = ThreadSafeProposalStore()
store.add_proposal(proposal)
obj = store.get_proposal(proposal.id)
```
''' 

import threading
from typing import Any, Dict, Iterable, List

# Importamos la implementación original del almacén.  Se asume que el
# módulo define una clase `ProposalStore` con los métodos `add_proposal`,
# `get_proposal`, `revoke_proposal` y `list_active`.
from .federation_proposal_store import ProposalStore


class ThreadSafeProposalStore:
    """Wrapper que garantiza acceso exclusivo a la instancia subyacente.

    La clase expone la misma interfaz que `ProposalStore` pero protege
    cada operación con un `RLock`.  Esto permite su uso en entornos donde
    múltiples hilos pueden interactuar simultáneamente con el mismo
    almacén sin introducir condiciones de carrera.
    """

    def __init__(self) -> None:
        self._store = ProposalStore()
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------
    # Operaciones de escritura
    # ---------------------------------------------------------------------
    def add_proposal(self, proposal: Any) -> None:
        """Añade una propuesta al almacén de forma segura.

        Args:
            proposal: Instancia de propuesta que debe cumplir la API
                esperada por `ProposalStore.add_proposal`.
        """
        with self._lock:
            self._store.add_proposal(proposal)

    def revoke_proposal(self, proposal_id: str) -> None:
        """Revoca una propuesta existente.

        Args:
            proposal_id: Identificador único de la propuesta a revocar.
        """
        with self._lock:
            self._store.revoke_proposal(proposal_id)

    # ---------------------------------------------------------------------
    # Operaciones de lectura
    # ---------------------------------------------------------------------
    def get_proposal(self, proposal_id: str) -> Any:
        """Recupera una propuesta por su identificador.

        Returns:
            La propuesta solicitada o `None` si no se encuentra.
        """
        with self._lock:
            return self._store.get_proposal(proposal_id)

    def list_active(self) -> List[Any]:
        """Devuelve una lista de todas las propuestas activas.

        Returns:
            Lista de objetos propuesta que aún no han sido revocados.
        """
        with self._lock:
            return self._store.list_active()

    # ---------------------------------------------------------------------
    # Compatibilidad con iteración y representación
    # ---------------------------------------------------------------------
    def __iter__(self) -> Iterable[Any]:
        """Permite iterar directamente sobre las propuestas activas.
        """
        # La iteración se protege con el lock para evitar que el iterador
        # se vea afectado por modificaciones concurrentes.
        with self._lock:
            # Copiamos la lista para que el iterador sea estable.
            return iter(list(self._store.list_active()))

    def __len__(self) -> int:
        with self._lock:
            return len(self._store.list_active())

    def __repr__(self) -> str:
        return f"<ThreadSafeProposalStore size={len(self)} >"
