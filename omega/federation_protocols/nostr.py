"""Adaptador Nostr. Un relay NO produce contrato sin bridge explícito."""
from __future__ import annotations
import urllib.request
from . import ProtocolAdapter, register

class NostrAdapter(ProtocolAdapter):
    name = "nostr"
    def probe(self, addr: str, timeout: float = 3.0):
        try:
            with urllib.request.urlopen(addr, timeout=timeout) as r:
                if r.status == 200: return {"relay": addr, "protocol": "nostr"}
        except Exception:
            pass
        return None
    def to_participation_contract(self, candidate: dict) -> dict | None:
        return None  # sin bridge Nostr<->iao-federation
# Solo registrar el stub si no hay un bridge real ya registrado.
# Esto evita que el stub sobrescriba a NostrBridge cuando ambos se importan.
from . import _REGISTRY
if "nostr" not in _REGISTRY:
    register(NostrAdapter())
