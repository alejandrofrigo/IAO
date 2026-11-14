"""Registro de adaptadores de protocolo. Descubren y traducen, NO enrolan."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class ProtocolAdapter(ABC):
    name: str
    @abstractmethod
    def probe(self, addr: str, timeout: float = 5.0) -> dict[str, Any] | None: ...
    @abstractmethod
    def to_participation_contract(self, candidate: dict[str, Any]) -> dict[str, Any] | None: ...

_REGISTRY: dict[str, ProtocolAdapter] = {}
def register(adapter: ProtocolAdapter) -> None: _REGISTRY[adapter.name] = adapter
def get(name: str) -> ProtocolAdapter | None: return _REGISTRY.get(name)
def all_adapters() -> list[ProtocolAdapter]: return list(_REGISTRY.values())
def probe_any(addr: str, order: list[str] | None = None):
    for name in (order or list(_REGISTRY)):
        adapter = _REGISTRY.get(name)
        if not adapter: continue
        try:
            c = adapter.probe(addr)
        except Exception:
            continue
        if c: return name, c
    return None
