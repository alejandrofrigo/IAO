"""Omega package lazy loader

Esta fachada permite la importación perezosa de los sub‑módulos críticos del
paquete ``omega`` sin necesidad de cargar todos ellos al iniciar el proceso.
Se incluyen automáticamente los sub‑módulos cuyo nombre comienza con
``federation``.  Esto protege la carga temprana de dependencias pesadas y
garantiza que los módulos de federación estén disponibles tan pronto como se
accede a ellos.
"""

import importlib
import pkgutil
import sys
from types import ModuleType
from typing import List

# Detectar dinámicamente los sub‑módulos que forman parte de la infraestructura
# federada.  Se consideran críticos todos los módulos cuyo nombre inicia con
# "federation".
def _discover_federation_modules() -> List[str]:
    """Devuelve una lista de nombres de sub‑módulos de ``omega`` que empiezan
    por ``federation``.

    La detección se realiza en tiempo de importación del paquete y se almacena
    en la variable privada ``_FEDERATION_MODULES`` para evitar recalcular en
    cada acceso.
    """
    prefix = "federation"
    discovered = []
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name.startswith(prefix):
            discovered.append(module_info.name)
    return discovered

# Lista inmutable de módulos federados disponibles.
_FEDERATION_MODULES: List[str] = _discover_federation_modules()

# Exportar explícitamente los nombres descubiertos para que ``from omega import *``
# incluya los módulos federados.
__all__ = _FEDERATION_MODULES.copy()

def __getattr__(name: str) -> ModuleType:
    """Carga perezosamente el sub‑módulo solicitado.

    Si ``name`` corresponde a uno de los módulos federados descubiertos, se
    importa y se almacena en el namespace del paquete ``omega`` para futuros
    accesos.  En caso contrario, se lanza ``AttributeError`` estándar.
    """
    if name in _FEDERATION_MODULES:
        # Importar el sub‑módulo completo (p.ej. ``omega.federation``).
        full_name = f"{__name__}.{name}"
        module = importlib.import_module(full_name)
        # Cachear el módulo como atributo del paquete para que la próxima
        # solicitud sea directa.
        setattr(sys.modules[__name__], name, module)
        return module
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

def __dir__() -> List[str]:
    """Retorna los atributos disponibles del paquete.

    Combina los atributos estándar del módulo con los nombres de los módulos
    federados descubiertos.
    """
    standard_attrs = list(globals().keys())
    return sorted(standard_attrs + _FEDERATION_MODULES)
