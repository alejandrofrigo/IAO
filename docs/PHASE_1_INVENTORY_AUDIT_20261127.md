# Auditoría de inventario — Fase 1 (2026-11-27)

**Estado:** evidencia documental adicional; no sustituye la verificación del HEAD ni de CI.
**SHA base observado:** `0920643d05833a2a761f9168ae1e89ed9944fcc7`.
**HEAD observado al actualizar:** `88f9cd5f878bb3fbe376f08ede806efc5e0c21b6` (359 ahead / 0 behind).
**Rama destino:** `phase-1-core-foundation-20261127`
**Alcance:** objetivo 01 de `PHASE_1_CORE_FOUNDATION.md`.

## Fuentes inspeccionadas

Se inspeccionaron en la rama de Fase 1 los siguientes archivos:
- `docs/PHASE_1_CORE_FOUNDATION.md`
- `docs/CORE_ARCHITECTURE_CONTRACT.md`
- `docs/PHASE_1_OPERATIONS_RUNBOOK.md`
- `omega/config.py`, `omega/service.py`, `omega/store.py`, `omega/audit.py`
- `omega/operator_identity.py`, `omega/server.py`
- `apps/api/main.py`
- `pyproject.toml`, `requirements.txt`
- `tests/test_config.py`, `tests/test_packaging_contract.py`

La inspección confirma que existen dos adaptadores HTTP (stdlib y FastAPI), un servicio de aplicación `OmegaService`, un Store SQLite de piloto, autoridades de dispositivo/operador, registro de herramientas y una cola local con `TaskWorker`. No demuestra que ambos adaptadores se ejecuten simultáneamente, que compartan estado entre procesos ni que SQLite soporte multi-réplica.

## Dependencias entre PRs observadas

| PR | Rama / propósito | Relación documentada | Tratamiento |
|---:|---|---|---|
| #17 | Gates de calidad y readiness ledger; base `iao-production-gates-20261127T0856Z` | Base de trabajo de la Fase 1 | Mantener como base; comprobar SHA y CI exactos |
| #16 | Lifecycle opt-in del TaskWorker | Diverge de la base: 132 ahead / 40 behind, según el inventario de PR #20 | No fusionar ni cherry-pickear automáticamente |
| #19 | Diagnósticos de readiness del TaskWorker | Apilada sobre #16: 4 ahead / 0 behind, según PR #20 | Evaluar junto con #16; no duplicar TaskWorker |
| #18 | Recuperación IPFS DAG-JSON read-only | Rama independiente: 8 ahead / 0 behind, según PR #20 | Mantener fuera de la integración del núcleo salvo decisión explícita |

Las relaciones y distancias anteriores son las cifras registradas en el cuerpo de PR #20 y en el ledger de Fase 1; deben volver a comprobarse contra los refs actuales antes de cualquier integración. La búsqueda de PRs abiertas también confirma que #16, #17, #18, #19 y #20 permanecen como líneas de trabajo separadas en el inventario consultado. No se realizó merge, cherry-pick ni despliegue.

## Discrepancia de inventario que debe resolverse

El ledger de Fase 1 registra la rama como **359 commits ahead / 0 behind** de `iao-production-gates-20261127T0856Z`. Un resumen anterior registraba **2 commits ahead / 0 behind** antes de la ejecución técnica. Son cortes distintos o una cifra obsoleta; no deben mezclarse. El número definitivo requiere comparar los refs actuales y registrar los SHA de base y HEAD.

## Componentes y fuentes de verdad

| Responsabilidad | Implementación canónica observada | Límite |
|---|---|---|
| API stdlib | `omega/server.py` | Adaptador HTTP, no autoridad de negocio independiente |
| API ASGI | `apps/api/main.py` | Adaptador FastAPI; no crea una segunda cola |
| Servicio | `omega/service.py:OmegaService` | Orquestación y autorización |
| Persistencia | `omega/store.py:Store` | SQLite local/piloto; no PostgreSQL operativo ni multi-réplica demostrado |
| Auditoría | `omega/audit.py` y Store | Integridad encadenada y HMAC; requiere clave persistente |
| Identidad operador | `omega/operator_identity.py` | Raíz y sesiones; autenticación no equivale a capacidad |
| Configuración | `omega/config.py` | Configuración tipada; secretos se suministran por entorno/gestor |
| Worker | `omega/task_worker.py` y cola Store | Ejecución local y allowlist; no añadir una segunda cola |

## Criterios pendientes para cerrar el objetivo 01

1. Obtener SHA exactos de HEAD y base y ejecutar comparación de refs actual.
2. Registrar el resultado actual de los workflows de CI para el SHA exacto de la rama.
3. Confirmar que los PRs apilados conservan sus relaciones y que no hay divergencia nueva.
4. Decidir explícitamente si #16/#19 se integran en esta rama o permanecen separados; no resolverlo mediante cherry-pick automático.
5. Mantener #18 independiente de la consolidación del núcleo salvo que una dependencia real lo exija.

**Resultado:** inventario estático y mapa de dependencias ampliados. El objetivo 01 permanece **EN CURSO** hasta verificar los refs/SHAs y CI actuales. Esta auditoría no modifica código de ejecución ni declara producción.
