# Auditoría de inventario — Fase 1 (2026-11-27)

**Estado:** evidencia documental adicional; no sustituye la verificación del HEAD ni de CI.
**SHA base observado:** `0920643d05833a2a761f9168ae1e89ed9944fcc7`.
**HEAD observado al actualizar:** `1cde5344903a5a436d6a3221ccc731c2cf8debda` (479 ahead / 0 behind de la base).
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
| #16 | Lifecycle opt-in del TaskWorker | Rama apilada sobre chat task intake/capability grants; se adaptó e integró en Fase 1 `apps/api/main.py` (worker opt-in, mismo Store/registry/authority, heartbeat y apagado limitado). | No integrar otra copia; conservar PR original para revisión de divergencias restantes |
| #19 | Diagnósticos de readiness del TaskWorker | Apilada sobre #16; se integró el estado `blocked/start_failed/running/worker_exited/stop_timeout` y pruebas de lifecycle en Fase 1. | No integrar otra copia; comparar únicamente diferencias pendientes |
| #18 | Recuperación IPFS DAG-JSON read-only | Rama independiente sobre production gates. | Mantener fuera del núcleo hasta verificar egress, CID, CI y disponibilidad real |
| #2 | Base Tor/P2P y descubrimiento onion/libp2p | Rama separada sobre `iao-production-build-20261126`; no forma parte de la cadena Fase 1/2. | Bloque crítico de integración para objetivo descentralizado; revisar tests y límites antes de incorporar |
| #3–#8 | Gateway Cloudflare, proxy fijo y delegación Termux | Cadena de PRs separada desde main; despliegue/activación explícitamente deshabilitados. | Mantener fuera hasta unificar autoridad y decidir backend sin coste; nunca introducir Quick Tunnel |
| #9–#10 | Protocolo de lease y grants duales root/dispositivo | Rama de agente separada; PR #10 implementa grants de `knowledge.search` con expiración/revocación. | Reconciliar con el allowlist READ_ONLY de Fase 2; no duplicar autoridades ni otorgar scopes globales |
| #13 | Chat → task intake | Apilada sobre PR #10; panel y E2E con grants. | Comparar con el panel mínimo de Fase 2 y conservar el flujo con grants si sus pruebas superan CI |
| #20–#21 | Fase 1 y Fase 2 | Cadena actual: PR #20 sobre production gates; PR #21 sobre PR #20. | Mantener como línea principal de consolidación; gates exactos pendientes |

El inventario REST de PRs abiertas del 2026-11-27 confirma la cadena y bases descritas. El código de worker lifecycle/readiness de #16/#19 ya fue adaptado en Fase 1; no se fusionaron sus ramas. #2, #3–#10, #13 y #18 siguen siendo líneas separadas. El manifiesto Render y el workflow Cloud Run dependiente de facturación se retiraron de las ramas Fase 1/2; el API origin del navegador ahora falla cerrado si no se configura HTTPS explícitamente. No se realizó merge ni despliegue.

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
4. Verificar CI del worker lifecycle/readiness integrado y comparar #16/#19 para identificar solo cambios restantes.
5. Integrar el chat task intake con capability grants de #10/#13 sin duplicar la autoridad ni debilitar el vínculo al dispositivo.
6. Evaluar #2 Tor/P2P y #18 IPFS con pruebas de red reales, manteniendo candidatos públicos en cuarentena.
7. Reconciliar #3–#8 con el backend sin coste y sin activar un segundo plano de autoridad.

## Cambios de consolidación desde el inventario anterior

- PR #16/#19: el ciclo de vida opt-in del TaskWorker se adaptó a `apps/api/main.py`; usa el Store/registry/autoridad existentes, valida lease/poll, publica heartbeat, distingue `blocked/start_failed/running/worker_exited/stop_timeout` y apaga con join limitado. Se añadieron pruebas en `tests/test_api_task_worker_lifecycle.py`. Esto no activa el worker por defecto ni acredita ejecución de producción.
- Despliegue: `render.yaml` y el workflow `deploy-cloud-run.yml` se retiraron de Fase 1 por incompatibilidad con la restricción de no usar Render ni infraestructura que pueda generar facturación. El cliente web eliminó Quick Tunnel y ahora bloquea chat/API si no recibe un origen HTTPS explícito. GitHub Pages sigue siendo solo frontend; no constituye backend.
- La PR #21 de Fase 2 continúa apilada sobre esta rama; sus cambios no se consideran aceptados ni sustituyen el cierre de Fase 1.

**Resultado:** inventario y mapa de dependencias actualizados con refs exactos. El objetivo 01 permanece **EN CURSO** hasta CI verde en los HEAD exactos, revisión final de las ramas independientes y cierre de discrepancias. Esta auditoría no declara producción.
