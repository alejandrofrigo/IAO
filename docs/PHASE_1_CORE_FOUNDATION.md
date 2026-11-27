# Fase 1 — Núcleo operativo y arquitectura

**Estado:** EN CURSO  
**Rama de trabajo:** phase-1-core-foundation-20261127  
**Base:** iao-production-gates-20261127T0856Z  
**Política:** no modificar main, no fusionar PRs apilados, no desplegar ni habilitar workers privilegiados desde esta fase.

## Propósito

Establecer una base operativa coherente, reproducible, observable y verificable para IAO. Esta fase consolida el núcleo, la API, la configuración, la persistencia, la auditoría y los contratos de ejecución. No declara producción ni disponibilidad mundial.

## Reglas de evidencia

- **PENDIENTE:** no se ha implementado o verificado el criterio.
- **EN CURSO:** hay inspección o implementación activa, todavía sin aceptación completa.
- **IMPLEMENTADO:** el cambio existe en la rama, pero puede faltar validación.
- **VERIFICADO:** criterio satisfecho con pruebas reproducibles en el alcance indicado.
- **BLOQUEADO:** depende de una decisión, infraestructura o evidencia externa.

La presencia de un módulo, un PID, un workflow en verde o un artefacto histórico no demuestra por sí sola que un servicio esté operativo. Los resultados CI no equivalen a pruebas físicas ni a despliegue.

## Los 20 objetivos técnicos

| Nº | Objetivo | Criterio de aceptación | Estado |
|---:|---|---|---|
| 01 | Inventario técnico y fuente de verdad | Identificar HEAD/base, ramas y PRs apilados; inventariar API, núcleo, stores, configuración, workers y pruebas sin sobrescribir trabajo previo. | EN CURSO |
| 02 | Contrato de arquitectura del núcleo | Documentar límites entre API, servicio, dominio, persistencia, herramientas y adaptadores; no duplicar autoridades ni colas. | IMPLEMENTADO |
| 03 | Configuración tipada y validada | Validar entorno, puertos, host, URL pública y adaptadores; rechazar valores inválidos de forma determinista y sin filtrar secretos. | IMPLEMENTADO |
| 04 | Gestión segura de secretos | Exigir secretos persistentes donde corresponda; no generar identidades silenciosamente en producción ni registrar valores sensibles. | IMPLEMENTADO |
| 05 | Ciclo de vida de la API | Arranque y parada explícitos, idempotentes y observables; fallos críticos reflejados en readiness sin ocultar excepciones. | IMPLEMENTADO |
| 06 | Servicio de aplicación único | Una única construcción del servicio y sus autoridades por proceso; inicialización segura y concurrencia controlada. | IMPLEMENTADO |
| 07 | Persistencia y esquema | Definir backend soportado, inicialización/migraciones repetibles, integridad y comportamiento ante corrupción o indisponibilidad. | IMPLEMENTADO |
| 08 | Auditoría íntegra | Verificar encadenamiento, persistencia de claves, detección de alteración y degradación fail-closed sin exponer datos personales. | PENDIENTE |
| 09 | Readiness verificable | Separar liveness de readiness; publicar estados y códigos de causa acotados para dependencias y workers. | EN CURSO |
| 10 | Recuperación determinista | Recuperar estados interrumpidos sin reejecución ciega; probar reinicio, leases expirados y consistencia. | PENDIENTE |
| 11 | Contratos HTTP estables | Esquemas, códigos de estado, errores, límites de cuerpo, cabeceras y compatibilidad documentados y probados. | PENDIENTE |
| 12 | Seguridad de entrada y salida | Validación de entradas, egress mediado, límites de tiempo/tamaño, SSRF y rechazo de redirects no autorizados. | PENDIENTE |
| 13 | Identidad y autorización desacopladas | Autoridad única, principio de mínimo privilegio y separación entre autenticación, sesión y capacidades. | PENDIENTE |
| 14 | Privacidad operacional | Minimizar datos, redactar logs, evitar identificadores del operador en artefactos y aplicar no-store donde corresponda. | PENDIENTE |
| 15 | Supervisión funcional | Supervisores comprueban salud funcional, heartbeats y recuperación; un PID nunca basta para declarar un motor sano. | PENDIENTE |
| 16 | Manejo uniforme de errores | Errores internos tipados, códigos públicos estables, no filtración de excepciones ni secretos. | PENDIENTE |
| 17 | Empaquetado reproducible | Dependencias fijadas, instalación limpia y build reproducible en versiones Python soportadas. | PENDIENTE |
| 18 | Contrato de contenedor | Imagen construible, usuario/permisos adecuados, healthcheck y configuración explícita; sin secretos en capas. | PENDIENTE |
| 19 | Puertas de calidad y regresión | CI ejecuta compilación, tests, lint, contratos y gates críticos en Python soportado; fallos bloquean integración. | PENDIENTE |
| 20 | Cierre de fase y guía operativa | Informe de evidencia por objetivo, brechas restantes, procedimiento de recuperación y criterios para iniciar Fase 2. | PENDIENTE |

## Inventario inicial conocido — no equivale a verificación actual

- El repositorio contiene `omega/config.py`, una API FastAPI bajo `apps/api`, servicio `OmegaService`, persistencia SQLite, auditoría, identidad de dispositivos, cola de tareas, workers y workflows.
- `omega/server.py` es un adaptador HTTP basado en stdlib y `apps/api/main.py` es el adaptador ASGI. Ambos son entrypoints separados; no se afirma que ambos estén ejecutándose ni que compartan una instancia entre procesos.
- `omega/store.py` implementa SQLite para el piloto. La dependencia psycopg en `pyproject.toml` no demuestra un Store PostgreSQL funcional.
- El README declara que la autenticación de desarrollo no es OIDC y que SQLite es el backend de desarrollo; también advierte que FastAPI, Docker e infraestructura externa no se ejecutan en el entorno offline de validación.
- PR #16 contiene el lifecycle opt-in del TaskWorker; PR #19 aporta diagnósticos de readiness apilados sobre #16. PR #17 contiene gates de producción; PR #18 agrega IPFS read-only. Son líneas independientes y no están incorporadas automáticamente en esta rama.
- PR #20 (esta hoja de ruta) se basa en `iao-production-gates-20261127T0856Z`; la rama estaba 2 commits por delante y 0 por detrás de esa base antes de la ejecución técnica de esta continuación.
- El informe `docs/IAO_OBJECTIVES_GAP_ANALYSIS.md` tiene un corte estático anterior y no sustituye una inspección de la revisión actual.
- No se afirma que exista un runtime persistente mundial ni que los workers estén activos en producción.

## Secuencia de ejecución

1. Completar el inventario del objetivo 01 y fijar las dependencias entre ramas/PRs.
2. Cerrar contratos y configuración (02–04).
3. Consolidar ciclo de vida, servicio, persistencia y auditoría (05–08).
4. Cerrar readiness, recuperación y contratos de API (09–11).
5. Reforzar seguridad, autoridad, privacidad, supervisión y errores (12–16).
6. Verificar empaquetado, contenedor y CI (17–19).
7. Publicar evidencia y decidir el paso a Fase 2 (20).

## Registro de evidencia

| Objetivo | Evidencia | Resultado / brecha |
|---:|---|---|
| 01 | Rama aislada `phase-1-core-foundation-20261127`, base `iao-production-gates-20261127T0856Z`; comparación GitHub actualizada durante esta continuación; inspección de entrypoints, servicio, Store, auditoría y tres workers de descubrimiento. | Inventario sustancial; falta cerrar la matriz completa de dependencias entre PRs apilados y confirmar CI de la revisión actual. |
| 02 | `docs/CORE_ARCHITECTURE_CONTRACT.md`, enlazado desde README. | Límites y fuentes de verdad documentados; falta prueba de integración de ambos adaptadores. |
| 03 | `omega/config.py` y `tests/test_config.py`; validación de APP_ENV, PORT, HOST, adaptador y URL pública; casos inválidos y representación sin datos de configuración. | Implementado; pendiente CI Python 3.12/3.13 y verificación del contrato en los entrypoints. |
| 04 | `validate_persistent_keys` en `omega/config.py`; FastAPI `_get_service` y `omega.server.build_service` validan claves de 32+ caracteres, formato y no reutilización. El entrypoint stdlib carga la clave de auditoría persistente desde `AUDIT_HMAC_KEY` o el archivo local existente; no genera una clave alternativa. `tests/test_config.py` y `tests/test_server_persistent_keys.py` cubren reglas y rechazo antes de crear Store. | Aplicado a ambos entrypoints. Estado IMPLEMENTADO; pendiente ejecución CI y pruebas integrales de arranque con almacenamiento real antes de VERIFICADO. |
| 05 | `apps/api/main.py::_runtime_lifespan` informa fallos de arranque configurado sin registrar mensajes sensibles y coordina el cierre de los workers de autojoin, descubrimiento y red externa. Los tres módulos incorporan señales de parada, espera interrumpible, joins acotados y arranque idempotente que informa correctamente si el worker ya está activo. `omega/server.py::main` aplica limpieza en `finally`, cierra HTTP y solo cierra Store si los workers terminaron; retira el PID únicamente si pertenece al proceso actual. Pruebas añadidas en `tests/test_background_worker_lifecycle.py` y ampliadas en `tests/test_api_runtime_lifespan.py`. | Ciclo de cierre implementado en ambos entrypoints; pendiente ejecutar suite CI e integración con interrupciones reales antes de VERIFICADO. |
| 06 | `apps/api/main.py::_get_service` serializa la construcción con `_service_lock`; `_get_device_authority` reutiliza la autoridad propiedad del servicio en lugar de crear una segunda instancia sobre el mismo archivo SQLite. `_ensure_federation` mantiene su bloqueo de inicialización. Se añadieron pruebas concurrentes de 16 accesos y de identidad de la autoridad reutilizada. El entrypoint stdlib construye el servicio una vez en su ruta de arranque `main`; no se afirma singleton compartido entre procesos. | Implementado; pendiente CI verde y revisión integral de ambos entrypoints antes de VERIFICADO. |
| 07 | `omega/store.py` registra migraciones SQLite versionadas (1–3): esquema base, columnas/índice de leases y transición de auditoría. Las migraciones son aditivas y transaccionales (`BEGIN IMMEDIATE`); se rechazan versiones futuras y estados incoherentes. Se añade `busy_timeout=5000` y `PRAGMA quick_check` al arranque. `tests/test_store_file_permissions.py` cubre reinicio repetible, migración desde esquema de tareas legado y rechazo de versión futura. SQLite sigue siendo solo backend local/piloto; no hay claim de multi-réplica ni PostgreSQL. | Implementado; pendiente CI y pruebas de recuperación/corrupción antes de VERIFICADO. |
