# Fase 2 — Inteligencia operativa y ejecución gobernada

**Estado:** EN CURSO — planificación técnica y primera implementación.
**Base:** rama `phase-1-core-foundation-20261127` (PR #20 aún abierta y sin fusionar; SHA base se mantiene sincronizado en la cadena de ramas).
**Regla de integración:** esta rama queda apilada sobre el HEAD de Fase 1. No fusionar ni desplegar automáticamente; antes debe resolverse la aceptación de Fase 1 y su integración de ramas/PRs.

## Propósito

Convertir el núcleo de Fase 1 en un plano de ejecución de tareas gobernado: planificación explícita, selección de herramientas/modelos, ejecución aislada, límites de recursos, trazabilidad y recuperación segura. La Fase 2 no declara autonomía irrestricta. Toda acción externa o con efectos permanece sometida a identidad, capacidades, políticas, consentimiento y auditoría.

## Criterios generales de aceptación

Cada objetivo requiere: implementación en código, pruebas positivas y negativas, evidencia CI sobre el mismo SHA, documentación operativa y un estado honesto. Un adaptador configurado no equivale a proveedor disponible; un proceso vivo no equivale a ciclo saludable; una respuesta de modelo no constituye autoridad.

## Los 20 objetivos

| Nº | Objetivo | Criterio verificable | Estado |
|---:|---|---|---|
| 01 | Contrato de tareas versionado | `omega/task_contract.py` valida la versión 1.0, campos exactos, capacidades/scopes, digest, presupuesto, expiración, profundidad y tamaño de entrada antes de persistir; `tests/test_task_contract.py` cubre entradas válidas y negativas. | IMPLEMENTADO — CI pendiente |
| 02 | Planificador determinista | `omega/task_planner.py` valida DAGs acotados, rechaza ciclos/referencias desconocidas y produce orden topológico estable sin ejecutar herramientas ni conceder permisos; `tests/test_task_planner.py` cubre orden, invariancia, ciclos y entradas hostiles. | IMPLEMENTADO — CI pendiente |
| 03 | Motor de estados de ejecución | `omega.control` define el grafo determinista; `Store.transition_task_state` aplica compare-and-swap atómico y `OmegaService` lo usa para cada transición, devolviendo conflicto si el estado cambió concurrentemente. Pruebas positivas, de transición ilegal y conflicto CAS en `tests/test_task_queue.py`. | IMPLEMENTADO — CI pendiente |
| 04 | Cola persistente con leases | `Store.claim_next_task` usa `BEGIN IMMEDIATE`, incrementa `lease_generation` monotónica y devuelve el token junto al lease; `TaskWorker` lo propaga en transiciones/finalización y amplía el lease antes de la herramienta hasta cubrir su timeout acotado; `update_claimed_task` y `renew_task_lease` exigen worker, generación exacta y lease vigente. Migraciones aditivas v3/v4, test de worker obsoleto tras recuperación/reencolado explícito, renovación, concurrencia y recuperación fail-closed. | IMPLEMENTADO — CI pendiente |
| 05 | Despacho por capacidades | `TaskWorker` resuelve capability en `ToolRegistry`, exige READ_ONLY/allowlist, valida input, vuelve a comprobar dispositivo primario y grant dual firmado, y revalida la capacidad vigente inmediatamente antes de invocar; revocación/expiración impide ejecutar tareas ya encoladas. | IMPLEMENTADO — CI pendiente |
| 06 | Router multi-LLM | `omega.llm_router` filtra por capabilities/modalities declaradas, aplica techo de coste configurado por 1K tokens, ordena determinísticamente por fallos, coste, latencia EWMA y prioridad, respeta cooldown, limita timeout por proveedor y hace failover sin persistir secretos ni cuerpos de error. Costes son metadatos configurados, no facturación verificada. `tests/test_llm_router.py` cubre filtros, límites, orden y estados corruptos. | IMPLEMENTADO — CI pendiente |
| 07 | Contrato común de proveedor | `omega/provider_contract.py` valida configuración HTTPS, referencia de secreto, capacidades, modalidades, coste, prioridad y timeout; limita mensajes, tamaño de petición/respuesta y valida estructura de respuesta OpenAI-compatible. `tests/test_provider_contract.py` cubre positivos y entradas hostiles. | IMPLEMENTADO — CI pendiente |
| 08 | Evaluación de respuestas | `omega.response_evaluator` valida texto/tamaño, claims requeridos, presencia de referencias citadas y digest; declara explícitamente `truth_verified=false` y `authoritative=false`. No confunde coincidencia de citas con veracidad. Pruebas positivas y adversariales. | IMPLEMENTADO — CI pendiente |
| 09 | Comparación y síntesis multi-modelo | `omega.model_comparison` compara hasta 8 salidas ya generadas, aplica criterios deterministas de completitud/evidencia, conserva desacuerdos y respuestas originales, no ejecuta modelos ni selecciona autoridad (`selection=null`). El coste de llamadas queda bajo el control del router/presupuesto. | IMPLEMENTADO — CI pendiente |
| 10 | Registro de herramientas | `ToolRegistry` valida nombre/capability, versión, scope, clase de efecto, timeout, schema JSON acotado y procedencia; publica manifiesto determinista no ejecutable y no expone callables. La allowlist del worker permanece más restrictiva. | IMPLEMENTADO — CI pendiente |
| 11 | Sandbox de ejecución | `process_runner` usa proceso hijo killable, elimina variables de entorno heredadas y aplica límites POSIX de CPU, memoria, ficheros, descriptores y core; limita entrada/salida/tiempo. **No es sandbox de SO:** no hay aislamiento filesystem/network/namespaces/seccomp demostrado; permanece bloqueante para herramientas no confiables. | PARCIAL — requiere sandbox de SO |
| 12 | Política de efectos | `omega.effect_policy` clasifica READ_ONLY, REVERSIBLE, EXTERNAL e IRREVERSIBLE (más alias heredados); solo READ_ONLY está concedido en las rutas actuales. Todo otro efecto requiere grant explícito vinculado a la petición. La API y worker vuelven a comprobar la política; pruebas deny-by-default. | IMPLEMENTADO — CI pendiente |
| 13 | Gestión de presupuesto | Contrato de tarea acota timeout (≤300 s) y llamadas; router impone máximo de 1–8 intentos por petición y techo de coste configurado; comparación limita 8 candidatos. **Parcial:** falta contabilización real de tokens/coste y cuota agregada por tarea/operador. | PARCIAL — CI pendiente |
| 14 | Reintentos y recuperación | Router aplica failover limitado por presupuesto, cooldown exponencial con jitter y salud por proveedor; cola usa idempotencia, leases y recuperación fail-closed sin replay automático de tareas interrumpidas. **Parcial:** falta política de reintentos por tarea con idempotency proof y estados inciertos. | PARCIAL — CI pendiente |
| 15 | Evidencia y procedencia | `tool_execution` registra versión, estado, digest de entrada/salida y código de error; auditoría registra decisiones, versión de policy y digests; evaluador preserva referencias y hash de respuesta sin afirmar veracidad. **Parcial:** falta correlación uniforme de proveedor/modelo/coste en cada ejecución. | PARCIAL — CI pendiente |
| 16 | Observabilidad de tareas | Estados persistentes, eventos auditados, heartbeat del worker y estado de proveedores con fallos/latencia; errores públicos acotados. **Parcial:** falta métricas agregadas de duración/cola y correlación completa entre chat, intent, worker y proveedor. | PARCIAL — CI pendiente |
| 17 | Cancelación y pausa segura | Migración aditiva v4 `cancel_requested_at`; endpoint POST de cancelación con prueba criptográfica del dispositivo primario y verificación de sesión; cancelación atómica de QUEUED y solicitud cooperativa en RUNNING/VERIFYING; worker revisa checkpoints antes/después de herramienta y no puede completar si hay cancel pendiente. No promete matar instantáneamente el proceso hijo: la cancelación activa espera al retorno/timeout acotado de la herramienta. **Parcial:** falta pausa y cancelación inmediata del proceso hijo con resultado incierto explícito. | PARCIAL — CI pendiente |
| 18 | Integración con centro de mando | Chat público incluye `task-intake.js` para búsqueda local READ_ONLY, con idempotencia, estado y cancelación; `operator-identity.js` crea/revoca grants de 15 minutos con doble firma root+dispositivo; API revalida grant al encolar y worker antes de ejecutar; navegador visitante no obtiene mando. FastAPI lifespan puede iniciar TaskWorker con opt-in explícito, mismo Store/registry/authority, heartbeat y apagado limitado. **Parcial:** falta convertir directivas naturales generales del chat en tareas gobernadas, historial persistente en UI y sincronización del resultado en el hilo. | PARCIAL — CI pendiente |
| 19 | Pruebas adversariales | Pruebas de prompt injection, herramienta maliciosa, salida no confiable, SSRF, agotamiento de recursos y escalada de capacidades. | PENDIENTE |
| 20 | Aceptación de Fase 2 | CI, pruebas de integración, runbook, inventario de brechas y evidencia reproducible en un SHA único. | PENDIENTE |

## Arquitectura objetivo

1. **Plano de control:** identidad, autorización, política, presupuesto y auditoría; determinista y separado de modelos.
2. **Plano de planificación:** convierte solicitudes autorizadas en DAG de tareas versionadas y precondiciones.
3. **Plano de ejecución:** workers aislados que reclaman leases y solo ejecutan herramientas registradas.
4. **Plano de modelos:** router y adaptadores intercambiables; los modelos proponen, no conceden permisos.
5. **Plano de evidencia:** recibos, hashes, resultados y métricas minimizadas.
6. **Interfaz de mando:** el Chat público IAO incorpora un flujo inicial de consultas de solo lectura, con sesión, dispositivo primario y grant dual firmado; la URL o el navegador por sí solos nunca autentican el dispositivo. Las directivas generales siguen bloqueadas hasta completar el flujo y las pruebas adversariales.

## Secuencia de implementación

- Lote A: objetivos 01–05 (contrato, planificación, estados, leases y despacho).
- Lote B: objetivos 06–10 (router, proveedores, evaluación, comparación y herramientas).
- Lote C: objetivos 11–17 (sandbox, efectos, presupuesto, recuperación, evidencia y cancelación).
- Lote D: objetivos 18–20 (centro de mando, adversarial y aceptación).

## Límites explícitos

- No se declara descubrimiento o uso efectivo de nodos externos hasta probar conectividad y protocolo.
- Tor/onion/P2P se incorporarán mediante adaptadores explícitos y aislados, no como bypass de controles.
- Los peers públicos se tratarán como no confiables; descubrimiento no concede confianza, acceso a datos privados ni ejecución.
- No se habilita mando privilegiado desde otros dispositivos.
- No se declara disponibilidad mundial, escalabilidad multi-réplica ni coste cero de infraestructura sin evidencia.
- Ningún merge, despliegue o activación de workers privilegiados queda autorizado por este documento.

## Registro inicial

| Evidencia | Resultado |
|---|---|
| Base de trabajo | Rama `phase-1-core-foundation-20261127`; PR #20 abierta/draft, sin fusión. |
| Estado Fase 1 | PR #20 abierta/draft; worker lifecycle opt-in y heartbeat integrados; CI del HEAD actualizado pendiente. |
| Bloqueos heredados | `uv.lock` aún no incorporado; API origin HTTPS aún no configurado; frontend permanece fail-closed; no hay backend público gratuito desplegado; runtime Tor/libp2p/IPFS adaptado a Fase 1 pero pendiente smoke CI y verificación de red real; Cloudflare gateway y recuperación IPFS DAG-JSON siguen en revisión independiente; objetivos 13–16 y 20 conservan brechas. |
| Estado de Fase 2 | Objetivos 01–10 y 12 implementados en código; 11 y 13–18 parciales con brechas documentadas; 19–20 pendientes. Incluye fencing/renovación, router multi-LLM, contrato de proveedor, evaluación no autoritativa, comparación, manifiesto, grants duales, chat task intake y cancelación cooperativa. CI del HEAD actual pendiente. |