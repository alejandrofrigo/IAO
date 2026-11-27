# Fase 2 — Inteligencia operativa y ejecución gobernada

**Estado:** EN CURSO — planificación técnica y primera implementación.
**Base:** d5b011cff1b620b00a468a5bad84b720fbc8fec4 (rama de Fase 1, PR #20 aún no fusionado).
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
| 04 | Cola persistente con leases | `Store.claim_next_task` usa `BEGIN IMMEDIATE`, incrementa `lease_generation` monotónica y devuelve el token junto al lease; `TaskWorker` lo propaga en transiciones y finalización; `update_claimed_task` exige worker, generación exacta y lease vigente en el mismo UPDATE. Migración aditiva v3, test de worker obsoleto tras recuperación/reencolado explícito, concurrencia y recuperación fail-closed. | IMPLEMENTADO — CI pendiente |
| 05 | Despacho por capacidades | `TaskWorker` resuelve capability en `ToolRegistry`, revalida policy/scopes, exige READ_ONLY y `QUEUED_TOOL_ALLOWLIST`, valida el input y vuelve a comprobar la autoridad del dispositivo antes de invocar; pruebas negativas impiden ejecutar herramientas no allowlisted o con autoridad revocada. | IMPLEMENTADO — CI pendiente |
| 06 | Router multi-LLM | `omega.llm_router` filtra por capabilities/modalities declaradas, aplica techo de coste configurado por 1K tokens, ordena determinísticamente por fallos, coste, latencia EWMA y prioridad, respeta cooldown, limita timeout por proveedor y hace failover sin persistir secretos ni cuerpos de error. Costes son metadatos configurados, no facturación verificada. `tests/test_llm_router.py` cubre filtros, límites, orden y estados corruptos. | IMPLEMENTADO — CI pendiente |
| 07 | Contrato común de proveedor | `omega/provider_contract.py` valida configuración HTTPS, referencia de secreto, capacidades, modalidades, coste, prioridad y timeout; limita mensajes, tamaño de petición/respuesta y valida estructura de respuesta OpenAI-compatible. `tests/test_provider_contract.py` cubre positivos y entradas hostiles. | IMPLEMENTADO — CI pendiente |
| 08 | Evaluación de respuestas | `omega.response_evaluator` valida texto/tamaño, claims requeridos, presencia de referencias citadas y digest; declara explícitamente `truth_verified=false` y `authoritative=false`. No confunde coincidencia de citas con veracidad. Pruebas positivas y adversariales. | IMPLEMENTADO — CI pendiente |
| 09 | Comparación y síntesis multi-modelo | `omega.model_comparison` compara hasta 8 salidas ya generadas, aplica criterios deterministas de completitud/evidencia, conserva desacuerdos y respuestas originales, no ejecuta modelos ni selecciona autoridad (`selection=null`). El coste de llamadas queda bajo el control del router/presupuesto. | IMPLEMENTADO — CI pendiente |
| 10 | Registro de herramientas | `ToolRegistry` valida nombre/capability, versión, scope, clase de efecto, timeout, schema JSON acotado y procedencia; publica manifiesto determinista no ejecutable y no expone callables. La allowlist del worker permanece más restrictiva. | IMPLEMENTADO — CI pendiente |
| 11 | Sandbox de ejecución | Aislamiento por tarea, filesystem mínimo, sin secretos heredados, límites CPU/memoria/tiempo y pruebas de escape. | PENDIENTE |
| 12 | Política de efectos | Clasificar READ_ONLY, REVERSIBLE, EXTERNAL y IRREVERSIBLE; bloquear por defecto efectos no autorizados. | PENDIENTE |
| 13 | Gestión de presupuesto | Cuotas por tarea/proveedor, límites de tokens/tiempo/llamadas y parada al alcanzar el presupuesto. | PENDIENTE |
| 14 | Reintentos y recuperación | Reintentos acotados, backoff, deduplicación y recuperación sin repetir efectos no idempotentes. | PENDIENTE |
| 15 | Evidencia y procedencia | Registrar digest de entradas/salidas, versiones de modelos/herramientas, decisiones de policy y referencias de evidencia sin datos sensibles. | PENDIENTE |
| 16 | Observabilidad de tareas | Estados, duración, causa pública acotada, métricas sin PII y correlación de extremo a extremo. | PENDIENTE |
| 17 | Cancelación y pausa segura | Migración aditiva v4 `cancel_requested_at`; endpoint POST de cancelación con prueba criptográfica del dispositivo primario y verificación de sesión; cancelación atómica de QUEUED y solicitud cooperativa en RUNNING/VERIFYING; worker revisa checkpoints antes/después de herramienta y no puede completar si hay cancel pendiente. No promete matar instantáneamente el proceso hijo: la cancelación activa espera al retorno/timeout acotado de la herramienta. Pruebas de ownership, CAS, carrera y API. | IMPLEMENTADO — CI pendiente |
| 18 | Integración con centro de mando | Protocolo de directivas desde Chat público IAO, autenticación del dispositivo autorizado, firma, nonce, deduplicación y recibos verificables. | PENDIENTE |
| 19 | Pruebas adversariales | Pruebas de prompt injection, herramienta maliciosa, salida no confiable, SSRF, agotamiento de recursos y escalada de capacidades. | PENDIENTE |
| 20 | Aceptación de Fase 2 | CI, pruebas de integración, runbook, inventario de brechas y evidencia reproducible en un SHA único. | PENDIENTE |

## Arquitectura objetivo

1. **Plano de control:** identidad, autorización, política, presupuesto y auditoría; determinista y separado de modelos.
2. **Plano de planificación:** convierte solicitudes autorizadas en DAG de tareas versionadas y precondiciones.
3. **Plano de ejecución:** workers aislados que reclaman leases y solo ejecutan herramientas registradas.
4. **Plano de modelos:** router y adaptadores intercambiables; los modelos proponen, no conceden permisos.
5. **Plano de evidencia:** recibos, hashes, resultados y métricas minimizadas.
6. **Interfaz de mando:** el Chat público IAO de este teléfono será el punto de mando una vez que la vinculación criptográfica y el flujo de directivas estén implementados y probados. La URL o el navegador por sí solos nunca autentican el dispositivo.

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
| Base de trabajo | HEAD de Fase 1 d5b011cff1b620b00a468a5bad84b720fbc8fec4 |
| Estado Fase 1 | PR #20 abierto/draft; cuatro workflows del HEAD base completados con éxito. |
| Bloqueos heredados | Lockfile generado como artefacto CI pero aún no incorporado; objetivos 13–16 y 20 con brechas documentadas; dependencias entre PRs aún requieren reconciliación. |
| Estado de Fase 2 | Objetivos 01–10 implementados en código; incluye fencing monotónico, routing multi-LLM, contrato de proveedor, evaluación no autoritativa, comparación multi-modelo y manifiesto de herramientas. La verificación CI del HEAD actual sigue pendiente; objetivos 11–20 permanecen pendientes. |