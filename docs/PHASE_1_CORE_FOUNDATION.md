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
| 02 | Contrato de arquitectura del núcleo | Documentar límites entre API, servicio, dominio, persistencia, herramientas y adaptadores; no duplicar autoridades ni colas. | PENDIENTE |
| 03 | Configuración tipada y validada | Validar entorno, puertos, adaptadores y límites; rechazar valores inválidos de forma determinista y sin filtrar secretos. | PENDIENTE |
| 04 | Gestión segura de secretos | Exigir secretos persistentes donde corresponda; no generar identidades silenciosamente en producción ni registrar valores sensibles. | PENDIENTE |
| 05 | Ciclo de vida de la API | Arranque y parada explícitos, idempotentes y observables; fallos críticos reflejados en readiness sin ocultar excepciones. | EN CURSO |
| 06 | Servicio de aplicación único | Una única construcción del servicio y sus autoridades por proceso; inicialización segura y concurrencia controlada. | PENDIENTE |
| 07 | Persistencia y esquema | Definir backend soportado, inicialización/migraciones repetibles, integridad y comportamiento ante corrupción o indisponibilidad. | PENDIENTE |
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

- El repositorio ya contiene omega/config.py, una API FastAPI bajo apps/api, servicios y persistencia SQLite, auditoría, identidad de dispositivos, cola de tareas, workers y workflows.
- El README de main declara que la autenticación de desarrollo no es OIDC y que SQLite es de desarrollo; también advierte que FastAPI, PostgreSQL, Docker e infraestructura externa no se ejecutan en ese entorno de validación.
- Existe trabajo pendiente en PR #16 (lifecycle del TaskWorker), PR #19 (diagnóstico de readiness apilado sobre #16), PR #17 (gates de producción) y PR #18 (IPFS read-only). Deben revisarse sus bases y dependencias antes de integrar; esta rama no los incorpora automáticamente.
- El informe docs/IAO_OBJECTIVES_GAP_ANALYSIS.md tiene un corte estático anterior y no sustituye una inspección de la revisión actual.
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
| 01 | Rama creada desde iao-production-gates-20261127T0856Z; PRs #16–#19 identificados en el repositorio. | Inventario parcial; falta inspección completa del HEAD, workflow y dependencias exactas. |
