# Auditoría de cierre de Fase 1 — corte 2026-11-27

**PR:** #20 — rama phase-1-core-foundation-20261127
**HEAD verificado:** d5b011cff1b620b00a468a5bad84b720fbc8fec4
**Base:** iao-production-gates-20261127T0856Z
**Comparación actual:** 468 commits ahead, 0 behind. Esta cifra reemplaza los cortes documentales antiguos de 359 y 2 commits.
**Estado de PR:** abierta, draft, no fusionada.
**Estado de despliegue:** no se ha desplegado.

## Evidencia CI exacta

En el HEAD d5b011cff1b620b00a468a5bad84b720fbc8fec4 los cuatro workflows asociados terminaron en completed/success:

- IAO CI — Python 3.12 y 3.13; compilación, lint de integración, pip check y suite completa.
- IAO CI — instalación bloqueada con uv para Python 3.12 y 3.13.
- IAO quality gate.
- IAO container build qualification.
- IAO mobile browser integration.

La ejecución CI publicó el artefacto iao-uv-lock (artifact ID 15231320262, SHA-256 26f8a1d44b54de09e9b5d02f6ec6f56c2c07acfe0a6a595033f9ccf3025ae34d). La instalación bloqueada se verificó en ambas versiones. El artefacto generado no equivale a un uv.lock revisado e incorporado al repositorio; el objetivo 17 permanece abierto hasta que el lockfile se comprometa y CI use --locked contra ese archivo.

## Matriz de salida actualizada

| Objetivo | Estado al corte | Brecha restante |
|---:|---|---|
| 01 | EN CURSO | Reconciliar PRs #16/#19/#18 y confirmar inventario de refs; el conteo de commits queda corregido a 468/0. |
| 02–12 | IMPLEMENTADO | Falta evidencia de aceptación específica por criterio; CI verde no sustituye pruebas de integración/runtime. |
| 13 | EN CURSO | Completar matriz positiva/negativa por ruta y capability, en ambos adaptadores; demostrar que solo el dispositivo criptográficamente vinculado puede enviar directivas de mando. |
| 14 | EN CURSO | Barrido de historial Git completo, artefactos CI, imágenes y launchers; revisar retención y exposición histórica, no solo el árbol actual. |
| 15 | EN CURSO | Heartbeat/identidad de proceso para Guardian, ciclo de vida y recuperación por motor; pruebas de runtime y estados de parada incierta. |
| 16 | EN CURSO | Auditoría integral de rutas/métodos y pruebas de paridad de errores en ambos adaptadores, incluyendo límites de cuerpo y fallos internos. |
| 17 | PENDIENTE | Revisar y añadir el uv.lock del artefacto CI; convertir la instalación principal a uv sync --locked; comprobar Python 3.12/3.13. |
| 18 | IMPLEMENTADO | CI de build verde; falta runtime de imagen con volumen persistente y configuración de secretos real para aceptar operación. |
| 19 | EN CURSO | Los workflows listados están verdes en este HEAD; falta que el SHA final posterior a las correcciones de cierre conserve todas las puertas verdes. |
| 20 | EN CURSO | Actualizar runbook con evidencias finales, probar restore/rollback y publicar acta de salida por objetivo. |

## Decisión

**Fase 1 NO CERRADA.** CI verde confirma las puertas automatizadas del SHA indicado, no el funcionamiento productivo del sistema. No se asigna VERIFICADO globalmente a los 20 objetivos. No se fusiona ni despliega PR #20 hasta cerrar los bloqueos enumerados y revisar las ramas apiladas.

La Fase 2 puede desarrollarse en una rama apilada para evitar bloquear el trabajo, pero su aceptación e integración quedan condicionadas a resolver la Fase 1.