# Guía operativa — Fase 1 de IAO

## Estado y alcance

Esta guía describe el comportamiento verificable del código de Fase 1. No certifica una instalación desplegada, disponibilidad pública, alta disponibilidad, multi-réplica ni ejecución autónoma continua en infraestructura externa.

- `/health/live` demuestra que el proceso HTTP responde.
- `/health/ready` evalúa dependencias locales. Su estado degradado o `production_ready=false` no puede elevarse a producción por configuración cosmética.
- Un PID demuestra, como máximo, que existe un proceso con ese identificador. El supervisor solo clasifica PADGE como funcional cuando el PID coincide con el propietario del lock advisory y con un heartbeat reciente.
- Un peer descubierto no es un worker, no recibe confianza ni grants y no puede ejecutar herramientas con efectos.

## Supervisión local

El coordinador registra fases `starting`, `cycle_running` y `cycle_completed` en un heartbeat atómico. Los lectores rechazan symlinks y archivos no regulares; el lock se abre con `O_NOFOLLOW`. El supervisor conserva `starttime` de `/proc/<pid>/stat` para detectar reutilización de PID, solo señaliza grupos de sesión aislada que coinciden con el PID del hijo, y conserva los hijos cuya parada no pudo verificarse. `STOP_INCOMPLETE` no equivale a parada exitosa. El estado se clasifica como:

| Estado | Significado |
|---|---|
| `HEALTHY` | Lock activo y coincidente con PID/heartbeat reciente; el último ciclo terminó |
| `CYCLE_IN_PROGRESS` | Lock activo y heartbeat reciente durante un ciclo |
| `DEGRADED_UNVERIFIED` | Lock y heartbeat ausentes, caducados o no coincidentes |
| `STOPPED` | No hay lock advisory activo |
| `PROCESS_ALIVE_UNVERIFIED` | Hay PID de un motor, pero no existe protocolo de salud funcional para él |
| `STALE` (heartbeat) | `read_heartbeat` detecta que el heartbeat superó el límite de frescura; el estado agregado del coordinador pasa a `DEGRADED_UNVERIFIED` |

El `TaskWorker` standalone publica opcionalmente un heartbeat `TASK_WORKER` sin `worker_id`, sujeto ni task ID. Su resultado de ciclo fallido se clasifica `DEGRADED`. Esta señal todavía no está integrada en el supervisor de cinco motores ni se usa para elevar readiness de la API.

Los heartbeats y eventos operativos se guardan bajo directorios privados (0700) y archivos privados (0600). El logger redacta prompts, consultas, trazas, comandos y rutas; los campos string desconocidos y listas de texto no confiables se convierten en digest por defecto. Solo conserva etiquetas de esquema/códigos acotados y nombres de capabilities validados. No deben añadirse prompts, consultas, credenciales ni contenido de usuario a los logs. El barrido del árbol de trabajo no limpia commits anteriores ni artefactos históricos. Una reescritura de historial o force-push requiere autorización explícita y coordinación de la revisión; no se realiza automáticamente.

## Contrato operativo de errores HTTP

Las respuestas JSON de error de API deben usar un código público estable en `error`, un `correlation_id` hexadecimal de 32 caracteres y la cabecera `X-Correlation-ID` con el mismo valor. Deben incluir `Cache-Control: no-store` y `X-Content-Type-Options: nosniff`; los 405 incluyen `Allow`. No se devuelven excepciones, trazas, rutas internas, detalles de framework ni mensajes de proveedores. La correlación sirve para localizar evidencia privada sin copiar el cuerpo de la solicitud a logs.

- `NOT_FOUND` y `METHOD_NOT_ALLOWED` son errores de contrato, no evidencia de caída del proceso.
- `INTERNAL_ERROR`, `IAO_SERVICE_UNAVAILABLE` y `FEDERATION_UNAVAILABLE` no exponen causa interna; el diagnóstico se obtiene de logs privados por clase de excepción y del estado de readiness.
- Una denegación de preflight devuelve `CORS_PREFLIGHT_DENIED`; no debe añadirse una cabecera CORS permisiva a la respuesta denegada.
- Los errores de cuerpo (longitud, tamaño, codificación o framing) deben conservar el mismo sobre de correlación y privacidad en ambos adaptadores. El adaptador stdlib debe rechazar transfer-encoding, Content-Length que no sea decimal ASCII, longitud negativa, cuerpos mayores que `MAX_BODY` y lecturas incompletas antes de invocar `OmegaService`; debe cerrar la conexión en esos casos. El adaptador FastAPI valida el tamaño de forma incremental y no debe acumular un cuerpo que supere el límite, tanto en `/v1/*` como en `/fed/v1/*`; la federación usa `MAX_MSG` y el mismo envelope de error. Todas las respuestas de `OmegaService` en stdlib deben pasar por `_send_service_json`, que asegura correlación hexadecimal y cabeceras comunes tanto en respuestas correctas como de error.

Los fallos inesperados de `OmegaService.handle` deben devolver 503 `IAO_SERVICE_UNAVAILABLE` en ambos adaptadores, sin propagar el mensaje de excepción; el log privado solo registra la clase de excepción. El contrato y sus regresiones de FastAPI/stdlib están en proceso de cualificación. No declarar el objetivo 16 como VERIFICADO hasta que la suite completa pase en el SHA exacto y se revise la matriz de rutas y métodos.

## Instalación reproducible

Cuando `uv.lock` haya sido generado, revisado e incorporado al repositorio, la instalación de desarrollo debe usar exclusivamente el lock:

```sh
uv sync --locked --python 3.12 --extra dev
uv run --locked --python 3.12 --with pip python -m pip check
uv sync --locked --python 3.13 --extra dev
uv run --locked --python 3.13 --with pip python -m pip check
```

No eliminar `--locked` para ocultar divergencias entre `pyproject.toml` y `uv.lock`. Si el lock no resuelve o la instalación falla en una versión soportada, el objetivo 17 permanece PENDIENTE y no se integra.

## Persistencia y recuperación

1. Antes de recuperar o actualizar, detener ordenadamente el proceso que escribe en SQLite. No copiar una base de datos activa como si fuera un backup consistente.
2. Crear un backup consistente mediante la API de backup de SQLite o con el proceso detenido; conservar por separado el material de autenticación/auditoría en un gestor de secretos.
3. Restringir el directorio de estado a 0700 y archivos sensibles a 0600.
4. Restaurar base de datos y clave HMAC de auditoría como un conjunto coherente. Si el fingerprint de la clave no coincide con el ledger, el servicio debe fallar cerrado; no regenerar una clave para “arreglar” el estado.
5. Tras restaurar, ejecutar comprobación de integridad, validar la cadena de auditoría y revisar `/health/ready`. La liveness no sustituye estas comprobaciones.
6. Las tareas cuyo resultado de ejecución sea incierto se marcan fallidas/cerradas; no se reencolan automáticamente. Una lease expirada no autoriza a un segundo worker a repetir efectos.

## PADGE y rollback

PADGE trabaja con candidatos acotados y protegidos. La promoción requiere compilación, suite de pruebas, autoridad central, política determinista y verificación posterior. Ante fallo:

- no continuar la promoción;
- restaurar los archivos previos desde el backup de esa versión;
- verificar contenido y permisos restaurados;
- volver a ejecutar las pruebas post-rollback;
- mantener el evento de auditoría y el informe de fallo;
- si el rollback no puede verificarse, declarar estado crítico y bloquear nuevas promociones.

Los eventos operativos son diagnósticos; no sustituyen la cadena HMAC de auditoría.

## Puertas de aceptación antes de integrar

- CI verde en el SHA exacto que se pretende integrar: Python 3.12/3.13, lint/quality gate, contrato API, construcción y arranque de contenedor, e integración Chromium.
- Cobertura ruta por ruta de `/v1/*` y `/fed/v1/*` en ambos adaptadores, con autorización positiva/negativa y métodos incorrectos. La matriz actual cubre métodos de 30 rutas `/v1` y cinco rutas federadas; aún falta cerrar cada caso positivo/negativo de autorización.
- Barrido de privacidad del árbol, historial Git, logs de launchers, imágenes de contenedor y artefactos CI.
- Heartbeat y recuperación verificables para cada motor habilitado; ningún estado funcional basado solo en PID.
- Instalación reproducible con dependencias transitivas bloqueadas y comprobación de compatibilidad Python.
- Evidencia real de despliegue, almacenamiento persistente y monitorización antes de afirmar preparación de producción.

## Criterios de entrada a Fase 2

Fase 2 no debe empezar como si Fase 1 estuviera cerrada hasta que los 20 objetivos estén aceptados con evidencia. Como mínimo, deben resolverse los objetivos 13–17 y 20, verificarse el contrato de contenedor (18) en el HEAD actual y mantenerse verdes las puertas de calidad (19). La migración desde SQLite local a un almacén apropiado para concurrencia multi-réplica es una decisión arquitectónica separada, no una propiedad implícita de esta fase.

## Límites de control

La autenticación de un bearer, un navegador, una URL, una IP o un user-agent no concede autoridad de mando. La autoridad privilegiada exige la cadena de identidad y dispositivo definida en el contrato; los peers federados solo reciben capacidades READ_ONLY concedidas explícitamente. No fusionar, desplegar, ampliar permisos externos ni activar workers de producción sin aprobación explícita.
