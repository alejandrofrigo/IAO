# Guía operativa — Fase 1 de IAO

## Estado y alcance

Esta guía describe el comportamiento verificable del código de Fase 1. No certifica una instalación desplegada, disponibilidad pública, alta disponibilidad, multi-réplica ni ejecución autónoma continua en infraestructura externa.

- `/health/live` demuestra que el proceso HTTP responde.
- `/health/ready` evalúa dependencias locales. Su estado degradado o `production_ready=false` no puede elevarse a producción por configuración cosmética.
- Un PID demuestra, como máximo, que existe un proceso con ese identificador. El supervisor solo clasifica PADGE como funcional cuando el PID coincide con el propietario del lock advisory y con un heartbeat reciente.
- Un peer descubierto no es un worker, no recibe confianza ni grants y no puede ejecutar herramientas con efectos.

## Supervisión local

El coordinador registra fases `starting`, `cycle_running` y `cycle_completed` en un heartbeat atómico. El estado se clasifica como:

| Estado | Significado |
|---|---|
| `HEALTHY` | Lock activo y coincidente con PID/heartbeat reciente; el último ciclo terminó |
| `CYCLE_IN_PROGRESS` | Lock activo y heartbeat reciente durante un ciclo |
| `DEGRADED_UNVERIFIED` | Lock y heartbeat ausentes, caducados o no coincidentes |
| `STOPPED` | No hay lock advisory activo |
| `PROCESS_ALIVE_UNVERIFIED` | Hay PID de un motor, pero no existe protocolo de salud funcional para él |
| `STALE_HEARTBEAT` | El coordinador conserva PID, pero el heartbeat superó el límite de frescura |

Los heartbeats y eventos operativos se guardan bajo directorios privados (0700) y archivos privados (0600). Los logs redactan texto libre, trazas, comandos y rutas; no deben ampliarse para incluir prompts, consultas, credenciales ni contenido de usuario.

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
- Cobertura ruta por ruta de `/v1/*` y `/fed/v1/*` en ambos adaptadores, con autorización positiva/negativa y métodos incorrectos.
- Barrido de privacidad del árbol, historial Git, logs de launchers, imágenes de contenedor y artefactos CI.
- Heartbeat y recuperación verificables para cada motor habilitado; ningún estado funcional basado solo en PID.
- Instalación reproducible con dependencias transitivas bloqueadas y comprobación de compatibilidad Python.
- Evidencia real de despliegue, almacenamiento persistente y monitorización antes de afirmar preparación de producción.

## Criterios de entrada a Fase 2

Fase 2 no debe empezar como si Fase 1 estuviera cerrada hasta que los 20 objetivos estén aceptados con evidencia. Como mínimo, deben resolverse los objetivos 13–17 y 20, verificarse el contrato de contenedor (18) en el HEAD actual y mantenerse verdes las puertas de calidad (19). La migración desde SQLite local a un almacén apropiado para concurrencia multi-réplica es una decisión arquitectónica separada, no una propiedad implícita de esta fase.

## Límites de control

La autenticación de un bearer, un navegador, una URL, una IP o un user-agent no concede autoridad de mando. La autoridad privilegiada exige la cadena de identidad y dispositivo definida en el contrato; los peers federados solo reciben capacidades READ_ONLY concedidas explícitamente. No fusionar, desplegar, ampliar permisos externos ni activar workers de producción sin aprobación explícita.
