# Fase 2 — Centro de mando seguro y orquestación de tareas

**Estado:** INICIADA — diseño técnico y criterios de aceptación.  
**Rama:** `phase-2-secure-control-plane-20261127`  
**Base:** HEAD de la rama Fase 1 `d5b011cff1b620b00a468a5bad84b720fbc8fec4`.  
**Dependencia:** esta fase está apilada sobre el PR #20. No declara Fase 1 cerrada, no fusiona ramas y no habilita producción.

## Propósito

Convertir la identidad de dispositivo y las capacidades existentes en un flujo persistente, verificable y limitado de órdenes desde el Chat público IAO autorizado hasta el coordinador y los workers. El teléfono registrado es el único origen de mando privilegiado. Otros clientes pueden consultar según sus permisos, pero nunca heredan autoridad por usar la misma URL, cuenta, IP, navegador o user-agent.

El primer alcance ejecutable será local/piloto y de solo lectura. Las capacidades que impliquen escribir, ejecutar código, cambiar configuración, desplegar, gastar dinero, acceder a secretos o actuar de forma irreversible permanecerán bloqueadas hasta disponer de una política explícita, aprobación requerida, aislamiento y pruebas.

## Reglas de aceptación

- Un objetivo solo pasa a **VERIFICADO** cuando su código, pruebas, CI en el SHA exacto y evidencia de integración cumplen su criterio.
- Una firma demuestra posesión de una clave; no concede permisos por sí sola.
- La autenticación de un modelo, nodo o peer no le otorga identidad de operador ni autoridad.
- Los mensajes del LLM, los datos remotos y los resultados de herramientas son entrada no confiable.
- Los comandos deben ser idempotentes, auditables, revocables y tener límites de tamaño, tiempo, frecuencia y recursos.
- La pérdida de conectividad, la expiración de leases o una respuesta ambigua nunca provocan reejecución ciega.
- El estado debe poder reconstruirse desde almacenamiento persistente; no se considera operativo por un PID o una respuesta HTTP aislada.

## Los 20 objetivos técnicos

| Nº | Objetivo | Criterio de aceptación |
|---:|---|---|
| 01 | Contrato de órdenes | Definir un esquema versionado y cerrado para órdenes: ID, emisor, dispositivo, fecha, nonce, expiración, tipo, argumentos, capacidades requeridas y hash del contenido. Rechazar campos duplicados/desconocidos y tipos ambiguos. |
| 02 | Identidad del dispositivo primario | Completar enrolamiento de una sola identidad primaria, prueba de posesión ECDSA y vínculo a la sesión raíz; documentar rotación y recuperación sin permitir dos primarios activos. |
| 03 | Autorización por acción | Crear una matriz explícita de acciones permitidas, denegadas y condicionadas. Ningún scope genérico debe equivaler a ejecutar código o conceder autoridad administrativa. |
| 04 | Firma canónica de órdenes | Definir canonicalización estable y firma de extremo a extremo que cubra método, destino, versión, emisor, dispositivo, nonce, expiración, capacidades y hash del cuerpo. |
| 05 | Protección anti-replay | Persistir nonces/contadores y consumirlos atómicamente; rechazar repetición, expiración, desorden y concurrencia duplicada. |
| 06 | Ingreso autenticado | Implementar un endpoint de recepción que solo acepte órdenes del dispositivo primario vigente y responda con recibo firmado/correlacionado; no ejecutar dentro de la petición HTTP. |
| 07 | Bandeja persistente de órdenes | Añadir inbox durable con estados RECEIVED, VALIDATED, QUEUED, RUNNING, SUCCEEDED, FAILED, REJECTED, EXPIRED y UNKNOWN; migraciones transaccionales y retención acotada. |
| 08 | Idempotencia y deduplicación | La misma orden/reintento devuelve el mismo recibo y no crea ejecuciones duplicadas; conflictos de ID/hash se rechazan y auditan. |
| 09 | Enrutador de tareas | Enrutar por tipo, capacidades, límites y estado funcional del worker; no despachar a motores UNVERIFIED, DEGRADED o STALE. |
| 10 | Leases y fencing | Adquirir leases transaccionales con propietario e identidad de proceso; cada escritura de resultado requiere lease vigente y fencing token monotónico. |
| 11 | Máquina de estados | Aplicar transiciones deterministas, monotónicas y auditadas; bloquear transiciones imposibles y resultados tardíos de un worker antiguo. |
| 12 | Planificador autónomo acotado | Descomponer tareas en pasos tipados con presupuesto de tiempo/tokens/recursos; el planificador no puede ampliar sus propias capacidades ni autoaprobar acciones. |
| 13 | Broker de capacidades | Entregar a cada tarea solo capacidades explícitas, temporales y mínimas; secretos y credenciales nunca entran en prompts ni payloads del worker. |
| 14 | Ejecución aislada | Ejecutar herramientas en un límite de aislamiento verificable, sin acceso al host/archivos/secretos por defecto; límites de CPU, memoria, red, tiempo y salida. |
| 15 | Aprobaciones humanas críticas | Implementar aprobación firmada desde el dispositivo primario para acciones sensibles, con resumen de impacto, hash exacto de la acción, caducidad y consumo único. |
| 16 | Auditoría de órdenes | Registrar digest del contenido, decisión, actor lógico, identidad del dispositivo seudonimizada, transición y resultado; nunca guardar secretos, IP ni argumentos sensibles en claro. |
| 17 | Recibos y seguimiento | Devolver recibos verificables y estados consultables; diferenciar recepción, validación, ejecución y resultado; no afirmar finalización antes de persistirla. |
| 18 | Desconexión y reconciliación | Implementar outbox/reintentos con backoff y reconciliación tras reconexión; estados ambiguos quedan UNKNOWN hasta verificación, nunca se repiten automáticamente. |
| 19 | Revocación y recuperación | Revocar el dispositivo, invalidar sesiones y órdenes pendientes, rotar claves con procedimiento fuera de banda y probar recuperación segura. |
| 20 | Prueba extremo a extremo del centro de mando | Probar el flujo Chat autorizado → firma del teléfono → API → inbox → policy → worker → resultado → recibo → chat; un segundo dispositivo debe fallar al intentar emitir órdenes privilegiadas. |

## Entregas por bloques

1. **Identidad y protocolo (01–05):** contrato de orden, vínculo de dispositivo, firma y anti-replay.
2. **Recepción y persistencia (06–08):** endpoint, inbox, idempotencia y recibos de aceptación.
3. **Ejecución controlada (09–14):** enrutamiento, leases, estados, planificador, broker y sandbox.
4. **Control y continuidad (15–19):** aprobación, auditoría, seguimiento, desconexión y revocación.
5. **Aceptación integral (20):** pruebas de extremo a extremo en entorno piloto y verificación negativa desde dispositivos no autorizados.

## Dependencias y bloqueos heredados de Fase 1

- No desplegar el centro de mando hasta cerrar Fase 1 y resolver sus PRs apiladas de forma explícita.
- Objetivo 13 de Fase 1: completar matriz positiva/negativa por ruta y adaptador.
- Objetivo 14: auditar historial Git, launchers, imágenes y artefactos históricos; el sanitizador actual no purga información histórica.
- Objetivo 15: heartbeat persistente de Guardian, gestión del ciclo de vida de TaskWorker y recuperación por motor; probar procesos reales.
- Objetivo 16: terminar la auditoría de rutas/métodos/errores en ambos adaptadores.
- Objetivo 17: incorporar `uv.lock` generado y revisado; mantener instalación `--locked` en CI.
- Objetivo 19: conservar CI verde sobre el HEAD exacto de cada cambio.
- Objetivo 20: actualizar el runbook con resultados reproducibles, no solo procedimientos previstos.

## Límites del primer incremento

El primer incremento de Fase 2 no ejecutará shell arbitrario, no descargará ni ejecutará código remoto, no modificará el sistema operativo del teléfono, no habilitará control desde otros dispositivos, no concederá confianza automática a nodos descubiertos y no tendrá autoridad para desplegar o efectuar gastos. Las órdenes iniciales se limitarán a consultas de estado, lectura autorizada y tareas internas no destructivas.

## Registro de implementación

| Objetivo | Estado inicial | Evidencia |
|---:|---|---|
| 01 | IMPLEMENTADO — pendiente CI | `omega/command_protocol.py` valida un esquema cerrado y versionado, límites, expiración, nonce, capacidades ordenadas, ID UUID, device ID y firma codificada; rechaza miembros JSON duplicados y números no finitos. `tests/test_command_protocol.py` añade regresiones negativas y de canonicalización. |
| 02 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 03 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 04 | PARCIAL — pendiente CI | `canonical_command_bytes()` define bytes estables con dominio `IAO-COMMAND-V1` y excluye la firma del contenido firmado. La verificación ECDSA contra la clave primaria del dispositivo aún no está conectada al ingreso. |
| 05 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 06 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 07 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 08 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 09 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 10 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 11 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 12 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 13 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 14 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 15 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 16 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 17 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 18 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 19 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |
| 20 | PENDIENTE | Criterios definidos; implementación y pruebas aún no aceptadas. |

**Resultado:** Fase 2 queda abierta como rama de trabajo dependiente de Fase 1. Este documento define el contrato y la secuencia; no equivale a una implementación funcional ni a una conexión ya operativa entre el chat móvil y el daemon.


## Primer incremento implementado — protocolo de órdenes

En la rama inicial se añadieron:
- `omega/command_protocol.py`: parseo JSON acotado con rechazo de miembros duplicados/NaN, esquema exacto `iao.command.v1`, audiencia fija, emisor operador, UUID canónico, device ID SHA-256, ventana temporal máxima de 120 segundos, skew futuro máximo de 30 segundos, nonce base64url, tipo de orden y capacidades explícitas ordenadas y únicas, cuerpo objeto de hasta 16 KiB y firma codificada canónicamente.
- `canonical_command_bytes()`: serialización determinista con separador de dominio binario; la firma no se incluye en los bytes que ella misma autentica.
- `command_digest()`: huella SHA-256 para correlación/auditoría; no reemplaza firma ni autorización.
- `tests/test_command_protocol.py`: regresiones para esquema cerrado, campos inválidos, duplicados JSON, no finitos, expiración, capacidades duplicadas/no canónicas, límites, codificación de firma y bytes estables.
- El lint bloqueante de integración incluye el módulo y su suite de pruebas.

**Límite explícito:** el campo `signature` se valida sintácticamente, pero aún no se verifica criptográficamente contra la clave enrolada; tampoco se persiste ni consume el nonce. Por tanto, este módulo no debe usarse aún para aceptar o ejecutar órdenes. La rama permanece en desarrollo hasta que CI pase y se implemente la verificación de extremo a extremo.
