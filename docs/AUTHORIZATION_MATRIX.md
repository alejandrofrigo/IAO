# Matriz de autenticación y autorización

**Estado:** matriz de implementación parcial para Fase 1, objetivo 13.  
**Fuente de autoridad:** `OmegaService`, `omega/auth.py`, `omega/operator_identity.py`, `omega/device_authority.py` y `omega/policy.py`.  
**Regla:** autenticación válida no equivale a autorización; un modelo, peer o dato recuperado nunca concede permisos.

## Matriz por clase de ruta

| Clase | Rutas / operación | Requisitos comprobados | Permiso resultante |
|---|---|---|---|
| Salud pública | `GET /health/live`, `GET /health/ready` | Sin bearer; readiness comprueba dependencias y autenticación de auditoría. | Solo diagnóstico. |
| Inicio de sesión público | `POST /v1/public/session` | Rate limit; emite sujeto `guest:` con scopes vacíos y TTL limitado. | Sesión pública; no concede capacidades. |
| Consulta pública autenticada | Conversaciones, mensajes propios y chat | Bearer válido; aislamiento por sujeto; acceso a tareas/mensajes solo del propietario. | Consulta y chat dentro del alcance de la sesión; no concede mando privilegiado. |
| Capacidad explícita | `POST /v1/tasks` en modo sync y operaciones de memoria | `authorize()` compara la capacidad requerida con scopes explícitos; herramientas deben existir en el registro y validar entradas/salida. | Solo la capacidad concedida. |
| Consulta de internet | `POST /v1/federation/internet` | Bearer válido y scope explícito `federation.internet`; denegación auditada antes de invocar el proveedor. | Consulta externa solo con scope. |
| Sesión de operador | Rutas que autentican un sujeto `operator:` | `_auth` exige que el token exacto siga asociado a una sesión raíz activa; revocación invalida la asociación. | Identidad de operador autenticada; no eleva scopes ni concede por sí sola ejecución. |
| Bootstrap / recuperación | Rutas `/v1/operator/bootstrap/*` y `/v1/operator/recovery/*` | Secreto de un solo uso/fuera de banda, expiración y firmas de claves raíz/dispositivo según el protocolo. | Establece o recupera identidad; no es un permiso genérico de ejecución. |
| Vinculación de sesión/dispositivo | `/v1/operator/session/*`, `/v1/operator/device/bind` | Challenge de un solo uso, firma raíz, asociación al sujeto y al bearer exacto; clave del dispositivo debe estar enrolada y pertenecer al sujeto. | Asociación criptográfica de solo lectura. |
| Enrolamiento de dispositivo | `POST /v1/device/enroll` | Deshabilitado salvo habilitación explícita y código de enrolamiento de un solo uso; sujeto invitado rechazado. | Registra clave pública; no concede scopes ni autoridad de mando. |
| Estado de dispositivo | `POST /v1/device/challenge`, `/v1/device/command` | Bearer autenticado; challenge/nonce y prueba de posesión cuando se verifica estado. | Diagnóstico de solo lectura. |
| Tarea en cola | `POST /v1/tasks` con `execution_mode=queued` | Sesión raíz asociada al bearer exacto; prueba ECDSA del dispositivo sobre método, ruta, timestamp, nonce y hash del cuerpo; dispositivo primario vinculado a esa sesión; scope de herramienta; efecto READ_ONLY y allowlist de cola. | Encolado limitado a capacidades read-only aprobadas. No se admite ejecución privilegiada/destructiva. |
| Auditoría | `GET /v1/audit/events` | Bearer válido; `audit.admin` determina vista global; en otro caso, eventos del propio sujeto. | Lectura acotada por sujeto o scope. |

## Inventario de rutas de aplicación `/v1/*`

La siguiente tabla refleja los controles observados en `OmegaService._route`, `handle` y sus autoridades. Los endpoints de bootstrap/login/recovery son públicos en el sentido de que no exigen un bearer preexistente; no son anónimos sin prueba: exigen códigos de un solo uso, challenges y/o firmas raíz y de dispositivo según la operación.

| Ruta y método | Autenticación / autorización | Efecto y límite |
|---|---|---|
| `POST /v1/public/session` | Pública; rate limit por dirección de socket | Emite token `guest:` de vida limitada con scopes vacíos. |
| `POST /v1/operator/bootstrap/status` | Pública; verifica par de claves raíz/dispositivo ya comprometido | Solo informa estado de bootstrap; no concede sesión. |
| `POST /v1/operator/bootstrap` | Código de bootstrap + recovery code distinto + firmas raíz/dispositivo | Bootstrap de identidad; operación de una sola vez. |
| `POST /v1/operator/recovery/status` | Pública; verifica par de claves y pertenencia de dispositivo | Solo informa si la recuperación quedó comprometida. |
| `POST /v1/operator/recovery/challenge` | Recovery code, nuevo recovery code y claves públicas; rate limit | Emite challenge de recuperación acotado. |
| `POST /v1/operator/recovery/complete` | Challenge + firmas raíz y dispositivo; rate limit | Recupera identidad y sustituye dispositivo activo; autoridad resultante READ_ONLY. |
| `POST /v1/operator/login/challenge` | Pública; exige autoridades configuradas, clave raíz y dispositivo primario activo; rate limit | Emite challenge; no emite bearer por sí solo. |
| `POST /v1/operator/login/complete` | Challenge + firmas raíz/dispositivo | Emite bearer de operador de vida limitada y vincula clave activa del dispositivo. |
| `POST /v1/operator/identity/revoke` | Bearer de operador con sesión raíz vigente + firma raíz + versión de clave | Revoca identidad y dispositivo activo. |
| `POST /v1/operator/device/bind` | Bearer de operador/sesión vigente + clave ya enrolada + firma raíz | Vincula dispositivo primario a la sesión. |
| `POST /v1/operator/session/challenge` | Bearer de operador; rechaza guest | Emite challenge de asociación del bearer exacto. |
| `POST /v1/operator/session/bind` | Bearer de operador + firma raíz sobre challenge de un solo uso | Asocia criptográficamente el bearer exacto; no añade scopes. |
| `GET /v1/operator/session/status` | Bearer válido; guest solo obtiene estado READ_ONLY | Consulta asociación; no cambia permisos. |
| `GET /v1/federation/status` | Pública | Diagnóstico `unknown/discovery_only`; no afirma peers ni red operativa. |
| `POST /v1/federation/internet` | Bearer + scope explícito `federation.internet` | Consulta externa; la denegación se audita y la consulta se registra por digest. |
| `POST /v1/device/enroll` | Bearer no guest + `IAO_DEVICE_ENROLLMENT_ENABLED=1` + código de enrolamiento | Registra clave pública; no concede scopes. |
| `POST /v1/device/challenge` | Bearer no guest | Emite challenge para el dispositivo perteneciente al sujeto. |
| `POST /v1/device/command` | Bearer + prueba de posesión del dispositivo | Devuelve estado READ_ONLY; no ejecuta comandos arbitrarios. |
| `GET /v1/me` | Bearer; sujetos `operator:` requieren sesión raíz vigente | Devuelve sujeto y scopes del propio token. |
| `POST /v1/conversations` | Bearer | Crea conversación del sujeto autenticado; guest permitido para chat público. |
| `GET /v1/conversations/{uuid}/messages` | Bearer + propiedad de la conversación | Lee solo mensajes propios. |
| `POST /v1/chat` | Bearer + propiedad de conversación | Guarda mensaje y respuesta; salida LLM no autoritativa. |
| `POST /v1/tasks` | Bearer + scope de la capability + herramienta registrada y validación determinista | Modo sync sujeto a policy; modo queued añade sesión raíz, firma de dispositivo, lease y allowlist READ_ONLY. |
| `GET /v1/tasks/{uuid}` | Bearer + propiedad de tarea | Lee solo la tarea propia. |
| `GET /v1/memory`, `GET /v1/memory/export` | Bearer + `memory.read` | Lee/exporta memoria propia. |
| `POST /v1/memory` | Bearer + `memory.write` + `consent=true` | Crea memoria explícitamente consentida; auditoría conserva digest, no contenido. |
| `PUT /v1/memory/{uuid}`, `DELETE /v1/memory[/{uuid}]` | Bearer + `memory.write` | Actualiza/elimina memoria propia. |
| `GET /v1/audit/events` | Bearer; `audit.admin` para vista global | Sin scope admin, devuelve solo eventos del propio sujeto. |

Las rutas exactas tienen métodos allowlist y devuelven 405 con `Allow` cuando el método no está permitido. Las rutas de memoria, conversación y tarea validan ownership; las rutas privilegiadas de operador están además cubiertas por el rollback anchor cuando está configurado. Esta tabla es una revisión estática; los tests de integración exhaustivos para cada fila y ambos adaptadores siguen pendientes.

## Protocolo de federación `/fed/v1/*`

| Ruta | Exposición | Comprobaciones y autoridad |
|---|---|---|
| `GET /fed/v1/identity`, `GET /fed/v1/contract` | Pública | Publica identidad criptográfica y capacidades declaradas; no enrola peers ni concede grants. |
| `GET /fed/v1/publication` | Pública y opt-in | Solo publica si `IAO_FEDERATION_PUBLIC_PEERING=true` y existe un origen HTTPS válido configurado; `consent=true` expresa esa configuración local explícita. |
| `POST /fed/v1/handshake` | Pública, prueba de posesión | Responde a un nonce fresco con prueba firmada; no crea confianza ni enrola al solicitante. |
| `POST /fed/v1/message` | Protocolo de peer firmado | Verifica peer previamente enrolado, firma Ed25519, destinatario, ventana temporal, nonce anti-replay, lease, límite por peer, grant entrante local, capability servida y `effect_class=READ_ONLY`. Las denegaciones se auditan. |

El protocolo de peers no usa bearer de usuario: su autenticación es la clave Ed25519 del peer. La clave pública publicada o descubierta no basta para enrolarlo; los grants entrantes se almacenan por separado y permanecen vacíos salvo concesión local explícita.

Pruebas de regresión: `tests/test_federation_http_adapters.py` envía firmas falsificadas y JSON con miembros duplicados a FastAPI y al adaptador stdlib; ambos deben rechazar el mensaje. También se prueba el rechazo de miembros duplicados en `/fed/v1/handshake`. `Node.handle` exige un sobre cerrado (`v/from/to/ts/nonce/capability/body/sig`), versión entera, peer hexadecimal, timestamp finito y acotado, nonce ASCII de 16–128 caracteres, cuerpo objeto y firma Base64 canónica. `Node.answer_challenge` aplica sobre cerrado y JSON sin claves duplicadas. Las respuestas de peers usan un esquema cerrado y firmado, se vinculan al nonce/destinatario/capability de la solicitud y se verifican localmente con el `ToolSpec` antes de aceptar el resultado; el transporte rechaza JSON con miembros duplicados. La cobertura completa de cada ruta de API y de todos los métodos sigue pendiente.
## Invariantes de seguridad

1. Un bearer token solo autentica el sujeto y transporta scopes firmados; no prueba por sí mismo posesión de la clave raíz ni del dispositivo.
2. Los sujetos `operator:` requieren una asociación de sesión raíz vigente para pasar `_auth`; una sesión revocada o no vinculada falla cerrada.
3. El enrolamiento de dispositivo usa un secreto de un solo uso y permanece deshabilitado por defecto; no se trata como autorización de operador.
4. Las tareas en cola exigen una cadena de pruebas independiente y solo aceptan herramientas READ_ONLY incluidas en allowlist.
5. `federation.internet` exige un scope específico; la mera posesión de cualquier bearer no habilita consultas externas.
6. Las decisiones de capacidad se toman en código determinista, no por el modelo LLM ni por instrucciones recuperadas.
7. Los errores públicos usan códigos estables y no incluyen secretos ni mensajes internos.

## Brechas restantes antes de cerrar el objetivo 13

- Convertir esta matriz en pruebas de integración exhaustivas para cada ruta y ambos adaptadores HTTP.
- Auditar todas las rutas heredadas y protocolos `/fed/v1/*` para comprobar que no exista una ruta alternativa que omita la matriz.
- Verificar CI de la revisión actual y resolver cualquier regresión.
- Mantener explícito que el flujo de mando privilegiado no está habilitado por este objetivo; el encolado actual es read-only.

La matriz describe la implementación inspeccionada en esta rama; no afirma que la infraestructura externa ni el cliente móvil hayan sido desplegados o validados físicamente.
