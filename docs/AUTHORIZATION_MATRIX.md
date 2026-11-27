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

## Protocolo de federación `/fed/v1/*`

| Ruta | Exposición | Comprobaciones y autoridad |
|---|---|---|
| `GET /fed/v1/identity`, `GET /fed/v1/contract` | Pública | Publica identidad criptográfica y capacidades declaradas; no enrola peers ni concede grants. |
| `GET /fed/v1/publication` | Pública y opt-in | Solo publica si `IAO_FEDERATION_PUBLIC_PEERING=true` y existe un origen HTTPS válido configurado; `consent=true` expresa esa configuración local explícita. |
| `POST /fed/v1/handshake` | Pública, prueba de posesión | Responde a un nonce fresco con prueba firmada; no crea confianza ni enrola al solicitante. |
| `POST /fed/v1/message` | Protocolo de peer firmado | Verifica peer previamente enrolado, firma Ed25519, destinatario, ventana temporal, nonce anti-replay, lease, límite por peer, grant entrante local, capability servida y `effect_class=READ_ONLY`. Las denegaciones se auditan. |

El protocolo de peers no usa bearer de usuario: su autenticación es la clave Ed25519 del peer. La clave pública publicada o descubierta no basta para enrolarlo; los grants entrantes se almacenan por separado y permanecen vacíos salvo concesión local explícita.

Pruebas de regresión: `tests/test_federation_http_adapters.py` envía firmas falsificadas y JSON con miembros duplicados a FastAPI y al adaptador stdlib; ambos deben rechazar el mensaje. También se prueba el rechazo de miembros duplicados en `/fed/v1/handshake`. `Node.handle` exige un sobre cerrado (`v/from/to/ts/nonce/capability/body/sig`), versión entera, peer hexadecimal, timestamp finito y acotado, nonce ASCII de 16–128 caracteres, cuerpo objeto y firma Base64 canónica. `Node.answer_challenge` aplica sobre cerrado y JSON sin claves duplicadas. La cobertura completa de cada ruta de API y de todos los métodos sigue pendiente.
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
