# Contrato HTTP común de IAO

**Estado:** contrato base implementado; ampliación y verificación ruta por ruta pendientes.  
**Fuente de verdad de la lógica:** `OmegaService.handle(method, path, headers, body)`.  
**Adaptadores:** `omega/server.py` (stdlib HTTP) y `apps/api/main.py` (FastAPI/ASGI).

## Reglas comunes

- Los dos adaptadores delegan las rutas de aplicación en el mismo `OmegaService`; no deben redefinir autenticación, autorización ni códigos de dominio.
- El cuerpo máximo de las rutas de aplicación es **65.536 bytes** (`omega.service.MAX_BODY`). La API ASGI lee por fragmentos y rechaza antes de acumular más del límite. El adaptador stdlib no consume cuerpos declarados por encima del límite y cierra esa conexión.
- `Content-Length` no numérico o negativo produce `400 INVALID_CONTENT_LENGTH`; longitud declarada distinta del cuerpo recibido produce `400 INCOMPLETE_BODY`; tamaño superior al límite produce `413 PAYLOAD_TOO_LARGE`.
- Las rutas JSON de aplicación esperan un objeto JSON. JSON inválido o un valor JSON de tipo distinto de objeto produce `400 INVALID_JSON` cuando la ruta lo procesa.
- Los errores de método para rutas conocidas producen `405 METHOD_NOT_ALLOWED`, incluyen `allowed_methods` en el JSON y la cabecera HTTP `Allow`. Una ruta desconocida produce `404 NOT_FOUND`.
- La envoltura de servicio incluye `correlation_id` en respuestas de aplicación y los adaptadores lo reflejan en `X-Correlation-ID`. No se incluye el texto de excepciones internas en respuestas públicas.
- Las respuestas de aplicación llevan `Cache-Control: no-store` y `X-Content-Type-Options: nosniff`.
- Los errores de autenticación, autorización y límites conservan códigos estables: `401 AUTHENTICATION_REQUIRED`, `403` para denegaciones de política, `429 RATE_LIMITED`, `413 PAYLOAD_TOO_LARGE`, `503` para dependencias no disponibles y `500 INTERNAL_ERROR` para fallos internos no clasificados.

## Métodos fijados para las rutas principales

| Ruta | Método | Resultado de método incorrecto |
|---|---|---|
| `/health/live` | GET | 405 |
| `/health/ready` | GET | 405 |
| `/v1/public/session` | POST | 405 |
| `/v1/operator/bootstrap` y subrutas de bootstrap | POST | 405 |
| `/v1/operator/recovery/*` | POST | 405 |
| `/v1/operator/login/*` | POST | 405 |
| `/v1/operator/identity/revoke` | POST | 405 |
| `/v1/operator/device/bind` | POST | 405 |
| `/v1/operator/session/challenge`, `bind` | POST | 405 |
| `/v1/operator/session/status` | GET | 405 |
| `/v1/federation/status` | GET | 405 |
| `/v1/federation/internet` | POST | 405 |
| `/v1/device/enroll`, `challenge`, `command` | POST | 405 |
| `/v1/me` | GET | 405 |
| `/v1/conversations` | POST | 405 |
| `/v1/conversations/{uuid}/messages` | GET | 405 |
| `/v1/chat` | POST | 405 |
| `/v1/tasks` | POST | 405 |
| `/v1/tasks/{uuid}` | GET | 405 |
| `/v1/audit/events` | GET | 405 |
| `/v1/memory` y subrutas | GET, POST, PUT, DELETE según operación | 405 para métodos fuera de ese conjunto |

Las rutas de federación `/fed/v1/*` tienen un protocolo y límites propios en cada adaptador; no se consideran intercambiables con las rutas `/v1/*`.

## Contratos de entrada principales

- `POST /v1/public/session`: objeto JSON; la respuesta de sesión contiene el token y sus metadatos de expiración.
- `POST /v1/conversations`: `title` es texto de hasta 200 caracteres; responde `201` con `conversation_id`.
- `POST /v1/chat`: requiere `conversation_id` y `message` de 1 a 20.000 caracteres; el resultado identifica la salida del modelo como no autoritativa.
- `GET /v1/conversations/{uuid}/messages`: requiere autenticación y limita la lectura al propietario.
- `POST /v1/tasks` y `GET /v1/tasks/{uuid}`: usan la cola persistente y el ámbito del propietario; los resultados no conceden autoridad a los modelos ni a peers externos.

## Alcance y brechas

Este documento fija el sobre HTTP común, límites de cuerpo, cabeceras, errores genéricos y métodos de las rutas principales. No pretende sustituir esquemas OpenAPI completos ni documenta todavía cada campo de todos los flujos de identidad, recuperación, memoria y federación. La compatibilidad debe seguir verificándose con pruebas de ambos adaptadores; una prueba unitaria del servicio no prueba por sí sola el comportamiento de red.
