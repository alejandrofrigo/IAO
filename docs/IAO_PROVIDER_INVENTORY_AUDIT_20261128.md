# Auditoría del inventario de proveedores y modelos IAO — 2026-11-28

**Rama:** `phase-1-core-foundation-20261127`  
**HEAD de código inspeccionado:** `107dd7bec53c12784be91b6c41542accca472d61`  
**Resultado:** inventario de código y referencias de configuración inspeccionado. No se añadieron proveedores ni se consultaron credenciales reales.

## 1. Inventario existente

### Router OpenAI-compatible

Fuente: `omega/llm_router.py`.

- Archivo de configuración local esperado: `~/.config/iao/llm-providers.json`.
- Campos consumidos por el router: `id`, `url`, `model`, `key_env`, `priority`, `enabled`.
- La URL debe usar HTTPS y el modelo debe ser una cadena no vacía.
- Endpoint derivado: `url.rstrip("/") + "/chat/completions"`.
- La credencial se resuelve por el nombre indicado en `key_env`; el valor no se escribe en el estado de salud.
- El router devuelve identidad de proveedor, modelo configurado y modelo upstream cuando el servidor lo informa.
- El estado diferencia `declared`, `credential_present` y `connectivity`. Solo un `last_success` persistido después de una llamada real exitosa produce `connectivity=confirmed`; la configuración sola produce `unverified`.

**Límite de la evidencia:** `connectivity=confirmed` refleja que existió una llamada exitosa previa, no una comprobación live ni una garantía de disponibilidad actual. El timestamp de último éxito debe evaluarse antes de interpretar frescura.

La configuración `~/.config/iao/llm-providers.json` no está versionada en el repositorio ni es accesible a GitHub Actions. Por tanto, este inventario de código no permite afirmar qué IDs, modelos, URLs o referencias de secreto están configurados en el runtime del operador.

### Adaptadores fijos

Fuente: `omega/adapters/model.py`.

| Proveedor declarado en el adaptador | Host fijo | Endpoint | Autenticación |
|---|---|---|---|
| `anthropic` | `api.anthropic.com` | `/v1/messages` | `x-api-key` |
| `gemini` | `generativelanguage.googleapis.com` | `/v1beta/models/{model}:generateContent` | `x-goog-api-key` |
| `groq` | `api.groq.com` | `/openai/v1/chat/completions` | `Authorization: Bearer` |

Variables de entorno consumidas:

- `MODEL_ADAPTER` (`disabled`, `anthropic`, `gemini`, `groq`)
- `MODEL_PROVIDER` (compatibilidad de selección)
- `MODEL_ID`
- `MODEL_API_KEY`
- `MODEL_TIMEOUT_SECONDS`
- `MODEL_MAX_OUTPUT_TOKENS`

`.env.example` deja `MODEL_ADAPTER=disabled` y no contiene IDs de modelos ni credenciales de proveedores. Los hosts de los tres adaptadores son fijos en código; el modelo se selecciona mediante `MODEL_ID`.

## 2. Probes, manifiestos y evidencia histórica

- `artifacts/model-adapter-probe.json` tiene fecha 2026-10-23. Declara explícitamente que se usó un placeholder y que ninguna clave real fue ejercitada. Anthropic terminó en `EGRESS_DENIED_BY_SANDBOX`, Gemini en `PROVIDER_UNREACHABLE`; el artefacto clasifica el resultado como `BLOCKED_NETWORK`. No contiene una llamada real exitosa.
- Ese probe no incluye un resultado de Groq.
- `artifacts/MANIFEST.sha256` contiene hashes de una instantánea histórica, incluido el probe y `omega/adapters/model.py`, pero no incluye `omega/llm_router.py` ni las pruebas actuales del router. No es un manifiesto completo del HEAD actual ni demuestra disponibilidad.
- `artifacts/network-connectivity.json` y `artifacts/runtime-report.json` son evidencias fechadas 2026-10-23 de pruebas generales del entorno y runtime local; no son probes de proveedores de IA ni evidencia actual de inferencia externa.

## 3. Pruebas existentes

- `tests/test_llm_router.py`: failover, cooldown, sanitización de errores, no exposición de secretos sintéticos y distinción entre proveedor declarado/credencial/conectividad.
- `tests/test_llm_router_cooldown_failover.py`: prueba el recorrido de proveedores en cooldown hasta encontrar una respuesta válida.
- `tests/test_model_adapter.py`: pruebas del contrato de los adaptadores fijos.
- Las pruebas de CI usan transportes simulados, fixtures y secretos sintéticos. No se enviaron credenciales reales ni llamadas a proveedores desde GitHub Actions.

## 4. Disponibilidad demostrada

| Dimensión | Resultado verificable |
|---|---|
| Proveedor/adaptador declarado en código | Anthropic, Gemini y Groq; además, gateways OpenAI-compatible definidos en inventario local |
| IDs/modelos concretos configurados en runtime | NO VERIFICABLE desde GitHub; el archivo local no está en el repositorio |
| Credenciales presentes en runtime | NO VERIFICABLE desde GitHub; no se inspeccionaron secretos del dispositivo |
| Conectividad a hosts de proveedores | No confirmada por evidencia actual |
| Llamada real exitosa | No demostrada |
| Router/failover con mocks | Probado por CI |
| Nuevos proveedores añadidos | Ninguno |

No se deben describir los proveedores como disponibles, conectados o utilizables solo porque estén en el enum o en el inventario.

## 5. Riesgo de seguridad y prioridad técnica

El adaptador fijo limita el proveedor a hosts definidos en código y rechaza redirects, aunque su transporte HTTPS directo no pasa todavía por la política compartida de egress.

El riesgo más alto está en el router OpenAI-compatible dinámico: `omega/llm_router.py::_request` construye el endpoint desde `url` del inventario y usa `urllib.request.urlopen` directamente. No aplica el allowlist/DNS pinning de `omega/egress.py` y el opener predeterminado puede seguir redirects. Esto debe corregirse antes de activar proveedores configurados: HTTPS estricto, host explícito del inventario, DNS fijado, rechazo de IPs privadas/no globales, redirects rechazados, límite de bytes/tiempo y transporte mockeable. Los secretos deben permanecer solo en referencias de entorno y nunca en logs, artefactos, mensajes de error o documentación.

**Siguiente aceptación:** integrar el POST del router con transporte de egress seguro y añadir pruebas deterministas de SSRF/DNS/redirect/timeout/tamaño/secret-redaction. Después, y solo con autorización explícita, verificar presencia de credenciales y hacer una llamada real controlada por proveedor.
