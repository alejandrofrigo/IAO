# IAO — contrato de arquitectura del núcleo

**Estado:** contrato de límites documentado; su cumplimiento integral sigue sujeto a pruebas e integración.

## 1. Propósito

Este documento fija las responsabilidades y las fuentes de verdad del núcleo para evitar colas, identidades, almacenes o políticas paralelas. Describe el código versionado, no afirma que exista un runtime externo activo.

## 2. Componentes y responsabilidades

| Capa | Componente canónico | Responsabilidad | No debe asumir |
|---|---|---|---|
| Adaptador HTTP stdlib | `omega/server.py` | Arranque del servidor HTTP basado en stdlib, rutas de federación y adaptación al servicio. | Ser una segunda lógica de negocio o una autoridad de identidad independiente. |
| Adaptador HTTP ASGI | `apps/api/main.py` | Exponer la API FastAPI, contratos HTTP y lifecycle ASGI. | Mantener otra cola o base de datos distinta para las mismas tareas. |
| Servicio de aplicación | `omega/service.py:OmegaService` | Validar solicitudes, aplicar autorización/política, orquestar herramientas, conversaciones y tareas. | Confiar en decisiones de un LLM como autorización. |
| Persistencia piloto | `omega/store.py:Store` | SQLite, transacciones, tareas, conversaciones, memoria y eventos de auditoría. | Presentarse como backend multi-réplica o PostgreSQL de producción. |
| Auditoría | `omega/audit.py` + Store | Canonicalización, hashes/HMAC y verificación de cadena. | Regenerar silenciosamente claves o reparar/eliminar eventos para ocultar corrupción. |
| Identidad de dispositivo | `omega/device_authority.py` | Registro y verificación de dispositivos. | Autorizar por URL, IP, navegador o user-agent. |
| Identidad del operador | `omega/operator_identity.py` | Raíz del operador, sesiones y autoridad criptográfica. | Compartir autoridad privilegiada con sesiones visitantes o peers externos. |
| Política determinista | `omega/policy.py`, `omega/policy_gate.py` | Autorizar capacidades y clasificar acciones según estado y evidencia. | Delegar decisiones de autoridad al modelo. |
| Registro de herramientas | `omega/tools/registry.py` | Registrar contratos de herramienta, validar entrada, ejecutar y verificar salida. | Ejecutar código arbitrario o ampliar allowlists por descubrimiento. |
| Adaptadores de modelos | `omega/adapters/model.py`, `omega/llm_router.py` | Traducir solicitudes de inferencia y enrutar proveedores configurados. | Conceder permisos, ejecutar acciones administrativas o tratar respuestas como autoridad. |
| Cola y worker | `omega/store.py` + `omega/task_worker.py` | Persistir tareas y ejecutar solo capacidades explícitamente permitidas con leases. | Introducir una segunda cola o aceptar órdenes privilegiadas de nodos remotos. |

## 3. Flujos canónicos

### Solicitud HTTP / chat

`Cliente → adaptador HTTP → OmegaService.handle → política/identidad → registro de herramientas → Store/auditoría → respuesta`

Los adaptadores deben delegar la lógica de aplicación al mismo contrato `OmegaService.handle` o a servicios de dominio compartidos. No deben copiar reglas de autorización o persistencia.

### Tarea persistente

`Chat autorizado → API de tareas → Store (cola única) → TaskWorker local → revalidación de identidad/capacidad → herramienta allowlisted → evidencia → Store/auditoría`

La cola SQLite existente es la fuente de verdad del piloto. No se considera segura para workers concurrentes distribuidos o réplicas API sin una solución de almacenamiento/locking compartido y pruebas específicas.

### Federación

`Descubrimiento público → candidato no confiable → verificación criptográfica/protocolo → consentimiento/capacidades explícitas → transporte mediado → auditoría`

Descubrimiento no equivale a confianza, enrolamiento, ejecución remota ni autoridad. La incorporación de peers no puede saltarse las autoridades locales ni conceder privilegios de mando.

## 4. Fuentes de verdad

- Una implementación de `OmegaService` por proceso de runtime.
- Un almacén de tareas persistente por instalación/piloto; no crear colas paralelas.
- Una autoridad raíz y una autoridad de dispositivo vinculadas criptográficamente.
- Una política determinista común; los adaptadores no redefinen permisos.
- El estado de auditoría y su clave persistente deben sobrevivir reinicios; la pérdida o invalidez de clave bloquea operaciones que dependan de integridad.
- La configuración efectiva procede del entorno validado; secretos no se incluyen en archivos, informes o representaciones de configuración.

## 5. Límites actuales verificados por inspección estática

1. `omega/store.py` implementa SQLite; el repositorio no demuestra todavía un backend PostgreSQL operativo ni migraciones productivas.
2. `omega/server.py` y `apps/api/main.py` son dos adaptadores/runtime entrypoints. Su coexistencia no demuestra que ambos estén ejecutados ni que compartan una instancia entre procesos.
3. El worker y la cola están diseñados alrededor del Store local; no se certifica escalado multi-réplica.
4. La disponibilidad de FastAPI, Docker, proveedores LLM y red externa depende de instalación/configuración/runtime real; los tests unitarios o CI no demuestran despliegue.
5. El inicio del worker permanece opt-in y no debe habilitarse en producción por esta fase.
6. Las respuestas de modelos y contenido obtenido de peers se consideran datos no confiables.

## 6. Reglas de cambio

- Reutilizar las autoridades, el Store, el registro y la política existentes.
- No añadir una segunda cola, raíz de identidad, registro de capacidades ni almacén de auditoría.
- Cambios de esquema deben ser aditivos, repetibles, probados con bases existentes y nuevos fixtures.
- Toda operación externa requiere destino permitido, egress mediado, límites y auditoría.
- No incluir identificadores personales del operador, secretos, IPs ni tokens en logs, documentación pública o artefactos.
- Mantener cambios en ramas aisladas y PRs; no fusionar `main`, desplegar ni activar workers privilegiados sin autorización explícita.

## 7. Evidencia pendiente

Este contrato es una especificación de arquitectura. Para declararlo verificado se requieren pruebas de integración que demuestren:
- ambos adaptadores invocan los mismos contratos de aplicación;
- la inicialización es idempotente dentro de un proceso;
- la cola y el Store preservan integridad bajo reinicio;
- las autoridades se revalidan en el límite de ejecución;
- los fallos se reflejan en readiness con códigos públicos acotados.
