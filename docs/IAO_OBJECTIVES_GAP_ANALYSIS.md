# IAO — Inventario de capacidades y brechas de integración

**Corte de revisión:** 2026-11-24  
**Repositorio revisado:** `alejandrofrigo/IAO`, rama `main`  
**Commit revisado:** `6c588672b7bff883e3aa1b4910992c0f09fb1040`  
**Alcance:** inspección estática del código y documentación versionados. No equivale a una auditoría del estado vivo de Termux ni a una prueba de producción.

## 1. Regla de estado

- **IMPLEMENTADO EN CÓDIGO:** existe un componente identificable.
- **PROBADO EN UN ENTORNO LIMITADO:** existe evidencia reproducible con alcance explícito.
- **INTEGRACIÓN PENDIENTE:** hay piezas, pero no está demostrado el recorrido completo.
- **NO IMPLEMENTADO EN EL REPOSITORIO REVISADO:** no se encontraron adaptadores, rutas o pruebas específicos.
- **NO VERIFICADO EN PRODUCCIÓN:** el código o un informe histórico no prueban el funcionamiento actual.

No se marcará una capacidad como completa por el mero hecho de que exista un módulo, una configuración o un proceso con PID.

## 2. Inventario de lo que IAO ya contiene

### 2.1 Núcleo autónomo y autoprogramación

**Existente:**
- `omega/autonomous_core.py`: cola persistente JSON, eventos y recuperación de tareas interrumpidas.
- `omega/autonomous_coordinator.py` y `tools/iao_autonomous_coordinator.py`: recepción de planes, inventario de componentes y ciclos PADGE.
- `omega/padge.py`, `omega/autobuilder.py`, `omega/autoconstruction.py` y políticas de promoción: generación/revisión de candidatos, límites de archivos, pruebas y promoción controlada.
- Pruebas de núcleo, recuperación, worker, scheduler y política autónoma.

**Brecha:**
- El núcleo de tareas expone una allowlist reducida: `self_check`, `capability_scan` e `improvement_plan`. No es todavía un motor general de ejecución distribuida.
- La autoprogramación está limitada por políticas y componentes protegidos; no se debe retirar esa protección para simular autonomía.
- Falta demostrar de forma continua el ciclo completo detectar → planificar → programar → probar → integrar → verificar → rollback en el runtime vivo.

### 2.2 Cinco motores

**Existente:** `tools/iao_five_motor_supervisor.py` y `tools/iao_autonomous_coordinator.py` contienen supervisión e inventario de PADGE, AUTONOMY_CONTINUOUS, GUARDIAN, NODE_NETWORK y DISTRIBUTED_INTELLIGENCE.

**Brecha en los valores predeterminados versionados:** el supervisor crea por defecto PADGE habilitado y los adaptadores GUARDIAN, NODE_NETWORK y DISTRIBUTED_INTELLIGENCE deshabilitados; AUTONOMY_CONTINUOUS no tiene una entrada separada en ese bloque predeterminado. Una configuración local puede diferir, por lo que el estado real debe leerse en Termux. El propio supervisor advierte que un PID no demuestra salud funcional.

### 2.3 Federación y autoasimilación

**Existente:**
- Amplia familia de módulos `omega/federation_*`, identidad Ed25519, challenges firmados, leases, nonces, revocación, auditoría, validación de capacidades y registro de candidatos.
- `tools/iao_federation_autonomous.py` descubre feeds/directorios firmados y consulta peers de IPFS DHT.
- `tools/iao_node_network_engine.py` mantiene directorios, registro de peers, heartbeats, capacidades y tareas seguras.
- `docs/FEDERATION_AUTONOMOUS.md` documenta una prueba histórica de dos nodos propios a través de Internet usando HTTPS/TLS 1.3 y un túnel público efímero, con intercambio bidireccional de `knowledge.search`.

**Límites y contradicciones que deben resolverse:**
- La prueba documentada de dos nodos no demuestra una federación abierta con terceros independientes ni una red P2P general.
- `docs/ADR/ADR-007-open-p2p-deferred.md` mantiene explícitamente aplazada la participación P2P abierta.
- `omega/federation_assimilation.py` valida endpoints HTTPS con ruta fija `/fed/v1/message`; no es un transporte I2P/SAM ni un cliente Tor/SOCKS.
- La detección de peers IPFS no equivale a hablar el protocolo IAO sobre libp2p ni a demostrar identidad/capacidad de cada peer IPFS.
- Debe existir una única política coherente para descubrimiento, verificación, autorización progresiva, cuarentena, admisión, concesión mínima de capacidades y revocación.

### 2.4 IPFS y BitTorrent

**Existente en código:** el agente federativo puede consultar la API local de IPFS para enumerar peers DHT y convertir algunos multiaddresses IPv4/TCP en candidatos de endpoint.

**Evidencia operativa histórica externa al repositorio:** se generó un torrent de la release de IAO y el seeder aria2 mantuvo el contenido completo; la última evidencia recuperada indicaba cero peers y cero bytes subidos.

**Brecha:** no se ha demostrado distribución de tareas IAO mediante libp2p, transferencia verificable entre peers, replicación externa del estado/contenido ni descubrimiento fiable de instancias IAO a través de IPFS. El número de peers del swarm IPFS no equivale al número de nodos IAO federados.

### 2.5 Tor, servicios onion e I2P

**Estado del repositorio revisado:** no se encontraron módulos dedicados, adaptadores de transporte ni pruebas específicas para Tor SOCKS/onion o I2P SAM/túneles. `omega/net.py` realiza conexiones TLS directas y `omega/egress.py` aplica una política de salida HTTP/HTTPS; no implementan esos transportes.

**Brecha Tor:** adaptador SOCKS5 con aislamiento y límites, resolución/conexión onion, publicación y comprobación de servicio onion, health-check y pruebas de extremo a extremo.

**Brecha I2P:** cliente SAMv3 de larga duración, creación y persistencia segura de destino, sesiones STREAM/DATAGRAM, publicación/descubrimiento de servicios .i2p, health-check y pruebas bidireccionales. Para aplicaciones no Java, la documentación oficial de I2P recomienda SAMv3; deben utilizarse parámetros criptográficos modernos y mantener sesiones estables.

Referencias técnicas: https://www.i2p.net/en/docs/api/samv3/

### 2.6 Router multi-LLM

**Existente:** `omega/llm_router.py` carga proveedores OpenAI-compatible HTTPS desde `~/.config/iao/llm-providers.json`, lee secretos por referencia a variables de entorno, mantiene estado de salud/cooldown e intenta proveedores alternativos.

**Brecha:**
- La última prueba E2E del chat registrada en el historial informó cero proveedores activos y respuesta fallback, no una generación upstream confirmada.
- La configuración no demuestra por sí sola que el proveedor sea accesible, autorizado, gratuito o funcional.
- Faltan pruebas actuales de selección real, failover, identidad del modelo upstream, comparación y síntesis multi-modelo en el runtime conectado al chat.

### 2.7 Chat público y autoridad del teléfono

**Existente:** `web/device-authority.js` implementa en el navegador generación de identidad ECDSA P-256, almacenamiento IndexedDB y llamadas previstas a `/v1/device/enroll` y `/v1/device/command`.

**Brecha de integración observada en el repositorio:**
- `site/index.html` de `IAO-web` no carga `device-authority.js`.
- `omega/service.py` expone sesiones, conversaciones y chat, pero en las rutas revisadas no implementa los endpoints `/v1/device/enroll` ni `/v1/device/command`.
- Por tanto, el cliente de autoridad no está conectado de extremo a extremo con el backend/chat público.
- Falta enrolamiento real del teléfono principal, vinculación criptográfica, firma de órdenes, nonce/idempotencia, allowlist de tareas y prueba de que otros dispositivos no pueden ejecutar órdenes.

### 2.8 Seguridad, persistencia y despliegue

**Existente:** auditoría, almacenamiento SQLite, autenticación de desarrollo, pruebas de recuperación, políticas de acceso, egress con allowlist/defensa SSRF, manifiestos y ensayo local de rollback.

**Brecha:**
- El README declara que los tokens de desarrollo no son OIDC, que SQLite es backend de desarrollo y que PostgreSQL, la API FastAPI, Docker e infraestructura externa no están ejecutados en ese entorno de validación.
- Los artefactos de runtime versionados datan de octubre de 2026; no son evidencia del estado operativo actual.
- El README y los workflows deben reflejar el requisito de presupuesto cero; no se debe desplegar en Render.
- El 2026-11-24, el workflow de Pages terminó correctamente, pero los workflows IAO CI y quality gate fallaron: CI falló en Lint para Python 3.12 y 3.13; quality gate compiló correctamente y falló en la suite de tests. Hasta reparar ambos gates no se debe considerar estable la rama.

## 3. Orden de cierre de brechas

1. **Fijar una fuente de verdad:** comparar el HEAD y los cambios locales de `~/so-omega-prime` con esta rama GitHub antes de copiar o desplegar cambios. No sobrescribir ni descartar modificaciones locales.
2. **Restablecer CI:** corregir Lint y tests fallidos; exigir compile, pruebas unitarias, seguridad y regresión antes de integrar nuevas funciones.
3. **Cerrar autoridad del dispositivo:** implementar y probar los endpoints de enrolamiento/órdenes, integrar el cliente en el chat público y demostrar privilegio exclusivo del teléfono principal.
4. **Cerrar los cinco motores:** configurar los cinco adaptadores, verificar procesos, health funcional, tareas reales, logs y recuperación; no inferir salud por PID.
5. **Activar inteligencia real:** conseguir al menos un proveedor upstream operativo sin coste obligatorio; verificar modelo y failover; después habilitar comparación y síntesis multi-LLM.
6. **Unificar federación:** resolver ADR-007 frente a la política de admisión; separar descubrimiento de confianza; probar un tercero independiente con identidad, lease, permisos mínimos, revocación y tareas auditadas.
7. **Implementar transportes reales:** añadir adaptadores separados Tor SOCKS/onion e I2P SAMv3, con pruebas locales simuladas y pruebas reales controladas. No reutilizar el cliente HTTPS directo como si fuera Tor o I2P.
8. **Completar P2P/IPFS:** integrar transporte libp2p o protocolo compatible, identidad de nodo, intercambio de capacidades y tareas, almacenamiento/replicación verificable y métricas de peers IAO reales.
9. **Cerrar el ciclo autónomo:** conectar chat autorizado → cola persistente → coordinador → motores/nodos → resultado → auditoría → mejora PADGE → pruebas → rollback.
10. **Certificar operación:** publicar evidencia fechada y reproducible; estados NORMAL/DEGRADED/RESTRICTED deben derivarse de comprobaciones reales.

## 4. Criterios de aceptación global

IAO solo podrá declararse integral cuando existan pruebas reproducibles de:

- orden firmada desde el teléfono principal y rechazo desde otro dispositivo;
- respuesta de un LLM upstream identificado y failover real;
- cinco motores funcionales y coordinados;
- admisión y revocación de un nodo externo independiente;
- tarea distribuida con resultado verificable y auditoría en ambos extremos;
- comunicación Tor/onion e I2P bidireccional comprobada;
- intercambio y replicación P2P/IPFS verificables;
- mejora de código propuesta por PADGE, probada, promovida y recuperable;
- CI y quality gate completamente verdes;
- operación sin servicios de pago obligatorios y sin depender de Render.

**Conclusión:** IAO ya contiene una base considerable de autonomía, PADGE, federación HTTPS, registro de nodos, router LLM, seguridad y supervisión. Las brechas mayores no son la ausencia de más nombres de módulos: son la integración del mando del dispositivo, el estado real de los motores y proveedores, la participación P2P, los transportes Tor/I2P, la federación con terceros independientes y la certificación E2E.

---

## 5. Actualización de revisión — 2026-11-28

**Rama revisada:** `codex/iao-node-factory-20261127`  
**HEAD revisado:** `a35e888839a729bc962e24764ab128e6feac87da`  
**PR:** #22, abierta y en borrador; no fusionada.  
**Alcance:** revisión del código versionado y de las ejecuciones de GitHub Actions asociadas a ese HEAD. No es una certificación del runtime desplegado.

### 5.1 Evidencia automatizada del HEAD

Las seis verificaciones principales asociadas al HEAD indicado terminaron con conclusión `success`:

- IAO CI (matriz Python 3.12 y 3.13).
- IAO quality gate.
- IAO candidate sandbox qualification.
- IAO container build qualification.
- IAO mobile browser integration (Chromium automatizado).
- IAO node factory safety tests.

Esta evidencia confirma los controles automatizados de esa revisión concreta. No demuestra ejecución física en Android, despliegue público, disponibilidad 24/7, uso gratuito de un proveedor LLM ni conectividad con peers independientes.

### 5.2 Correcciones verificadas en la rama

- El estado de red incluye explícitamente `cryptographic_trust_confirmed: false` cuando el inventario aún no existe; ausencia de datos no se interpreta como confianza.
- Las pruebas de evolución crean correctamente el directorio de estado requerido y verifican el rechazo del manifiesto inválido.
- El límite de descriptores del sandbox de candidatos se elevó de 64 a 1024 tanto en el workflow como en el ejecutor, para evitar agotamiento de descriptores durante la suite.
- Las seis verificaciones anteriores pasaron después de esos cambios.

### 5.3 Estado real de las capacidades críticas

| Área | Estado verificado en código | Brecha para producción |
|---|---|---|
| Identidad del operador | Bootstrap, recuperación, rotación, revocación y login con claves P-256; sesión de solo lectura | Validar despliegue HTTPS/CORS, comportamiento físico Android y recuperación ante caída entre las dos bases SQLite |
| Vinculación del teléfono | Vinculación de sesión y dispositivo; pruebas de navegador automatizadas | Prueba física en el teléfono registrado y demostración negativa desde otros dispositivos |
| Mando privilegiado | Deshabilitado; los estados de identidad siguen siendo READ_ONLY | No habilitar hasta completar OIDC/identidad de producción, pruebas E2E y revisión de autorización |
| Autenticación externa | `omega/auth.py` sigue siendo HMAC de desarrollo; OIDC permanece bloqueado | Integrar y probar un issuer OIDC/JWT con validación de firma, issuer, audience, expiración, rotación de claves y política de scopes |
| Worker autónomo | Cola persistente y tareas de mantenimiento limitadas a diagnóstico/planificación; worker de producción bloqueado | Pruebas de muerte real del proceso, idempotencia, aislamiento OS/red, revalidación de autoridad y backend durable |
| Sandbox de candidatos | Comparación baseline/candidate en contenedores Docker endurecidos; elegibilidad de promoción separada | Mantener la distinción entre aislamiento Docker y sandbox de kernel; validar en runtime soportado |
| Router LLM | Adaptadores y failover presentes en el repositorio | Probar un modelo upstream realmente accesible y de coste cero; confirmar identidad del modelo, latencia, cuotas y failover sin activar gasto |
| Red externa | Inventarios y descubrimiento de candidatos; confianza criptográfica no confirmada | Ejecutar pruebas reales de Tor/IPFS/Nostr y peers independientes; descubrimiento nunca debe otorgar autoridad |
| Federación | El enrolamiento remoto falla cerrado mientras falte verificador mTLS vinculado a la conexión | Implementar verificación mutua real, consentimiento, revocación y pruebas bidireccionales con un operador independiente |
| Producción | Contrato de runtime y build de contenedor presentes | No hay despliegue persistente certificado; faltan secretos externos, TLS, almacenamiento, copias, monitorización y prueba de restauración |

### 5.4 Orden técnico inmediato

1. Cerrar la autenticación de producción: OIDC/JWT verificable, sin sustituirlo por un HMAC de desarrollo ni conceder scopes por defecto.
2. Validar el canal de identidad con pruebas físicas Android y pruebas negativas desde dispositivos no registrados.
3. Resolver la atomicidad/recuperación entre las bases de identidad y dispositivo ante caída del proceso.
4. Mantener deshabilitado el worker privilegiado y completar las pruebas de proceso, aislamiento e idempotencia antes de cualquier activación.
5. Demostrar al menos un proveedor LLM upstream realmente operativo, seleccionable y sin coste obligatorio.
6. Integrar un peer independiente con transporte autenticado, consentimiento, capacidades mínimas y revocación.
7. Realizar pruebas reales de conectividad Tor/onion e IPFS/libp2p sin confundir inventario con una red IAO funcional.
8. Ejecutar despliegue de cualificación con persistencia, TLS, copias y restauración; solo entonces reconsiderar el estado NORMAL.

**Conclusión actualizada:** la rama tiene una base sustancial y los seis controles automatizados del HEAD revisado están verdes. IAO todavía no cumple producción: identidad externa OIDC, worker seguro de producción, proveedor LLM comprobado, federación independiente autenticada y despliegue persistente siguen siendo puertas explícitas. Ninguna de estas brechas debe ocultarse mediante etiquetas, estados de UI o simples procesos activos.


## 6. Actualización de auditoría — 2026-11-28, HEAD e8226fe

**Rama:** `codex/iao-node-factory-20261127` · **PR:** #22 (draft, no fusionada).  
**Alcance:** revisión del código de esa rama y de CI. Esta actualización sustituye las afirmaciones anteriores sobre ausencia de Tor en el código; no certifica conectividad de producción.

### 6.1 Evidencia CI del HEAD e8226fe

- IAO CI: Python 3.12 y 3.13, cada uno con **615 passed, 1 skipped, 2 warnings**.
- Quality gate: success.
- Candidate sandbox qualification: success.
- Container build qualification: success; pruebas de contrato API: **23 passed**.
- Node factory safety tests: success.
- Mobile browser integration: success.

La imagen Docker se construyó en CI; no se desplegó como servicio persistente ni se conectó a un backend público.

### 6.2 Corrección del inventario de transportes

En esta rama sí existe implementación de transporte Tor v3 onion:
- `omega/federation_transport.py` contiene cliente SOCKS5 con resolución remota onion, límites de respuesta/tiempo, rechazo de redirecciones y publicación/intercambio federativo firmado por onion.
- El proxy SOCKS está restringido a loopback; la dependencia PySocks es opcional.
- `omega/external_network.py` incluye descubrimiento de directorios onion y adaptador opcional de descubrimiento libp2p Kademlia.
- `tests/test_federation_transport.py` y `tests/test_external_network.py` cubren contratos simulados, validación y rutas onion/libp2p.

Por tanto, la afirmación de la sección 2.5 sobre ausencia total de adaptadores Tor ya no describe el HEAD actual y debe leerse como observación histórica de la revisión de `main` del 24 de noviembre.

### 6.3 Límites que siguen abiertos

- Las pruebas Tor son pruebas de contrato con proxy simulado; no prueban una conexión real a un servicio onion remoto.
- El descubrimiento libp2p/IPFS registra peers de transporte, pero no acredita que sean nodos IAO, que tengan identidad federativa verificada ni que hayan aceptado tareas.
- No se encontró en esta revisión un transporte I2P SAMv3 integrado.
- No hay evidencia actual de un peer IAO externo independiente admitido, de una tarea distribuida ni de replicación externa verificada.
- El router LLM aún requiere una prueba conectada que identifique proveedor/modelo upstream; el modo fallback no satisface ese criterio.
- OIDC sigue sin estar configurado; HMAC no es OIDC. El worker de ejecución privilegiada permanece bloqueado en producción.
- La plantilla de producción deja secretos y origen CORS vacíos deliberadamente. El backend no está desplegado ni conectado al sitio público.

### 6.4 Estado de aceptación

| Gate | Estado en esta revisión |
|---|---|
| CI Python 3.12/3.13 | **APROBADO en CI** |
| Quality gate y sandbox | **APROBADO en CI** |
| Build Docker y contrato API | **APROBADO en CI** |
| Transporte Tor onion | **Implementado; E2E real pendiente** |
| Descubrimiento libp2p/IPFS | **Adaptadores presentes; peer IAO confiable no demostrado** |
| Identidad OIDC | **Bloqueado / no configurado** |
| Ejecución privilegiada de tareas | **Bloqueada en producción** |
| Proveedor LLM upstream | **No verificado** |
| Backend público persistente | **No desplegado** |
| Federación externa y replicación | **No demostradas** |

No se debe cambiar ningún gate a aprobado por la mera existencia del adaptador o por CI verde. La siguiente cualificación de red debe ejecutarse entre dos instalaciones independientes y voluntarias, primero mediante Tor onion, verificando identidad, challenge, capabilities mínimas, revocación y auditoría en ambos extremos.
