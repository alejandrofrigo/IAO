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