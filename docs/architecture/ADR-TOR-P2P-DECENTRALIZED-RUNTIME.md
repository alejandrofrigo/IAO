# IAO — Diseño de transporte descentralizado Tor + P2P

**Estado:** propuesta técnica en rama aislada; no desplegada ni activada en nodos.
**Fecha:** 2026-11-26

## Objetivo

Conectar el runtime de IAO con redes P2P abiertas mediante una arquitectura que combine:
- IPFS/libp2p para descubrimiento, direccionamiento y transporte P2P.
- Tor SOCKS5 para salidas TCP que puedan atravesar Tor.
- Servicios onion v3 para alcanzar nodos IAO detrás de NAT/firewalls.
- Federación IAO autenticada para intercambiar capacidades y tareas entre nodos que superen la verificación.

Tor no es por sí mismo una red P2P mundial ni convierte automáticamente todos los peers IPFS en peers onion. La integración debe mantener transportes diferenciados y seleccionar rutas compatibles.

## Inventario conocido que debe revalidarse en cada nodo

Un informe local anterior (2026-11-21) registró IPFS Kubo 0.42.0, un peer ID libp2p, bootstrappers públicos, protocolos DHT/Bitswap/Floodsub y entre 34 y 96 peers observados. También registró herramientas locales `tools/iao_open_p2p_assimilator.py`, `tools/iao_p2p_autonomy_bridge.py` y `tools/iao_federation_worker.py`. Es evidencia histórica, no una afirmación del estado actual.

El diagnóstico posterior (2026-11-26) mostró Tor sin SOCKS accesible en 127.0.0.1:19050 y ningún backend escuchando en 8443/8080/8765. Las identidades onion estaban presentes en dos directorios, pero no se debe regenerar, copiar ni publicar ninguna clave durante la recuperación.

## Arquitectura objetivo

### 1. Plano de transporte
- **Tor client:** SOCKS5 en loopback, con comprobación de bootstrap y circuitos antes de habilitar rutas Tor.
- **Onion ingress:** HiddenServicePort dirigido únicamente a un listener local verificado; nunca a un puerto supuesto.
- **P2P nativo:** mantener libp2p/IPFS para peers TCP/QUIC compatibles y rutas directas permitidas.
- **P2P sobre Tor:** habilitar solo cuando la implementación y el tipo de dirección del peer soporten explícitamente SOCKS/TCP u onion. No fingir soporte QUIC/UDP a través de SOCKS TCP.
- **Fallback:** si Tor cae, no degradar silenciosamente a una conexión directa cuando la política de privacidad exija Tor.

### 2. Plano de descubrimiento
- Consultar bootstrap peers públicos documentados y DHT/IPFS.
- Normalizar multiaddresses y clasificar transportes (TCP, QUIC, relay, onion).
- Mantener caché de peers con TTL y métricas de última conexión.
- Descubrimiento no concede confianza, permisos ni capacidad de ejecutar código.

### 3. Plano de confianza y tareas
- Verificar identidad criptográfica IAO, challenge firmado, nonce, expiración/lease y revocación.
- Incorporar peers nuevos inicialmente en cuarentena y con capacidades de solo lectura.
- No descargar/ejecutar código de peers externos automáticamente.
- Las tareas distribuidas deben estar tipadas, limitadas, deduplicadas, auditadas y autorizadas.
- El mando privilegiado permanece vinculado criptográficamente al dispositivo operador registrado; peers externos y otros clientes solo pueden consultar o realizar tareas explícitamente permitidas.

### 4. Alojamiento distribuido
- Replicar artefactos públicos e inmutables mediante CID/IPFS.
- Separar almacenamiento de artefactos de ejecución de servicios: IPFS no ejecuta el backend.
- Ejecutar workers solo en nodos IAO propios o expresamente enrolados, con límites de CPU, memoria, disco y concurrencia.
- Mantener un manifiesto firmado de versiones, capacidades y salud; no publicar secretos, datos privados, claves ni identificadores del operador.

## Secuencia de implementación

1. Revalidar IPFS, peers, procesos y Tor SOCKS en cada runtime.
2. Añadir un adaptador Tor aislado con timeout, circuit isolation, DNS remoto donde aplique, límites y métricas; sin cambiar el comportamiento directo por defecto.
3. Añadir pruebas unitarias de configuración, SOCKS5, fallo de proxy, no-fallback y filtrado de direcciones.
4. Implementar el registro de transportes por peer y el dialer compatible; rechazar explícitamente transportes no soportados.
5. Publicar el servicio onion existente solo después de verificar backend, rutas y autenticación.
6. Integrar el bridge P2P con el coordinador y el worker de federación, manteniendo cuarentena y permisos mínimos.
7. Probar dos nodos controlados: descubrimiento, handshake, tarea READ_ONLY, resultado firmado, auditoría y revocación.
8. Añadir pruebas de reinicio, pérdida de Tor, pérdida de peers y recuperación.
9. Publicar evidencia reproducible. Solo declarar NORMAL si todas las comprobaciones críticas pasan.

## Implementación incremental en la rama de construcción

La rama incluye ahora un primer ciclo ejecutable de descubrimiento P2P:

- `omega/libp2p_discovery.py` implementa un cliente Kademlia outbound-only, con bootstrappers públicos, identidad libp2p persistente y almacenamiento privado de inventario.
- `tools/iao_libp2p_discovery.py` añade ejecución puntual, supervisor continuo, lock de instancia única e informe atómico. El ciclo registra errores de dependencias/red como errores; no los presenta como descubrimiento exitoso.
- `tools/iao_five_motor_supervisor.py` incorpora el worker como configuración predeterminada de `NODE_NETWORK` cuando el operador aún no ha definido ese motor. Una configuración existente del operador se conserva sin sobrescritura.
- Las pruebas verifican persistencia, estados de fallo, límites de intervalo, rechazo de symlinks y que la integración no autoriza peers ni ejecuta código.

Activación en un nodo IAO con Python 3.12/3.13:

```bash
python -m pip install -e ".[p2p,tor]"
python tools/iao_libp2p_discovery.py --status
python tools/iao_libp2p_discovery.py --once
```

Para ejecución continua aislada del supervisor:

```bash
python tools/iao_libp2p_discovery.py --run
```

Para que el supervisor de cinco motores lo gestione, el motor `NODE_NETWORK` debe estar habilitado en `.state/iao-five-motors/adapters.json`. La migración automática solo añade una configuración ausente; respeta cualquier configuración ya definida.

**Alcance actual:** descubrimiento de peers visibles en la tabla de enrutamiento Kademlia y registro local como `DISCOVERED_UNVERIFIED`. No es un escáner global, no garantiza descubrir todos los nodos, no abre un listener, no publica un servicio onion, no transfiere tareas ni concede permisos. La integración de intercambio de contenido/CID, presencia autenticada, transporte onion de mensajes y ejecución de workers se desarrolla en fases posteriores. La capa onion existente de `omega/federation_transport.py` es explícita y requiere PySocks y un SOCKS Tor local accesible.

## Criterios de aceptación

- Tor bootstrap 100% y SOCKS accesible desde el proceso IAO.
- El tráfico marcado Tor no sale por una ruta directa al fallar SOCKS.
- Peer ID y multiaddresses validados; peers reales conectados y clasificados.
- Intercambio de contenido por CID comprobado con hash.
- Tarea federada READ_ONLY completada entre dos nodos independientes y resultado autenticado.
- Servicio onion llega al backend correcto sin exponer puertos administrativos.
- Prueba negativa: peer desconocido no puede ejecutar tareas, acceder a datos privados ni cambiar políticas.
- Prueba de revocación efectiva.
- CI y quality gates verdes.

## Límites explícitos

- GitHub Actions valida código; no aloja un Tor persistente ni mantiene encendido el teléfono.
- Una red P2P global no ofrece almacenamiento o cómputo gratuito garantizado: cada nodo aporta recursos voluntariamente y puede desconectarse.
- Un nodo IPFS no equivale automáticamente a un nodo IAO.
- No se conoce ni se ha verificado una infraestructura independiente llamada “red UAO”. Si el término se refiere a la red IPFS/libp2p existente, esta especificación la trata como la capa P2P objetivo; si es otra red, se requiere identificar su protocolo/endpoints antes de conectarla.
- No se instalarán servicios, claves ni workers en equipos de terceros sin enrolamiento y autorización de sus operadores.

## Política de apertura respecto a ADR-007

La instrucción del operador reabre el alcance de participación P2P pública de forma limitada:
- Se permite descubrir automáticamente peers públicos, consultar metadatos/protocolos y verificar conectividad.
- Los peers descubiertos se registran como candidatos en cuarentena, sin enrolamiento automático ni autoridad.
- Se permite intercambio de contenido público direccionado por CID, sujeto a verificación de hash y límites de recursos.
- No se permite ejecutar código, herramientas, órdenes o modelos proporcionados por un peer desconocido.
- La promoción a nodo federado con capacidades de tarea requiere identidad criptográfica IAO, contrato/lease, permisos explícitos, límites, auditoría y revocación.
- El mando administrativo nunca se delega a la red P2P.

Esto reabre descubrimiento y participación de datos públicos; no elimina las salvaguardas de confianza de ADR-007 ni habilita ejecución remota arbitraria.


## Implementación de asimilación automática en cuarentena

El ciclo Kademlia incorpora ahora una etapa de asimilación local automática:
- Cada peer válido observado en la tabla de routing se agrega o actualiza en `.state/federation/libp2p/p2p-assimilated-peers.json` (o bajo `IAO_STATE_DIR`).
- La identidad de transporte permanece `UNVERIFIED`; el registro declara `AUTO_ASSIMILATED_UNVERIFIED`, `DHT_ROUTING_TABLE_OBSERVED` y `CANDIDATE_ONLY`.
- Las observaciones repetidas actualizan `last_seen`, conservan `first_seen`, incrementan un contador acotado y combinan multiaddresses sin duplicados.
- El archivo se escribe atómicamente con permisos privados; se rechazan enlaces simbólicos, registros corruptos y entradas malformadas.
- Las capacidades concedidas permanecen vacías; ejecución remota y autoridad de control permanecen desactivadas.

Esta etapa significa que IAO incorpora automáticamente peers públicos al inventario P2P para seguimiento y fases posteriores. No afirma que cada Peer ID sea una identidad IAO autenticada, que todos los peers de Internet hayan sido enumerados, ni que los peers estén ofreciendo cómputo. La autenticación de identidad IAO, presencia firmada y la vinculación criptográfica entre Peer ID y node_id siguen siendo etapas separadas.


## Integración Tor como transporte nativo de NODE_NETWORK

La fase siguiente incorpora Tor como un segundo brazo de descubrimiento ejecutado por el mismo motor de red:

- `omega/onion_discovery.py` consume una lista privada y explícita `onion_feeds` en `.state/iao-federation-sources.json`.
- Cada feed se obtiene mediante `fetch_onion_json`, SOCKS5 en loopback y resolución remota del nombre onion. Se limita el tamaño de respuesta, timeout, número de feeds y entradas.
- Solo se aceptan direcciones onion v3 HTTP en los puertos virtuales 80 y 8443. No se hacen peticiones HTTP directas al onion ni resolución DNS local.
- Los servicios anunciados se incorporan automáticamente a `.state/iao-onion-candidates.json`, separados del inventario HTTPS y del inventario libp2p.
- Un anuncio de directorio se marca `FEED_ADVERTISED_UNPROBED`; no se presenta como servicio alcanzable. La identidad sigue `UNVERIFIED`, la participación `CANDIDATE_ONLY`, y las capacidades/autoridad/ejecución permanecen desactivadas.
- `tools/iao_libp2p_discovery.py` ejecuta el ciclo onion de forma independiente: un fallo de bootstrap libp2p no bloquea el descubrimiento Tor, y un fallo Tor no convierte el resultado libp2p en éxito.
- El supervisor NODE_NETWORK gestiona ambos brazos mediante el mismo proceso persistente, cuando el nodo operador lo active.

Ejemplo de configuración privada (añadir únicamente direcciones reales de feeds onion v3 conocidos y confiables como fuentes de datos, no como identidades confiables):

```json
{
  "onion_feeds": [
    "http://<56-caracteres-base32>.onion:8443/directory.json"
  ]
}
```

No existe un directorio onion global que permita enumerar automáticamente todos los servicios Tor. Sin feeds configurados o una fuente de descubrimiento pública identificable, IAO no puede inventar direcciones onion ni afirmar que ha descubierto la red Tor completa. El acceso Tor requiere además que el SOCKS local esté realmente activo; GitHub no puede encender el daemon Tor del teléfono.
