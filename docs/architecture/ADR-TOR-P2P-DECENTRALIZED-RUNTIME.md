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
