# Federación de IAO: capacidades y límites verificados

**Estado de ingeniería: 26 de noviembre de 2026.** Este documento describe el estado del código en la rama de construcción; no declara que exista una federación pública activa.

## Lo que sí está implementado

- Descubrimiento de candidatos por directorios y feeds configurados y de peers IPFS/libp2p.
- El descubrimiento libp2p funciona como cliente Kademlia, en modo DHT CLIENT, y no abre un listener entrante.
- Los peers P2P se guardan en un inventario separado, con estado DISCOVERED_UNVERIFIED, capacidades vacías y sin ejecución de código remoto.
- El inventario está limitado en tamaño, se escribe atómicamente y con permisos privados.
- La identidad persistente libp2p se protege con permisos de archivo 0600; los directorios de estado usan 0700 cuando el sistema lo permite.
- La identidad IAO HTTP usa Ed25519; el challenge vincula clave pública, ID del nodo, nonce, requester y timestamp.
- Las respuestas federadas se tratan como datos no confiables, aunque su firma sea válida.
- Los directorios y feeds públicos de descubrimiento usan un cliente HTTPS fijado a una IP DNS global verificada, sin proxies ambientales ni redirects, con validación TLS del hostname, límite de respuesta y tipo JSON obligatorio.
- El envío de mensajes federados también usa transporte fijado y limitado: DNS público validado, conexión a la IP fijada, TLS con validación del hostname, sin redirects/proxies y con tamaño/tipo de respuesta controlados.
- Cada peer necesita un endpoint exacto fijado en su registro antes de poder recibir un envío; una URL aportada por el llamante no basta. Los registros antiguos sin endpoint quedan bloqueados hasta que se fije uno mediante una operación controlada.
- HTTP sin TLS solo se acepta para direcciones IP literales loopback en pruebas e integración local; nunca para peers remotos.
- El cliente puede presentar certificado mTLS mediante IAO_TLS_CLIENT_CERT_FILE e IAO_TLS_CLIENT_KEY_FILE; IAO_TLS_CA_FILE permite una CA específica. La clave cliente debe tener permisos privados. La opción IAO_TLS_REQUIRE_CLIENT_CERT exige que exista la pareja de archivos, pero no demuestra por sí sola que el servidor remoto exija el certificado.

## Bloqueos de seguridad intencionados

**No se permite el enrolamiento automático de peers remotos todavía.** Una firma Ed25519 válida demuestra posesión de una clave, pero no demuestra por sí sola que el canal de transporte sea seguro. El código anterior aceptaba campos JSON como https_verified=true y redirected=false; esos booleanos podían ser falsificados por quien construyera el objeto de evidencia.

Por ello, las rutas CandidateRegistry.record_verified_identity() y CandidateRegistry.authorize() fallan cerradas con TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED. El pipeline autónomo también bloquea todo enrolamiento remoto: `_enroll_one()` devuelve TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED antes de realizar cualquier petición de red. La configuración opcional de certificado cliente solo demuestra que el cliente puede presentar un certificado; no demuestra que el servidor remoto lo haya exigido y validado en esa misma conexión. Ni `require_mutual_tls=true` ni campos declarativos sustituyen una atestación verificable ligada a la conexión.

El descubrimiento continúa disponible, pero un peer descubierto no obtiene confianza, permisos, acceso al corpus privado, capacidad de ejecutar código ni autoridad sobre IAO. El pipeline también evita iniciar handshakes HTTP salientes hacia peers remotos hasta que exista el transporte confiable; solo se permiten pruebas loopback de desarrollo.

## Trabajo pendiente para habilitar federación externa

1. Integrar el cliente HTTPS fijado y limitado también en el handshake de federación, sin abrir el acceso remoto hasta completar las pruebas.
2. Integrar mTLS real (certificado de cliente y validación de CA) en la misma conexión usada para el handshake; no aceptar flags declarativos.
3. Vincular la atestación de transporte al challenge Ed25519 y a la URL/peer esperado; evitar replay y sustitución de endpoint.
4. Separar capacidades públicas explícitamente exportables de conocimiento, registros, memoria y datos privados del operador.
5. Añadir pruebas negativas para redirects, IPs privadas/resolución DNS cambiante, certificados inválidos, expiración, replay y revocación.
6. Solo después habilitar enrolamiento de capacidades READ_ONLY publicadas explícitamente, con leases cortos, cuotas, auditoría y revocación.

## Verificación

Las pruebas unitarias y los workflows de GitHub Actions comprueban el código y la construcción del contenedor. Un resultado verde de CI no demuestra conectividad DHT real, peers públicos disponibles, despliegue persistente ni intercambio entre dos organizaciones independientes. Esas propiedades requieren pruebas de red externas reproducibles y evidencias recientes.

## Comandos de referencia

- python -m pytest tests/test_federation_ipfs_discovery.py tests/test_federation_assimilation_security.py
- python -m pytest
- El punto de entrada síncrono del DHT es discover_sync() en omega/libp2p_discovery.py.

## Descubrimiento público y registro de candidatos

El motor `NODE_NETWORK` del supervisor de cinco motores puede ejecutar
`python -m omega.federation_discovery --run`. El ciclo consulta únicamente
búsquedas públicas de repositorios GitHub y recupera manifiestos JSON mediante
la API Contents. Ambas rutas usan `omega.federation_transport`, con HTTPS,
validación de hostname/TLS, resolución pública fijada, rechazo de redirecciones
y límites de respuesta.

Los manifiestos válidos se guardan en
`.state/iao-node-network/discovered-candidates.json` como
`DISCOVERED_UNVERIFIED`. El registro es privado (directorio 0700, archivo
0600), atómico y rechaza rutas de auditoría/registro que atraviesen enlaces
simbólicos. La clave de candidato es determinista a partir de la identidad
declarada y el origen. La huella SHA-256 de la clave pública debe coincidir
con el identificador declarado.

Este inventario es solo una cola de pistas públicas:
- `identity_verified=false`, `enrolled=false`;
- `granted_capabilities=[]`;
- ejecución de código remoto y acceso a datos privados permanecen desactivados;
- las capacidades anunciadas se conservan únicamente como solicitudes no confiables;
- las actualizaciones de descubrimiento no sustituyen estados de revocación,
  identidad verificada, autoridad ni concesiones existentes.

El descubrimiento no realiza handshake con candidatos ni los enrola. La
admisión y el transporte remoto siguen bloqueados hasta integrar y probar una
atestación mTLS vinculada a la conexión. El supervisor solo añade el adaptador
NODE_NETWORK cuando falta en una configuración existente; una desactivación
explícita del operador se conserva.
