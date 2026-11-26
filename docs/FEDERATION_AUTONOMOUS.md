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

## Bloqueos de seguridad intencionados

**No se permite el enrolamiento automático de peers remotos todavía.** Una firma Ed25519 válida demuestra posesión de una clave, pero no demuestra por sí sola que el canal de transporte sea seguro. El código anterior aceptaba campos JSON como https_verified=true y redirected=false; esos booleanos podían ser falsificados por quien construyera el objeto de evidencia.

Por ello, las rutas CandidateRegistry.record_verified_identity() y CandidateRegistry.authorize() fallan cerradas con TRUSTED_TRANSPORT_VERIFIER_NOT_INTEGRATED. El pipeline autónomo también bloquea el enrolamiento de peers no-loopback, incluso si la configuración declara require_mutual_tls=true. Esa configuración no sustituye una prueba real de mTLS ligada a la conexión.

El descubrimiento continúa disponible, pero un peer descubierto no obtiene confianza, permisos, acceso al corpus privado, capacidad de ejecutar código ni autoridad sobre IAO. El pipeline también evita iniciar handshakes HTTP salientes hacia peers remotos hasta que exista el transporte confiable; solo se permiten pruebas loopback de desarrollo.

## Trabajo pendiente para habilitar federación externa

1. Implementar un cliente HTTPS de transporte confiable que valide certificados y hostname, rechace redirects, limite tiempo/tamaño y resuelva DNS con protección SSRF y DNS rebinding.
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
