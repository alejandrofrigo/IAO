# Red externa autónoma de IAO

Estado de ingeniería: 27 de noviembre de 2026. El servidor integra adaptadores opcionales para directorios HTTPS y onion v3, Kademlia/libp2p, IPFS Swarm y autorizaciones Nostr verificadas. Esto implementa conectores y ciclos de inventario; no demuestra por sí solo que haya peers remotos disponibles, que una federación esté operativa ni que exista servicio 24/7.

## Fuentes conectadas al worker

- GitHub público: búsqueda indirecta a través del registro local de descubrimiento; nunca es autoridad.
- Feeds HTTPS y directorios Ed25519 configurados localmente.
- Directorios onion v3 por Tor SOCKS5 con resolución DNS remota, sin redirecciones y con límites de tamaño/tiempo.
- Federación saliente hacia peers IAO con endpoint onion v3: mensajes Ed25519 firmados viajan por Tor SOCKS5. El endpoint debe estar fijado en el contrato del peer y el peer debe estar enrolado de forma independiente.
- libp2p Kademlia DHT en modo cliente outbound-only, cuando está instalada la dependencia `p2p`.
- IPFS Swarm: lee peers conectados desde la API local IPFS, nunca desde una API remota arbitraria.
- Nostr: consulta relays WebSocket públicos y verifica eventos Schnorr de autorización dirigidos al bridge IAO. Un relay o autor Nostr no se convierte en nodo IAO ni recibe permisos.
- Inventario local de peers P2P existentes.

Los errores de una fuente no detienen las demás. Los resultados se separan en candidatos HTTP, peers P2P y eventos de protocolo.

## Configuración

Archivo opcional `~/.config/iao/network-discovery.json`:

```json
{
  "github": {"enabled": true},
  "libp2p": {"enabled": true},
  "https_feeds": [],
  "tor_onion_feeds": [
    "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/iao/peers.json"
  ],
  "signed_directories": [],
  "ipfs": {"enabled": true, "api": "http://127.0.0.1:5001"},
  "nostr": {
    "enabled": true,
    "relays": [
      "wss://relay.damus.io",
      "wss://nos.lol",
      "wss://relay.nostr.band"
    ]
  }
}
```

Activa IPFS solo si el daemon local está instalado y su API está limitada a loopback. Activa Nostr si deseas consultar autorizaciones firmadas en los relays indicados. No se aceptan URLs de API IPFS remotas. Los feeds onion deben ser servicios v3 y entregar JSON.

### Tor saliente y publicación onion

El transporte saliente requiere Tor en ejecución con un proxy SOCKS5 local:

- `IAO_TOR_SOCKS_HOST=127.0.0.1`
- `IAO_TOR_SOCKS_PORT=9050` (o el puerto SOCKS local real)
- Instalar el extra `.[tor]` (PySocks); el Dockerfile raíz lo incluye.
- El proxy se restringe a loopback y el hostname onion se resuelve dentro de Tor, nunca por DNS local.

Para ofrecer voluntariamente un servicio onion, configura Tor Hidden Service en el equipo que controla la API, con un directorio de servicio privado y un reenvío equivalente a `HiddenServicePort 80 127.0.0.1:8080`. Protege el directorio de claves de Tor y no publiques su clave privada. Configura además:

- `IAO_FEDERATION_PUBLIC_PEERING=true`
- `IAO_FEDERATION_PUBLIC_ORIGIN=http://<hostname-v3>.onion`

La ruta pública de publicación seguirá exigiendo consentimiento explícito. No actives el peering si no controlas el servicio y sus claves. El Compose actual ejecuta la API en un contenedor: su loopback no es el loopback del host; por tanto, el SOCKS de Tor debe estar en el mismo espacio de red que el proceso API para que el transporte saliente funcione. No se afirma que Compose inicie Tor automáticamente.

## Persistencia y confianza

- Los registros se guardan en `OMEGA_STATE_DIR/external-network/registry.json` con permisos privados, escritura atómica, deduplicación y límites.
- Los nodos HTTP descubiertos empiezan como `DISCOVERED_UNVERIFIED`; no se confía en capacidades anunciadas.
- Los peers IPFS/libp2p se guardan separados por peer ID y multiaddr; no se inventan endpoints HTTPS.
- Los eventos Nostr se guardan en `protocol_peers` como autorización de evento verificada; eso no verifica la identidad de un nodo IAO ni equivale a enrolamiento.
- Los peers onion solo pueden comunicarse mediante mensajes firmados y contratos de capacidades; Tor aporta transporte/privacidad de red, no confianza de aplicación.
- No se ejecuta código de terceros, no se comparten datos privados y no se conceden capacidades administrativas automáticamente.

## Límites reales

- Tor no se instala ni inicia como daemon automáticamente; el operador debe proporcionar un SOCKS5 local.
- libp2p necesita bootstrappers accesibles y la dependencia opcional instalada.
- IPFS necesita un daemon local y peers en su swarm.
- Nostr necesita conectividad WebSocket y relays disponibles; las autorizaciones deben ser eventos firmados válidos.
- El worker solo vive mientras el proceso IAO está activo. No es un daemon de sistema garantizado ni un servicio 24/7.
- No se han validado todavía intercambios reales Tor/IPFS/libp2p/Nostr entre instalaciones independientes en un despliegue de producción.

## Verificación

```bash
python -m pytest tests/test_external_network.py tests/test_federation_transport.py tests/test_federation_discovery_transport.py tests/test_federation.py tests/test_federation_ipfs_discovery.py
python -m pytest
```

El CI prueba contratos y aislamiento de código; no sustituye la prueba de conectividad externa.

## Federacion por consentimiento

La publicación está desactivada por defecto. Cada instalación debe configurar explícitamente `IAO_FEDERATION_PUBLIC_PEERING=true` y un origen HTTPS o onion v3 exacto. IAO verifica firma Ed25519, identidad, concesión y challenge antes de considerar una relación federada. El transporte de mensajes onion pasa por Tor SOCKS5; un anuncio o descubrimiento por sí solo no enrola un peer ni concede capacidades.
