# Red externa autónoma de IAO

Estado de ingeniería: 26 de noviembre de 2026. Este hito añade un coordinador de descubrimiento multifuente al arranque del servidor. No demuestra que exista ya una red pública de peers conectados ni un servicio alojado 24/7.

## Ciclo autónomo

El servidor inicia un worker de baja frecuencia que repite el descubrimiento cada 30 minutos por defecto (mínimo: 5 minutos). Los adaptadores son independientes:

- Búsqueda pública de repositorios GitHub como fuente opcional, nunca como autoridad o registro central.
- Feeds HTTPS públicos configurados.
- Directorios HTTPS firmados con claves Ed25519 previamente configuradas.
- Inventario local de peers libp2p, almacenado por separado de los nodos HTTP.

Los fallos de una fuente no detienen las demás. El registro se actualiza atómicamente, con permisos privados, límites, deduplicación, first_seen/last_seen y observaciones. El worker no necesita APIs comerciales.

## Configuración

Archivo opcional \`~/.config/iao/network-discovery.json\`:

\`\`\`json
{
  "github": {"enabled": true},
  "https_feeds": ["https://directory.example.org/iao/peers.json"],
  "signed_directories": [
    {
      "url": "https://directory.example.org/iao/signed.json",
      "pubkey_hex": "CLAVE_PUBLICA_ED25519_DE_64_CARACTERES_HEXADECIMALES"
    }
  ]
}
\`\`\`

Feeds y directorios deben publicar JSON accesible por HTTPS. Los directorios firmados verifican Ed25519 contra la clave pública configurada localmente. Los anuncios sin firma solo son pistas; las claves de confianza nunca se aprenden del propio candidato.

Variables: \`IAO_NETWORK_DISCOVERY_CONFIG\`, \`IAO_EXTERNAL_NETWORK_INTERVAL\` y \`OMEGA_STATE_DIR\`.

## Separación de seguridad

Todo nodo HTTP queda \`DISCOVERED_UNVERIFIED\`, \`identity_verified=false\`, \`enrolled=false\`, con permisos vacíos. Las capacidades anunciadas son datos no confiables, nunca permisos. Los peers libp2p permanecen en un inventario P2P separado y no se convierten en endpoints HTTP. El descubrimiento no ejecuta código remoto, no lee datos privados de peers, no realiza handshakes de enrolamiento ni activa tareas.

## Límites actuales

- La búsqueda GitHub y los feeds necesitan conectividad saliente; GitHub puede aplicar límites de API.
- La conexión DHT real sigue dependiendo del adaptador libp2p existente, sus dependencias y bootstrappers accesibles; este coordinador solo incorpora su inventario local.
- No se ha integrado todavía un transporte Tor/SOCKS ni acceso onion. La interfaz DiscoverySource permite añadirlo como adaptador sin modificar el registro ni la política de confianza.
- No se ha probado intercambio real entre instalaciones independientes, ejecución federada ni despliegue persistente. El worker solo se ejecuta mientras el proceso servidor está activo.

## Verificación

\`python -m pytest tests/test_external_network.py tests/test_federation_ipfs_discovery.py\`

\`python -m pytest\`

El CI comprueba código y contratos; no sustituye pruebas externas de conectividad.
