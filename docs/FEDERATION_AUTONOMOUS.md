# IAO - Federacion autonoma (estado verificado)
Ultima verificacion: 20261114T025638Z UTC

## Que esta construido y verificado

El pipeline de federacion autonoma de IAO esta completo y verificado sobre loopback y sobre HTTPS real con TLS 1.3. Ningun paso requiere intervencion humana. Las decisiones de confianza se basan en evidencia criptografica verificable, no en flags de operador.

### Propiedades garantizadas

1. **Identidad criptografica obligatoria**
   Cada peer debe demostrar posesion de su clave Ed25519 mediante un challenge firmado. `verify_identity_challenge` comprueba: protocolo `iao-federation` v1, `node_id` ligado a la clave publica, firma Ed25519 valida, nonce y timestamp del challenge, skew maximo 60 s.

2. **Autorizacion autonoma basada en evidencia**
   `CandidateRegistry.authorize()` opera en modo autonomo cuando no se le pasa `operator_id`. Solo autoriza si el candidato esta en `AUTHORIZATION_PENDING` con `verification_evidence` integro y `transport.https_verified=True`. La decision queda auditada como `IAO_AUTONOMOUS_POLICY_V1`.

3. **Solo capacidades READ_ONLY**
   El pipeline autonomo filtra las capacidades solicitadas contra una allowlist READ_ONLY (`knowledge.search` es la unica concedida hoy). Cualquier capacidad de escritura, administracion o shell es rechazada.

4. **Transporte HTTPS con TLS verificado**
   `FedServer` acepta un `ssl.SSLContext` inyectado. `Node._post`, `NativeAdapter.probe` y `probe_and_verify` respetan `IAO_TLS_CA_FILE` cuando esta definido. TLS minimo 1.2; verificado en la practica con TLS 1.3.

5. **Salvaguarda mTLS por-peer**
   Si `require_mutual_tls=False`, el pipeline solo enrola peers con host `127.0.0.1`/`::1`/`localhost`. Cualquier peer externo queda bloqueado con `BLOCKED_MTLS_REQUIRED_NON_LOOPBACK`. En produccion, `require_mutual_tls=True` es obligatorio.

6. **Revocacion inmediata**
   `Node.revoke()` marca al peer como revocado en memoria y persiste en `peers.json`. El siguiente `send()` devuelve `UNKNOWN_PEER`/`PEER_REVOKED`. Verificado end-to-end.

7. **Expiracion de lease**
   Contratos con `lease_expires_at` en el pasado son rechazados al enrolar (`INVALID_PEER_LEASE`) y al enviar (`LEASE_EXPIRED`). Verificado end-to-end.

8. **Proteccion contra replay**
   Cada envelope firmado lleva un nonce de 32 hex. `Node.handle()` mantiene una cache con ventana de 2*skew y rechaza duplicados con `REPLAY`.

9. **Respuestas firmadas y no confiables**
   `Node._post` verifica la firma Ed25519 de la respuesta, comprueba `in_reply_to`, `from`/`to` y skew. Devuelve `untrusted=True` siempre, incluso cuando la verificacion es `PASS`.

10. **Auditoria completa**
    Cada enrolamiento, intercambio y revocacion queda registrado en `federation-audit/events.jsonl` con modo (`AUTONOMOUS` vs `OPERATOR`), peer_id, capacidades y timestamp.

## Como reproducir la verificacion

### Loopback HTTP (desarrollo)

Ejecutar el script e2e de loopback con `IAO_ALLOW_LOOPBACK_HTTP=1`. Verifica enrolamiento mutuo, intercambio bidireccional, revocacion y expiracion de lease. La variable solo relaja el puerto 443; el host debe seguir siendo loopback.

### HTTPS TLS 1.3 (integracion)

Ejecutar el script e2e TLS. Genera CA efimera con SKID/AKID, certificados de servidor para ambos nodos, levanta `FedServer` con `ssl_context` y ejecuta el ciclo completo sobre TLS 1.3. Criterios de exito:

- `BOTH_TLS_DISCOVERY_READY=True`
- `MUTUAL_TLS_ENROLLMENT_OK=True`
- `TLS_EXCHANGE_A_TO_B_OK=True` con `verification=PASS`
- `TLS_EXCHANGE_B_TO_A_OK=True` con `verification=PASS`
- `TLS_VERSION_A=TLSv1.3` y `TLS_VERSION_B=TLSv1.3`

### Requisitos TLS en OpenSSL 3.x

Los certificados hoja DEBEN incluir: `SubjectKeyIdentifier`, `AuthorityKeyIdentifier` (obligatorio desde OpenSSL 3), `KeyUsage` con `digitalSignature` y `keyEncipherment`, `ExtendedKeyUsage` con `serverAuth`, `BasicConstraints` con `ca=False`, y `SubjectAlternativeName` con los hosts/IPs reales. Sin AKID, la verificacion falla con `Missing Authority Key Identifier`.

## Fase pendiente: federacion externa publica

La base esta lista. Para federar con un tercero real falta infraestructura:

1. Exposicion publica con TLS valido: tunel Cloudflare/ngrok con dominio propio, VPS con Let's Encrypt, o proxy inverso (Caddy/Nginx) con certificado real.
2. mTLS entre organizaciones: cada org emite su CA, intercambio fuera de banda, `require_mutual_tls=True` en `federation-policy.json`, `IAO_FEDERATION_MTLS_CERT`/`KEY`/`CA` en el entorno.
3. Directorio de confianza o allowlist de identidades: cada peer externo con `expected_node_id` fijado por el operador. `verify_binding()` antes de enrolar.
4. Primer tercero real: segundo despliegue de IAO o nodo compatible. Intercambio auditado en ambos lados.

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `omega/federation_assimilation.py` | `authorize()` con modo autonomo |
| `omega/federation.py` | `FedServer` acepta `ssl_context`; `Node._post` respeta `IAO_TLS_CA_FILE`; validacion de puerto relajada solo con CA explicita |
| `omega/federation_protocols/native.py` | `NativeAdapter.probe` respeta `IAO_TLS_CA_FILE` |
| `tools/iao_federation_autonomous.py` | Enrolamiento autonomo sin flag humano; salvaguarda mTLS por-peer; handshake con contexto TLS |
| `tests/test_federation_assimilation_security.py` | Tests del contrato autonomo |

Todos los cambios mantienen compatibilidad con el diseno estricto de produccion: cuando `IAO_TLS_CA_FILE` no esta definido y `require_mutual_tls` es `True`, el comportamiento es el original.

## Suites verificadas

- `tests/test_federation.py`
- `tests/test_federation_proposals.py`
- `tests/test_federation_assimilation_security.py`
- `tests/test_federation_open_policy.py`
- `tests/test_federation_public_node.py`
- suite completa: 252 passed, 4 skipped
