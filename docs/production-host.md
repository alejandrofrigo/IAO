# IAO single-host production runtime

This deployment path is independent of Vercel. Vercel is not a runtime,
compute, storage, or networking dependency for IAO and is not part of the
production acceptance path. See [hosting independence](hosting-independence.md)
for the supported infrastructure boundary.

This is the reproducible, persistent single-host deployment target for the
current SQLite-backed runtime. It is intentionally a **single API instance**:
do not scale replicas or place the SQLite state volume on a network filesystem.
A future multi-host deployment requires a transactional shared database and
a reviewed migration; this Compose file does not provide that.

## Host requirements

- A maintained Linux server with Docker Engine and the Docker Compose v2 plugin.
- Persistent local storage with enough capacity for `/var/lib/iao`.
- A DNS name and an HTTPS reverse proxy managed by the host operator.
- Firewall access restricted to the reverse proxy; the API itself binds only
  to host loopback on port 8080.
- Operator-managed backups of the named `iao-state` volume.

## Configure and start

Generate independent secrets on the host. Never commit them or paste them into
chat, GitHub issues, or build logs:

```sh
export OMEGA_TOKEN_SIGNING_KEY="$(openssl rand -hex 32)"
export AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export IAO_CORS_ORIGINS="https://alejandrofrigo.github.io"
docker compose -f compose.production.yaml config --quiet
docker compose -f compose.production.yaml up -d --build
```

Configure the host reverse proxy to forward HTTPS traffic to
`http://127.0.0.1:8080`. Keep the backend port private. The browser origin in
`IAO_CORS_ORIGINS` must exactly match the deployed public chat origin.

## Verify

```sh
curl --fail http://127.0.0.1:8080/health/live
curl --include http://127.0.0.1:8080/health/ready
docker compose -f compose.production.yaml ps
docker compose -f compose.production.yaml logs --tail=100 iao
```

A live response only proves that the HTTP process answers. Readiness may report
`degraded`; that is not a production acceptance pass. Configured model providers
must complete a real upstream request, and independent federation peers must
complete cryptographic handshakes before those capabilities can be called
operational.

## Persistence and scaling boundary

The named volume preserves local state across container replacement on this
host. It does not protect against host or disk loss. Back up the volume and
secrets separately, encrypt backups, and test restoration. Keep exactly one
application replica while the runtime uses SQLite. Do not use a generic object
store mount as a substitute for a transactional database.

## Explicitly not claimed

This package does not provision a server, domain, TLS proxy, cloud account,
secrets, Tor daemon, IPFS daemon, external federation peers, or paid LLM
provider. It does not establish global P2P connectivity or prove 24/7 service.
Tor/IPFS and independent peer connectivity still require runtime integration
and live verification. Privileged phone-bound operations remain governed by
the existing device-authority checks.
