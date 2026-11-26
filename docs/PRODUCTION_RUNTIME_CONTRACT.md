# IAO runtime and production qualification

This document describes the real runtime contract for the FastAPI container. A
successful image build is not a deployment and a running container is not proof
that the autonomous or federated system is operational.

## Persistent runtime

The container runs as the unprivileged `iao` user. Mount a durable volume at
`/var/lib/iao`; the service stores the SQLite database, task records and device
authority database there. Back up this volume before upgrades. Do not use an
ephemeral container filesystem as the only copy of operational state.

Required secret environment variables:

- `OMEGA_DEV_TOKEN_KEY`: at least 32 characters. This currently signs the
  short-lived public-session tokens; it is a development HMAC mechanism, not
  OIDC and not a substitute for device-bound proof.
- `AUDIT_HMAC_KEY`: at least 32 characters. Persistent audit-chain key. Keep
  it stable across restarts and backups; changing it invalidates verification
  of the existing chain.
- `IAO_DEVICE_ENROLLMENT_CODE`: one-time enrollment secret, at least 32
  characters. Supply it only for the initial primary-device enrollment, then
  remove it from the runtime environment. The server stores its digest and
  rejects reuse.
- `IAO_CORS_ORIGINS`: comma-separated exact browser origins allowed to call
  the API. Do not use a wildcard for the public control surface.

Optional runtime configuration:

- `IAO_STATE_DIR`: defaults to `/var/lib/iao`.
- `IAO_CORPUS_DIR`: defaults to `/app/knowledge`.
- `MODEL_ADAPTER`, `MODEL_PROVIDER`, `MODEL_ID`, `MODEL_API_KEY`:
  configure an explicitly supported upstream model. A configured key does not
  prove provider reachability or free usage.
- `IAO_LLM_ROUTER=1`: selects the repository's multi-provider router. Provider
  credentials must be supplied through the runtime secret manager/environment.

Never commit secret values, device enrollment codes, private keys, operator
identity, email addresses or IP addresses.

## Device authority

The public client uses WebCrypto ECDSA P-256. The server accepts one active
primary device, stores only its public key, consumes the enrollment code once,
issues 60-second random challenges, verifies timestamp- and nonce-bound
signatures, and rejects replayed challenges.

The implemented device action is `status` only. It returns
`READ_ONLY_DEVICE_VERIFIED`. It does **not** authorize task execution, code
changes, deployment, credential access or administrative operations. Privileged
commands remain disabled until a separate policy-bound command queue, explicit
scope grants, revocation flow and end-to-end rejection tests are implemented.

## Health semantics

- `/health/live` reports only that the HTTP process can answer.
- `/health/ready` checks the persistent service, database, audit chain and
  registered tools. Its overall status intentionally remains `degraded`
  while device command authority, OIDC-grade identity, verified upstream model
  access and independent federation are incomplete.
- `NORMAL` must not be inferred from a live process, configured secret or
  successful container build.

## What this container does not provide

GitHub Actions builds and tests the image; GitHub Pages can serve the static
client. Neither is a persistent API host. A production deployment still needs
an external runtime with durable storage, secret injection, TLS, backups and
monitoring. Do not deploy this image to a paid service or claim a public API is
live until those requirements and the end-to-end acceptance tests are met.
