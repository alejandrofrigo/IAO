# IAO runtime and production qualification

This document describes the real runtime contract for the FastAPI container. A
successful image build is not a deployment and a running container is not proof
that the autonomous or federated system is operational.

## Persistent runtime

The container runs as the unprivileged `iao` user. Mount a durable volume at
`/var/lib/iao`; the service stores the SQLite database, task records and device
authority database there. Back up this volume before upgrades. Do not use an
ephemeral container filesystem as the only copy of operational state. The
runtime enforces mode `0700` on the state directory and `0600` on the SQLite
main database, and refuses a symlink at the database path. The mounted volume
must be writable by the unprivileged `iao` user.

Required secret environment variables:

- `IAO_SESSION_SIGNING_KEY`: at least 32 characters of random secret
  material, distinct from `AUDIT_HMAC_KEY`. Production reads this key only;
  it never falls back to `OMEGA_DEV_TOKEN_KEY`. It signs short-lived bearer
  envelopes after the operator has proved possession of both the root key and
  the registered primary-device key. Guest tokens have no scopes.
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

The read-only device status proof remains separate from command authorization.
For queued task submissions, the API now exposes authenticated
`POST /v1/device/challenge` for a 60-second one-time nonce. The client signs
the HTTP method, fixed path, timestamp, nonce and SHA-256 digest of the exact
request body using the enrolled P-256 key, then sends the proof in
`X-IAO-Device-Proof`. The API verifies and consumes the challenge before
idempotency handling or task persistence. Missing, malformed, altered or
replayed proofs are rejected. The device identifier and proof are not written
to audit events.

The device key is enrolled through `POST /v1/device/enroll`, which is disabled
unless the operator explicitly sets `IAO_DEVICE_ENROLLMENT_ENABLED=1` and
provides `IAO_DEVICE_ENROLLMENT_CODE`. Enrollment also requires an authenticated
browser session. The endpoint returns only the algorithm; the browser derives
the public-key fingerprint locally and does not display it. The deployment
operator must ensure TLS at the public edge before enabling enrollment. The code
is consumed once and is never written to audit events. The operator login protocol issues a challenge that must be signed by both the
root identity key and the registered primary-device key. The server then issues
a short-lived bearer token and stores its credential digest against the root
identity; protected routes revalidate that binding. Capability grants are
separately dual-signed and scoped. Guest sessions remain unprivileged. This is
an internal cryptographic identity provider, not an OIDC federation. Browser
keys are non-extractable WebCrypto keys, but hardware-backed attestation is not
claimed; physical Android validation and recovery/rollback exercises remain
release gates. No write, deployment, credential or administrative authority is
granted by the current read-only worker.

## Durable operator identity

The key hierarchy, bootstrap/recovery rules, device lifecycle and privacy
constraints are specified in [OPERATOR_IDENTITY_PROTOCOL.md](OPERATOR_IDENTITY_PROTOCOL.md).
Root/device dual-signature login and session binding are implemented; the
protocol's physical-device, recovery, rollback and operational acceptance gates
remain outstanding.

## Health semantics

- `/health/live` reports only that the HTTP process can answer.
- `/health/ready` checks the persistent service, database, audit chain and
  registered tools. Its overall status intentionally remains `degraded`
  while physical device validation, independent recovery/rollback evidence,
  verified upstream model access and independent federation are incomplete.
- `NORMAL` must not be inferred from a live process, configured secret or
  successful container build.

## Durable task queue and worker

The existing synchronous `POST /v1/tasks` behavior remains the default for
compatibility. A caller may explicitly request asynchronous acceptance with
`"execution_mode": "queued"`. After authentication, capability authorization,
and policy checks, the API persists the task and returns HTTP 202 with its
`task_id`, `state: "QUEUED"`, and `status_url`. The input and authorization
snapshot are stored in the private SQLite state database; do not put secrets in
task inputs.

Run the worker as a separate process against the same durable state directory:

```sh
python -m omega.task_worker
```

The worker claims only `QUEUED` tasks using a SQLite write transaction, then
revalidates the policy version, saved capability scope and task expiry before
calling the registered tool. Both API acceptance and the worker enforce
`effect_class == READ_ONLY`; queued write, execution and administrative
capabilities are rejected. Queued submissions additionally require a fresh
cryptographic primary-device proof bound to the exact HTTP request body.
Completion is fenced by the worker lease owner and lease expiry. A stale or
expired worker cannot commit a result. A task whose execution outcome is
uncertain is failed closed; it is not automatically requeued or replayed.

The HTTP server does **not** launch the worker implicitly. A running worker
process is not guaranteed by CI or image qualification. Production startup uses `IAO_SESSION_SIGNING_KEY` and the internal dual-signed
root/primary-device login; the standalone worker performs the same persistent
key validation and a live bubblewrap sandbox preflight before starting. The API
worker starts only when `IAO_TASK_WORKER_ENABLED=true`. The worker remains
restricted to `knowledge.search` and fails closed when its session, device,
lease, budget or sandbox checks fail. A passing CI sandbox test does not prove
the target hosting kernel supports user namespaces; that must be tested on the
actual deployment runtime.

## Federation status semantics

- `/v1/federation/status` currently reports `unknown` and
  `discovery_only`. It does not claim an active orchestrator, active network
  nodes, trusted peers or a verified federation.
- Public repository discovery creates unverified leads only. A discovered
  repository, manifest, public key or reachable HTTPS endpoint is not by itself
  proof of operator consent, key possession, peer enrollment or granted
  capabilities.
- Remote enrollment and privileged peer capabilities remain disabled until
  the runtime exposes a verified peer registry and the mutual-authentication,
  consent, revocation and authorization gates have end-to-end tests.

## What this container does not provide

GitHub Actions builds and tests the image; GitHub Pages can serve the static
client. Neither is a persistent API host. A production deployment still needs
an external runtime with durable storage, secret injection, TLS, backups and
monitoring. Do not deploy this image to a paid service or claim a public API is
live until those requirements and the end-to-end acceptance tests are met.
