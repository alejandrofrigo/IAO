# Termux delegated agent — read-only request protocol

This milestone adds a local P-256 key holder and a narrowly scoped API client. It is not a remote shell, task runner, or privileged controller.

## Local key creation

Run from the IAO repository on the authorized Termux device:

```sh
python tools/iao_termux_agent.py init
```

The command creates `~/.local/share/iao-agent/agent-ecdsa-p256.key` with mode 0600 and a 0700 parent directory. It prints the public key and SHA-256 fingerprint. The private key never leaves the device. Keep the public key for the separate, dual-signed delegation enrollment step.

The key creation command refuses to overwrite an existing key. Back it up securely before replacing a device or recovering the agent.

## Read-only status

After a dual-signed delegation has been enrolled and an `agent_id` returned, the local client can make a signed status request:

```sh
python tools/iao_termux_agent.py status \
  --origin https://YOUR-VERIFIED-IAO-API-ORIGIN \
  --agent-id YOUR_AGENT_ID \
  --key ~/.local/share/iao-agent/agent-ecdsa-p256.key
```

Optional continuous status monitoring:

```sh
python tools/iao_termux_agent.py watch \
  --origin https://YOUR-VERIFIED-IAO-API-ORIGIN \
  --agent-id YOUR_AGENT_ID \
  --key ~/.local/share/iao-agent/agent-ecdsa-p256.key \
  --interval 60
```

Use only an API origin whose deployment and TLS certificate have been independently verified. The client rejects HTTP, credentials in URLs, URL paths, query strings, fragments, nonstandard ports, and redirects. It uses normal TLS certificate validation and bounded request timeouts/responses.

## Request protocol

1. Agent requests a short-lived challenge at `POST /v1/agent/challenge` with its opaque agent ID.
2. Server returns a random 256-bit nonce with a 60-second lifetime.
3. Agent signs canonical JSON containing the HTTP method, exact path, SHA-256 body digest, nonce, timestamp, and protocol identifier. Signature domain: `IAO-AGENT-REQUEST-V1\0`.
4. Agent sends the signature in `X-IAO-Agent-Signature`, with ID, nonce and timestamp in the corresponding `X-IAO-Agent-*` headers.
5. Server verifies the current delegated grant, active root-key version, expiry, scope, timestamp, signature and one-use nonce in a SQLite transaction.
6. Only `GET /v1/agent/status` is accepted. The response contains only the authenticated agent's own status.

Challenges are single-use; stale, replayed, revoked, expired, rotated, incorrectly scoped, or tampered requests fail closed.

## Explicitly not implemented

- No task polling, task claim or task completion.
- No remote shell, arbitrary Python, JavaScript, package installation or filesystem mutation.
- No access to other agents' status or private operator data.
- No automatic enrolment: a separate grant must be signed by both the active operator root and the authorized primary device.
- No deployment or production API origin is assumed by this document.

The current API implementation remains behind the existing service identity rollback-anchor gate. This PR must pass repository CI and a real end-to-end handshake against a verified deployment before any installation or activation is considered complete.
