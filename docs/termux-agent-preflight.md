# Termux agent preflight

The current Termux component is a **read-only preflight probe**, not a
persistent task agent. It verifies the public gateway contract without
sending credentials or executing commands.

## Run from the repository root

```sh
python tools/iao_termux_agent_preflight.py --gateway-url https://YOUR-GATEWAY.workers.dev
```

Or set `IAO_GATEWAY_URL` in the local runtime environment and omit the flag.
The script accepts only an HTTPS origin, uses the platform TLS trust store,
does not follow redirects, limits response size and reports no tokens or
private identity material.

Expected current outcome is exit code 2 and
`BLOCKED_AGENT_PROTOCOL_NOT_ENABLED`, because task polling is intentionally
disabled. This is a correct safety result, not a gateway outage.

## Why this is not yet a daemon

The primary device key belongs to the authenticated IAO chat. Termux must
not copy that private key or its browser bearer token. A delegated agent
identity needs to be generated locally, approved by the primary device,
registered by the API with a narrow scope, and revocable. Only after the API
supports that protocol can a persistent poll/claim/complete loop be added.

The authoritative task store remains the existing IAO SQLite store. No
separate Cloudflare queue is introduced. The delegated agent must never
accept arbitrary shell or code instructions; its first execution scope will
be read-only and allowlisted.

See [ADR: Termux agent delegation](adr/ADR-TERMUX-AGENT-DELEGATION.md).
