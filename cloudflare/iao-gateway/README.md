# IAO Cloudflare gateway foundation

**Status: foundation only — not deployed, not connected to Termux, and not ready.**

This isolated Worker workspace deliberately exposes only liveness and a public,
non-sensitive protocol contract. Task submission, agent polling, task claims,
result submission and all command routes return HTTP 503. The Durable Object
binding is reserved but its fetch handler fails closed.

## Why the gateway is not enabled

The existing IAO API has a root identity and one cryptographically bound
primary device. A queued task is accepted only after operator-session and
device-proof checks. The existing Python task worker also revalidates that
authority and currently blocks production execution pending its documented
readiness evidence.

A Cloudflare broker must not create a second, weaker authority registry or
accept a bearer secret as a substitute for the root plus primary-device proof.
The remaining integration must define and test:

1. A server-verifiable handoff from the existing API authority to the broker,
   without exporting private keys, bearer tokens or recovery material.
2. A Termux agent identity bound to the same registered primary device, not a
   second independently enrolled controller.
3. Signed, nonce-bound, expiring poll/claim/complete requests with replay
   protection, idempotency, short leases and revocation checks.
4. A fixed task-type allowlist; no arbitrary shell, Python, URL fetch or
   peer-originated command execution.
5. Redacted, integrity-protected results and audit reconciliation with the
   existing IAO store.
6. Tests for revocation during leases, replay, clock skew, duplicate delivery,
   lost responses, worker restart and Android process interruption.

## Local checks

From this directory:

```sh
npm test
```

No dependency installation is required for the tests; they use Node's built-in
test runner.

## Cloudflare deployment boundary

Configure the Cloudflare Git integration's root directory as
`cloudflare/iao-gateway` only after reviewing this workspace. Do not point
the existing production Worker at this directory yet. The repository's
`fonstr-data` static app is separate and must remain untouched.

Even if deployed, this foundation should report readiness as degraded and
must not be treated as a working Termux bridge. No Cloudflare secrets or
operator credentials are required or accepted by this foundation.
