# IAO Cloudflare gateway — fixed-origin API proxy phase

**Status: code and tests added; not deployed; not connected to Termux; not production-ready.**

The Worker can forward versioned IAO API requests to one operator-configured,
fixed HTTPS origin. The origin API remains the only authority for operator
identity, registered primary-device signatures, authorization, task storage,
leases, audit and execution policy.

## What this phase does

- Exposes liveness independently of readiness.
- Forwards `/v1/*` requests to the fixed `IAO_API_ORIGIN`.
- Preserves only the API headers required for the existing authentication
  protocol: `Authorization`, `Content-Type`, `Idempotency-Key` and
  `X-IAO-Device-Proof`.
- Does not forward cookies, client IP headers, browser identity headers or
  arbitrary incoming headers.
- Requires an HTTPS origin with no credentials, path, query or fragment;
  rejects localhost and IP-literal targets.
- Caps request bodies at 64 KiB, allows only GET/POST, blocks redirects and
  never follows an upstream redirect.
- Keeps `/v1/agent/*` disabled. No agent claim or completion protocol exists.
- Keeps privileged commands disabled. The Worker does not execute tasks.
- Leaves the Durable Object broker disabled: IAO's existing Python SQLite
  task store remains the single queue and lease authority.

## Configuration

Set `IAO_API_ORIGIN` as a Worker environment variable in Cloudflare, for
example the HTTPS origin of an operator-managed IAO API or its authenticated
Cloudflare Tunnel endpoint. Do not put tokens, private keys, recovery codes
or other secrets in this variable or in source control.

The origin must already serve the IAO API and enforce its existing root,
operator-session and primary-device proof checks. A public tunnel URL alone
does not authenticate the caller and does not make Termux continuously
available.

## Current limitations

- The proxy does not create or deploy an IAO API origin.
- It does not install or start the Termux task worker.
- It does not add remote agent claim/lease/complete endpoints.
- It does not connect ChatGPT to this API; a separately configured connector
  with appropriate user authorization would be required.
- The API's current production readiness remains degraded; this gateway will
  report degraded readiness unless the upstream API reports `normal`.
- No Cloudflare deployment, tunnel, secret, DNS or production setting has
  been changed by this repository change.

## Local checks

From this directory:

```sh
npm test
```

Tests use Node's built-in test runner and require no dependency installation.

## Deployment boundary

Keep the Cloudflare Git integration root directory set to
`cloudflare/iao-gateway` only when deliberately reviewing this Worker.
Do not repoint the existing static `fonstr-data` deployment. Do not deploy
until the API origin, access policy, production readiness and end-to-end
device proof have been independently verified.
