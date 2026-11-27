# IAO Cloudflare gateway — fixed-origin API proxy phase

**Status: code and tests added; not deployed; not connected to Termux; not production-ready.**

The Worker forwards a narrow set of requests to one operator-configured, fixed HTTPS API origin. The origin API remains the only authority for operator identity, delegated-agent grants, authorization, task storage, leases, audit and execution policy.

## What this phase does

- Exposes liveness independently of readiness.
- Forwards only an explicit allowlist of public-chat, operator/device authentication, signed task submission/status, health and read-only agent challenge/status routes to the fixed IAO_API_ORIGIN. Unknown `/v1/*` paths are rejected by default.
- Forwards only POST /v1/agent/challenge and GET /v1/agent/status for the signed, read-only Termux agent protocol.
- Preserves the four signed agent headers: X-IAO-Agent-Id, X-IAO-Agent-Nonce, X-IAO-Agent-Timestamp and X-IAO-Agent-Signature.
- Also preserves only the existing API headers required for ordinary authentication: Authorization, Content-Type, Idempotency-Key and X-IAO-Device-Proof.
- Does not forward cookies, client IP headers, browser identity headers or arbitrary incoming headers.
- Requires an HTTPS origin with no credentials, path, query or fragment; rejects localhost and IP-literal targets.
- Caps request bodies at 64 KiB, allows only GET/POST, blocks redirects and never follows an upstream redirect.
- Keeps agent task polling, claiming, completion and all other /v1/agent/* routes disabled.
- Keeps unlisted sensitive API routes (including federation internet actions, audit reads, memory endpoints and unknown operator/device controls) blocked. The API remains responsible for authorization on every forwarded route.
- Keeps privileged commands disabled. The Worker does not execute tasks.
- Leaves the Durable Object broker disabled: IAO's existing Python SQLite task store remains the single queue and lease authority.

The challenge and status routes are only transport pass-throughs. They do not enroll an agent or grant authority. The upstream API must validate the delegated-agent record, one-time challenge, signature, expiry, revocation and root/primary-device binding.

## Configuration

Set IAO_API_ORIGIN as a Worker environment variable in Cloudflare, for example the HTTPS origin of an operator-managed IAO API or its authenticated Cloudflare Tunnel endpoint. Do not put tokens, private keys, recovery codes or other secrets in this variable or in source control.

The origin must already serve the IAO API and enforce its existing root, operator-session, primary-device and delegated-agent proof checks. A public tunnel URL alone does not authenticate the caller and does not make Termux continuously available.

## Current limitations

- The proxy does not create or deploy an IAO API origin.
- It does not enroll the Termux public key or produce a dual-signed grant.
- It does not install or start a persistent Termux task worker.
- It does not add remote agent claim/lease/complete endpoints.
- It does not connect ChatGPT to this API; a separately configured connector with appropriate user authorization would be required.
- The API's current production readiness remains degraded; this gateway will report degraded readiness unless the upstream API reports normal.
- No Cloudflare deployment, tunnel, secret, DNS or production setting has been changed by this repository change.

## Local checks

Run npm test from cloudflare/iao-gateway. Tests use Node's built-in test runner and require no dependency installation.

## Deployment boundary

Keep the Cloudflare Git integration root directory set to cloudflare/iao-gateway only when deliberately reviewing this Worker. Do not repoint the existing static fonstr-data deployment. Do not deploy until the API origin, access policy, production readiness and end-to-end device proof have been independently verified.
