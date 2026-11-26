# Operator authentication handoff (implementation contract)

## Status

Design contract only. No login endpoint or production operator authentication is implemented by this document. The current public-session endpoint remains guest-only. The existing session-association routes require a previously authenticated non-guest bearer token, and the current development HMAC token issuer is not an external identity provider. Do not describe the operator as logged in until a separate implementation and its tests exist.

## Goal

Provide a passwordless operator sign-in that is cryptographically tied to the enrolled root key and the one registered primary device. The public chat must never upgrade a guest session. Authentication establishes an opaque operator principal; it does not grant command authority.

## Proposed protocol: IAO-OPERATOR-LOGIN-V1

### 1. Start challenge

Unauthenticated client sends `POST /v1/operator/login/challenge` with only the public device key (or its canonical public-key digest). The server:

- Requires an active root identity and an active, already-enrolled primary device binding.
- Confirms that the submitted public key is the exact enrolled primary device key; it must not accept a caller-supplied owner, subject, role, or authority.
- Creates a cryptographically random challenge handle and nonce, stored only as a digest where possible.
- Persists a canonical signing payload containing protocol, fixed purpose `OPERATOR_LOGIN`, root key version, device-key digest, nonce, issued-at and short expiry (maximum 90 seconds).
- Applies per-source and global rate limits without writing raw IP addresses into audit events.
- Returns the opaque challenge handle, payload and expiry only. Never return internal identity IDs, device IDs, key material or existing session tokens.

### 2. Complete challenge

Client signs the exact domain-separated payload with both the active root private key and the enrolled device private key. It submits the handle and both signatures to `POST /v1/operator/login/complete`.

The server must, in one transaction or an equivalent atomic protocol:

- Load the challenge and active root/device records.
- Reject unknown, consumed, expired, superseded, revoked, rotated or version-mismatched challenges.
- Verify both P-256 ECDSA/SHA-256 signatures against the exact active public keys and fixed protocol domain.
- Consume the challenge exactly once, including under concurrent replay attempts.
- Derive an opaque stable principal from a server-side random identity identifier; do not derive it from name, email, IP, user-agent or device fingerprint.
- Issue a short-lived bearer token (maximum 15 minutes) for that principal with an empty scope set. The token is transport only; each sensitive request still requires fresh device proof and deterministic policy checks.
- Persist only a keyed digest of the token for session association/revocation checks. Never persist or audit the bearer token or signatures.
- Return the token, expiry and a fixed `OPERATOR_AUTHENTICATED_READ_ONLY` state. Do not return privileged scopes or device identifiers.

A token response must not be sent until challenge consumption and durable audit evidence have succeeded. Any storage, signature, clock, audit or issuance failure fails closed.

### 3. Browser integration

- Add an explicit operator sign-in action separate from the public guest-chat action.
- The browser obtains the enrolled device public key from the existing device-key store and signs the challenge locally with both non-exportable private keys.
- Do not export, upload, log or persist private key bytes, signatures, challenge payloads beyond their short operational lifetime, or bearer tokens in localStorage.
- Keep the operator bearer token in memory only; clear it on logout, expiry, authentication failure and page teardown where feasible.
- Dispatch a session-state event only after the server has returned a valid, structurally checked response. UI labels are informational and never authorize server operations.
- The existing public chat remains guest-only and must not silently retry or upgrade itself to operator authentication.

### 4. Authorization boundary

The login result is read-only. It must not add WRITE, EXECUTE, DEPLOY, CREDENTIAL, ADMIN or task-worker scopes. Queued tasks continue to require the existing exact-session association, primary-device request proof, policy decision, audit evidence and worker-side revalidation. The worker remains disabled until its separate release gate passes.

### 5. Required server tests

- No active root/device, wrong device key, wrong root key, guest substitution and malformed inputs.
- Both signatures required; wrong signature, wrong domain, altered payload, unknown protocol and unsupported curve rejected.
- Expiry, future timestamps, root rotation, root revocation and device revocation invalidate outstanding challenges.
- Challenge handle and nonce are one-time under concurrent completion; replay never returns another token.
- Token has only the opaque operator subject and an empty scope set; guest and operator principals cannot be confused.
- Token digest is keyed; raw token, signatures, nonce, public key, device fingerprint and private material are absent from DB, audit, logs and errors.
- Audit failure or DB failure prevents token issuance.
- Rate limits, restart persistence, clock skew and transaction rollback are tested.

### 6. Required browser tests

- Target Android mobile browser supports P-256 WebCrypto and IndexedDB CryptoKey persistence.
- Existing enrolled keys sign both payloads correctly; key loss or storage denial fails closed.
- Guest session remains guest after any failed login attempt.
- Logout, expiry and 401 clear in-memory token and disable operator controls.
- No bearer token is sent to an origin other than the configured API origin; API origin must be HTTPS outside local development.
- Browser E2E must exercise the deployed API, not a mocked success response.

## Release gate

Until the protocol is implemented and independently tested:

- report operator login as NOT IMPLEMENTED;
- keep the public chat guest-only;
- keep privileged scopes disabled and worker startup blocked;
- keep the pull request open and in draft;
- do not claim phone-to-server operator authentication or production command capability.

The existing OIDC requirement remains BLOCKED_EXTERNAL unless a real issuer is configured. This protocol is a separate proposed device-bound authentication path and must receive its own security review before implementation.
