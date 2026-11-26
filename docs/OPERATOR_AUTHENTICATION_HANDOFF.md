# Operator authentication handoff (implementation contract)

## Status

The first implementation slice is now present in `omega/operator_identity.py`, `omega/device_authority.py`, `omega/service.py`, `web/device-authority.js`, `web/operator-identity.js` and `web/index.html`. It implements a one-time 90-second challenge signed by both the active root key and the currently bound primary device key, atomic challenge consumption, a 15-minute bearer session with an empty scope set, a keyed session-token digest, and a separate browser operator-login action. The public guest-session route remains guest-only. The implementation is not yet production-authenticated: target Android browser E2E is unverified, and device revocation is not yet exposed as a complete operator-controlled API workflow. The login path now rebinds the active enrolled device to the opaque operator principal under a DeviceAuthority write transaction held across the operator-session commit. Do not describe the full operator command channel as production-ready.

## Goal

Provide a passwordless operator sign-in that is cryptographically tied to the enrolled root key and the one registered primary device. The public chat must never upgrade a guest session. Authentication establishes an opaque operator principal; it does not grant command authority.

## Proposed protocol: IAO-OPERATOR-LOGIN-V1

### 1. Start challenge

Unauthenticated client sends an empty `POST /v1/operator/login/challenge`. The server obtains the primary public key from its own root-bound registry; the client cannot choose a device, owner, subject, role or authority. It:

- Requires an active root identity and a current primary-device binding.
- Confirms that the exact root-bound public key is currently enrolled and active in DeviceAuthority.
- Creates a cryptographically random challenge handle and nonce; stores only a digest of the handle.
- Persists a canonical signing payload containing protocol, fixed purpose `OPERATOR_LOGIN`, root key version, device-key digest, nonce and short expiry (maximum 90 seconds).
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

## Implementation details and remaining gates

Implemented endpoints:

- `POST /v1/operator/login/challenge`: rate-limited; requires an active root, current primary-device binding and currently active enrolled device public key. It returns an opaque one-time challenge and canonical payload without identifiers or keys.
- `POST /v1/operator/login/complete`: requires both root and device ECDSA signatures over their distinct domain-separated messages; validates current root/device binding and active device key; atomically consumes the challenge and stores a keyed digest of the newly issued session token. The response contains a 15-minute token, empty scopes and a fixed read-only authority label.
- The browser signs locally with the stored non-exportable root and device CryptoKeys, then switches to a separate operator chat conversation. The guest chat flow is not upgraded automatically.

Tests cover valid dual-signature login, wrong device signature, one-time replay rejection, API token scopes, status verification, audit privacy, atomic device-owner transfer and rollback. CI for the latest commit must still complete successfully before this slice is considered validated.

Remaining security/production gates:

- Login now transfers the exact active enrolled public key's `owner_subject` to the root-derived opaque `operator:<identity_id>` principal only after both signatures verify. The DeviceAuthority write transaction is held open while the operator session binding commits; failures roll back the owner transfer. Existing device challenge and request-proof routes can then enforce the same operator principal. This is a coordinated two-database protocol, not a distributed atomic commit; a process crash between the two database commits can require recovery and must remain a release gate.
- Device revocation still needs a complete root-authorized challenge/API flow that deactivates the DeviceAuthority record and invalidates outstanding device challenges. Do not treat removal of the root-side primary binding alone as device revocation.
- Add explicit logout, token revocation and server-side session expiry/revocation handling; verify expiry and revocation under restart and concurrent requests.
- Complete target Android browser E2E and HTTPS/CORS deployment verification.
- Keep worker production startup blocked, privileged scopes disabled, public guest chat guest-only, and PR open in draft.

The existing OIDC requirement remains BLOCKED_EXTERNAL unless a real issuer is configured. This device-bound path is a distinct implementation and still grants no command capability.
