# Operator authentication handoff (implementation contract)

## Status

The operator authentication and recovery slices are now present in `omega/operator_identity.py`, `omega/device_authority.py`, `omega/service.py`, `web/device-authority.js`, `web/operator-identity.js` and `web/index.html`. It implements a one-time 90-second challenge signed by both the active root key and the currently bound primary device key, atomic challenge consumption, a 15-minute bearer session with an empty scope set, a keyed session-token digest, and a separate browser operator-login action. The public guest-session route remains guest-only. The implementation is not yet production-authenticated: target Android browser E2E and deployed HTTPS/CORS behavior remain unverified. The login path now rebinds the active enrolled device to the opaque operator principal under a DeviceAuthority write transaction held across the operator-session commit. Do not describe the full operator command channel as production-ready.

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

Tests cover valid dual-signature login, wrong device signature, one-time replay rejection, API token scopes, status verification, audit privacy, device-owner transfer and rollback, root-authorized revocation, recovery after revocation, two-key proof validation, recovery challenge replay rejection, device replacement isolation, pending-proof invalidation, and recovery-secret rotation. CI for the latest commit must still complete successfully before this slice is considered validated.

Remaining security/production gates:

- Login now transfers the exact active enrolled public key's `owner_subject` to the root-derived opaque `operator:<identity_id>` principal only after both signatures verify. The DeviceAuthority write transaction is held open while the operator session binding commits; failures roll back the owner transfer. Existing device challenge and request-proof routes can then enforce the same operator principal. This is a coordinated two-database protocol, not a distributed atomic commit; a process crash between the two database commits can require recovery and must remain a release gate.
- `POST /v1/operator/identity/revoke` requires the exact active operator session and a root signature. It deactivates the enrolled device, deletes outstanding device challenges, revokes the root identity, removes the root-side primary binding and session digest, and closes the browser session. The device database is committed first; failure in the root database leaves the device inactive (fail-closed).
- Initial bootstrap now requires a distinct offline recovery code of at least 32 characters. Only its SHA-256 digest is stored; it must be kept outside the device/browser and must never be sent to logs or support channels.
- `POST /v1/operator/recovery/challenge` accepts the offline recovery code, a new P-256 root public key, a new P-256 device public key and a distinct replacement recovery code. It creates a one-time challenge bound to the two new public keys, identity generation, next key version and a 90-second expiry.
- `POST /v1/operator/recovery/complete` requires both new private keys to sign separate domain-separated payloads. It atomically consumes the challenge in the operator database, replaces the root key, restores the same opaque operator identity at the next key version, binds the replacement primary device, invalidates old login/session challenges and session bindings, and rotates the recovery-code digest. The old recovery code cannot be reused.
- Device replacement is fail-closed: only the exact prior root-bound public key or a device already owned by that same opaque operator principal can be replaced. An unrelated active device blocks recovery. The device database is committed before the operator identity database; a failure between commits can leave an orphan device but cannot grant an operator session. The still-unconsumed recovery code permits a retry. This is a coordinated recovery protocol, not a distributed atomic commit.
- The browser stores pending root and device CryptoKeys separately from the current keys until server recovery succeeds. The operator supplies and keeps the replacement recovery code offline; the browser does not retain either recovery secret.
- Recovery is unavailable for identities bootstrapped before an offline recovery code was provisioned; those identities need a separately authorized migration/rotation procedure. No recovery secret can be reconstructed from the server-side digest.
- Complete target Android browser E2E and HTTPS/CORS deployment verification, including key persistence and recovery after clearing browser data.
- Test the device-first/operator-second commit failure window and recovery retry on the deployed storage backend.
- Complete target Android browser E2E and HTTPS/CORS deployment verification.
- Keep worker production startup blocked, privileged scopes disabled, public guest chat guest-only, and PR open in draft.

The existing OIDC requirement remains BLOCKED_EXTERNAL unless a real issuer is configured. This device-bound path is a distinct implementation and still grants no command capability.
