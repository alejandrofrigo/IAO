# Durable operator identity protocol (implementation gate)

## Status

Design contract only. This document does not claim that durable operator
identity, account recovery, device revocation, or privileged command authority
is implemented. The current public-session subject remains an expiring guest.
The current device proof proves possession of one enrolled device key only.

## Security objectives

- Separate durable operator identity from browser sessions and guest tokens.
- Bind the primary phone's device key to an operator-controlled root public key.
- Keep private keys, recovery material, personal identifiers and device
  fingerprints out of public responses, prompts, documentation examples and
  audit payloads.
- Make identity proof, device proof, authorization and task policy independent
  checks. A valid signature is not permission to perform an action.
- Support explicit device revocation, root-key rotation and recovery without
  silently transferring authority to another browser or device.
- Preserve fail-closed behavior during database, clock, key or audit failures.

## Key hierarchy

1. **Operator root key**: a P-256 signing key generated client-side. Its private
   component never leaves the trusted operator device or an explicitly
   controlled offline recovery medium. The server stores only its public key.
2. **Device key**: a distinct P-256 key per enrolled device. The operator root
   key signs a canonical device-binding statement containing the device public
   key, key algorithm, a random enrollment identifier, creation time and
   permitted device class. The device key signs individual requests.
3. **Session token**: short-lived transport convenience only. A token may name
   an opaque durable operator subject, but cannot create, rotate or recover an
   identity and cannot replace request signatures.

Use canonical, versioned serialization for signed statements. Reject unknown
versions, duplicate fields, non-canonical encodings, unsupported curves,
expired challenges and replayed nonces. Signatures must cover the HTTP method,
fixed route, timestamp, nonce and digest of the exact request bytes.

## Bootstrap and recovery

- Initial root enrollment must require a one-time high-entropy bootstrap
  capability supplied out-of-band by the deployment operator. It must be
  disabled by default, consumed atomically, rate-limited and never logged.
- The first root public key creates an opaque operator record. Do not derive
  subjects from names, email addresses, IP addresses or device fingerprints.
- Recovery must not be based on a guest session, email-only reset, public
  device identifier or support override. Recovery material must be generated
  client-side, displayed once, and stored offline by the operator.
- A recovery operation must require a threshold or equivalent independent
  proof defined before implementation; it must create an auditable key
  transition and invalidate superseded recovery material.
- If recovery proof is unavailable or inconsistent, fail closed. Do not add a
  hidden administrator bypass.

## Device lifecycle

- A new device is accepted only when the current operator root key signs its
  binding statement, or the approved recovery protocol authorizes the change.
- The server must verify both the device request signature and the operator
  binding before treating a device as enrolled.
- Support explicit revocation and rotation. Revocation must take effect
  transactionally before subsequent task acceptance and must invalidate
  outstanding challenges.
- Enforce one active primary device until a separately reviewed multi-device
  policy exists. Do not silently enroll a replacement.
- Device status remains read-only. Enrollment and identity proof alone grant
  no WRITE, EXECUTE, DEPLOY, CREDENTIAL or ADMIN capability.

## Authorization and task flow

For every queued command, require all of the following in order:

1. A valid, unexpired session associated with the durable operator record.
2. A currently active device bound to that operator root.
3. A fresh, one-time device signature over the exact request.
4. A deterministic policy decision for the requested tool and effect class.
5. A durable audit decision and task persistence in a transactionally safe
   order; failures must not leave an accepted task without its authorization
   evidence.
6. Worker-side revalidation of identity binding, device revocation state,
   policy version, scope, task expiry and READ_ONLY restrictions.

Guest sessions must remain read-only and must never bootstrap or inherit an
operator identity. Other devices and sessions must not gain command authority
through a shared URL, browser profile, IP address or user-agent.

## Privacy and audit

Audit only opaque internal event references, decision, reason code, key
algorithm/version and non-reversible event digests where necessary. Do not
record raw public keys, private keys, recovery codes, bearer tokens, signatures,
nonces, request bodies, names, email addresses, IP addresses or device
fingerprints. Public status responses must not disclose operator or device
identifiers. Review exception messages, traces, metrics and CI artifacts for
the same leakage.

## Required tests before enabling production

- Root bootstrap: disabled, missing/invalid code, one-time consumption,
  concurrency, replay and rate-limit cases.
- Device binding: valid root signature; wrong root; substituted device key;
  malformed/canonicalization mismatch; expired timestamp and nonce.
- Request proof: exact body/method/path binding, replay, cross-operator and
  cross-device substitution.
- Lifecycle: revocation racing with task acceptance, rotation, recovery,
  superseded recovery material and restart persistence.
- Authorization: guest denied; unbound/revoked device denied; valid identity
  without scope denied; READ_ONLY enforced by API and worker.
- Privacy: assert that identifiers, keys, signatures, nonces and recovery
  values do not appear in API responses, audit events, logs or artifacts.
- Browser E2E on the target mobile browser, plus independent server tests.
  Unit tests alone do not establish successful phone enrollment.
- Failure injection for database locks, partial writes, audit failures, clock
  skew, interrupted recovery and worker restart.

## Release gate

Until every required test and lifecycle control is implemented and reviewed:

- keep worker production startup blocked;
- keep privileged scopes disabled;
- keep the public chat guest-only;
- keep the pull request in draft;
- report identity as incomplete and readiness as degraded.

A successful build, CI run, container startup or device signature test is not
proof of a durable operator account or a production-ready command channel.
