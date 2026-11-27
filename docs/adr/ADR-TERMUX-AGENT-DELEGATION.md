# ADR: Termux agent delegation from the primary IAO device

- Status: Proposed; implementation intentionally gated
- Date: 2026-11-27
- Scope: Chat-to-Termux remote task execution

## Context

IAO currently authenticates the operator root and one registered primary
ECDSA P-256 device. The web client stores its private CryptoKey in IndexedDB.
The current client creates the key as extractable only long enough to export
and re-import it as non-extractable before persistence. The API's device
challenge is single-use, expires after 60 seconds, and signs an exact method,
path, timestamp, nonce and body digest. Queued task creation requires both
the authenticated operator session and a proof from that primary device.

The existing Python task worker claims leases directly from the authoritative
SQLite store. It revalidates the operator session digest, primary device,
policy version, capability allowlist and READ_ONLY effect class before
execution. The Cloudflare Worker is only a fixed-origin API proxy; its agent
routes remain disabled.

## Decision

Termux must not receive or export the primary device private key, browser
session bearer token, operator root key or recovery material. A copied primary
key would destroy the distinction between the authorized chat device and
other clients, and would expand the attack surface of the root authority.

The Termux process will require a separate delegated agent key generated
locally in Termux. The primary device must explicitly authorize that public
key using a short-lived, one-time, domain-separated delegation statement.
The server must verify the statement against the current root identity and
primary device, store the delegated public key as a subordinate identity,
and enforce its narrow scope and expiry. Delegation must be revocable by the
primary device and invalidated on primary-device revocation or root rotation.

The delegated agent key is not a second primary device and cannot enroll,
recover, rotate, revoke, or issue operator commands. Its initial permitted
scope is limited to health, status, and read-only task execution types that
are separately allowlisted by the server. Unknown capabilities fail closed.

## Required protocol before enabling polling

1. Termux creates an ECDSA P-256 keypair locally; private material remains
   in a private file or Android-backed secure storage with restrictive
   permissions. No private key crosses the network.
2. The Termux client displays a short-lived enrollment request containing
   only the public key, nonce, protocol version and requested minimal scopes.
3. The already-authenticated primary IAO chat presents that request to the
   operator and signs a canonical, domain-separated delegation payload.
4. The API verifies the operator session, current root version, primary
   device proof, nonce, expiry and requested scope. It stores the delegated
   public key and parent-device binding atomically and audits the decision.
5. Agent requests use fresh server challenges, exact method/path/body digest,
   bounded timestamps, single-use nonces and delegated-key signatures.
6. Task claims use the existing SQLite task table and lease fencing. No
   second queue is introduced. Claims are restricted to the delegated
   capability set; stale leases and duplicate completions are rejected.
7. Results are size-limited, schema-validated, redacted and signed. The API
   verifies the current delegation and lease before storing results and
   appends an audit event.
8. Revocation, root rotation, primary-device replacement, clock skew,
   replay, duplicate delivery, process interruption and API restart are
   covered by tests before any polling route is enabled.

## Explicit non-goals

- No arbitrary shell, Python, JavaScript, URL fetch or remote code execution.
- No acceptance of commands from discovered peers, onion services or other
  devices as operator authority.
- No SSH listener or publicly exposed Termux port.
- No second Durable Object queue.
- No transfer of the browser primary private key or bearer token.
- No claim that Android will keep a process alive indefinitely.

## Current phase outcome

This repository phase adds a non-authenticated preflight probe and tests for
the deployed gateway contract. It does not implement delegated enrollment,
task polling, task claiming or remote execution. Those routes remain
intentionally disabled until the complete delegation protocol above is
implemented and reviewed.
