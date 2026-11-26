# IAO identity rollback anchor

## Purpose and trust boundary

The paired identity backup manifest detects accidental corruption and mismatched
snapshots, but it is itself part of the backup and therefore cannot establish
freshness. The rollback anchor adds an authenticated monotonic sequence and
privacy-minimized digests of the complete identity and device databases, as
well as explicit root, primary-device binding and revocation summaries. This
covers recovery-code digests, consumed bootstrap capabilities, login/session/
recovery challenges, device nonces and replay records, table schemas and
historical device/root rows. Only database digests are retained in the anchor;
raw rows and secrets are never exported.

The anchor JSON, its independent 256-bit HMAC key and its lock file must be
stored in a private state directory outside both SQLite databases and outside
all backup/export/snapshot sets. The key is never stored in either database or
backup. The anchor file is atomically replaced, fsynced and protected by a
process lock plus an OS file lock. The record uses a domain-separated HMAC-SHA256.

## API

- `capture_identity_state(identity_db, device_db)` derives the current paired
  state without exporting identifiers, public keys, subjects or secrets.
- `IdentityRollbackAnchor.initialize(state)` explicitly provisions the key
  and sequence 1. It refuses to recreate a missing key or anchor silently.
- `verify(state)` fails closed on missing, malformed, tampered or mismatched
  anchor state.
- `advance(state, expected_sequence=N)` performs compare-and-swap to N+1;
  stale writers and no-op advances are rejected.

A revoked root is represented by zero active roots plus the revoked-root
ledger digest. Inactive device records remain part of the digest. Restoring
either or both older database snapshots therefore produces a different state.

## Live service integration

The production HTTP runtime now provisions this anchor only when both anchor
files are absent and the identity/device databases are demonstrably empty. If
either anchor file is missing, if a prior identity exists without an anchor, or
if the stored state does not match, startup fails closed. It never silently
reinitializes an existing installation.

Every operator/device API request, every request authenticated by the operator
root, and every queued task submission is serialized through a durable
write-ahead pending marker. The marker is written and fsynced before the route runs. After
the route, the paired databases are re-read; if their state changed, the
sequence advances exactly once before the marker is removed. An operation
error is propagated only after a coherent partial state has been anchored.
If the process crashes or the two databases are left incoherent, the pending
marker remains and all protected requests fail closed until offline
reconciliation. Health endpoints and anonymous public-session issuance remain
available.

The runtime stores the anchor and key by default under
`~/.config/iao/identity-trust/`, outside the repository state and normal
backup directory. Operators may set `IAO_IDENTITY_ROLLBACK_DIR` to a separately
protected location. Do not include this directory in database backup or
restore operations.

This is local rollback detection, not protection against an attacker who can
restore the entire device filesystem including the anchor and key. Resisting
that threat requires a hardware monotonic counter or independently
administered remote witness. Pending transitions are intentionally not
auto-reconciled after crashes: an offline recovery procedure must inspect both
databases and the pending marker before explicitly authorizing a new anchor.

The integration does not enable task execution, write/admin scopes or the
worker.
