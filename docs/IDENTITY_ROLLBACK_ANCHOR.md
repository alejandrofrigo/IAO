# IAO identity rollback anchor

## Purpose and trust boundary

The paired identity backup manifest detects accidental corruption and mismatched
snapshots, but it is itself part of the backup and therefore cannot establish
freshness. The rollback anchor adds an authenticated monotonic sequence and a
privacy-minimized digest of the complete root, primary-device binding and device
ledger.

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

## Important integration limitation

This commit provides the anchor primitive and replay tests only. It does **not**
yet connect every bootstrap, recovery, root rotation/revocation, primary-device
binding, enrollment and device-replacement mutation to the anchor, and it does
not yet gate live API authentication on anchor verification. Until that
transactional integration is complete, the production service does not claim
rollback enforcement. Never initialize a fresh anchor automatically when an
existing installation reports a missing anchor: that could bless a restored
old database.

A complete deployment must provision the anchor outside the backup set, then
make every authority mutation a recoverable two-phase operation: persist a
pending transition, commit the paired SQLite state, advance the external
anchor, and reconcile/deny all privileged identity operations while pending or
mismatched. A hardware monotonic counter or independently administered remote
witness is required to resist rollback of the entire device filesystem,
including both the anchor and its key. The local primitive alone cannot make
that stronger guarantee.

The primitive is not permission to enable task execution, write/admin scopes or
the worker.
