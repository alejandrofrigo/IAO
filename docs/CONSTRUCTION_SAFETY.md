# IAO Construction Safety and Continuity

## Non-negotiable operating rules

1. **Protect the known-good baseline.** Work only on the dedicated feature branch and pull request. Never force-push, rewrite shared history, delete user data, or modify `main` as part of routine construction.
2. **No unverified production changes.** Do not merge, publish, deploy, rotate production credentials, enroll peers, or enable privileged execution as a side effect of a code change. Those actions require explicit authorization and a separate release checklist.
3. **Preserve recoverability.** Before a destructive or schema-changing operation, create and verify a restorable backup. Prefer additive migrations and reversible changes. Every risky change must have a documented rollback.
4. **Fail closed, not open.** If identity, transport, signature, policy, audit, persistence, or resource limits cannot be verified, deny the privileged action and preserve read-only operation where safe.
5. **Separate code health from infrastructure health.** A third-party CI/deployment outage, rate limit, or unavailable provider must not trigger source rollback, credential changes, provider migration, or weakening of tests. Report it as an external blocker; keep independent tests running.
6. **No false production claims.** Green unit/integration tests prove only the tested behavior. Never infer public availability, persistent autonomy, decentralization, peer connectivity, or production readiness without direct end-to-end evidence.
7. **Protect operator privacy.** Never place operator identity, contact details, IP addresses, secrets, or device-binding material in public code, docs, test fixtures, artifacts, or logs.
8. **Keep autonomy bounded.** Discovery is not trust. A discovered peer receives no authority, private data, code execution, or capabilities until identity, transport, policy, and revocation controls are independently verified.
9. **Do not weaken gates to make a build green.** Fix the defect or accurately classify an external/informational failure. Keep security and regression tests enabled.
10. **Maintain independent verification.** For each meaningful change, run syntax/compile checks, focused tests, full tests where practical, and inspect the resulting commit and CI status before proceeding.

## Sandbox network requirement

Every production sandbox must meet the persistent global outbound connectivity,
redundant-egress, destination filtering, control-plane isolation, recovery, and
soak-test requirements in `docs/SANDBOX_GLOBAL_NETWORK.md`. A child process
sharing its host network or passing a one-time HTTP probe does not qualify.
Network loss must degrade sandbox network status without stopping the IAO
control plane or corrupting queued work.

## External provider failures

External build/deployment systems are not the source of truth for IAO's source integrity. Rate limits and outages are recorded as external availability incidents. They must not block local/source-level verification, and must never be worked around by silently enabling a paid plan, exposing secrets, or switching to an unapproved provider.

## Current release posture

The construction branch and PR remain isolated from `main`. Production deployment and PR merge remain disabled until the security gates, persistent runtime, recovery procedure, and independent end-to-end checks are demonstrated. Any component that has not passed those checks remains explicitly restricted.


## Persistent autonomous task worker

The production API starts the existing `omega.autonomous_core.AutonomousCore`
worker during application lifespan after the persistent authentication and audit
keys have passed the runtime gate. The worker stores its queue under
`IAO_STATE_DIR/autonomous-core`, recovers tasks left in `RUNNING` after a
process interruption, and resumes only the existing deterministic read-only
task allowlist. Its polling interval is controlled by
`IAO_AUTONOMY_INTERVAL_SECONDS` (10–3600 seconds; default 30).

Set `IAO_AUTONOMY_WORKER_ENABLED=false` to disable it explicitly. A running
worker is not evidence of autonomous code promotion, external-node trust,
production readiness, or 24/7 availability. Code evolution remains a separate
staging workflow and cannot deploy itself or grant authority to discovered peers.


### Recurring autonomous maintenance

The autonomous worker schedules three bounded local task classes without a new
operator request: `self_check` hourly, `capability_scan` every six hours, and
`improvement_plan` daily. It deduplicates queued/running work by task kind,
persists each next-due timestamp, and retains at most the 1,000 most recent
terminal task records while preserving all queued/running tasks. The append-only
event stream records scheduling and history-pruning events.

These jobs are local diagnostics and planning only. They do not generate or
execute arbitrary code, enroll remote peers, grant network permissions, deploy
changes, or claim external connectivity. Autonomous code evolution remains
staged and requires functional, security, and integration verification.
