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
