# Task worker production readiness

## Current enforced state

The task worker is an independent execution loop hosted by the FastAPI API lifespan only when `IAO_TASK_WORKER_ENABLED=true`. It reuses the API service's existing Store, registry and operator identity authority; it does not create a second queue. The standalone worker entry point still refuses to start when `APP_ENV=production`. API readiness reports `disabled_by_default`, `blocked`, `start_failed`, `running`, `worker_exited`, or `stop_timeout`, with a bounded reason code when startup or shutdown fails. An explicitly requested worker is never silently reported as healthy. The lifespan supplies a task-worker heartbeat path; readiness distinguishes a live thread from a fresh worker-cycle heartbeat.

Queued task execution is restricted to an explicit allowlist containing only
`knowledge.search`, the deterministic local corpus lookup. The general tool
registry may expose other read-only capabilities (for example, network fetch
when an egress allowlist is configured), but those are not queue-executable.
The API rejects unreviewed tools before enqueueing, and the worker independently
rechecks the same allowlist before invocation. A read-only label alone is not
sufficient evidence of safe isolation, bounded execution, or cancellation.
The worker runs the approved tool's `run` and `verify` callables in a fresh
spawned child process, removes inherited environment variables before calling
the tool, enforces a wall-clock deadline, and terminates a timed-out child.
On POSIX it also attempts CPU, address-space, file-size, open-file, and core
limits. This is process containment, not a complete security sandbox.

Queued task execution is restricted to registered `READ_ONLY` capabilities.
Before invoking a tool, the worker validates the persisted policy version,
expiry, capability authorization, input schema, exact operator-session
credential digest, and primary-device binding. The bearer token itself is not
stored in the task intent. If operator authority is unavailable, expired,
rotated, revoked, or mismatched, the worker marks the task failed without
calling the tool.

Queue leases fence claims and completion. A worker cannot complete another
worker's claim, and an expired lease cannot be used to complete a task. Worker startup now reconciles expired `RUNNING` and `VERIFYING` leases and marks
those tasks `FAILED` with `PROCESS_INTERRUPTED`; live leases are preserved.
Interrupted work is never silently replayed. This is a fail-closed recovery
mechanism, not proof of exactly-once tool effects.

## Required evidence before removing the production block

- [ ] Full Python test matrix passes on supported Python versions.
- [x] API lifespan exposes fail-closed worker startup diagnostics for missing persistent keys and invalid worker settings; regression tests cover both states.
- [ ] Browser integration passes on supported Chromium; physical Android
      browser validation is still required and is not implied by CI.
- [x] Unit test covers an expired `VERIFYING` lease: startup recovery marks it
      failed and it cannot be claimed again. Full process-kill fault injection
      across external tool side effects remains outstanding.
- [x] Fault-injection test raises a process-interruption exception after the
      tool has been invoked but before execution/result persistence; recovery
      marks the task failed and proves it is not re-invoked. This is an in-process
      boundary simulation, not a physical process-kill or power-loss test.
- [ ] Physical process-kill tests cover death before tool invocation, during
      invocation, after invocation, and before result persistence.
- [ ] Tool execution has an explicit idempotency contract. A timeout or worker
      crash after an external side effect must not trigger blind replay.
- [ ] Lease renewal and maximum execution duration are bounded and tested.
- [x] Queued tool invocation and verification now run in a separate,
      killable child process with a wall-clock timeout and POSIX CPU, address
      space, file-size, file-descriptor, and core-dump limits where supported.
      Tests verify child-process execution and timeout termination.
- [ ] OS-level filesystem and network isolation are still required. The child
      runs under the same OS account and is not a container/seccomp sandbox;
      resource limits are best-effort on platforms that do not support them.
- [ ] Authorization is revalidated immediately before each externally
      observable side effect, not only when a task is first claimed.
- [ ] Operator recovery, session expiry, device revocation, and root rotation
      are tested against queued and running tasks.
- [ ] Production database durability, backup, restore, migration, and
      concurrent-worker behavior are tested on the actual deployment backend.
- [ ] Worker isolation, resource limits, network egress policy, secret
      provisioning, monitoring, and incident rollback are reviewed.
- [ ] A production deployment target and operational owner are explicitly
      configured and verified.

## Non-goals and prohibitions

Passing CI does not mean the worker is deployed or continuously running.
GitHub Actions is a CI runner, not a persistent worker host. No privileged
write, execute, administrative, or remote-node authority is granted by this
document. Federated nodes must independently offer and authorize any work.

Do not remove the production startup block until every required evidence item
has an implementation, an automated test where applicable, and an operator
review. Keep production execution disabled while any item is incomplete.
