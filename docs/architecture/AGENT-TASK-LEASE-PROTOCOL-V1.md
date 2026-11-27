# IAO Task Intake and Lease Protocol v1

Status: architecture decision implemented in draft PR #10; CI, merge and end-to-end verification are pending. No production activation.

## Purpose

Connect authenticated IAO chat instructions to the existing SQLite task queue and the local TaskWorker without introducing a second queue, a second authority registry, or a remote shell.

The queue in the IAO API's existing Store remains the sole durable source of truth. The TaskWorker remains the only component that claims queued work and executes registered tools.

## Verified implementation baseline

The current Store provides:

- `create_task` with owner-scoped idempotency;
- `queue_task`, which only transitions `AUTHORIZED` to `QUEUED`;
- atomic `claim_next_task` using `BEGIN IMMEDIATE`, a lease owner, expiry, and attempt counter;
- `update_claimed_task`, which fences state changes by task ID, worker ID, state and unexpired lease;
- `recover_interrupted_tasks`, which marks expired `RUNNING`/`VERIFYING` tasks failed rather than replaying them.

The current TaskWorker revalidates the policy version, registered capability, read-only effect class, tool allowlist, task expiry, operator session digest and primary-device binding before execution. It runs tools in an isolated process and verifies results before success.

The delegated-agent authority currently permits only `agent.status.read`. It is not authorized to claim tasks or complete them. The Termux client is read-only. Operator capability grants are implemented in draft PR #10, but the browser task-submission/status workflow and end-to-end activation remain incomplete.

## Decision: do not add remote agent claim/complete in v1

A remote agent claim endpoint would create a second execution path alongside TaskWorker. It could race the local worker, split lease ownership, or accept caller-supplied results that bypass tool execution and evidence verification.

Therefore v1 uses authenticated task intake, not remote task execution:

1. The authorized primary IAO chat submits a structured task intent to the existing API.
2. The API authenticates the operator session and verifies the primary-device proof for queued execution.
3. The API validates the requested capability against the registered tool catalogue and policy, captures an immutable authorization snapshot, enforces expiry/budget/idempotency, and audits the decision.
4. Only after successful authorization does the API transition the task to `QUEUED` in the existing SQLite Store.
5. The local TaskWorker atomically claims the task using the existing lease mechanism, revalidates current authority and policy, executes only a registered read-only capability, verifies evidence, and records the terminal result.
6. The authorized chat reads task status/results through owner-scoped API reads. No result supplied by the browser or delegated agent can mark a task successful.

## Required security invariants

- Only the cryptographically bound primary device can authorize operator task intake. A guest token, unbound operator session, other device, URL, IP address, browser identity or user-agent is insufficient.
- Delegated Termux identity remains subordinate and revocable. It must never receive the root key, primary-device private key, operator bearer token, or authority to mint grants.
- The agent must not submit arbitrary shell, Python, JavaScript, filesystem paths, URLs to execute, or free-form tool names.
- The task intent is structured and schema-validated. Capability names come from a server-side allowlist; arguments are validated by that capability's registered schema.
- The API creates one durable task record. Retries use an owner-scoped idempotency key and return the existing task rather than duplicating work.
- Authorization is checked at intake and rechecked immediately before execution. Revocation, root-key version change, primary-device rebind, policy change, expiry, or missing evidence fails closed.
- The queue has one claim authority: TaskWorker. No Cloudflare Durable Object queue and no agent claim/complete endpoint may compete with it.
- Lease updates remain fenced by worker ID and unexpired lease. A stale worker cannot complete a task after losing its lease.
- Interrupted execution is not automatically replayed. Recovery marks ambiguous work failed and requires a new explicit task.
- Public peers, onion services and external models never receive operator authority or direct task-queue access.
- Public status and audit output must not disclose operator identity, email, IP address, device identifiers, private keys, bearer tokens, task arguments or private results.

## API and UI work required before activation

- Audit the existing `POST /v1/tasks` handler to confirm queued-mode authorization is cryptographically tied to the primary device, not merely a bearer session.
- Ensure a task request cannot choose a capability outside the registry allowlist or enlarge its budget, timeout, scopes, or expiry.
- Ensure task status reads are owner-scoped and never expose lease-owner identifiers or private intent fields to guests.
- Ensure the browser only submits tasks from the authorized operator session and only after primary-device proof; public chat remains guest/read-only.
- Add tests for duplicate idempotency keys, guest rejection, unbound-device rejection, invalid signatures, cross-owner reads, revoked identity, policy-version changes, queue transition failures, lease expiry, stale completion, worker restart and audit integrity.
- Keep the Termux agent read-only until this end-to-end path is proven. Its role may later be narrowed to local health/worker supervision and authenticated status reporting, not task claiming.

## Activation gates

No production activation until all of the following are true:

1. The task-intake proof is verified against the active root identity and registered primary device.
2. Python test suite and quality gates pass without weakening existing baselines.
3. Mobile browser tests prove guest and secondary devices cannot issue queued tasks.
4. TaskWorker lease and crash-recovery tests pass against the same SQLite Store.
5. End-to-end tests prove one chat submission creates exactly one task and one local worker execution.
6. A verified HTTPS API origin, exact browser origin allowlist and upstream access controls exist.
7. The operator explicitly approves any merge, deployment, tunnel or production configuration.

Until then, the system must report the bridge as not enabled. A successful chat response is not evidence that a task was queued or executed.


## Additional implementation audit finding

The current browser device module already exposes `IAODeviceAuthority.submitQueuedTask(payload)`, which obtains a one-use device challenge, signs the exact POST method/path/timestamp/nonce/body digest, and sends the proof with the operator bearer session. The API's queued `POST /v1/tasks` handler verifies that proof, verifies the primary-device binding for the current operator session, checks the registered capability and read-only queued-tool allowlist, stores the authorization snapshot, and queues the task in the existing Store.

However, the current operator login response is deliberately read-only and carries an empty capability-scope list. The task intake handler intersects requested capability authorization with the authenticated principal's scopes. Consequently, a valid device signature alone does not authorize a queued capability. The browser UI also does not yet expose a complete task-submission/status workflow.

This is an intentional security boundary, not a reason to widen the operator token implicitly. The explicit capability-grant mechanism is now implemented in draft PR #10 with these restrictions:

- The only initially grantable capability is `knowledge.search`, a local read-only tool. No other registry scope is grantable.
- The grant is bound to the active operator subject, exact bearer-session digest, root key version, primary-device fingerprint, capability, expiry and policy version.
- The root key and primary device sign the same canonical payload under separate domain-separation prefixes. Both signatures are verified against the current keys before the one-use challenge is consumed.
- Grant lifetime is bounded to 15 minutes. Challenges are short-lived, single-use, replay-protected and limited to five outstanding challenges per identity.
- The grant is persisted in the existing `OperatorIdentityAuthority` SQLite database. No second authority registry or client-supplied scope list is trusted.
- Operator authentication derives effective scopes from live grants on every request; login remains empty-scope by default.
- Explicit revocation also requires fresh root and primary-device signatures. Root rotation, device replacement, session replacement, expiry or policy-version change invalidates the grant.
- Task intake rechecks the live grant immediately before queue transition. TaskWorker checks it again, together with the existing session/device/policy gates, immediately before local tool execution.
- The browser identity panel exposes explicit grant and revoke controls with confirmation. Draft PR #13 adds a restricted chat task-intake panel for `knowledge.search`, idempotent submission and owner-scoped status lookup. It does not expose general-purpose task or tool selection. If the Cloudflare fixed-origin gateway is later used as the browser API origin, its path allowlist must explicitly add `POST /v1/tasks` and owner-scoped `GET /v1/tasks/{uuid}` before this UI can use it; this PR does not broaden or activate that gateway.

Do not solve the remaining UI gap by assigning all registry capabilities to operator sessions or by adding an agent scope such as `agent.task.claim`. The initial worker continues to claim and execute tasks locally under the existing lease fencing.


## Concrete API contract observed during source audit

The existing service already routes:

- `POST /v1/tasks` to task intake;
- `GET /v1/tasks/{uuid}` through owner-scoped Store lookup;
- queued intake through `x-iao-device-proof`, whose signature binds method, path, timestamp, one-use nonce and SHA-256 of the exact request body;
- the active primary-device binding to the exact authenticated bearer session;
- the capability decision to `authorize(capability, approved_capabilities=principal.scopes ∩ registry)`;
- queued mode to a registered `READ_ONLY` tool and `QUEUED_TOOL_ALLOWLIST`;
- task creation to the existing Store, with idempotency, quota, expiry and policy snapshot.

The worker rechecks expiry, policy version, registry membership, read-only effect class, queued allowlist, input schema, operator-session digest and primary-device binding before calling the isolated tool runner.

The operator login flow explicitly returns `OPERATOR_AUTHENTICATED_READ_ONLY` with an empty scope list. Therefore, current behavior is fail-closed: a correctly signed queued request still cannot authorize a capability unless a separately authorized scope is present. Do not alter this default.

### Implemented capability-grant protocol (draft PR #10; pending CI and merge)

The draft implementation uses a challenge/complete protocol rather than trusting a browser-supplied scope list:

1. `POST /v1/operator/capability-grant/challenge` requires an authenticated operator session and the currently bound primary device. The server supplies a short-lived, single-use nonce and a canonical payload containing protocol version, identity tag, root key version, primary-device fingerprint, exact capability, policy version, exact grant expiry, session digest and purpose.
2. The browser asks for explicit confirmation, then signs the same canonical payload with the non-exportable root key and primary-device key under separate domain-separation prefixes.
3. `POST /v1/operator/capability-grant/complete` verifies both signatures against the current active keys, consumes the nonce atomically, checks the server-side allowlist and verifies that the policy/session/device/root versions still match the signed payload.
4. The server persists the grant in the existing `OperatorIdentityAuthority` database. The record contains a random opaque ID, exact capability, identity/session/device binding, key version, policy version, issue/expiry times and revocation state. Signatures are never stored as bearer credentials.
5. Authenticated requests derive operator scopes from active grants, not from caller-supplied scope lists. Login remains empty-scope by default. The grant is checked at task intake and rechecked by TaskWorker before execution.
6. Revocation uses a fresh dual-signed challenge and atomically marks the exact grant revoked. Root rotation, primary-device replacement, session replacement, expiry or policy version change also invalidates it.
7. The task intake handler continues to enforce its signed request proof, primary-device session binding, policy gate, registry allowlist, idempotency and quota. The worker continues to revalidate authority immediately before execution.

The challenge endpoint is rate-limited by the service and limited to five outstanding challenges per identity. Challenges are short-lived and single-use. Signature lengths and canonical payload are validated; guest sessions, other devices, agent identities, model outputs and public peers cannot request or approve grants.

### Required grant-specific tests

- Login remains empty-scope by default.
- Missing, malformed, expired, replayed and cross-identity grant challenges are rejected.
- Root signature without primary-device signature is rejected, and vice versa.
- A signature for capability A cannot grant capability B.
- A capability outside the server allowlist or not currently grantable is rejected.
- Root key rotation, primary-device replacement, explicit revocation, expiry and policy change invalidate existing grants and stale sessions.
- A revoked grant cannot authorize a new queued task even with an unexpired bearer token.
- Task intake with a valid device request proof but no active capability grant is denied and never transitions to `QUEUED`.
- A grant cannot change task budget, timeout, tool schema, effect class, or queued allowlist.
