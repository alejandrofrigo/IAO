# IAO production readiness ledger

This document is a living, reproducible gate ledger. A capability is not considered complete until its acceptance test and the relevant GitHub Actions job pass on the same commit.

## Current objective state

| Objective | Evidence required | Current state |
|---|---|---|
| Persistent API and public chat | API tests for sessions, conversations, chat audit and fail-closed model handling | Implemented in code; verify on every CI run |
| Authorized chat → persistent queue | Device-bound authorization, idempotency, queued state, status retrieval, worker re-check | Implemented in code; acceptance suite must remain green |
| Cryptographic primary-device authority | Enrollment, proof, revocation and cross-route rejection tests | Implemented in code; production OIDC still not complete |
| Safe PADGE/autoprogramming | Candidate validation, tests, rollback and protected-component policy | Partially implemented; no production completion claim |
| Multi-LLM router | Inventory inspection, secret-free mocks in CI, live provider connectivity evidence | Configurable code exists; live availability is unverified in CI |
| Independent federation | Signed identity/handshake with an actually independent node | Local contract and guarded publication exist; independent-node proof missing |
| NORMAL readiness | External identity provider, persistent deployment, verified model and federation gates | Not achieved; readiness must remain DEGRADED/NOT_READY |

## Dependencies, gaps and risks

- CI must use mocks/fixtures only; no provider credentials are committed or transmitted.
- The repository is public, so logs and artifacts must avoid secrets, personal data and private operator identifiers.
- GitHub Actions validates code; it does not provide persistent hosting.
- Production deployment, OIDC, real provider calls, and independent-node federation require external infrastructure or operator action.
- No merge to `main` or privileged production activation is authorized by this ledger.

## Acceptance rule

Only a green `deterministic-gates` job plus the full repository CI on the same commit may be cited as reproducible evidence for this change. A green CI run does not prove live provider availability, production hosting, or independent federation.
