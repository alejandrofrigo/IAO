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

## Latest CI evidence (2026-11-27)

- PR #17 production-gates run #3: compile and browser syntax passed on Python 3.12 and 3.13; deterministic tests passed on both (86 passed each).
- The run failed only at Ruff because `omega/server.py` assigned a lambda to `state_supplier` (E731).
- Follow-up commit `367b96785cd283b1781866c02fea9570330e5872` replaces that lambda with an equivalent local function; behavior is unchanged.
- The corrected commit passed production-gates run #5 on both Python versions; see the evidence record below.

## Corrected commit validation (2026-11-27)

Commit `367b96785cd283b1781866c02fea9570330e5872`:
- IAO Production Gates run #5: **success**, Python 3.12 and 3.13; compile, browser syntax, deterministic API/identity/federation tests and Ruff all passed.
- IAO quality gate run #1590: **success**.
- IAO CI run #1590: **success**, full test suite on Python 3.12 and 3.13.
- Container build qualification run #1258: **success**, API contract tests, image build and liveness verification passed; image was not published.
- Mobile browser integration run #633: **success**, mobile Chromium identity flow passed.
- Earlier production-gates run #3 failed only on Ruff E731; the failure was corrected in `367b967`. The 86 deterministic tests passed on each Python version in run #3.
- These checks validate the commit above. Any subsequent source or workflow change must be validated again on its own resulting commit.

## Router and federation verification (2026-11-27)

- Added `tests/test_llm_router.py` with mocked provider calls for priority-based failover, cooldown skipping, success metadata, sanitized provider failures, and secret-free health/status output. CI does not send provider credentials or call live providers.
- Added the router test module to the deterministic production-gates workflow.
- Added `tests/test_federation.py` to the deterministic gate. This suite creates two separately keyed Ed25519 nodes and exercises signed challenge verification, signed request/response, READ_ONLY capability grants, revocation, replay rejection, and partition/recovery over a local test HTTP server. This is reproducible two-node protocol evidence, not proof of an independently operated public node.
- Production-gates run #15 initially found a defect in the new router test fixture: the mocked health reader did not retain persisted state between failover attempts. The product router was not implicated; 127 other selected tests passed in the failing job. Test fixture corrected in commit `eb109bc208f0b7e60637b9f90e15601ddf90efe3`; validation on this correction is pending.
- Independent external federation remains unverified. `omega/federation_autonomous.py` has mocked transport tests for signed publication, explicit remote consent, identity challenge, contract-key matching and local revocation. `tools/iao_federation_autonomous.py` still blocks non-loopback enrollment while trusted public transport is not integrated. No external peer endpoint or independently operated node has been supplied or verified; no peer was enrolled.
- Provider inventory distinction: the repository contains fixed adapters for Anthropic, Gemini and Groq, plus a separate OpenAI-compatible gateway router whose actual provider inventory is read from the operator runtime file under `~/.config/iao/llm-providers.json`. GitHub CI cannot inspect that private runtime file; provider/model declarations, credential presence, connectivity and successful live inference remain separate unverified facts.
