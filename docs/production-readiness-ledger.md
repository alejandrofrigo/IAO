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
- Production-gates run #15 and the follow-up run #17 both exposed a defect in the new router test fixture: the fake persistence callback cleared the same dictionary object it was asked to persist. The product router was not implicated; the selected run had 127 other passing tests. The fixture now snapshots the state before updating it in commit `ab19cc1eb2ab2d9e6275b21fa222dc7e3468e149`; validation on this correction is pending.
- Independent external federation remains unverified. `omega/federation_autonomous.py` has mocked transport tests for signed publication, explicit remote consent, identity challenge, contract-key matching and local revocation. `tools/iao_federation_autonomous.py` still blocks non-loopback enrollment while trusted public transport is not integrated. No external peer endpoint or independently operated node has been supplied or verified; no peer was enrolled.
- Provider inventory distinction: the repository contains fixed adapters for Anthropic, Gemini and Groq, plus a separate OpenAI-compatible gateway router whose actual provider inventory is read from the operator runtime file under `~/.config/iao/llm-providers.json`. GitHub CI cannot inspect that private runtime file; provider/model declarations, credential presence, connectivity and successful live inference remain separate unverified facts.

- The deterministic gate now explicitly includes `tests/test_federation.py`, exercising two independently generated node identities and a real local HTTP round-trip. It does not include the separate mocked external auto-enrollment suite as a live-network test.
- Current correction commit for the router test fixture: `ab19cc1eb2ab2d9e6275b21fa222dc7e3468e149`. Do not mark router acceptance green until the exact commit's CI run passes.

## Latest validated router and federation gate (commit `7c4781cd9f5291b87deea23cebe938c4bd92e8d0`)

- IAO Production Gates run #23: **success** on Python 3.12 and 3.13; 128 deterministic API/identity/queue/federation/router tests passed per matrix job and Ruff passed on the production gate surface.
- IAO CI run #1608: **success** on Python 3.12 and 3.13; full suite reported 449 passed, 1 skipped on each version.
- IAO quality gate run #1608: **success**.
- IAO container qualification run #1267: **success**, API contract tests and container build/liveness qualification passed; no image published.
- Mobile Chromium integration run #651: **success**.
- The repository-wide legacy lint report still identifies 178 pre-existing lint findings in `tools/test_nostr_bridge.py`; the dedicated production integration lint and production-gate lint both pass. This legacy lint debt is not silently treated as clean.
- Federation evidence is a two-node local integration with separately generated Ed25519 identities, signed handshake and messages, READ_ONLY grants, replay/revocation checks and partition/recovery. A genuinely independent public node remains unverified and blocked by absence of a verified peer endpoint and trusted public transport/enrollment prerequisites.
- Router evidence is entirely mocked. No live provider credentials, connectivity or inference have been tested. The actual operator runtime inventory under `~/.config/iao/llm-providers.json` is not available to GitHub Actions and remains unverified here.

## External bootstrap expansion: Tor onion directories (2026-11-27)

- Added optional `onion_feeds` discovery sources to `tools/iao_federation_autonomous.py`. Directory JSON is fetched through the existing Tor SOCKS5 transport (`fetch_onion_json`), with response-size and timeout bounds.
- Only v3 onion HTTP endpoint shapes are accepted. Candidates are deduplicated and persisted separately in `.state/iao-onion-candidates.json`; they remain `DISCOVERED_UNVERIFIED`, with no identity verification, enrollment, inbound grants, private-data access, or remote-code execution.
- Added `tests/test_federation_onion_discovery.py` for validation, isolated persistence, unverified state and idempotency. These tests mock Tor transport; they do not contact a real onion service.
- IAO Production Gates run #32: **success** on Python 3.12 and 3.13; 131 deterministic tests passed per matrix job and Ruff passed.
- IAO CI run #1617: **success** on Python 3.12 and 3.13; full suite reported 452 passed, 1 skipped on each version. Quality gate #1617, container qualification #1271 (API contract tests and build/liveness; no publication), and mobile Chromium run #660 also passed.
- These CI runs were triggered from workflow commit `3a34d7f4c9404935973ef93d1dc9297604c590be`. A subsequent test-only change `c1905d7fc3568cda960dca467579a607d146ce27` redirects test audit output into the temporary test directory; the CI evidence above predates that final test-isolation-only commit.
- This is a discovery/bootstrap improvement, not proof of live Tor reachability or a usable external compute node. No onion feed has been configured or contacted in production, and no external candidate has been enrolled.
- Remaining gap: libp2p DHT peers and onion/HTTPS feed entries are still discovery records. Most arbitrary external peers do not speak IAO's federation protocol. A safe adapter layer for genuinely open, documented, read-only services is still required before IAO can use them as workers or model endpoints. Do not describe discovery as assimilation or claim an active node count.

## Public IAO peer autojoin wired to trusted transport (2026-11-27)

- The autonomous CLI now routes HTTPS candidates originating from configured `public_feed` or `signed_directory` sources into `omega.federation_autonomous.run_discovered_cycle`. It no longer sends these public candidates through the legacy `urllib` probe path.
- Candidate admission requires a normalized public HTTPS origin and a 16-character lowercase hexadecimal node ID. Conflicting IDs for an already-known origin are quarantined as `IDENTITY_CONFLICT`.
- The trusted path uses bounded HTTPS transport with public-DNS pinning, TLS hostname validation and redirect refusal; it verifies the peer's signed publication, explicit `consent=true`, nonce-bound Ed25519 challenge, matching public identity and participation-contract key. Capabilities are intersected with locally served capabilities and inbound grants remain empty.
- The local enrollment path is now connected to the autonomous CLI. The integration test mocks the trusted cycle and proves the CLI routes public candidates there without calling the legacy probe. Existing `tests/test_federation_autonomous.py` separately exercises the signed publication/challenge/contract flow with mocked transport.
- IAO Production Gates run #40: **success** on Python 3.12 and 3.13; 132 deterministic tests passed per matrix job and Ruff passed.
- IAO CI run #1625: **success** on Python 3.12 and 3.13; full suite reported 453 passed, 1 skipped on each version. Quality gate #1625, container qualification #1275 (API contract tests and build/liveness; no publication), and mobile Chromium run #668 also passed.
- This makes a consenting, compatible public IAO peer technically eligible for the autonomous signed enrollment path. It does **not** make arbitrary public servers IAO workers: non-IAO IPFS/libp2p peers, Nostr relays and onion endpoints still need protocol-specific, documented read-only service adapters. No external peer endpoint has been contacted or independently verified in this run; active external node count remains unproven.
- The legacy CLI probe remains loopback-only. Public HTTPS autojoin must continue to use the pinned `omega.federation_autonomous` path; do not relax the legacy guard or fall back to `urllib`.

## Public peer autojoin path hardening (2026-11-27)

- Added the mocked autonomous-enrollment and federation-transport suites to the deterministic production gate: `tests/test_federation_autonomous.py` and `tests/test_federation_transport.py`. These cover signed publication, explicit remote consent, nonce-bound Ed25519 identity proof, contract-key matching, local revocation, pinned public HTTPS, DNS/private-address rejection, redirect refusal, bounded JSON responses, Tor SOCKS restrictions, and TLS client-identity configuration.
- Fixed a real discovery-to-enrollment interoperability defect: public feeds may advertise the native IAO message endpoint (`https://peer.example/fed/v1/message`), while the autojoin intake previously accepted only a bare origin. The intake now normalizes only the exact root, root slash, or native message path to the HTTPS origin; it rejects other paths, query/fragment components, userinfo, non-default ports, loopback and non-HTTPS values.
- Added direct normalization/rejection tests and changed the end-to-end intake fixture to advertise the actual `/fed/v1/message` endpoint.
- Final validation commit: `bce681e3222da36a4d280b4a7c65a5b074da241c`. IAO Production Gates run #? completed successfully on Python 3.12 and 3.13: 154 deterministic tests passed per version and Ruff passed. IAO CI run associated with this commit passed on Python 3.12 and 3.13 (454 passed, 1 skipped per version). Quality gate, container API-contract/build qualification, and mobile Chromium integration also passed. Container image was built and checked but not published.
- The initial newly-expanded lint gate exposed three one-line statements and one unused import in the pre-existing autonomous-enrollment test module. These were corrected before the final green validation above.
- This removes a code-level blocker for advertised native IAO peers; it does not establish that any external peer is currently online or enrolled. No public feed or external endpoint was contacted in CI, and no external peer was enrolled in production.
- Important remaining boundary: arbitrary libp2p DHT peers and onion directory entries are not automatically IAO workers. They remain discovery-only until they expose a compatible, documented capability protocol. The next technical milestone is capability-specific, read-only adapters for externally published services (starting with content retrieval and compatible inference APIs), with per-adapter verification, timeouts, quotas, isolation and revocation. Never turn arbitrary peer discovery into remote code execution or silently treat a peer as a trusted compute worker.

