# ADR-007: Controlled federation before granting peer authority

Status: superseded in part by ADR-008 (2026-11-28).
Original decision date: 2026-10-21.

## Historical decision

The original decision restricted federation to nodes enrolled by an operator through a ParticipationContract (Ed25519 identity, capabilities, lease, rate limit, revocation). It prohibited open/public P2P discovery, unauthenticated peer admission, peer-supplied code execution, and broad peer scanning.

The original rationale remains valid for trust and execution: node identity does not prove hardware/software/result honesty, and discovery is not consent.

## Current interpretation

ADR-008 supersedes the blanket restriction on open-network discovery and voluntary participation. IAO's target architecture now includes broad, bounded discovery across compatible open P2P networks and public federation directories, plus a documented owner-consented participation path for independently operated nodes.

The following safeguards from this ADR remain in force:
- Discovery alone grants no trust, capabilities, private-data access, or execution.
- Identity verification is distinct from owner consent and workload trust.
- Remote enrollment requires a verifiable participation contract and explicit operator consent.
- Peers remain quarantined until protocol, lease, revocation, and safety checks pass.
- Peer-supplied code is never executed outside an independently qualified sandbox and explicit task authorization.
- Transport exposure and direct-IP discovery must be explicit and privacy-reviewed.

## Reopening and acceptance

Open-network participation is an architectural objective, not a claim of a live global network. Follow the participation levels, transport requirements, security boundaries, and acceptance gates in [ADR-008](ADR-008-open-global-network-participation.md).

No production or worldwide-federation claim is permitted until independent external peers complete reproducible bidirectional tests.
