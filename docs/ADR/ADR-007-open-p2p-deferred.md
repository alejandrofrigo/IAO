# ADR-007: Open P2P participation is deferred; controlled federation (F5) first
Status: accepted. Date: 2026-10-21.
Decision: SO-OMEGA federates only with nodes enrolled by an operator through a ParticipationContract
(Ed25519 identity, capabilities, lease, rate limit, revocation). It does not join open/public P2P networks,
accept unauthenticated peers, run peer-supplied code, or scan for peers.
Why: spec Annex O.7/P.7 and sections 10, 17; node identity does not prove hardware/software/result honesty.
Reopen when: F5 gates pass against real independent nodes AND the operator signs a ParticipationContract
policy for open peers AND sandbox egress for the chosen transport is explicitly enabled.
