# ADR-008: Global open-network participation with capability-gated federation

Status: accepted for the IAO target architecture; implementation and production qualification are pending.
Date: 2026-11-28.
Supersedes the blanket deferral in ADR-007 only with respect to discovery and voluntary participation. It does not remove the trust, authorization, privacy, or execution safeguards established there.

## Context

IAO's decentralization objective requires broad interoperability with independently operated open nodes and servers across the public Internet and open P2P ecosystems. A federation restricted to a hand-maintained list of pre-enrolled IAO instances would not meet that objective.

At the same time, discovery is not consent, a reachable endpoint is not a trustworthy peer, a public server is not necessarily an IAO node, and a valid cryptographic identity does not prove that a remote machine is honest or safe to execute.

No protocol can guarantee that every Internet host participates: operators may be offline, incompatible, firewalled, private, or unwilling to join. IAO must therefore avoid intentionally excluding compatible, publicly reachable nodes while respecting operator choice and network boundaries.

## Decision

IAO will implement a global, multi-transport, opt-in federation with the following invariant:

**Every compatible open node may be discovered and offered a documented participation path; no node is enrolled, assigned work, granted data access, or used for compute without the required owner/operator consent and verification.**

"Open node" includes independently operated servers and peers that expose a documented protocol or can run an adapter. It does not mean arbitrary Internet hosts are automatically IAO workers.

## Participation levels

1. **DISCOVERED_UNVERIFIED** — a candidate found through a public directory, signed feed, DHT, peer exchange, onion/I2P directory, or operator submission. Store only bounded public metadata; no trust or authority.
2. **REACHABLE_UNVERIFIED** — a bounded protocol probe confirms reachability and supported protocol version. This is not identity verification.
3. **IDENTITY_VERIFIED** — a fresh challenge proves possession of a key bound to the advertised node identifier. This is not owner consent or workload trust.
4. **OWNER_CONSENTED** — the operator explicitly accepts the IAO participation contract and the node's advertised role, data boundary, resource limits, and transport.
5. **QUARANTINED** — a consenting node is isolated while protocol conformance, rate limits, revocation checks, and safety tests run.
6. **FEDERATED_LIMITED** — the node receives only explicitly granted, least-privilege capabilities, initially public metadata exchange and read-only knowledge exchange.
7. **FEDERATED_ACTIVE** — broader capabilities may be granted only through a separate, explicit operator approval and verifiable task contract. Remote code execution is never implied by federation membership.
8. **REVOKED / EXPIRED** — leases expire by default; revocation removes grants and blocks new work. Re-admission requires a fresh challenge and consent.

A node may participate at a low-trust level without becoming a compute worker. Public metadata and public content must remain separate from private operator data, credentials, local memory, and control-plane authority.

## Discovery and transport requirements

Implement independent adapters behind one normalized candidate interface:

- libp2p Kademlia/DHT and peer exchange;
- IPFS peer discovery and content-addressed public artifacts;
- Tor SOCKS5 and v3 onion services;
- I2P SAMv3 and .i2p services;
- signed public federation directories and feeds;
- Nostr or other signed event relays where a verifiable IAO announcement schema is published;
- ordinary HTTPS for compatible public endpoints.

Transport adapters must not silently downgrade security. Onion and I2P destinations must be resolved by their respective transports, never public DNS. Direct P2P must be an explicit operator-configured transport because it can reveal the operator's network address. Each adapter must expose independent health, reachability, privacy, and failure metrics.

Discovery is broad and continuous but bounded: rate limits, response-size limits, timeouts, deduplication, backoff, private-address/SSRF protections for public HTTPS, and a local opt-out policy are mandatory. No indiscriminate port scanning, exploitation, credential guessing, or forced installation is permitted.

## Interoperability contract

Publish a versioned, language-neutral protocol specification and reference adapters. A compatible node must be able to:
- publish a signed capability manifest and protocol version;
- expose a fresh challenge/response identity proof;
- declare its owner-controlled participation policy and resource limits;
- accept or reject an enrollment request;
- advertise revocation and lease expiry;
- exchange bounded, schema-validated messages;
- return signed task receipts and verifiable result metadata when explicitly authorized.

Implementations may be written in different languages and run on different operating systems. No single cloud provider, repository host, DNS provider, or commercial model vendor may be a mandatory control plane.

## Security and autonomy boundaries

- Discovery never grants trust, capabilities, private-data access, or execution.
- A signature proves key possession, not hardware integrity, operator identity, or result correctness.
- Public peers are untrusted inputs. Validate schemas, signatures, freshness, quotas, and result provenance.
- Workloads run only in a qualified sandbox with no network by default, bounded CPU/memory/time/storage, and no ambient secrets.
- Task assignment requires an explicit grant, an idempotent task contract, a lease, and auditable receipt/result states.
- The phone's cryptographic primary-device authority remains the sole source of privileged IAO control. Federation peers cannot become operators.
- Nodes can leave, revoke consent, rotate keys, or disable any transport without losing control of their own machines.

## Acceptance gates

Do not claim global federation or production readiness until evidence demonstrates all of the following:

1. independent discovery through at least two distinct open transports;
2. successful bidirectional federation with at least two independently operated external nodes;
3. explicit owner consent and cryptographic identity binding for every enrolled node;
4. quarantine, lease expiry, revocation, and key-rotation tests;
5. bounded public-data exchange and a read-only task with verifiable receipts on both ends;
6. negative tests proving discovered/unconsented nodes cannot receive tasks, capabilities, private data, or code;
7. Tor onion and I2P transport tests using their actual local daemons and independent remote peers;
8. recovery and continued operation when one directory, relay, transport, or peer disappears;
9. privacy review confirming direct-IP disclosure is opt-in and metadata is minimized;
10. reproducible runtime evidence; CI alone is not proof of a live global network.

## Current implementation status at decision time

Existing code includes libp2p discovery, IPFS candidate inventory, onion-feed discovery through Tor SOCKS, Ed25519 identity/challenge primitives, bounded federation messages, and quarantine-oriented candidate records. These components are not evidence that a worldwide network is connected.

The current production branch still has explicit gaps in I2P SAMv3, public multi-source discovery coverage, end-to-end owner-consented admission with independent organizations, distributed task execution, and real external-peer qualification. The actual number of confirmed independent IAO nodes must remain zero until runtime evidence proves otherwise.

## Consequences

IAO will not deliberately exclude compatible open nodes from discovery or from the documented route to voluntary participation. The network can grow without a central gatekeeper while each node retains ownership, local policy, and the ability to leave. "All the world can participate" is an interoperability goal, not a claim that every Internet server has joined or can be compelled to join.
