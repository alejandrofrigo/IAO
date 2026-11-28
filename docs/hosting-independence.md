# IAO hosting independence and production path

## Decision

IAO production must not depend on Vercel. Vercel is excluded from the runtime
architecture and from production acceptance. No Vercel deployment, quota,
preview, or build status is required to run the backend.

## Runtime ownership

The production runtime is a long-lived Linux host controlled by the operator.
The repository provides a reproducible single-instance Docker Compose package
in `compose.production.yaml`. That package is a deployment specification; it
does not provision a host or prove that a host is online.

The runtime boundary is:

1. Public HTTPS reverse proxy, managed on the production host.
2. Private loopback API on `127.0.0.1:8080`.
3. Persistent local Docker volume for SQLite-backed state.
4. API process supervised with bounded restart and shutdown behavior.
5. Explicitly configured authentication, audit keys, and browser CORS origin.
6. Optional Tor/IPFS/libp2p transports and independently authorized peers,
   enabled only after end-to-end verification.

GitHub is used for source control, review, and automated qualification only.
A GitHub Actions runner is ephemeral and is never counted as a production node.

## Acceptance gates

Do not label IAO as production-ready until each applicable gate has evidence:

- [ ] Operator-controlled Linux host provisioned and reachable.
- [ ] Docker Engine and Compose installed; image built from reviewed commit.
- [ ] Strong independent signing and audit secrets installed outside Git.
- [ ] HTTPS reverse proxy configured; backend port remains loopback-only.
- [ ] API liveness and readiness checked on the actual host.
- [ ] Public chat completes an authenticated end-to-end request to that API.
- [ ] State survives container replacement and a tested backup restore.
- [ ] Autonomous worker recovers interrupted tasks and records durable results.
- [ ] Phone-bound privileged authority and replay protection verified end-to-end.
- [ ] Tor transport and at least one independent, consenting federation peer
      complete authenticated handshakes in a live test.
- [ ] Monitoring, alerting, restart behavior, and recovery are exercised.

A checked item must have a timestamped test result or operator evidence.
A successful CI job, generated node identity, container image, or health
endpoint alone does not satisfy a runtime gate.

## Explicit boundaries

- No Vercel dependency.
- No claim of 24/7 availability without a monitored persistent host and
  measured uptime.
- No claim of global P2P or federation from locally generated identities.
- No node receives authority merely by being created or discovering a peer.
- No paid model provider is activated without explicit operator configuration
  and consent.
- SQLite remains a single-instance boundary; horizontal replicas require a
  reviewed transactional database migration.

## Current operational status

This document records the deployment contract, not an assertion that the host
exists. Until an operator-controlled host is provisioned and the acceptance
gates are evidenced, deployment status remains `BLOCKED_HOST_REQUIRED`.
