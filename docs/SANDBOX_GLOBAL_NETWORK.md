# IAO sandbox global network connectivity

## Requirement

Every long-lived IAO sandbox that is eligible to run network-capable tasks must
have persistent outbound Internet connectivity to globally reachable public
services. Network access is a runtime capability, not a one-off setup check.
A sandbox must be able to recover automatically after DNS, route, proxy, ISP,
gateway, or remote-service interruptions.

This requirement does not mean that every destination, country, ISP, Tor
service, or public endpoint is continuously reachable. IAO cannot guarantee
the availability of the global Internet or bypass local law, censorship,
provider outages, geoblocking, or remote rate limits. It must report observed
reachability and degraded paths truthfully.

## Implemented application-layer egress mode

`omega.egress.EgressPolicy` now supports an explicit
`allow_public_hosts=True` mode for globally addressed public hostnames. It
retains HTTPS-only behavior by default, the configured port set (443 by
default), DNS pinning, rejection of any private/non-global DNS answer,
redirect revalidation, TLS certificate verification, response limits, and
timeouts. The default remains deny-by-hostname unless the caller opts in.
The existing `web.fetch` tool can be constructed with this policy; it is not
automatically enabled or added to the queued-tool allowlist.

This is an application-layer HTTP(S) capability, not a transparent network
interface for arbitrary protocols. It does not create a persistent tunnel,
route all sandbox sockets, provide redundant gateways, or prove continuous
Internet availability. Those deployment/runtime capabilities remain
unimplemented and are mandatory production gates.

## Network architecture

- Keep sandbox workloads on a dedicated network segment/namespace with
  outbound routing through an explicit egress gateway or proxy.
- Use redundant egress paths where the deployment has independent routes.
  Health-check each path and fail over without restarting the IAO control
  plane; restore preferred paths only after stable health checks.
- Support normal public IPv4 and IPv6 destinations, DNS resolution, HTTPS,
  and explicitly enabled protocol adapters such as IPFS/libp2p and Tor.
  Protocol availability is reported separately; installing an adapter does
  not prove that a network or daemon is running.
- Maintain long-lived connection pools where useful, reconnect with bounded
  exponential backoff and jitter, and expose per-path latency, DNS, TLS,
  packet/connection errors, and last-success timestamps.
- Do not require inbound Internet exposure of a sandbox. Replies to
  sandbox-initiated connections are allowed by stateful egress policy.
- Keep control-plane, operator-device, state-volume, and secret-management
  networks separate from sandbox egress.

## Mandatory egress protections

- Deny access to loopback, private, link-local, multicast, reserved, and
  cloud-instance metadata destinations by default, including IPv4 and IPv6.
- Resolve and validate every destination address at connection time; defend
  against DNS rebinding, redirects to forbidden ranges, alternate IP
  encodings, and proxy bypass.
- Revalidate every redirect and every newly resolved address. Do not trust a
  hostname merely because its first DNS answer was public.
- Do not forward operator credentials, control-plane tokens, private files,
  or inherited environment secrets into sandbox tasks.
- Apply per-task and per-sandbox limits for bandwidth, concurrent sockets,
  connection duration, response size, CPU, memory, and disk.
- Log policy decisions and aggregate network telemetry without recording
  secrets, authorization headers, private payloads, or operator identifiers.
- A discovered public host or peer is untrusted. Network reachability never
  grants identity, authority, private-data access, or code-execution rights.

## Availability and failure behavior

- A single failed probe must not be interpreted as total Internet failure.
  Probe multiple independent public destinations and distinguish DNS,
  routing, TLS, proxy, and remote-service failures.
- If one egress path fails, retry through another approved path. If all paths
  fail, keep local/read-only work available, queue retryable tasks, and report
  NETWORK_DEGRADED; do not weaken policy or silently claim connectivity.
- A sandbox must not hold privileged control-plane credentials, and loss of
  Internet must not stop the control plane or corrupt durable task state.
- Readiness must expose sandbox network health separately from API liveness,
  database readiness, federation health, and model-provider availability.

## Verification gates

Before production approval, demonstrate in an isolated test environment:

1. Persistent outbound HTTPS and DNS across a sustained soak test.
2. IPv4 and IPv6 reachability where the host network supports both.
3. Recovery and failover after terminating one egress route and restoring it.
4. Correct behavior during DNS failure, TLS failure, remote rate limiting, and
   total network loss.
5. Denial of loopback, private, link-local, metadata, and DNS-rebinding targets.
6. No route from sandbox to operator/control-plane/private-state networks.
7. Bounded resource use and durable task retry without duplicate execution.
8. Working protocol-specific tests for each enabled P2P/Tor adapter.

Passing unit tests or sharing the host network namespace is not evidence of
global, persistent sandbox connectivity. The current process runner is a
killable child-process boundary, not a network-isolated OS sandbox or a
persistent network service. Production qualification remains blocked until
the deployment supplies and verifies the network architecture above.
