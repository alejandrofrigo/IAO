# IAO Node Factory

## Purpose

The factory creates independent IAO node identity workspaces on infrastructure
controlled by the operator. GitHub stores and tests the factory source; GitHub
Actions runners are ephemeral CI workers, not persistent IAO nodes.

## Create and inspect

```bash
python tools/iao_node_factory.py create --count 3 --role worker
python tools/iao_node_factory.py status
```

The batch limit is 10. A batch is rolled back if any later node creation fails, so a failed batch does not leave a misleading partial set. Each node receives a distinct Ed25519 identity. Private
keys remain in the local node workspace under `identity/private.key` with
0600 permissions; parent directories are private where supported. The factory
never prints, exports, uploads, or commits private keys.

## Trust boundary

A created workspace is `CREATED_UNENROLLED`, has no endpoint, no capabilities,
and `authority=NONE`. Creation does not start a server, enroll a peer, grant
trust, or permit remote execution. A node must be deployed on a host the
operator controls and pass the existing federation's transport, identity,
lease, and policy gates before any capability is granted.

The current federation assimilation path deliberately fails closed because
the live trusted-transport attestation is not yet integrated. The factory does
not weaken or bypass that gate. Publicly discovered nodes remain untrusted
candidates.

## GitHub's role

GitHub is used for source control, reproducible tests, and packaging templates.
GitHub-hosted Actions jobs terminate after each run; they must not be described
as always-on nodes. This workflow creates no Gmail accounts, GitHub accounts,
tokens, cloud resources, or paid services.
