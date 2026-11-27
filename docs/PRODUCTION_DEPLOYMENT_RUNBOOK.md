# IAO production deployment runbook

This runbook prepares a self-hosted Docker Compose deployment. It does not
create a cloud account, domain, public IP, DNS record or external host. A
production launch is possible only on an always-on host that can accept inbound
TCP 80/443 and preserve Docker volumes.

## 1. Provision private secrets

From the repository root on the deployment host:

```bash
python3 tools/iao_prepare_production_secrets.py
chmod 600 .env.production
```

The script creates independent random session-signing, audit, device-enrollment
and operator-bootstrap secrets. It never prints their values and refuses to
overwrite an existing file. The file is git-ignored.

Edit `.env.production` with a secure editor and set:
- `IAO_DOMAIN`: a DNS name whose A/AAAA records point to this host.
- `IAO_CORS_ORIGINS`: the exact HTTPS browser origin, e.g. `https://chat.example`.

Do not use placeholders. Compose derives `PUBLIC_BASE_URL=https://IAO_DOMAIN`.
Caddy obtains and renews TLS certificates automatically when DNS and ports
80/443 are correctly configured.

## 2. Validate and start

```bash
docker compose --env-file .env.production -f deploy/compose.yaml config --quiet
docker compose --env-file .env.production -f deploy/compose.yaml up --build -d
docker compose --env-file .env.production -f deploy/compose.yaml ps
```

The API container runs as a non-root user with a read-only root filesystem,
dropped capabilities, no-new-privileges and persistent state volumes. Caddy
terminates HTTPS and proxies to the private API network. The identity rollback
trust directory is on a separate named volume from the primary state volume.

Verify:
```bash
curl --fail https://${IAO_DOMAIN}/health/live
curl --fail https://${IAO_DOMAIN}/health/ready
```

A live response is not production acceptance. Readiness must report all
required gates accurately; `degraded` or `not_ready` must not be overridden.

## 3. First operator/device bootstrap

The generated file initially enables the one-time device enrollment gate and
contains expiring bootstrap codes. Complete the root identity and primary
Android browser enrollment through the IAO identity flow. Do not send the
codes to a public chat, commit them, or place them in logs.

Immediately after successful enrollment:
1. Set `IAO_DEVICE_ENROLLMENT_ENABLED=0`.
2. Remove `IAO_DEVICE_ENROLLMENT_CODE`.
3. Remove `IAO_OPERATOR_BOOTSTRAP_CODE` and
   `IAO_OPERATOR_BOOTSTRAP_EXPIRES_AT`.
4. Recreate the API container and verify the device-bound operator login.

The worker remains limited to the explicitly granted read-only capability
`knowledge.search`. Models and discovered peers do not gain command authority.

## 4. Backups and rollback

The state and identity-trust volumes are separate. Back up both consistently
and retain an offline copy outside the host. The identity backup helper
(`omega.identity_backup`) verifies the paired operator-identity and
device-authority databases, but it is not a full-system restore tool. Do not
claim full restore readiness until a tested restore procedure covers the task
queue, audit chain, knowledge state, identity databases and independent
rollback anchor together.

## 5. Production acceptance blockers

- A real host, public DNS name and inbound 80/443 connectivity are required.
- The actual host kernel must pass the live bubblewrap/user-namespace preflight.
  CI container success alone is insufficient.
- Configure at least one real upstream model provider and verify a live request;
  configured metadata alone is not evidence of availability or cost.
- Complete physical Android enrollment/login/recovery tests.
- Complete full backup/restore and rollback drills.
- Repeat all CI, quality, container, mobile and runtime gates on one final SHA.

Do not expose the API directly over plaintext HTTP. Do not publish secrets,
database files, bootstrap codes or device private keys.
