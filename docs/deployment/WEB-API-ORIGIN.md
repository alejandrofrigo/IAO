# IAO public web API origin

## Security state

The public web client intentionally fails closed when no API origin is configured. It does not contain a Cloudflare Quick Tunnel URL, account credential, tunnel token, operator secret, or device key.

The browser API helper accepts an explicitly configured HTTPS origin only. Plain HTTP is accepted only for loopback development (`localhost` or `127.0.0.1`). API calls are restricted to `/v1/*` and `/health/*` paths on that configured origin.

## Configure the origin

Set one of the following before loading `api-config.js`:

1. Define `window.IAO_API_BASE_OVERRIDE = "https://<deployed-api-host>";` in a deployment-specific script loaded before `api-config.js`; or
2. Add `<meta name="iao-api-base" content="https://<deployed-api-host>">` to the page head.

Use the final HTTPS hostname of the deployed IAO Cloudflare gateway, not the local Termux API origin. The gateway's `IAO_API_ORIGIN` must independently point to an already-running, authenticated IAO API.

Do not commit a temporary `trycloudflare.com` hostname. Do not place tunnel tokens, account certificates, bearer tokens, private keys, recovery codes, or device proofs in this setting. The API origin is routing information, not authentication.

## Expected behavior while unconfigured

When no valid origin is supplied:

- `window.IAO_API_BASE` is an empty string.
- `window.IAO_API_CONFIG_STATUS` is `blocked`.
- `window.iaoApiUrl(...)` throws `API_BASE_NOT_CONFIGURED` or `INVALID_API_BASE`.
- The UI must not silently fall back to a stale tunnel, Render, or an unrelated API host.

## Verification

Run:

```sh
node --check web/api-config.js
node --test web/api-config.test.js
```

The CI workflow runs these checks. A successful browser configuration test does not prove that the API is deployed, reachable, authenticated, or ready; verify the gateway and upstream health separately.
