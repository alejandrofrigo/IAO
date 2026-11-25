# IAO

Verified state lives in `artifacts/` (status.json, runtime-report.json, test-results.txt, build-manifest.json).

## Run (works offline, stdlib only)
    export OMEGA_DEV_TOKEN_KEY=$(python3 -c "import os;print(os.urandom(16).hex())")
    python3 -m omega.supervisor              # supervised runtime on 127.0.0.1:8080
    python3 tools/run_runtime.py             # start + attack over HTTP + crash/recover + backup/restore
    python3 tools/verify.py                  # unit/security tests + hashed manifest + network probe

## Status honesty
Dev bearer tokens are NOT OIDC (production start is refused). SQLite is the dev backend; PostgreSQL,
FastAPI app (apps/api), pydantic contracts, Docker, CI, a real model adapter and all external
infrastructure (Annex S) are NOT executed in this sandbox (no network / credentials).

## Project objectives and integration gaps

See [IAO objectives, verified capabilities and integration gaps](docs/IAO_OBJECTIVES_GAP_ANALYSIS.md) for the repository-based inventory, current blockers, implementation order and acceptance criteria. This document distinguishes code presence from tested runtime capability.

