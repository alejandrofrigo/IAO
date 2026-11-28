# IAO

Verified state lives in `artifacts/` (status.json, runtime-report.json, test-results.txt, build-manifest.json).

## Run (works offline, stdlib only)
    export OMEGA_DEV_TOKEN_KEY=$(python3 -c "import os;print(os.urandom(16).hex())")
    python3 -m omega.supervisor              # supervised runtime on 127.0.0.1:8080
    python3 tools/run_runtime.py             # start + attack over HTTP + crash/recover + backup/restore
    python3 tools/verify.py                  # unit/security tests + hashed manifest + network probe

See [ChatGPT × IAO: collaboration of construction](docs/CHATGPT_IAO_COLLABORATION.md) for the engineering attribution, collaboration boundaries and target architecture.

## Fase de construcción

La hoja de ruta técnica activa está en [Fase 1 — Núcleo operativo y arquitectura](docs/PHASE_1_CORE_FOUNDATION.md). Cada fase se cierra con 20 objetivos verificables y evidencia; el código presente no se considera capacidad operativa hasta superar sus pruebas.

La [matriz de autenticación y autorización](docs/AUTHORIZATION_MATRIX.md) describe los requisitos por clase de ruta y las brechas de verificación.

La [auditoría de inventario y dependencias de Fase 1](docs/PHASE_1_INVENTORY_AUDIT_20261127.md) registra los límites de la arquitectura y las relaciones entre PRs sin inferir capacidades no verificadas.

El [contrato de arquitectura del núcleo](docs/CORE_ARCHITECTURE_CONTRACT.md) fija las responsabilidades de los adaptadores, el servicio, el Store, la identidad, la política, las herramientas y la cola persistente.

Consulta también el [contrato HTTP](docs/HTTP_API_CONTRACT.md) y la [guía operativa y criterios de salida de Fase 1](docs/PHASE_1_OPERATIONS_RUNBOOK.md).

## Status honesty

Dev bearer tokens are NOT OIDC (production start is refused). SQLite is the dev backend; PostgreSQL,
FastAPI app (apps/api), pydantic contracts, Docker, CI, a real model adapter and all external
infrastructure (Annex S) are NOT executed in this sandbox (no network / credentials).

## Project objectives and integration gaps

See [IAO objectives, verified capabilities and integration gaps](docs/IAO_OBJECTIVES_GAP_ANALYSIS.md) for the repository-based inventory, current blockers, implementation order and acceptance criteria. This document distinguishes code presence from tested runtime capability.
