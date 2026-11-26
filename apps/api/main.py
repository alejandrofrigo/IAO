"""FastAPI adapter for the persistent IAO service.

The API delegates public sessions, conversations, chat, tasks and audit reads to
OmegaService. Production state and audit keys must be supplied by the runtime;
this module never silently creates a replacement audit identity.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="IAO API", version="11.2.0")
_service = None
_service_lock = threading.Lock()


def _get_service():
    """Create one process-wide service over the configured persistent state."""
    global _service
    if _service is not None:
        return _service
    with _service_lock:
        if _service is not None:
            return _service
        token_key = os.environ.get("OMEGA_DEV_TOKEN_KEY", "")
        audit_key = os.environ.get("AUDIT_HMAC_KEY", "")
        if len(token_key) < 32 or len(audit_key) < 32:
            raise RuntimeError("PERSISTENT_AUTH_AND_AUDIT_KEYS_REQUIRED")
        from omega.server import build_service

        state_dir = Path(os.environ.get("IAO_STATE_DIR", "/var/lib/iao"))
        corpus_dir = Path(os.environ.get("IAO_CORPUS_DIR", "/app/knowledge"))
        _service = build_service(state_dir, token_key, corpus_dir)
        return _service


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready():
    try:
        status, payload = _get_service().handle("GET", "/health/ready", {}, b"")
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "PERSISTENT_RUNTIME_UNAVAILABLE",
            },
        )
    if payload.get("status") == "ready":
        payload["status"] = "ready"
    elif payload.get("status") == "degraded":
        payload["status"] = "degraded"
    else:
        payload["status"] = "not_ready"
    return JSONResponse(status_code=status, content=payload)


@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def api_v1(path: str, request: Request):
    """Pass the complete v1 API through the audited persistent service."""
    try:
        service = _get_service()
        body = await request.body()
        headers = {key.lower(): value for key, value in request.headers.items()}
        # Use the socket peer only for the public-session rate limiter. Never
        # accept a caller-supplied forwarding header as device identity.
        if request.client is not None:
            headers["x-omega-client-ip"] = request.client.host
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        status, payload = service.handle(
            request.method,
            target,
            headers,
            body,
        )
        return JSONResponse(status_code=status, content=payload)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"error": "PERSISTENT_RUNTIME_UNAVAILABLE"},
        )
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"error": "IAO_SERVICE_UNAVAILABLE"},
        )
