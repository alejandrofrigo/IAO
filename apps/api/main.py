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
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="IAO API", version="11.2.0")
_service = None
_device_authority = None
_service_lock = threading.Lock()

_allowed_origins = [
    item.strip().rstrip("/")
    for item in os.environ.get(
        "IAO_CORS_ORIGINS",
        "https://alejandrofrigo.github.io",
    ).split(",")
    if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)


def _get_device_authority():
    global _device_authority
    if _device_authority is not None:
        return _device_authority
    with _service_lock:
        if _device_authority is None:
            from omega.device_authority import DeviceAuthority

            state_dir = Path(os.environ.get("IAO_STATE_DIR", "/var/lib/iao"))
            _device_authority = DeviceAuthority(
                state_dir / "device-authority.sqlite3",
                os.environ.get("IAO_DEVICE_ENROLLMENT_CODE", ""),
            )
    return _device_authority


async def _device_json(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


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
    if status != 200 or payload.get("status") == "not_ready":
        payload["status"] = "not_ready"
        return JSONResponse(status_code=503, content=payload)
    # Infrastructure readiness is not equivalent to production readiness:
    # device-bound command authority and independent federation are still
    # explicit acceptance gates, even when the database and audit chain work.
    payload["status"] = "degraded"
    payload["production_gates"] = {
        "device_bound_command_authority": "not_integrated",
        "independent_federation": "not_verified",
        "model_provider": "configured" if _get_service().model is not None else "not_configured",
    }
    return JSONResponse(status_code=200, content=payload)


@app.post("/v1/device/enroll")
async def device_enroll(request: Request):
    from omega.device_authority import DeviceAuthorityError

    payload = await _device_json(request)
    if payload is None:
        return JSONResponse(status_code=400, content={"error": "INVALID_REQUEST"})
    try:
        result = _get_device_authority().enroll(
            payload.get("code"),
            payload.get("public_key_pem"),
        )
        return JSONResponse(status_code=201, content=result)
    except DeviceAuthorityError as exc:
        return JSONResponse(status_code=exc.status, content={"error": exc.code})


@app.post("/v1/device/challenge")
async def device_challenge(request: Request):
    from omega.device_authority import DeviceAuthorityError

    payload = await _device_json(request)
    if payload is None:
        return JSONResponse(status_code=400, content={"error": "INVALID_REQUEST"})
    try:
        return JSONResponse(
            status_code=200,
            content=_get_device_authority().challenge(payload.get("device_id")),
        )
    except DeviceAuthorityError as exc:
        return JSONResponse(status_code=exc.status, content={"error": exc.code})


@app.post("/v1/device/command")
async def device_command(request: Request):
    from omega.device_authority import DeviceAuthorityError

    payload = await _device_json(request)
    if payload is None:
        return JSONResponse(status_code=400, content={"error": "INVALID_REQUEST"})
    try:
        result = _get_device_authority().verify_status(payload)
        return JSONResponse(status_code=200, content=result)
    except DeviceAuthorityError as exc:
        return JSONResponse(status_code=exc.status, content={"error": exc.code})


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
