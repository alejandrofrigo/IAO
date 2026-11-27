"""FastAPI adapter for the persistent IAO service.

The API delegates public sessions, conversations, chat, tasks and audit reads to
OmegaService. Production state and audit keys must be supplied by the runtime;
this module never silently creates a replacement audit identity.
"""
from __future__ import annotations

import logging
import os
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from omega.config import validate_persistent_keys
from omega.service import MAX_BODY

@asynccontextmanager
async def _runtime_lifespan(_app):
    # Start persistent service and network workers during configured production boot.
    # Liveness-only qualification may omit secrets; in that case the API remains
    # live but readiness and service routes stay fail-closed.
    if os.environ.get("OMEGA_DEV_TOKEN_KEY") or os.environ.get("AUDIT_HMAC_KEY"):
        try:
            _get_service()
        except Exception as exc:
            # Keep liveness available, but never hide a failed configured startup.
            # Log only the exception class; messages may contain paths or secrets.
            logging.getLogger("iao.runtime").error(
                "RUNTIME_START_FAILED error_type=%s",
                type(exc).__name__,
            )
    try:
        yield
    finally:
        _stop_background_workers()


def _stop_background_workers() -> None:
    """Stop API-owned discovery workers with bounded joins before store teardown."""
    stops = (
        ("autojoin", "omega.federation_autojoin", "stop_federation_autojoin"),
        ("discovery", "omega.federation_discovery", "stop_federation_discovery"),
        ("external_network", "omega.external_network", "stop_external_network"),
    )
    logger = logging.getLogger("iao.runtime")
    for worker_name, module_name, function_name in stops:
        try:
            module = __import__(module_name, fromlist=[function_name])
            stop = getattr(module, function_name)
            stopped = stop(timeout=15.0)
        except Exception as exc:
            logger.error(
                "RUNTIME_WORKER_STOP_FAILED worker=%s error_type=%s",
                worker_name,
                type(exc).__name__,
            )
            continue
        if stopped is not True:
            logger.error("RUNTIME_WORKER_STOP_TIMEOUT worker=%s", worker_name)


app = FastAPI(title="IAO API", version="11.2.0", lifespan=_runtime_lifespan)
_service = None
_federation_node = None
_federation_lock = threading.Lock()
_federation_worker_status = {"autojoin": False, "discovery": False, "external_network": False}
_service_lock = threading.Lock()

_allowed_origins = [
    item.strip().rstrip("/")
    for item in os.environ.get(
        "IAO_CORS_ORIGINS",
        "",
    ).split(",")
    if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-IAO-Device-Proof"],
)


def _get_device_authority():
    """Return the authority owned by the process-wide OmegaService."""
    authority = _get_service().device_authority
    if authority is None:
        raise RuntimeError("DEVICE_AUTHORITY_UNAVAILABLE")
    return authority


async def _read_bounded_service_body(request: Request):
    """Read API bodies incrementally and reject invalid or oversized requests."""
    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length)
        except ValueError:
            return None, JSONResponse(
                status_code=400,
                content={"error": "INVALID_CONTENT_LENGTH", "correlation_id": uuid.uuid4().hex},
            )
        if declared_length < 0:
            return None, JSONResponse(
                status_code=400,
                content={"error": "INVALID_CONTENT_LENGTH", "correlation_id": uuid.uuid4().hex},
            )
        if declared_length > MAX_BODY:
            return None, JSONResponse(
                status_code=413,
                content={"error": "PAYLOAD_TOO_LARGE", "correlation_id": uuid.uuid4().hex},
            )
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > MAX_BODY:
            return None, JSONResponse(
                status_code=413,
                content={"error": "PAYLOAD_TOO_LARGE", "correlation_id": uuid.uuid4().hex},
            )
    if raw_length is not None and len(chunks) != declared_length:
        return None, JSONResponse(
            status_code=400,
            content={"error": "INCOMPLETE_BODY", "correlation_id": uuid.uuid4().hex},
        )
    return bytes(chunks), None


def _service_response(status: int, payload: dict):
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    correlation_id = payload.get("correlation_id")
    if isinstance(correlation_id, str):
        headers["X-Correlation-ID"] = correlation_id
    allowed = payload.get("allowed_methods")
    if status == 405 and isinstance(allowed, list) and all(
        isinstance(item, str) for item in allowed
    ):
        headers["Allow"] = ", ".join(allowed)
    return JSONResponse(status_code=status, content=payload, headers=headers)


def _method_not_allowed(allowed_methods: tuple[str, ...]):
    correlation_id = uuid.uuid4().hex
    return JSONResponse(
        status_code=405,
        content={
            "error": "METHOD_NOT_ALLOWED",
            "allowed_methods": list(allowed_methods),
            "correlation_id": correlation_id,
        },
        headers={
            "Allow": ", ".join(allowed_methods),
            "X-Correlation-ID": correlation_id,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def _device_json(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _ensure_federation(service):
    """Create the local federation identity and start bounded discovery workers once."""
    global _federation_node
    with _federation_lock:
        if _federation_node is not None:
            return _federation_node
        state_dir = Path(os.environ.get("IAO_STATE_DIR", "/var/lib/iao"))
        from omega.federation import Node
        from omega.federation_identity import load_or_create_key
        from omega.federation_ledger import FederationLedger

        key = load_or_create_key(state_dir / "federation-node-ed25519.key")
        ledger = FederationLedger(
            state_dir / "federation-audit.jsonl",
            state_dir / "federation-audit.key",
        )
        node = Node(
            service.store,
            service.registry,
            key=key,
            peer_store_path=state_dir / "federation-peers.json",
            audit_fn=ledger.append,
        )
        ledger.append(
            "system", "FEDERATION_NODE_READY", node.node_id,
            capabilities=sorted(node.served),
        )
        _federation_node = node

        starters = (
            ("autojoin", "omega.federation_autojoin", "start_federation_autojoin"),
            ("discovery", "omega.federation_discovery", "start_federation_discovery"),
            ("external_network", "omega.external_network", "start_external_network"),
        )
        for status_key, module_name, function_name in starters:
            try:
                module = __import__(module_name, fromlist=[function_name])
                starter = getattr(module, function_name)
                if status_key == "external_network":
                    started = starter(state_dir / "external-network", fed_node=node)
                elif status_key == "autojoin":
                    started = starter(node, state_dir)
                else:
                    started = starter(state_dir)
                _federation_worker_status[status_key] = started is not False
            except Exception as exc:
                _federation_worker_status[status_key] = False
                try:
                    service.store.audit(
                        "system", "FEDERATION_WORKER_START_FAILED",
                        status_key, error_type=type(exc).__name__,
                    )
                except Exception:
                    pass
        return node


def _get_federation_node():
    service = _get_service()
    return _ensure_federation(service)


def _get_service():
    """Create the persistent service and activate federation discovery in this API process."""
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                token_key = os.environ.get("OMEGA_DEV_TOKEN_KEY", "")
                audit_key = os.environ.get("AUDIT_HMAC_KEY", "")
                try:
                    validate_persistent_keys(token_key, audit_key)
                except ValueError:
                    raise RuntimeError("PERSISTENT_AUTH_AND_AUDIT_KEYS_REQUIRED") from None
                from omega.server import build_service

                state_dir = Path(os.environ.get("IAO_STATE_DIR", "/var/lib/iao"))
                corpus_dir = Path(os.environ.get("IAO_CORPUS_DIR", "/app/knowledge"))
                _service = build_service(state_dir, token_key, corpus_dir)
    service = _service
    try:
        _ensure_federation(service)
    except Exception as exc:
        # Federation degradation must not take down local sessions or chat.
        try:
            service.store.audit(
                "system", "FEDERATION_INITIALIZATION_FAILED",
                "local", error_type=type(exc).__name__,
            )
        except Exception:
            pass
    return service



def _federation_json(status: int, payload: dict):
    return JSONResponse(
        status_code=status,
        content=payload,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


async def _federation_body(request: Request):
    if request.headers.get("transfer-encoding"):
        return None, _federation_json(400, {"error": "INVALID_TRANSFER_ENCODING"})
    raw_length = request.headers.get("content-length")
    try:
        length = int(raw_length) if raw_length is not None else -1
    except ValueError:
        length = -1
    from omega.federation import MAX_MSG
    if length < 0:
        return None, _federation_json(411, {"error": "CONTENT_LENGTH_REQUIRED"})
    if length > MAX_MSG:
        return None, _federation_json(413, {"error": "PAYLOAD_TOO_LARGE"})
    body = await request.body()
    if len(body) != length:
        return None, _federation_json(400, {"error": "INCOMPLETE_BODY"})
    return body, None


@app.get("/fed/v1/contract")
def federation_contract():
    try:
        node = _get_federation_node()
        return _federation_json(200, node.contract_for_self(sorted(node.served)))
    except Exception:
        return _federation_json(503, {"error": "FEDERATION_UNAVAILABLE"})


@app.get("/fed/v1/publication")
def federation_publication():
    try:
        node = _get_federation_node()
        origin = os.environ.get("IAO_FEDERATION_PUBLIC_ORIGIN", "").strip().rstrip("/")
        if os.environ.get("IAO_FEDERATION_PUBLIC_PEERING", "").lower() != "true" or not origin:
            return _federation_json(404, {"error": "PUBLIC_PEERING_NOT_OFFERED"})
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password
                or parsed.port not in (None, 443)
                or parsed.path or parsed.query or parsed.fragment):
            return _federation_json(503, {"error": "PUBLIC_PEERING_CONFIG_INVALID"})
        publication = node.identity_publication(
            origin + "/fed/v1/message",
            capabilities=sorted(node.served),
            consent=True,
        )
        return _federation_json(200, publication)
    except Exception:
        return _federation_json(503, {"error": "FEDERATION_UNAVAILABLE"})


@app.get("/fed/v1/identity")
def federation_identity():
    try:
        return _federation_json(200, _get_federation_node().identity_document())
    except Exception:
        return _federation_json(503, {"error": "FEDERATION_UNAVAILABLE"})


@app.post("/fed/v1/handshake")
async def federation_handshake(request: Request):
    try:
        node = _get_federation_node()
        body, error = await _federation_body(request)
        if error is not None:
            return error
        status, payload = node.answer_challenge(body)
        return _federation_json(status, payload)
    except Exception:
        return _federation_json(503, {"error": "FEDERATION_UNAVAILABLE"})


@app.post("/fed/v1/message")
async def federation_message(request: Request):
    try:
        node = _get_federation_node()
        body, error = await _federation_body(request)
        if error is not None:
            return error
        status, payload = node.handle(body)
        return _federation_json(status, payload)
    except Exception:
        return _federation_json(503, {"error": "FEDERATION_UNAVAILABLE"})


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.api_route("/health/ready", methods=["GET", "POST", "PUT", "DELETE"])
def ready(request: Request):
    if request.method != "GET":
        return _method_not_allowed(("GET",))
    try:
        service = _get_service()
        status, payload = service.handle("GET", "/health/ready", {}, b"")
    except Exception:
        return _service_response(
            503,
            {
                "status": "not_ready",
                "reason": "PERSISTENT_RUNTIME_UNAVAILABLE",
                "correlation_id": uuid.uuid4().hex,
            },
        )
    if status != 200 or payload.get("status") == "not_ready":
        payload["status"] = "not_ready"
        return _service_response(503, payload)

    # Local dependency checks are not proof of production readiness.
    # Worker start flags are not heartbeats or functional health checks.
    worker_checks = {
        name: ("start_reported_unverified" if started else "not_started_or_unavailable")
        for name, started in _federation_worker_status.items()
    }
    model_state = (
        "configured_unverified" if service.model is not None else "not_configured"
    )
    payload["status"] = "degraded"
    payload["readiness_scope"] = "local_infrastructure_only"
    payload["production_ready"] = False
    payload["checks"] = {
        **payload.get("checks", {}),
        "federation_workers": worker_checks,
        "model_adapter": model_state,
    }
    payload["production_gates"] = {
        "device_identity_verification": "integrated_read_only",
        "operator_session_association": "api_available_read_only",
        "operator_root_bootstrap": "out_of_band_configurable_not_verified",
        "privileged_device_commands": "disabled",
        "identity_provider": "dev_hmac_not_oidc",
        "independent_federation": "not_verified",
        "model_provider": model_state,
    }
    return _service_response(200, payload)

@app.api_route("/v1/device/enroll", methods=["GET", "POST", "PUT", "DELETE"])
async def device_enroll(request: Request):
    return await _device_service_route(request, "/v1/device/enroll")


@app.api_route("/v1/device/challenge", methods=["GET", "POST", "PUT", "DELETE"])
async def device_challenge(request: Request):
    return await _device_service_route(request, "/v1/device/challenge")


@app.api_route("/v1/device/command", methods=["GET", "POST", "PUT", "DELETE"])
async def device_command(request: Request):
    return await _device_service_route(request, "/v1/device/command")


async def _device_service_route(request: Request, path: str):
    """Keep device endpoints behind the same authenticated service boundary."""
    if request.method != "POST":
        return _method_not_allowed(("POST",))
    try:
        service = _get_service()
        body, body_error = await _read_bounded_service_body(request)
        if body_error is not None:
            return body_error
        headers = {key.lower(): value for key, value in request.headers.items()}
        status, payload = service.handle("POST", path, headers, body)
        return _service_response(status, payload)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"error": "PERSISTENT_RUNTIME_UNAVAILABLE", "correlation_id": uuid.uuid4().hex},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )


@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def api_v1(path: str, request: Request):
    """Pass the complete v1 API through the audited persistent service."""
    try:
        service = _get_service()
        body, body_error = await _read_bounded_service_body(request)
        if body_error is not None:
            return body_error
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
        return _service_response(status, payload)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"error": "PERSISTENT_RUNTIME_UNAVAILABLE", "correlation_id": uuid.uuid4().hex},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"error": "IAO_SERVICE_UNAVAILABLE", "correlation_id": uuid.uuid4().hex},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
