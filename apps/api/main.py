"""Production API surface. Unverified federation and unauthenticated chat fail closed."""
from __future__ import annotations

import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from omega.adapters.model import ModelError, adapter_from_env
from apps.api.schemas import ChatRequest, ChatResponse

app = FastAPI(title="IAO API", version="11.1.0")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready() -> dict[str, str]:
    model_configured = bool(
        os.environ.get("MODEL_PROVIDER")
        and os.environ.get("MODEL_ID")
        and os.environ.get("MODEL_API_KEY")
    )
    return {
        "status": "degraded",
        "federation": "not_verified",
        "model_provider": "configured" if model_configured else "not_configured",
        "chat_authorization": (
            "configured" if os.environ.get("IAO_API_BEARER_TOKEN") else "not_configured"
        ),
    }


@app.get("/v1/federation/manifest")
def get_manifest() -> dict:
    """Publish only capabilities whose operation has actually been verified."""
    return {
        "protocol": "IAO-FEDERATION-v1",
        "status": "development",
        "federation_status": "not_verified",
        "registration_endpoint": "/v1/federation/register",
        "registration_enabled": False,
        "capabilities": [],
    }


@app.post("/v1/federation/register")
def register_node() -> None:
    # Do not fetch caller-supplied URLs: admission needs signed identity,
    # challenge-response, capability policy and controlled egress first.
    raise HTTPException(
        status_code=503,
        detail="Federation registration is disabled pending authenticated admission.",
    )


@app.post("/v1/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    authorization: str | None = Header(default=None),
) -> ChatResponse:
    expected = os.environ.get("IAO_API_BEARER_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Chat authorization is not configured.")
    supplied = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        adapter = adapter_from_env(dict(os.environ))
        if adapter is None:
            raise HTTPException(status_code=503, detail="No model provider is configured.")
        reply = adapter.chat([{"role": "user", "content": request.message}])
        return ChatResponse(
            status="success",
            reply=reply,
            conversation_id=request.conversation_id,
            authority="NON_AUTHORITATIVE_MODEL_OUTPUT",
        )
    except ModelError:
        raise HTTPException(status_code=503, detail="The configured model provider is unavailable.") from None
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="IAO chat engine is unavailable.") from None
