from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_autonomous_hub import hub
from omega.federation_discovery_engine import discovery

app = FastAPI(title="IAO - API", version="11.0.0")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready() -> dict[str, str]:
    return {
        "status": "degraded",
        "federation": "not_verified",
        "model_provider": "not_verified",
    }


@app.get("/v1/federation/manifest")
def get_manifest() -> dict:
    """Public capability manifest; never claim an unverified federation."""
    return {
        "protocol": "IAO-FEDERATION-v1",
        "status": "development",
        "federation_status": "not_verified",
        "known_registry_entries": len(discovery.memory),
        "registration_endpoint": "/v1/federation/register",
        "registration_enabled": False,
    }


@app.post("/v1/federation/register")
def register_node() -> None:
    # The former implementation fetched caller-supplied URLs, creating an
    # unauthenticated SSRF surface. Registration stays closed until signed
    # identity, challenge-response, capability policy and egress controls exist.
    raise HTTPException(
        status_code=503,
        detail="Federation registration is disabled pending authenticated admission.",
    )


@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    try:
        respuesta_final = hub.delegate(request.message)
        return ChatResponse(
            status="success",
            reply=f"[IAO]\n{respuesta_final}",
            conversation_id=request.conversation_id,
        )
    except Exception:
        # Do not expose internal exception details, paths or configuration.
        raise HTTPException(status_code=503, detail="IAO chat engine is temporarily unavailable.")
