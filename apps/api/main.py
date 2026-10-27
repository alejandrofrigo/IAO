from fastapi import FastAPI, HTTPException

from apps.api.schemas import ChatRequest, ChatResponse

app = FastAPI(title="IAO", version="0.1.0")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready() -> dict[str, str]:
    # Process-only check. Replace with DB/migration checks before production promotion.
    return {"status": "ready", "checks": "process-only"}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    # The baseline does not pretend that a model or persistent store is configured.
    raise HTTPException(
        status_code=503,
        detail={
            "code": "MODEL_ADAPTER_NOT_CONFIGURED",
            "conversation_id": request.conversation_id,
        },
    )
