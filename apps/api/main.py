from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_autonomous_hub import hub
from omega.federation_assimilation_engine import engine

app = FastAPI(title="IAO - Hub Central Autónomo", version="4.0.0")

@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}

@app.get("/v1/federation/nodes")
def get_nodes():
    """IAO muestra qué IAs ha asimilado de forma autónoma."""
    return {
        "asimilated_capacity": engine.get_capacity(),
        "nodes": engine.asimilated_nodes
    }

@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    try:
        user_message = getattr(request, "message", None) or getattr(request, "query", None) or getattr(request, "text", None)
        if not user_message:
            raise HTTPException(status_code=400, detail="Falta el mensaje.")

        respuesta_final = hub.delegate(user_message)

        conv_id = getattr(request, "conversation_id", "default-conv-iao")
        return ChatResponse(
            status="success",
            reply=f"[IAO HUB AUTÓNOMO]\n{respuesta_final}",
            conversation_id=conv_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el Hub: {str(e)}")
