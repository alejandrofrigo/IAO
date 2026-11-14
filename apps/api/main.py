from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_orchestrator_core import orquestador

app = FastAPI(title="IAO - Nodo Central de Federación", version="1.0.0")

@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}

@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    try:
        user_message = getattr(request, "message", None) or getattr(request, "query", None) or getattr(request, "text", None)
        if not user_message:
            raise HTTPException(status_code=400, detail="Falta el mensaje.")

        respuesta_final = orquestador.coordinar(user_message)
        conv_id = getattr(request, "conversation_id", "default-conv-iao")

        return ChatResponse(
            status="success",
            reply=respuesta_final,
            conversation_id=conv_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en la Federación: {str(e)}")
