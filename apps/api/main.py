from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_autonomous_hub import hub

app = FastAPI(title="IAO - Hub Central Autónomo", version="3.0.0")

@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}

@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    try:
        user_message = getattr(request, "message", None) or getattr(request, "query", None) or getattr(request, "text", None)
        if not user_message:
            raise HTTPException(status_code=400, detail="Falta el mensaje.")

        # IAO escanea y delega
        hub.scan_and_register()
        
        # Decide la tarea basándose en el mensaje
        task_type = "reasoning" if "?" in user_message else "search"
        respuesta_final = hub.delegate(task_type, user_message)

        conv_id = getattr(request, "conversation_id", "default-conv-iao")
        return ChatResponse(
            status="success",
            reply=f"[IAO HUB AUTÓNOMO]\n{respuesta_final}",
            conversation_id=conv_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el Hub: {str(e)}")
