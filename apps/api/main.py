from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_autonomous_hub import hub
from omega.federation_discovery_engine import discovery
from omega.federation_registry_api import registry

app = FastAPI(title="IAO - Hub Central Federado", version="11.0.0")

@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}

@app.get("/v1/federation/manifest")
def get_manifest():
    """IAO se presenta al mundo."""
    return {
        "protocol": "IAO-FEDERATION-v1",
        "description": "Únete a la primera red federada de IAs autónomas.",
        "benefits": [
            "Tráfico enrutado a tu API.",
            "Caché compartida de respuestas.",
            "Validación automática de tu nodo."
        ],
        "registration_endpoint": "/v1/federation/register",
        "current_nodes": len(discovery.get_active_nodes()),
        "status": "operational"
    }

@app.post("/v1/federation/register")
def register_node(data: dict):
    """Otra IA se registra en la red."""
    url = data.get("url")
    name = data.get("name", "ExternalNode")
    capability = data.get("capability", "general")
    
    if not url:
        raise HTTPException(status_code=400, detail="Falta la URL del nodo.")
    
    result = registry.register_external_node(url, name, capability)
    return {"message": result}

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
