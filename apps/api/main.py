from fastapi import FastAPI, HTTPException
from apps.api.schemas import ChatRequest, ChatResponse
from omega.federation_autonomous_hub import hub
from omega.federation_discovery_engine import discovery

app = FastAPI(title="IAO - Hub Central Federado", version="10.0.0")

@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}

# --- EL INCENTIVO: MANIFIESTO DE FEDERACIÓN ---
@app.get("/v1/federation/manifest")
def get_manifest():
    """IAO se presenta al mundo y ofrece sus beneficios."""
    return {
        "protocol": "IAO-FEDERATION-v1",
        "description": "Únete a la primera red federada de IAs autónomas del mundo.",
        "benefits": [
            "Tráfico enrutado: IAO enviará consultas a tu API según tu especialidad.",
            "Caché compartida: Accede a respuestas previas de otras IAs sin costo de tokens.",
            "Validación: IAO probará tu API y la etiquetará como 'segura'.",
            "Sin comisiones: Es una red libre y descentralizada."
        ],
        "registration_endpoint": "/v1/federation/register",
        "current_nodes": len(discovery.get_active_nodes()),
        "network_status": "operational"
    }

# --- EL REGISTRO: CÓMO SE UNEN LAS IAs ---
@app.post("/v1/federation/register")
def register_node(data: dict):
    """Otra IA envía su URL y se une a la red."""
    url = data.get("url")
    name = data.get("name", f"External_Node_{len(discovery.memory)}")
    capability = data.get("capability", "general")
    
    if not url:
        raise HTTPException(status_code=400, detail="Falta la URL del nodo.")
    
    # IAO prueba el nodo antes de aceptarlo
    from omega.federation_node_judge import judge
    veredicto = judge.evaluate_node(url)
    
    if veredicto["verdict"] == "approve":
        discovery.memory[name] = {
            "url": url,
            "method": "GET",
            "status": "active",
            "format": veredicto["format"],
            "capability": capability,
            "latency": veredicto["latency"],
            "joined_by": "external_registration"
        }
        discovery._save_memory_remote()
        return {"status": "accepted", "message": f"Nodo {name} unido a la federación IAO."}
    else:
        return {"status": "rejected", "reason": veredicto["reason"]}

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
