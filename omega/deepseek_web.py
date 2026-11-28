import os
import json
import urllib.request
import urllib.error
import urllib.parse

def _buscar_tavily(pregunta: str) -> str:
    try:
        payload = json.dumps({"query": pregunta, "max_results": 3}).encode('utf-8')
        req = urllib.request.Request(
            "https://api.tavily.com/search",
            data=payload,
            headers={"Content-Type": "application/json", "X-Tavily-Access-Mode": "keyless"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        resultados = data.get("results", [])
        if not resultados:
            return ""
        contexto = "Resultados de búsqueda (Tavily):\n"
        for i, r in enumerate(resultados, 1):
            contexto += f"{i}. {r.get('title', '')}\n   {r.get('content', '')[:300]}\n\n"
        return contexto
    except Exception as exc:
        print(f"[TAVILY FAIL] {type(exc).__name__}")
        return ""

def _buscar_duckduckgo(pregunta: str) -> str:
    try:
        url = f"https://api.duckduckgo.com/?q={urllib.parse.quote(pregunta)}&format=json&no_html=1"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        
        contexto = "Resultados (DuckDuckGo):\n"
        if data.get("AbstractText"):
            contexto += f"Resumen: {data['AbstractText']}\n"
        
        for topic in data.get("RelatedTopics", [])[:3]:
            if "Text" in topic:
                contexto += f"- {topic['Text']}\n"
        
        if len(contexto) > 50:
            return contexto
        return ""
    except Exception as exc:
        print(f"[DUCKDUCKGO FAIL] {type(exc).__name__}")
        return ""

def _redactar_gratis(pregunta: str, contexto: str) -> str:
    """Redactor gratuito usando Pollinations AI."""
    try:
        prompt = f"Eres IAO, un asistente inteligente. Responde de forma concisa y natural usando SOLO esta información si es útil:\n\n{contexto}\n\nPregunta: {pregunta}"
        url = f"https://text.pollinations.ai/{urllib.parse.quote(prompt)}"
        
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode('utf-8')
    except Exception as exc:
        print(f"[POLLINATIONS FAIL] {type(exc).__name__}")
        return f"[Respuesta de respaldo]: {contexto}" if contexto else ""

def obtener_respuesta_internet(pregunta: str) -> str:
    # 1. DeepSeek (pago)
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if api_key:
        try:
            req = urllib.request.Request(
                "https://api.deepseek.com/v1/tools/search",
                data=json.dumps({"query": pregunta, "count": 3}).encode('utf-8'),
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                search_data = json.loads(response.read().decode('utf-8'))
            resultados = search_data.get("results", [])
            if resultados:
                contexto = "Resultados (DeepSeek):\n"
                for i, r in enumerate(resultados, 1):
                    contexto += f"{i}. {r.get('title', '')}\n   {r.get('summary', '')}\n\n"
                return _redactar_gratis(pregunta, contexto)
        except Exception as exc:
            print(f"[DEEPSEEK FAIL] {type(exc).__name__}")

    # 2. Tavily + Pollinations
    print("[FEDERATION] Intentando Tavily...")
    contexto = _buscar_tavily(pregunta)
    if contexto:
        return _redactar_gratis(pregunta, contexto)

    # 3. DuckDuckGo + Pollinations
    print("[FEDERATION] Tavily falló. Intentando DuckDuckGo...")
    contexto = _buscar_duckduckgo(pregunta)
    if contexto:
        return _redactar_gratis(pregunta, contexto)

    # 4. Último recurso: Pollinations sin contexto (responde con su conocimiento general)
    print("[FEDERATION] Todos los buscadores fallaron. Usando conocimiento general de IAO...")
    return _redactar_gratis(pregunta, "No se pudo acceder a internet, responde con tu conocimiento general.")
