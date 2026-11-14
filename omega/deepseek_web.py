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
        if not resultados: return ""
        contexto = "Resultados de búsqueda web:\n"
        for i, r in enumerate(resultados, 1):
            contexto += f"{i}. {r.get('title', '')}\n   {r.get('content', '')[:300]}\n\n"
        return contexto
    except Exception as e:
        print(f"[TAVILY FAIL] {e}")
        return ""

def _redactar_gratis(pregunta: str, contexto: str) -> str:
    """
    Redactor de respaldo usando Pollinations.ai (Gratis, sin API Key).
    """
    print("[FEDERATION] Intentando redactar con Pollinations (Gratis)...")
    try:
        prompt = f"Eres el módulo de búsqueda federada de IAO. Responde a la pregunta de forma concisa y natural usando SOLO esta información:\n\n{contexto}\n\nPregunta: {pregunta}"
        url = f"https://text.pollinations.ai/{urllib.parse.quote(prompt)}"
        
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            respuesta = resp.read().decode('utf-8')
            return respuesta
    except Exception as e:
        print(f"[POLLINATIONS FAIL] {e}")
        # Si Pollinations falla, intentamos con Groq (por si acaso la clave sigue viva)
        groq_key = os.getenv("MODEL_API_KEY")
        if groq_key and groq_key.startswith("gsk_"):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1")
                completion = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": "Responde de forma concisa usando solo el contexto."},
                        {"role": "user", "content": f"Pregunta: {pregunta}\n\n{contexto}"}
                    ],
                    stream=False,
                    timeout=10
                )
                return completion.choices[0].message.content
            except Exception as e_groq:
                print(f"[GROQ FAIL] {repr(e_groq)}")
        
        # Último recurso: devolver el contexto crudo
        return f"[Respuesta de respaldo - contexto crudo]:\n{contexto}"

def obtener_respuesta_internet(pregunta: str) -> str:
    # 1. Intentar con DeepSeek (si tuvieras saldo)
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
        except Exception as e:
            print(f"[DEEPSEEK FAIL] {e}")

    # 2. Tavily (Gratis) + Redacción con Pollinations
    print("[FEDERATION] Buscando en Internet con Tavily...")
    contexto = _buscar_tavily(pregunta)
    if contexto:
        return _redactar_gratis(pregunta, contexto)

    return "[Error IAO]: No se pudo obtener información de la web en este momento."
