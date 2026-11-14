import os
import json
import urllib.request
import urllib.error
import urllib.parse

class AutonomousHub:
    def __init__(self):
        self.registry = {
            "deepseek": {"status": "fallback", "type": "reasoning"},
            "tavily": {"status": "active", "type": "search"},
            "pollinations": {"status": "active", "type": "generation"},
        }

    def _buscar_web(self, pregunta: str) -> str:
        """IAO usa el nodo de búsqueda (Tavily)."""
        print("[IAO HUB] Solicitando datos al nodo de búsqueda (Tavily)...")
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
            
            contexto = "Resultados de búsqueda:\n"
            for i, r in enumerate(resultados, 1):
                contexto += f"{i}. {r.get('title', '')}\n   {r.get('content', '')[:300]}\n\n"
            return contexto
        except Exception as e:
            print(f"[IAO HUB] Error en Tavily: {e}")
            return ""

    def _redactar(self, pregunta: str, contexto: str) -> str:
        """IAO usa el nodo de redacción (Pollinations)."""
        print("[IAO HUB] Solicitando redacción al nodo Pollinations...")
        try:
            prompt = f"Responde a la pregunta de forma concisa usando esta información:\n{contexto}\n\nPregunta: {pregunta}"
            url = f"https://text.pollinations.ai/{urllib.parse.quote(prompt)}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode('utf-8')
        except Exception as e:
            print(f"[IAO HUB] Error en Pollinations: {e}")
            return f"[Respuesta de respaldo]: {contexto}"

    def delegate(self, prompt: str) -> str:
        """IAO orquesta la tarea."""
        print(f"[IAO HUB] Procesando: {prompt}")
        
        # 1. Buscar en la web
        contexto = self._buscar_web(prompt)
        
        # 2. Redactar la respuesta (incluso si no hay contexto, Pollinations responde con su conocimiento)
        respuesta = self._redactar(prompt, contexto if contexto else "No hay contexto web disponible.")
        
        return respuesta

hub = AutonomousHub()
