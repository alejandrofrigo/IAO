import os
import json
import urllib.request
import urllib.error
import urllib.parse

class FederationOrchestrator:
    def __init__(self):
        self.deepseek_key = os.getenv("DEEPSEEK_API_KEY")
        self.deepseek_url = "https://api.deepseek.com/v1/chat/completions"

    def _llamar_deepseek(self, pregunta: str) -> str:
        """DeepSeek actúa como el Organizador Principal (si tiene saldo)."""
        if not self.deepseek_key:
            return ""
        
        payload = json.dumps({
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "Eres el Nodo Organizador Central de la Federación IAO. Coordina y responde de forma concisa."},
                {"role": "user", "content": pregunta}
            ],
            "stream": False
        }).encode('utf-8')

        try:
            req = urllib.request.Request(
                self.deepseek_url,
                data=payload,
                headers={"Authorization": f"Bearer {self.deepseek_key}", "Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data['choices'][0]['message']['content']
        except Exception as e:
            print(f"[ORQUESTADOR] DeepSeek no disponible: {e}. Delegando a la red federada...")
            return ""

    def coordinar(self, pregunta: str) -> str:
        # 1. Intentar con DeepSeek (Organizador)
        respuesta_deepseek = self._llamar_deepseek(pregunta)
        if respuesta_deepseek:
            return f"[Nodo Organizador: DeepSeek]\n{respuesta_deepseek}"

        # 2. Si DeepSeek falla (sin saldo), usar la red de búsqueda (Tavily/Pollinations)
        try:
            from omega.deepseek_web import obtener_respuesta_internet
            respuesta_web = obtener_respuesta_internet(pregunta)
            return f"[Nodo de Búsqueda Federada]\n{respuesta_web}"
        except Exception as e:
            print(f"[ORQUESTADOR] Error en la red de búsqueda: {e}")

        # 3. Último recurso
        try:
            url = f"https://text.pollinations.ai/{urllib.parse.quote(pregunta)}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return f"[Nodo de Emergencia]\n{resp.read().decode('utf-8')}"
        except:
            return "La federación está experimentando problemas de conexión en todos sus nodos."

# Instancia global
orquestador = FederationOrchestrator()
