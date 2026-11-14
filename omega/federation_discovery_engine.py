import os
import json
import urllib.request
import urllib.error

MEMORY_FILE = "nodes_memory.json"

class DiscoveryEngine:
    def __init__(self):
        self.memory = self._load_memory()
        # Semillas conocidas para empezar
        self.seed_nodes = {
            "Pollinations": "https://text.pollinations.ai/",
            "DuckDuckGo": "https://api.duckduckgo.com/?q=test&format=json",
            "Tavily": "https://api.tavily.com/search"
        }

    def _load_memory(self):
        if os.path.exists(MEMORY_FILE):
            try:
                with open(MEMORY_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_memory(self):
        try:
            with open(MEMORY_FILE, "w") as f:
                json.dump(self.memory, f, indent=4)
        except Exception as e:
            print(f"[IAO DISCOVERY] Error guardando memoria: {e}")

    def _test_node(self, url: str) -> bool:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IAO-Crawler"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status == 200
        except:
            return False

    def hunt_new_nodes(self):
        """IAO busca y prueba nuevas IAs en la red."""
        print("[IAO DISCOVERY] Iniciando cacería de nuevos nodos...")
        
        # 1. Probar semillas conocidas
        for name, url in self.seed_nodes.items():
            if name not in self.memory:
                if self._test_node(url):
                    self.memory[name] = {"url": url, "status": "active"}
                    print(f"[IAO DISCOVERY] Nuevo nodo asimilado: {name}")
        
        # 2. Fase futura: Aquí IAO podría hacer peticiones a directorios de APIs
        # o leer respuestas de Tavily buscando "free AI API endpoints"

        self._save_memory()
        return len(self.memory)

    def get_active_nodes(self):
        return {k: v for k, v in self.memory.items() if v.get("status") == "active"}

discovery = DiscoveryEngine()
