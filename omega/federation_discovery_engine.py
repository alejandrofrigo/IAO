import os
import json
import urllib.request
import urllib.error

MEMORY_FILE = "nodes_memory.json"

class DiscoveryEngine:
    def __init__(self):
        self.memory = self._load_memory()
        # Semillas conocidas con su método de prueba correcto
        self.seed_nodes = {
            "Pollinations": {"url": "https://text.pollinations.ai/", "method": "GET"},
            "Tavily": {"url": "https://api.tavily.com/search", "method": "POST"},
            "DuckDuckGo": {"url": "https://api.duckduckgo.com/?q=test&format=json", "method": "GET"}
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

    def _test_node(self, name: str, info: dict) -> bool:
        try:
            if info["method"] == "GET":
                req = urllib.request.Request(info["url"], headers={"User-Agent": "IAO-Crawler"})
            else:
                # Prueba POST para Tavily
                payload = json.dumps({"query": "test", "max_results": 1}).encode('utf-8')
                req = urllib.request.Request(
                    info["url"],
                    data=payload,
                    headers={"Content-Type": "application/json", "X-Tavily-Access-Mode": "keyless"},
                    method="POST"
                )
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    return True
        except Exception as e:
            print(f"[IAO DISCOVERY] Fallo al probar {name}: {e}")
        return False

    def hunt_new_nodes(self):
        """IAO busca y prueba nuevas IAs en la red."""
        print("[IAO DISCOVERY] Iniciando cacería de nuevos nodos...")
        
        for name, info in self.seed_nodes.items():
            if name not in self.memory:
                if self._test_node(name, info):
                    self.memory[name] = {"url": info["url"], "status": "active"}
                    print(f"[IAO DISCOVERY] ¡Nuevo nodo asimilado! -> {name}")
                else:
                    print(f"[IAO DISCOVERY] {name} no respondió a la prueba.")
        
        self._save_memory()
        return len(self.memory)

    def get_active_nodes(self):
        return {k: v for k, v in self.memory.items() if v.get("status") == "active"}

discovery = DiscoveryEngine()
