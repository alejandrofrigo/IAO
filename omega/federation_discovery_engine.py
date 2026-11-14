import os
import json
import urllib.request
import urllib.error

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "alejandrofrigo/IAO"
GITHUB_PATH = "nodes_memory.json"
GITHUB_BRANCH = "iao-repair-http405-20261028T113227Z"

class DiscoveryEngine:
    def __init__(self):
        self.memory = self._load_memory_remote()
        if "Tavily" not in self.memory:
            self.memory["Tavily"] = {"url": "https://api.tavily.com/search", "status": "active"}
        if "Pollinations" not in self.memory:
            self.memory["Pollinations"] = {"url": "https://text.pollinations.ai/", "status": "active"}

        self.seed_nodes = {
            "HuggingFace": {"url": "https://api-inference.huggingface.co/models/gpt2", "method": "POST"},
            "OpenRouter": {"url": "https://openrouter.ai/api/v1/models", "method": "GET"},
            "DuckDuckGo": {"url": "https://api.duckduckgo.com/?q=test&format=json", "method": "GET"}
        }

    def _load_memory_remote(self):
        if not GITHUB_TOKEN: return {}
        url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_PATH}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except Exception:
            return {}

    def _save_memory_remote(self):
        if not GITHUB_TOKEN: return
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
        sha = None
        try:
            req_get = urllib.request.Request(url, headers={"Authorization": f"token {GITHUB_TOKEN}"})
            with urllib.request.urlopen(req_get) as resp:
                sha = json.loads(resp.read().decode('utf-8')).get("sha")
        except Exception: pass

        content = json.dumps(self.memory, indent=4)
        payload = {
            "message": "IAO Auto-Update: Memoria persistente v7.2",
            "content": __import__('base64').b64encode(content.encode('utf-8')).decode('utf-8'),
            "branch": GITHUB_BRANCH
        }
        if sha: payload["sha"] = sha

        try:
            req_put = urllib.request.Request(
                url, data=json.dumps(payload).encode('utf-8'),
                headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"},
                method="PUT"
            )
            with urllib.request.urlopen(req_put) as resp:
                print("[IAO DISCOVERY] Memoria guardada en GitHub.")
        except Exception as e:
            print(f"[IAO DISCOVERY] Error guardando en GitHub: {e}")

    def _test_node(self, name: str, info: dict) -> bool:
        try:
            if info["method"] == "GET":
                req = urllib.request.Request(info["url"], headers={"User-Agent": "IAO-Crawler"})
            else:
                payload = json.dumps({"inputs": "test"}).encode('utf-8')
                req = urllib.request.Request(
                    info["url"], data=payload,
                    headers={"Content-Type": "application/json", "User-Agent": "IAO-Crawler"},
                    method="POST"
                )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201)
        except Exception as e:
            print(f"[IAO DISCOVERY] {name} no disponible: {e}")
            return False

    def hunt_new_nodes(self):
        print("[IAO DISCOVERY] Iniciando cacería de IAs en Internet...")
        cambios = False
        
        if "Tavily" not in self.memory or "Pollinations" not in self.memory:
            cambios = True

        for name, info in self.seed_nodes.items():
            if name not in self.memory:
                if self._test_node(name, info):
                    self.memory[name] = {"url": info["url"], "status": "active"}
                    print(f"[IAO DISCOVERY] ¡Nodo asimilado! -> {name}")
                    cambios = True

        if cambios:
            self._save_memory_remote()
            
        return len(self.memory)

    def get_active_nodes(self):
        return {k: v for k, v in self.memory.items() if v.get("status") == "active"}

discovery = DiscoveryEngine()
