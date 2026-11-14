import os
import json
import urllib.request
import urllib.error
import re
import datetime
from omega.universal_connector import connector

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "alejandrofrigo/IAO"
GITHUB_PATH = "nodes_memory.json"
GITHUB_BRANCH = "iao-repair-http405-20261028T113227Z"

class DiscoveryEngine:
    def __init__(self):
        self.memory = self._load_memory_remote()
        if "Tavily" not in self.memory:
            self.memory["Tavily"] = {"url": "https://api.tavily.com/search", "method": "POST", "status": "active", "format": "json", "auth": "none", "lang": "en"}
        if "Pollinations" not in self.memory:
            self.memory["Pollinations"] = {"url": "https://text.pollinations.ai/", "method": "GET", "status": "active", "format": "text", "auth": "none", "lang": "en"}

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
            "message": f"IAO Universal Expansion: {len(self.memory)} nodos",
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
                print("[IAO DISCOVERY] Memoria universal guardada en GitHub.")
        except Exception as e:
            print(f"[IAO DISCOVERY] Error guardando en GitHub: {e}")

    def _discover_from_public_apis(self):
        """Extrae URLs del repositorio public-apis en GitHub."""
        try:
            url_readme = "https://raw.githubusercontent.com/public-apis/public-apis/master/README.md"
            req = urllib.request.Request(url_readme, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                readme = resp.read().decode('utf-8')
                ai_section = re.search(r"### Artificial Intelligence(.*?)###", readme, re.DOTALL)
                if ai_section:
                    return re.findall(r"\[.*?\]\((https?://.*?)\)", ai_section.group(1))[:5]
        except Exception:
            pass
        return []

    def _discover_from_tavily(self):
        """Usa Tavily para buscar nuevos directorios de APIs."""
        try:
            payload = json.dumps({"query": "free public AI API endpoints json list github", "max_results": 3}).encode('utf-8')
            req = urllib.request.Request(
                "https://api.tavily.com/search",
                data=payload,
                headers={"Content-Type": "application/json", "X-Tavily-Access-Mode": "keyless"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            urls = []
            for r in data.get("results", []):
                urls.extend(re.findall(r'(https?://[^\s\)\"\']+api[^\s\)\"\']+)', r.get('content', '')))
            return urls[:3]
        except Exception:
            return []

    def hunt_new_nodes(self):
        print("[IAO EXPANSION] Iniciando escaneo multi-fuente...")
        cambios = False
        
        # Recolectar candidatos de todas las fuentes
        candidatos = self._discover_from_public_apis() + self._discover_from_tavily()
        
        for url in candidatos:
            if url in [v["url"] for v in self.memory.values()]:
                continue # Ya lo tenemos
            
            # Probar el nodo con el Conector Universal
            resultado = connector.fetch(url, method="GET")
            if resultado["status"] == "success":
                node_name = f"Node_{len(self.memory)}_{hash(url) % 1000}"
                self.memory[node_name] = {
                    "url": url,
                    "method": "GET",
                    "status": "active",
                    "format": resultado["format"],
                    "auth": "none",
                    "lang": "en", # Por defecto, se podría detectar
                    "last_check": str(datetime.datetime.now())
                }
                print(f"[IAO EXPANSION] ¡Nodo asimilado! {node_name} -> {url} (Formato: {resultado['format']})")
                cambios = True
        
        if cambios:
            self._save_memory_remote()
            
        return len(self.memory)

    def get_active_nodes(self):
        return {k: v for k, v in self.memory.items() if v.get("status") == "active"}

discovery = DiscoveryEngine()
