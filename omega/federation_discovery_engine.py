import json
import os
import urllib.request
import re
import datetime
from pathlib import Path

STATE = Path(".state/iao-federation-discoveries.json")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "alejandrofrigo/IAO"
GITHUB_PATH = "nodes_memory.json"
GITHUB_BRANCH = "iao-repair-http405-20261028T113227Z"

REQUIRED_EVIDENCE = (
    "identity_verified",
    "protocol_verified",
    "real_exchange_confirmed",
)

def _normalize(item):
    if not isinstance(item, dict):
        item = {}
    item = dict(item)
    checks = item.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    item["checks"] = checks
    verified = all(checks.get(key) is True for key in REQUIRED_EVIDENCE)
    if not verified:
        item["status"] = "discovered"
        item["operational"] = False
    return item

class DiscoveryEngine:
    def __init__(self):
        self.memory = self._load_memory_remote()
        self.memory = {
            str(name): _normalize(item)
            for name, item in self.memory.items()
        }
        self.memory.setdefault("Tavily", _normalize({
            "url": "https://api.tavily.com/search",
            "method": "POST",
            "status": "discovered",
            "format": "json",
            "auth": "unknown",
            "lang": "en",
        }))
        self.memory.setdefault("Pollinations", _normalize({
            "url": "https://text.pollinations.ai/",
            "method": "GET",
            "status": "discovered",
            "format": "text",
            "auth": "unknown",
            "lang": "en",
        }))
        self._save_local()

    def _load_memory_remote(self):
        try:
            data = json.loads(STATE.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError, TypeError):
            pass

        if not GITHUB_TOKEN:
            return {}
        url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_PATH}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_local(self):
        STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.memory, indent=2))
        tmp.replace(STATE)

    def _save_memory_remote(self):
        # La persistencia local es automática. No se modifica un repositorio
        # remoto ni se publican nodos sin una operación explícita autorizada.
        self._save_local()

    def _discover_from_public_apis(self):
        try:
            url = "https://raw.githubusercontent.com/public-apis/public-apis/master/README.md"
            req = urllib.request.Request(url, headers={"User-Agent": "IAO-Discovery"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                readme = resp.read().decode("utf-8")
            section = re.search(
                r"### Artificial Intelligence(.*?)(?:\n### |\Z)",
                readme,
                re.DOTALL,
            )
            if section:
                return re.findall(r"\[.*?\]\((https?://.*?)\)", section.group(1))[:5]
        except Exception:
            pass
        return []

    def hunt_new_nodes(self):
        print("[IAO EXPANSION] Descubriendo candidatos...")
        for url in self._discover_from_public_apis():
            if any(v.get("url") == url for v in self.memory.values()):
                continue
            name = f"Candidate_{len(self.memory) + 1}"
            self.memory[name] = _normalize({
                "url": url,
                "method": "unknown",
                "status": "discovered",
                "operational": False,
                "format": "unknown",
                "auth": "unknown",
                "discovered_at": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "checks": {
                    "identity_verified": False,
                    "protocol_verified": False,
                    "real_exchange_confirmed": False,
                },
            })
        self._save_local()
        return len(self.memory)

    def get_active_nodes(self):
        return {
            name: item
            for name, item in self.memory.items()
            if item.get("status") == "active"
            and item.get("operational") is True
            and all(item.get("checks", {}).get(k) is True
                    for k in REQUIRED_EVIDENCE)
        }

discovery = DiscoveryEngine()
