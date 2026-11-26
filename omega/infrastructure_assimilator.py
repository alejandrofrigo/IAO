import ipaddress
import json
import os
import re
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "iao-infrastructure-discoveries.json"


def safe_url(value):
    try:
        p = urlparse(value)
        if p.scheme != "https" or not p.hostname:
            return False
        if p.username or p.password or p.port not in (None, 443):
            return False

        host = p.hostname.lower().rstrip(".")
        if host == "localhost" or host.endswith(
            (".localhost", ".local", ".internal", ".test", ".invalid")
        ):
            return False

        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host):
                return False
            if ".." in host or host.startswith(".") or host.endswith("."):
                return False

        return True
    except (TypeError, ValueError, AttributeError):
        return False


def classify_url(value):
    if not safe_url(value):
        return "REJECTED_URL"

    p = urlparse(value)
    host = (p.hostname or "").lower()
    path = p.path.lower()

    if host in {
        "github.com", "gitlab.com", "codeberg.org", "bitbucket.org"
    }:
        return "REPOSITORY"

    if host in {
        "learn.microsoft.com", "developer.mozilla.org",
        "docs.python.org", "httpd.apache.org",
        "developer.bitcoin.org", "ethereum.org", "docs.ipfs.tech"
    }:
        return "DOCUMENTATION"

    if any(x in path for x in (
        "/docs", "/documentation", "/guide", "/tutorial",
        "/blog", "/news", "/article", "/wiki"
    )):
        return "DOCUMENTATION"

    if host.startswith("api.") or any(x in path for x in (
        "/api/", "/v1/", "/v2/", "/rpc", "/graphql", "/mcp"
    )):
        return "ENDPOINT_CANDIDATE"

    return "UNCLASSIFIED_WEB_RESOURCE"


class InfrastructureAssimilator:
    def __init__(self):
        self.search_queries = [
            "official public IPFS bootstrap peers documentation",
            "official public Matrix homeserver directory",
            "public NTP pool server documentation",
            "public DNS over HTTPS endpoint documentation",
            "official public API endpoint directory",
            "public Model Context Protocol server directory"
        ]
        self.inventory = self._load()

    def _load(self):
        try:
            data = json.loads(STATE.read_text(encoding="utf-8"))
            if (
                isinstance(data, dict)
                and data.get("schema") == "IAO_INFRASTRUCTURE_DISCOVERY_V1"
                and isinstance(data.get("resources"), dict)
            ):
                return data
        except (OSError, ValueError, AttributeError):
            pass

        return {
            "schema": "IAO_INFRASTRUCTURE_DISCOVERY_V1",
            "updated_at": None,
            "resources": {}
        }

    def _save(self):
        STATE.parent.mkdir(parents=True, exist_ok=True)
        self.inventory["updated_at"] = time.time()

        tmp = STATE.with_name(STATE.name + ".tmp")
        try:
            tmp.write_text(
                json.dumps(self.inventory, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE)
            os.chmod(STATE, 0o600)
        finally:
            if tmp.exists():
                tmp.unlink()

    def search_web(self, query):
        try:
            payload = json.dumps({
                "query": query,
                "max_results": 10
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.tavily.com/search",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Tavily-Access-Mode": "keyless"
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))

            if not isinstance(data, dict):
                return []

            return [
                item.get("url", "")
                for item in data.get("results", [])
                if isinstance(item, dict)
            ]
        except Exception as exc:
            print(
                "[IAO INFRA] Búsqueda no disponible:",
                type(exc).__name__
            )
            return []

    def test_server(self, url):
        print(
            "[IAO INFRA] Sondeo genérico desactivado: "
            "HTTP 200 no acredita protocolo ni integración."
        )
        return False

    def assimilate(self):
        print("[IAO INFRA] Descubrimiento seguro de infraestructura.")
        resources = self.inventory["resources"]
        added = 0

        for query in self.search_queries:
            print("[IAO INFRA] Buscando:", query)

            for url in self.search_web(query):
                if not isinstance(url, str) or not safe_url(url):
                    continue

                category = classify_url(url)
                if category == "REJECTED_URL":
                    continue

                now = time.time()
                if url not in resources:
                    resources[url] = {
                        "category": category,
                        "stage": "DISCOVERED",
                        "source_query": query,
                        "first_seen": now,
                        "last_seen": now,
                        "checks": {
                            "reachable": False,
                            "protocol_verified": False,
                            "identity_verified": False,
                            "real_exchange_confirmed": False
                        },
                        "operational": False,
                        "integration": "NOT_INTEGRATED"
                    }
                    added += 1
                else:
                    resources[url]["last_seen"] = now

        self._save()

        print("[IAO INFRA] Nuevos candidatos:", added)
        print("[IAO INFRA] Total persistente:", len(resources))
        print("[IAO INFRA] Nodos operativos acreditados: 0")
        print("[IAO INFRA] Inventario:", STATE)
        return added


if __name__ == "__main__":
    assimilator = InfrastructureAssimilator()
    while True:
        try:
            assimilator.assimilate()
            print("[IAO INFRA] Próximo ciclo en 5 minutos.")
            time.sleep(300)
        except KeyboardInterrupt:
            print("[IAO INFRA] Detenido por el operador.")
            break
        except Exception as exc:
            print("[IAO INFRA] Error recuperable:", type(exc).__name__)
            time.sleep(60)
