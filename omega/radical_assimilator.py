import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state"
STATE_FILE = STATE / "iao-radical-assimilator.json"
INTEGRATIONS_FILE = STATE / "iao-api-integrations.json"
MAX_BYTES = 5 * 1024 * 1024
MAX_PER_CYCLE = 5
REGISTRIES = [
    "https://raw.githubusercontent.com/public-apis/public-apis/master/README.md",
    "https://raw.githubusercontent.com/n0shake/Public-APIs/master/README.md",
    "https://api.github.com/repos/APIs-guru/openapi-directory/git/trees/main?recursive=1",
]


class RadicalAssimilator:
    def __init__(self, state_file=None, integrations_file=None):
        self.registry_urls = list(REGISTRIES)
        self.state_file = Path(state_file) if state_file is not None else STATE_FILE
        self.integrations_file = (
            Path(integrations_file)
            if integrations_file is not None
            else INTEGRATIONS_FILE
        )
        self.assimilated = {}
        self.candidates = {}
        self._load_state()

    @staticmethod
    def _atomic_json(path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _load_state(self):
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                if isinstance(data.get("verified"), dict):
                    self.assimilated = data["verified"]
                if isinstance(data.get("candidates"), dict):
                    self.candidates = data["candidates"]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            print(f"[RADICAL] Estado anterior no legible: {exc}")

    def _save_state(self):
        self._atomic_json(self.state_file, {
            "schema": "iao.radical.state.v2",
            "updated_at": time.time(),
            "verified": self.assimilated,
            "candidates": self.candidates,
        })
        self._atomic_json(self.integrations_file, {
            "schema": "iao.api.integrations.openapi.v1",
            "updated_at": time.time(),
            "integrations": self.assimilated,
        })

    @staticmethod
    def _safe_url(url):
        try:
            p = urllib.parse.urlsplit(url.strip())
            return p.scheme == "https" and bool(p.hostname) and not p.username and not p.password
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def _is_openapi_document(data):
        if not isinstance(data, dict):
            return False
        info = data.get("info")
        paths = data.get("paths")
        if not isinstance(info, dict) or not isinstance(paths, dict):
            return False
        if not isinstance(info.get("title"), str) or not info["title"].strip():
            return False
        if not isinstance(info.get("version"), str) or not info["version"].strip():
            return False
        return (
            isinstance(data.get("openapi"), str) and data["openapi"].startswith("3.")
        ) or data.get("swagger") == "2.0"

    def _fetch(self, url, timeout=12):
        if not self._safe_url(url):
            raise ValueError("Se requiere URL HTTPS segura")
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "IAO-OpenAPI-Verifier/2.0",
                "Accept": "application/json, application/vnd.oai.openapi+json, text/plain",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"HTTP {response.status}")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError("Respuesta demasiado grande")
            return body

    def _fetch_json(self, url):
        return json.loads(self._fetch(url).decode("utf-8-sig"))

    def _extract_urls(self, text):
        found = re.findall(r'https://[^\s<>\)\]"\']+', text or "")
        result = []
        for raw in found:
            url = raw.rstrip(".,;")
            if self._safe_url(url) and url not in result:
                result.append(url)
        return result[:100]

    @staticmethod
    def _spec_candidates(url):
        p = urllib.parse.urlsplit(url)
        if p.path.lower().endswith((".json", ".yaml", ".yml")):
            return [url]
        base = urllib.parse.urlunsplit(
            (p.scheme, p.netloc, p.path.rstrip("/"), "", "")
        )
        return [url, base + "/openapi.json", base + "/swagger.json", base + "/api-docs"]

    def _candidate(self, url, reason):
        if url not in self.assimilated:
            self.candidates[url] = {
                "status": "pending_verification",
                "reason": str(reason)[:240],
                "last_seen": time.time(),
            }

    def _verify_spec(self, url):
        try:
            doc = self._fetch_json(url)
            if not self._is_openapi_document(doc):
                self._candidate(url, "No contiene un contrato OpenAPI/Swagger válido")
                return False

            info = doc["info"]
            canonical = json.dumps(doc, sort_keys=True, ensure_ascii=False)
            self.assimilated[url] = {
                "status": "openapi_spec_verified",
                "spec_url": url,
                "title": info["title"][:200],
                "version": info["version"][:100],
                "specification": doc.get("openapi", "Swagger 2.0"),
                "paths_count": len(doc["paths"]),
                "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                "verified_at": time.time(),
                "runtime_connectivity": "not_tested",
                "production_integration": "not_established",
            }
            self.candidates.pop(url, None)
            print(f"[RADICAL] CONTRATO VERIFICADO: {info['title']} ({len(doc['paths'])} rutas)")
            return True
        except Exception as exc:
            self._candidate(url, exc)
            return False

    def _registry_candidates(self, registry):
        try:
            if "APIs-guru/openapi-directory" in registry:
                data = self._fetch_json(registry)
                urls = []
                for item in data.get("tree", []):
                    path = item.get("path", "")
                    if (
                        item.get("type") == "blob"
                        and path.startswith("APIs/")
                        and path.endswith(".json")
                    ):
                        urls.append(
                            "https://raw.githubusercontent.com/APIs-guru/openapi-directory/main/"
                            + urllib.parse.quote(path, safe="/")
                        )
                return urls

            text = self._fetch(registry).decode("utf-8", errors="replace")
            return self._extract_urls(text)
        except Exception as exc:
            print(f"[RADICAL] Directorio no disponible: {registry}: {exc}")
            return []

    def _publish_to_ipfs(self):
        try:
            payload = json.dumps({
                "schema": "iao.api.integrations.openapi.v1",
                "published_at": time.time(),
                "integrations": self.assimilated,
            }, ensure_ascii=False, sort_keys=True).encode("utf-8")
            result = subprocess.run(
                ["ipfs", "add", "-Q"],
                input=payload,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                print("[RADICAL] Inventario publicado en IPFS:", result.stdout.decode().strip())
            else:
                print("[RADICAL] IPFS rechazó la publicación")
        except Exception as exc:
            print("[RADICAL] IPFS no disponible:", exc)

    def run_cycle(self):
        print("[RADICAL] Descubriendo y verificando contratos OpenAPI...")
        before = len(self.assimilated)
        checked = set()
        attempts = 0

        for registry in self.registry_urls:
            for discovered in self._registry_candidates(registry):
                for candidate in self._spec_candidates(discovered):
                    if attempts >= MAX_PER_CYCLE:
                        break
                    if candidate in checked or candidate in self.assimilated:
                        continue
                    checked.add(candidate)
                    attempts += 1
                    self._verify_spec(candidate)
                if attempts >= MAX_PER_CYCLE:
                    break
            if attempts >= MAX_PER_CYCLE:
                break

        self._save_state()
        added = len(self.assimilated) - before
        if added:
            self._publish_to_ipfs()

        print(
            f"[RADICAL] Ciclo: nuevos={added}, "
            f"contratos_verificados={len(self.assimilated)}, "
            f"pendientes={len(self.candidates)}, intentos={attempts}"
        )
        return added


if __name__ == "__main__":
    worker = RadicalAssimilator()
    while True:
        try:
            worker.run_cycle()
            print("[RADICAL] Próximo ciclo en 5 minutos")
            time.sleep(300)
        except KeyboardInterrupt:
            print("[RADICAL] Detenido por el operador")
            break
        except Exception as exc:
            print("[RADICAL] Error recuperable:", exc)
            time.sleep(60)
