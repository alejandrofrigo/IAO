"""Publicación verificable de identidad IAO mediante IPFS/Kubo.

IPFS anuncia el CID; la identidad y la publicación se verifican con Ed25519.
Encontrar un proveedor IPFS no implica que sea un peer IAO.
"""
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "iao-ipfs-discoveries.json"
REPORT = ROOT / ".state" / "federation-ipfs" / "publication.json"
MAX_BYTES = 65536


class IPFSAssimilator:
    def __init__(self):
        self.memory = {}
        try:
            data = json.loads(STATE.read_text())
            if isinstance(data, dict):
                self.memory = data
        except (OSError, ValueError, TypeError):
            pass
        self._sanitize()

    def _sanitize(self):
        for item in self.memory.values():
            if isinstance(item, dict):
                item["operational"] = False
                if item.get("status") == "active":
                    item["status"] = "discovered"

    def _save(self):
        STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.memory, indent=2) + "\n")
        tmp.replace(STATE)

    @staticmethod
    def _read_publication(endpoint):
        from omega.federation import Node

        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password
                or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("PUBLIC_ENDPOINT_INVALID")

        url = endpoint.rstrip("/") + "/.well-known/iao-federation.json"
        req = urllib.request.Request(
            url, headers={"Accept": "application/json",
                          "User-Agent": "IAO-IPFS-Publisher/1"}
        )
        with urllib.request.urlopen(req, timeout=12) as response:
            if response.status != 200:
                raise ValueError("PUBLICATION_HTTP_ERROR")
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("PUBLICATION_TOO_LARGE")

        doc = json.loads(raw)
        if not Node.verify_publication(doc):
            raise ValueError("PUBLICATION_SIGNATURE_INVALID")
        if doc.get("endpoint", "").rstrip("/") != endpoint.rstrip("/"):
            raise ValueError("PUBLICATION_ENDPOINT_MISMATCH")
        if "knowledge.search" not in doc.get("capabilities", []):
            raise ValueError("KNOWLEDGE_SEARCH_NOT_ADVERTISED")

        now = time.time()
        issued, expires = doc.get("issued_at"), doc.get("lease_expires_at")
        if (not isinstance(issued, (int, float))
                or isinstance(issued, bool)
                or not isinstance(expires, (int, float))
                or isinstance(expires, bool)
                or issued > now + 60 or expires <= now
                or expires <= issued or expires - issued > 7 * 86400):
            raise ValueError("PUBLICATION_LEASE_INVALID")
        return doc, raw

    @staticmethod
    def _ipfs(*args, input_bytes=None, timeout=90):
        result = subprocess.run(
            ["ipfs", *args],
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        return result.stdout.decode("utf-8", "replace").strip()

    def announce_self(self):
        endpoint = os.getenv("IAO_FEDERATION_PUBLIC_ENDPOINT", "").strip()
        if not endpoint:
            endpoint = os.getenv("IAO_PUBLIC_FEDERATION_URL", "").strip()
        if not endpoint:
            return None

        try:
            doc, raw = self._read_publication(endpoint)
            cid = self._ipfs(
                "add", "-Q", "--pin=true",
                input_bytes=raw, timeout=60
            )
            if not cid or any(ch.isspace() for ch in cid):
                raise ValueError("IPFS_CID_INVALID")

            # Anuncio explícito al sistema de routing configurado en Kubo.
            provide = self._ipfs("provide", "once", cid, timeout=120)

            report = {
                "schema": 1,
                "status": "CONTENT_ADDED_AND_PROVIDER_ANNOUNCED",
                "cid": cid,
                "node_id": doc["node_id"],
                "endpoint": endpoint.rstrip("/"),
                "publication_signature": "VERIFIED",
                "publication_lease_expires_at": doc["lease_expires_at"],
                "provider_announcement": "COMMAND_SUCCEEDED",
                "provider_output": provide[-1000:],
                "timestamp": time.time(),
                "peer_discovery": "NOT_PERFORMED",
                "federation_enrollment": "NOT_PERFORMED",
            }
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            tmp = REPORT.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2) + "\n")
            tmp.replace(REPORT)

            self.memory[doc["node_id"]] = {
                "node_id": doc["node_id"],
                "endpoint": endpoint.rstrip("/"),
                "cid": cid,
                "status": "published",
                "operational": False,
                "checks": {
                    "publication_signature_verified": True,
                    "provider_announcement_succeeded": True,
                    "remote_retrieval_confirmed": False,
                    "peer_handshake_confirmed": False,
                    "federation_enrolled": False,
                },
            }
            self._save()
            return report
        except Exception as exc:
            result = {
                "status": "PUBLICATION_FAILED",
                "error": type(exc).__name__,
                "detail": str(exc)[:240],
            }
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            REPORT.write_text(json.dumps(result, indent=2) + "\n")
            return result

    def discover_nodes(self):
        # Importa candidatos del catálogo IAO, sin atribuirles actividad.
        try:
            from omega.federation_discovery_engine import DiscoveryEngine
            catalog = DiscoveryEngine().memory
        except Exception:
            catalog = {}

        if isinstance(catalog, dict):
            for name, item in catalog.items():
                if not isinstance(item, dict):
                    continue
                candidate = dict(item)
                candidate["status"] = "discovered"
                candidate["operational"] = False
                self.memory.setdefault(name, candidate)

        self._sanitize()
        self._save()
        return len(self.memory)

    def start(self):
        while True:
            print(json.dumps(self.announce_self(), ensure_ascii=False))
            print("CANDIDATOS_IAO_REGISTRADOS=", self.discover_nodes())
            time.sleep(300)


if __name__ == "__main__":
    IPFSAssimilator().start()
