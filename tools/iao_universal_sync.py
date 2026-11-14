#!/usr/bin/env python3
"""Importa resultados de descubrimiento al registro universal de IAO."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REGISTRY = STATE / "iao-universal-registry.json"
GITHUB_REPORT = STATE / "iao-github-candidates.json"
FED_REPORT = STATE / "iao-federation-candidates.json"


def utc():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def valid_https(value):
    if not isinstance(value, str):
        return False
    u = urlparse(value)
    return (
        u.scheme == "https" and bool(u.hostname)
        and not u.username and not u.password
    )


def resource_id(kind, name, url):
    return hashlib.sha256(
        f"{kind}|{name}|{url}".encode()
    ).hexdigest()[:20]


def make_resource(kind, name, url, adapter, source, notes="", node_id=None):
    return {
        "id": resource_id(kind, name, url),
        "name": name,
        "kind": kind,
        "url": url,
        "adapter": adapter,
        "capabilities": [],
        "permission_status": "unknown",
        "stage": "DISCOVERED",
        "checks": {
            "identity_verified": False,
            "permission_verified": False,
            "adapter_tested": False,
            "real_exchange_confirmed": False,
        },
        "evidence": [{
            "type": "discovery_record",
            "source": source,
            "observed_at": utc(),
        }],
        "created_at": utc(),
        "updated_at": utc(),
        "notes": notes[:1000],
        **({"external_node_id": node_id} if node_id else {}),
    }


def discover_github():
    path = ROOT / "tools" / "iao_github_discovery.py"
    spec = importlib.util.spec_from_file_location("iao_github_discovery", path)
    if not spec or not spec.loader:
        raise RuntimeError("GITHUB_DISCOVERY_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.discover()


def sync(run_discovery):
    if run_discovery:
        report = discover_github()
    else:
        report = read_json(GITHUB_REPORT)

    registry = read_json(REGISTRY)
    if not registry:
        raise RuntimeError("UNIVERSAL_REGISTRY_NOT_INITIALIZED")
    resources = registry.get("resources")
    if not isinstance(resources, list):
        raise RuntimeError("UNIVERSAL_REGISTRY_SCHEMA_INVALID")

    known = {x.get("id") for x in resources if isinstance(x, dict)}
    added_repositories = 0
    added_peers = 0
    skipped = 0

    # Repositorios: fuente de código/conocimiento, nunca nodos activos por defecto.
    for repo in report.get("repositories", []):
        if not isinstance(repo, dict):
            skipped += 1
            continue
        name, url = repo.get("name"), repo.get("url")
        if not isinstance(name, str) or not valid_https(url):
            skipped += 1
            continue
        notes = "GitHub; lenguaje=" + str(repo.get("language") or "no indicado")
        if repo.get("description"):
            notes += "; " + str(repo["description"])

        # Pistas de integración: no prueban que el servicio esté operativo.
        text = " ".join([
            str(name), str(repo.get("description") or ""),
            " ".join(str(x) for x in repo.get("topics", [])),
        ]).lower()

        hints = []
        if any(x in text for x in ("mcp", "model-context-protocol")):
            hints.append("mcp")
        if any(x in text for x in ("openapi", "swagger", "rest api", "public api")):
            hints.append("rest_or_openapi")
        if any(x in text for x in ("graphql",)):
            hints.append("graphql")
        if any(x in text for x in ("openai-compatible", "inference server", "llm serving")):
            hints.append("model_api")
        if any(x in text for x in ("agent", "multi-agent", "autonomous agent")):
            hints.append("agent")
        if any(x in text for x in ("federation", "federated", "distributed compute")):
            hints.append("federation_or_compute")
        if any(x in text for x in ("knowledge base", "vector database", "rag")):
            hints.append("knowledge")

        item_hints = sorted(set(hints))
        item = make_resource(
            "repository", name, url, "github",
            "GitHub public repository search", notes,
        )
        item["integration_hints"] = item_hints
        item["integration_status"] = "NOT_TESTED"
        if item["id"] not in known:
            resources.append(item)
            known.add(item["id"])
            added_repositories += 1
        else:
            # Actualizar solo metadatos de descubrimiento; preservar etapa y evidencias.
            for existing in resources:
                if isinstance(existing, dict) and existing.get("id") == item["id"]:
                    existing["integration_hints"] = sorted(set(
                        existing.get("integration_hints", []) + item_hints
                    ))
                    existing["integration_status"] = existing.get(
                        "integration_status", "NOT_TESTED"
                    )
                    existing["updated_at"] = utc()
                    break

    # Candidatos con endpoint: se registran como pares por verificar,
    # no como nodos asimilados.
    peer_candidates = report.get("candidates", [])
    fed = read_json(FED_REPORT)
    peer_candidates += fed.get("candidates", []) if isinstance(
        fed.get("candidates", []), list
    ) else []

    for candidate in peer_candidates:
        if not isinstance(candidate, dict):
            skipped += 1
            continue
        url = candidate.get("endpoint")
        if not valid_https(url):
            skipped += 1
            continue
        node_id = candidate.get("node_id")
        name = str(candidate.get("repository") or node_id or url)[:200]
        item = make_resource(
            "iao_peer", name, url.rstrip("/"), "iao_federation",
            "Verified-format discovery candidate",
            "Pendiente de verificación de identidad, oferta, permisos e intercambio real.",
            node_id if isinstance(node_id, str) else None,
        )
        if item["id"] not in known:
            resources.append(item)
            known.add(item["id"])
            added_peers += 1

    registry["updated_at"] = utc()
    registry["resources"] = resources

    fd, temp = tempfile.mkstemp(prefix=".iao-universal-", dir=STATE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(registry, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, REGISTRY)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

    return {
        "repositories_imported": added_repositories,
        "peer_candidates_imported": added_peers,
        "invalid_records_skipped": skipped,
        "registry_total": len(resources),
        "active_nodes_created": 0,
        "real_capability_exchanges_created": 0,
        "discovery_report_repositories": len(report.get("repositories", [])),
        "github_search_errors": report.get("errors", []),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--discover-github", action="store_true",
        help="Ejecutar el descubridor GitHub antes de sincronizar.",
    )
    args = parser.parse_args()
    result = sync(args.discover_github)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
