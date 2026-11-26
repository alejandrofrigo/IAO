#!/usr/bin/env python3
"""Motor de evaluación y habilitación progresiva de proveedores IAO."""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REGISTRY = STATE / "iao-universal-registry.json"
CATALOG = STATE / "iao-universal-providers.json"
CONFIG = Path.home() / ".config/iao/llm-providers.json"
REPORT = STATE / "iao-universal-enablement.json"

def now():
    return datetime.now(timezone.utc).isoformat()

def read(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default

def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iao-enable-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def adapter_for(url, hint=None):
    hint = str(hint or "").lower()
    host = (urlparse(url).hostname or "").lower()

    if "anthropic" in hint or host == "api.anthropic.com":
        return "anthropic"
    if "gemini" in hint or host == "generativelanguage.googleapis.com":
        return "gemini"
    if "mcp" in hint:
        return "mcp"
    if "graphql" in hint:
        return "graphql"
    if "openai" in hint or host in (
        "api.openai.com", "open.bigmodel.cn",
        "api.groq.com", "api.llm7.io",
    ):
        return "openai_compatible"
    if "rest" in hint or urlparse(url).scheme == "https":
        return "rest_custom_adapter_required"
    return "custom_adapter_discovery_required"

def main():
    registry = read(REGISTRY, {})
    catalog = read(CATALOG, {"providers": []})
    config = read(CONFIG, {"providers": []})

    if not isinstance(registry.get("resources", []), list):
        raise SystemExit("REGISTRY_INVALID")
    if not isinstance(catalog.get("providers", []), list):
        raise SystemExit("CATALOG_INVALID")
    if not isinstance(config.get("providers", []), list):
        raise SystemExit("PROVIDER_CONFIG_INVALID")

    configured = []
    for p in config["providers"]:
        if not isinstance(p, dict) or p.get("enabled", True) is not True:
            continue
        url = p.get("url")
        if not isinstance(url, str) or urlparse(url).scheme != "https":
            continue
        key_env = p.get("key_env")
        key_ready = (
            bool(os.environ.get(key_env, "").strip())
            if isinstance(key_env, str) and key_env
            else True
        )
        configured.append({
            "id": str(p.get("id", "")),
            "url": url.rstrip("/"),
            "model": p.get("model"),
            "key_ready": key_ready,
            "key_required": bool(key_env),
            "adapter": p.get("adapter", "openai_compatible"),
        })

    results = []
    for resource in registry.get("resources", []):
        if not isinstance(resource, dict):
            continue
        if resource.get("kind") not in ("api", "model", "provider"):
            continue

        url = resource.get("url")
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            status = "SECURE_ENDPOINT_REQUIRED"
            adapter = "none"
            match = None
        else:
            adapter = adapter_for(url, resource.get("adapter"))
            match = next(
                (p for p in configured if p["url"] == url.rstrip("/")),
                None,
            )
            if match and not match["key_ready"]:
                status = "AUTHENTICATION_REQUIRED"
            elif match:
                status = "CONFIGURED_ROUTER_PROVIDER"
            elif adapter == "openai_compatible":
                status = "ADAPTER_SUPPORTED_CONFIGURATION_REQUIRED"
            else:
                status = "ADAPTER_DISCOVERY_REQUIRED"

        results.append({
            "resource_id": resource.get("id"),
            "name": resource.get("name"),
            "url": url,
            "adapter": adapter,
            "status": status,
            "configured_provider": match["id"] if match else None,
            "model_configured": bool(match and match.get("model")),
            "authentication_ready": match["key_ready"] if match else False,
            "operational": False,
            "checked_at": now(),
        })

    # También informa sobre proveedores ya configurados, aunque no estén
    # representados en el registro universal.
    registry_urls = {str(x.get("url", "")).rstrip("/") for x in results}
    for p in configured:
        if p["url"] not in registry_urls:
            results.append({
                "resource_id": None,
                "name": p["id"],
                "url": p["url"],
                "adapter": p["adapter"],
                "status": (
                    "CONFIGURED_ROUTER_PROVIDER"
                    if p["key_ready"] else "AUTHENTICATION_REQUIRED"
                ),
                "configured_provider": p["id"],
                "model_configured": bool(p["model"]),
                "authentication_ready": p["key_ready"],
                "operational": False,
                "checked_at": now(),
            })

    counts = {}
    for x in results:
        counts[x["status"]] = counts.get(x["status"], 0) + 1

    report = {
        "schema": "IAO_UNIVERSAL_ENABLEMENT_V1",
        "updated_at": now(),
        "policy": "ACCEPT_ALL_VERIFIABLE_PROVIDERS",
        "brand_allowlist": False,
        "single_protocol_required": False,
        "automatic_adapter_selection": True,
        "router_connection": "omega.llm_router provider configuration",
        "configured_router_providers": len(configured),
        "resources_evaluated": len(results),
        "status_counts": counts,
        "results": results,
        "operational_count": 0,
        "note": (
            "Configuration and adapter readiness are not proof of a live "
            "successful inference. Operational status requires a real "
            "authorized capability exchange."
        ),
        "secrets_stored": False,
        "external_code_executed": False,
    }
    atomic(REPORT, report)

    print("UNIVERSAL_ACCEPTANCE: ENABLED")
    print("BRAND_RESTRICTIONS: NONE")
    print("PROTOCOL_RESTRICTIONS: NONE")
    print("ROUTER_PROVIDERS_CONFIGURED:", len(configured))
    print("RESOURCES_EVALUATED:", len(results))
    for name, count in sorted(counts.items()):
        print(name + ":", count)
    print("OPERATIONAL_CLAIMS:", 0)
    print("REPORT:", REPORT.relative_to(ROOT))

if __name__ == "__main__":
    main()
