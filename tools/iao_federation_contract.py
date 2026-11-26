#!/usr/bin/env python3
"""IAO federation contract checker; offline by default."""

# IAO_PROJECT_IMPORT_PATH
import sys as _iao_sys
from pathlib import Path as _IAO_Path
_iao_root = str(_IAO_Path(__file__).resolve().parents[1])
if _iao_root not in _iao_sys.path:
    _iao_sys.path.insert(0, _iao_root)

from pathlib import Path  # noqa: E402
import ast  # noqa: E402
import hashlib  # noqa: E402
import importlib  # noqa: E402
import inspect  # noqa: E402
import json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
OUT = STATE / "iao-federation-contract.json"


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def main():
    # IAO_CONTRACT_HELP_V1: ayuda CLI sin ejecutar comprobaciones
    if any(arg in ("-h", "--help") for arg in __import__("sys").argv[1:]):
        print("IAO - Verificador offline del contrato federativo")
        print("Uso: python tools/iao_federation_contract.py")
        print("Ejecuta comprobaciones locales de estructura e identidad.")
        print("Codigos: 0=PASS, 1=ERROR, 2=BLOCKED_WITH_EVIDENCE")
        return 0
    result = {
        "system": "IAO",
        "mode": "OFFLINE_CONTRACT_CHECK",
        "utc": datetime.now(timezone.utc).isoformat(),
        "network_requests": 0,
        "secrets_printed": False,
        "checks": [],
        "federation": {},
        "blockers": [],
    }
    f = ROOT / "omega" / "federation.py"
    result["federation"]["source_sha256"] = digest(f)
    if not f.is_file():
        result["blockers"].append("omega/federation.py missing")
    else:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
            result["checks"].append({"name": "federation_ast", "status": "PASS"})
            result["federation"]["classes"] = [
                n.name for n in tree.body if isinstance(n, ast.ClassDef)
            ]
            result["federation"]["functions"] = [
                n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            result["federation"]["methods"] = {
                n.name: [
                    m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                for n in tree.body
                if isinstance(n, ast.ClassDef)
            }
        except Exception as e:
            result["checks"].append({"name": "federation_ast", "status": "FAIL", "error": str(e)})
            result["blockers"].append("Federation source does not parse")
    try:
        mod = importlib.import_module("omega.federation")
        result["checks"].append({"name": "federation_import", "status": "PASS"})
        api = {}
        for name in ("Node", "FedServer", "FedDenied", "node_id_of", "_sign", "_verify"):
            obj = getattr(mod, name, None)
            if obj is not None:
                try:
                    sig = str(inspect.signature(obj))
                except Exception:
                    sig = "signature unavailable"
                api[name] = {"type": type(obj).__name__, "signature": sig}
        result["federation"]["runtime_api"] = api
        if not hasattr(mod, "Node") or not hasattr(mod, "FedServer"):
            result["blockers"].append("Expected Node/FedServer API incomplete")
    except Exception as e:
        result["checks"].append({"name": "federation_import", "status": "FAIL", "error": str(e)})
        result["blockers"].append("Federation module cannot be imported")
    cfg = STATE / "iao-external-nodes.json"
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            nodes = data.get("nodes", []) if isinstance(data, dict) else []
            valid = isinstance(nodes, list)
            result["nodes"] = {
                "config_exists": True,
                "json_valid": True,
                "list_valid": valid,
                "configured_count": len(nodes) if valid else 0,
                "authorized_count": sum(
                    1 for n in nodes if isinstance(n, dict) and n.get("authorized") is True
                ),
            }
            if not valid:
                result["blockers"].append("nodes must be a JSON list")
            if valid and not nodes:
                result["blockers"].append("No external nodes configured")
        except Exception:
            result["nodes"] = {"config_exists": True, "json_valid": False}
            result["blockers"].append("External-node configuration invalid JSON")
    else:
        result["nodes"] = {"config_exists": False, "configured_count": 0, "authorized_count": 0}
        result["blockers"].append("External-node configuration missing")
    result["status"] = (
        "READY_FOR_INTEGRATION" if not result["blockers"] else "BLOCKED_WITH_EVIDENCE"
    )
    STATE.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("REPORT_JSON=" + str(OUT))
    print("REPORT_SHA256=" + digest(OUT))
    return 0 if result["status"] == "READY_FOR_INTEGRATION" else 2


if __name__ == "__main__":
    raise SystemExit(main())
