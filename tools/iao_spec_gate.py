#!/usr/bin/env python3
"""IAO Master Specification Gate: evidence-based construction tracker."""
import json
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state" / "construction"
STATE.mkdir(parents=True, exist_ok=True)
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
NOW = datetime.now(timezone.utc).isoformat()

DOMAINS = {
    "01_core": {
        "name": "Núcleo central",
        "artifacts": ["omega/supervisor.py", "omega/server.py",
                      "omega/policy_gate.py"],
    },
    "02_multi_llm": {
        "name": "Orquestación multi-LLM",
        "artifacts": ["omega/llm_router.py",
                      str(Path.home() / ".config/iao/llm-providers.json")],
        "patterns": ["omega/*llm*", "omega/*router*", "tools/*llm*"],
    },
    "03_self_programming": {
        "name": "Autoprogramación y evolución",
        "artifacts": ["omega/autonomous_core.py",
                      "omega/autonomous_coordinator.py"],
        "patterns": ["tools/*autonomous*", "tools/*autonomy*"],
    },
    "04_free_resources": {
        "name": "Descubrimiento de recursos gratuitos",
        "artifacts": ["tools/iao_internet_guardian.py"],
        "patterns": ["tools/*universal*", "tools/*resource*"],
    },
    "05_federation": {
        "name": "Federación y nodos autorizados",
        "artifacts": ["tools/iao_federation_worker.py",
                      "tools/iao_node_network_engine.py",
                      "tools/iao_external_node_agent.py"],
    },
    "06_knowledge": {
        "name": "Memoria y conocimiento",
        "patterns": ["omega/*knowledge*", "tools/*knowledge*"],
    },
    "07_public_platform": {
        "name": "Plataforma pública",
        "artifacts": ["web/index.html", "omega/server.py"],
    },
    "08_security": {
        "name": "Seguridad y gobernanza",
        "artifacts": ["omega/policy_gate.py"],
        "patterns": ["omega/*audit*", "omega/*security*"],
    },
    "09_android_control": {
        "name": "Centro de control Android y Termux",
        "artifacts": ["tools/iao_five_motor_supervisor.py"],
        "patterns": ["tools/*guardian*", "tools/*control_plane*"],
    },
    "10_continuity": {
        "name": "Continuidad y recuperación",
        "patterns": ["tools/*supervisor*", "tools/*continuity*",
                     "tools/*guardian*"],
    },
    "11_resource_management": {
        "name": "Gestión de recursos y cuotas",
        "patterns": ["omega/*resource*", "tools/*resource*",
                     "omega/*quota*", "tools/*quota*"],
    },
    "12_specialized_agents": {
        "name": "Agentes especializados",
        "patterns": ["omega/*agent*", "tools/*agent*"],
    },
    "13_advanced_intelligence": {
        "name": "Capacidades avanzadas y multimodales",
        "patterns": ["omega/*multimodal*", "tools/*multimodal*",
                     "omega/*vision*", "tools/*vision*"],
    },
    "14_validation": {
        "name": "Validación e integración",
        "patterns": ["tests/*", "pyproject.toml", "pytest.ini"],
    },
}

def exists(path):
    return Path(path).expanduser().exists()

def inspect_domain(domain):
    exact = domain.get("artifacts", [])
    exact_results = {p: exists(p) for p in exact}
    pattern_results = {}
    for pattern in domain.get("patterns", []):
        try:
            pattern_results[pattern] = sorted(
                str(p.relative_to(ROOT))
                for p in ROOT.glob(pattern)
                if p.is_file()
            )[:30]
        except Exception:
            pattern_results[pattern] = []
    found = any(exact_results.values()) or any(pattern_results.values())
    return {
        "name": domain["name"],
        "status": "present_unverified" if found else "not_located",
        "exact_artifacts": exact_results,
        "pattern_matches": pattern_results,
        "functional_test": "not_run",
    }

def http_check(path):
    url = "http://127.0.0.1:8080" + path
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as response:
            raw = response.read(12000).decode("utf-8", "replace")
            try:
                body = json.loads(raw)
            except Exception:
                body = raw[:1000]
            return {"http": response.status, "body": body}
    except Exception as exc:
        return {"error": type(exc).__name__ + ": " + str(exc)[:180]}

def safe_git(args):
    try:
        p = subprocess.run(["git"] + args, cwd=ROOT, capture_output=True,
                           text=True, timeout=10)
        return (p.stdout or p.stderr).strip()
    except Exception as exc:
        return "unavailable: " + type(exc).__name__

domains = {key: inspect_domain(value) for key, value in DOMAINS.items()}
live = http_check("/health/live")
ready = http_check("/health/ready")

ready_status = None
if isinstance(ready.get("body"), dict):
    ready_status = ready["body"].get("status")

report = {
    "project": "IAO",
    "specification": "Especificación maestra oficial",
    "timestamp_utc": NOW,
    "repository": str(ROOT),
    "git_branch": safe_git(["branch", "--show-current"]),
    "git_commit": safe_git(["rev-parse", "--short", "HEAD"]),
    "domains": domains,
    "runtime": {
        "health_live": live,
        "health_ready": ready,
        "readiness_status": ready_status,
    },
    "interpretation": {
        "present_unverified": "Hay archivos relacionados; falta prueba funcional.",
        "not_located": "No se localizó evidencia en las rutas examinadas.",
        "operational": "Solo se asignará después de pruebas funcionales específicas.",
    },
}

json_path = STATE / f"master_spec_{STAMP}.json"
txt_path = STATE / f"master_spec_{STAMP}.txt"
journal_path = STATE / "master_spec_journal.jsonl"

json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

lines = [
    "IAO — CONTROL DE LA ESPECIFICACIÓN MAESTRA",
    f"UTC: {NOW}",
    f"REPOSITORIO: {ROOT}",
    f"RAMA: {report['git_branch']}",
    f"COMMIT: {report['git_commit']}",
    "",
    "DOMINIOS Y EVIDENCIAS",
]
for key, value in domains.items():
    lines.append(f"{key} | {value['name']} | {value['status']}")
    for path, found in value["exact_artifacts"].items():
        lines.append(f"  {'ENCONTRADO' if found else 'NO ENCONTRADO'}: {path}")
    for pattern, matches in value["pattern_matches"].items():
        lines.append(f"  PATRÓN {pattern}: {len(matches)} coincidencias")
        for match in matches[:8]:
            lines.append(f"    - {match}")

lines += [
    "",
    "SERVIDOR",
    json.dumps(live, ensure_ascii=False),
    "",
    "PREPARACIÓN",
    json.dumps(ready, ensure_ascii=False),
    "",
    "CRITERIO: presencia de archivos no equivale a capacidad operativa.",
]
txt_path.write_text("\n".join(lines) + "\n")

event = {
    "timestamp_utc": NOW,
    "action": "master_spec_inventory",
    "json_report": str(json_path),
    "text_report": str(txt_path),
    "readiness_status": ready_status,
    "domains_present_unverified": sum(
        d["status"] == "present_unverified" for d in domains.values()
    ),
    "domains_not_located": sum(
        d["status"] == "not_located" for d in domains.values()
    ),
}
with journal_path.open("a", encoding="utf-8") as journal:
    journal.write(json.dumps(event, ensure_ascii=False) + "\n")

print("\n========== IAO — ESPECIFICACIÓN MAESTRA ==========")
print("Informe:", txt_path)
print("Datos:  ", json_path)
print("Diario: ", journal_path)
print("\nDOMINIOS:")
for key, value in domains.items():
    print(f"{value['status']:20} {key} — {value['name']}")
print("\nHEALTH LIVE:", live)
print("HEALTH READY:", ready)
print("\nDominios con archivos relacionados:",
      event["domains_present_unverified"], "de", len(domains))
print("Dominios sin evidencia localizada:", event["domains_not_located"])
print("\nLa presencia de archivos NO se considera prueba de funcionamiento.")
print("FASE DE CONTROL DE ESPECIFICACIÓN: EJECUTADA.")
