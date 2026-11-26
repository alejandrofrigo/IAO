#!/usr/bin/env python3
"""
IAO Integrated Control Plane
Descubrimiento, integración, federación y coordinación de componentes.

No reinicia procesos existentes.
No ejecuta código candidato.
No confía automáticamente en nodos remotos.
No inventa destinos de despliegue.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
import json
import os
import secrets
import sys
import time
import urllib.parse
import urllib.request
import ssl

from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "integrated-control"
REGISTRY = STATE / "integrations.json"
EVENTS = STATE / "events.jsonl"
FEDERATION = STATE / "federation.json"
DEPLOYMENT = STATE / "deployment.json"

STATE.mkdir(parents=True, exist_ok=True)

COMPONENTS = {
    "omega_service": [
        "omega.service",
        "omega.omega_service",
    ],
    "padge": [
        "omega.padge",
    ],
    "supervisor": [
        "omega.supervisor",
    ],
    "server": [
        "omega.server",
    ],
    "autonomous_core": [
        "omega.autonomous_core",
    ],
    "autonomous_coordinator": [
        "omega.autonomous_coordinator",
    ],
    "evolution_fabric": [
        "omega.iao_evolution_fabric",
    ],
}

CAPABILITY_NAMES = {
    "self_check": [
        "self_check", "health_check", "check_health",
    ],
    "capability_discovery": [
        "capability_scan", "discover_capabilities",
        "scan_capabilities",
    ],
    "improvement_planning": [
        "improvement_plan", "plan_improvements",
        "create_improvement_plan",
    ],
    "autonomous_execution": [
        "autonomous_cycle", "run_cycle",
        "execute_autonomous_cycle",
    ],
    "task_creation": [
        "create_task", "submit_task", "enqueue_task",
    ],
    "memory": [
        "memory_get", "get_memory", "memory_search",
    ],
    "federation": [
        "federate", "federation_sync",
        "discover_peers", "register_peer",
    ],
    "audit": [
        "audit", "audit_event", "record_event",
    ],
}

SAFE_METHODS = {
    "self_check",
    "health_check",
    "check_health",
    "capability_scan",
    "discover_capabilities",
    "scan_capabilities",
    "improvement_plan",
    "plan_improvements",
    "create_improvement_plan",
}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + secrets.token_hex(4))
    temp.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(temp, path)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def event(name: str, **data: Any) -> None:
    record = {
        "time": now(),
        "event": name,
        "data": data,
    }
    with EVENTS.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def safe_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False


class IAOIntegrator:

    def __init__(self) -> None:
        self.modules: dict[str, Any] = {}
        self.functions: dict[str, list[dict[str, Any]]] = {}
        self.objects: dict[str, Any] = {}
        self.registry = read_json(
            REGISTRY,
            {
                "version": 1,
                "created_at": now(),
                "components": {},
                "capabilities": {},
            },
        )

    def discover(self) -> dict[str, Any]:
        found = {}

        for component, candidates in COMPONENTS.items():
            selected = None
            module = None
            errors = []

            for module_name in candidates:
                try:
                    module = importlib.import_module(module_name)
                    selected = module_name
                    break
                except Exception as exc:
                    errors.append(
                        module_name + ": " + type(exc).__name__
                    )

            found[component] = {
                "available": module is not None,
                "module": selected,
                "errors": errors,
            }

            if module is not None:
                self.modules[component] = module

        event(
            "COMPONENT_DISCOVERY",
            available=[
                name for name, item in found.items()
                if item["available"]
            ],
        )

        return found

    def discover_interfaces(self) -> dict[str, Any]:
        result = {}

        for component, module in self.modules.items():
            methods = []

            for name, obj in inspect.getmembers(module):
                if name.startswith("_"):
                    continue

                if inspect.isfunction(obj) or inspect.isclass(obj):
                    try:
                        signature = str(inspect.signature(obj))
                    except (TypeError, ValueError):
                        signature = "unknown"

                    methods.append({
                        "name": name,
                        "kind": (
                            "class" if inspect.isclass(obj)
                            else "function"
                        ),
                        "signature": signature,
                    })

                elif inspect.isclass(obj):
                    try:
                        instance = obj()
                        self.objects[component] = instance
                    except Exception:
                        pass

            result[component] = methods

        self.functions = result
        return result

    def map_capabilities(self) -> dict[str, Any]:
        mapped = {}

        for capability, aliases in CAPABILITY_NAMES.items():
            matches = []

            for component, module in self.modules.items():
                for alias in aliases:
                    candidate = getattr(module, alias, None)

                    if callable(candidate):
                        try:
                            signature = str(
                                inspect.signature(candidate)
                            )
                        except (TypeError, ValueError):
                            signature = "unknown"

                        matches.append({
                            "component": component,
                            "module": module.__name__,
                            "function": alias,
                            "signature": signature,
                            "invocable_automatically": (
                                alias in SAFE_METHODS
                            ),
                        })

                    obj = self.objects.get(component)
                    if obj is not None:
                        method = getattr(obj, alias, None)
                        if callable(method):
                            matches.append({
                                "component": component,
                                "module": module.__name__,
                                "object_method": alias,
                                "invocable_automatically": (
                                    alias in SAFE_METHODS
                                ),
                            })

            mapped[capability] = {
                "available": bool(matches),
                "implementations": matches,
            }

        self.registry["capabilities"] = mapped
        return mapped

    def connect(self) -> dict[str, Any]:
        """
        Registra conexiones verificables entre módulos.
        No ejecuta métodos desconocidos.
        """
        connections = {}

        for component, module in self.modules.items():
            connections[component] = {
                "module": module.__name__,
                "loaded": True,
                "interfaces_discovered": len(
                    self.functions.get(component, [])
                ),
                "adapter": "dynamic-introspection",
                "runtime_restarted": False,
            }

        self.registry["components"] = connections
        self.registry["updated_at"] = now()

        write_json(REGISTRY, self.registry)

        event(
            "COMPONENT_ADAPTERS_REGISTERED",
            components=list(connections),
        )

        return connections

    def run_safe_planning(self) -> dict[str, Any]:
        """
        Invoca sólo métodos expresamente reconocidos como
        planificación o autocomprobación y sin argumentos obligatorios.
        """
        results = []

        for component, module in self.modules.items():
            for method_name in SAFE_METHODS:
                method = getattr(module, method_name, None)

                if not callable(method):
                    continue

                try:
                    signature = inspect.signature(method)
                    required = [
                        p for p in signature.parameters.values()
                        if p.default is inspect.Parameter.empty
                        and p.kind in (
                            inspect.Parameter.POSITIONAL_ONLY,
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        )
                    ]

                    if required:
                        results.append({
                            "component": component,
                            "method": method_name,
                            "status": "NOT_INVOKED",
                            "reason": "Required arguments",
                        })
                        continue

                    value = method()

                    results.append({
                        "component": component,
                        "method": method_name,
                        "status": "EXECUTED",
                        "result_type": type(value).__name__,
                        "result": repr(value)[:1500],
                    })

                except Exception as exc:
                    results.append({
                        "component": component,
                        "method": method_name,
                        "status": "ERROR",
                        "error": type(exc).__name__,
                    })

        event("SAFE_PLANNING_CYCLE", results=results)
        return {"results": results}

    def federation_identity(self) -> dict[str, Any]:
        identity_dir = STATE / "identity"
        identity_dir.mkdir(parents=True, exist_ok=True)
        secret_path = identity_dir / "node.key"

        if not secret_path.exists():
            secret_path.write_bytes(secrets.token_bytes(32))
            try:
                secret_path.chmod(0o600)
            except OSError:
                pass

        secret = secret_path.read_bytes()

        return {
            "node_id": sha(secret),
            "algorithm": "HMAC-SHA256",
            "private_key_exported": False,
        }

    def add_federation_proposal(
        self, endpoint: str, expected_node_id: str
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(endpoint)

        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("El nodo debe utilizar HTTPS")

        if not expected_node_id or len(expected_node_id) < 32:
            raise ValueError("Identidad esperada inválida")

        federation = read_json(
            FEDERATION,
            {"local_identity": self.federation_identity(),
             "peers": [], "proposals": []},
        )

        proposal = {
            "proposal_id": secrets.token_hex(12),
            "endpoint": endpoint,
            "expected_node_id": expected_node_id,
            "status": "PENDING_IDENTITY_VERIFICATION",
            "created_at": now(),
        }

        federation["proposals"].append(proposal)
        write_json(FEDERATION, federation)

        event(
            "FEDERATION_PROPOSAL_CREATED",
            proposal_id=proposal["proposal_id"],
        )

        return proposal

    def probe_federation(self) -> dict[str, Any]:
        federation = read_json(
            FEDERATION,
            {"peers": [], "proposals": []},
        )

        results = []

        for proposal in federation.get("proposals", []):
            endpoint = proposal["endpoint"].rstrip("/") + "/health/live"
            request = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "IAO-Federation/1.0"},
            )

            try:
                with urllib.request.urlopen(
                    request,
                    timeout=8,
                    context=ssl.create_default_context(),
                ) as response:
                    results.append({
                        "proposal_id": proposal["proposal_id"],
                        "http_status": response.status,
                        "status": "REACHABLE_IDENTITY_NOT_YET_TRUSTED",
                    })
            except Exception as exc:
                results.append({
                    "proposal_id": proposal["proposal_id"],
                    "status": "UNREACHABLE",
                    "error": type(exc).__name__,
                })

        event("FEDERATION_PROBE", results=results)
        return {"results": results}

    def boot_plan(self) -> dict[str, Any]:
        order = [
            "identity",
            "database",
            "audit",
            "omega",
            "policy_gate",
            "padge",
            "autonomous_workers",
            "federation",
            "http_api",
            "web_frontend",
        ]

        return {
            "status": "GENERATED",
            "order": order,
            "existing_processes": "PRESERVE",
            "duplicate_policy": "DO_NOT_START_DUPLICATES",
        }

    def deployment(self) -> dict[str, Any]:
        configured = {
            "public_backend": os.environ.get("IAO_PUBLIC_BACKEND_URL"),
            "public_frontend": os.environ.get("IAO_PUBLIC_FRONTEND_URL"),
            "deployment_provider": os.environ.get(
                "IAO_DEPLOYMENT_PROVIDER"
            ),
        }

        ready = bool(
            configured["public_backend"]
            and configured["public_frontend"]
            and configured["deployment_provider"]
        )

        manifest = {
            "application": "IAO",
            "entrypoint": "python -m omega.supervisor",
            "health_routes": [
                "/health/live",
                "/health/ready",
            ],
            "public_configuration": configured,
            "status": (
                "CONFIGURED_FOR_DEPLOYMENT"
                if ready else "WAITING_FOR_REAL_DEPLOYMENT_TARGET"
            ),
            "https_required": True,
            "authentication_required": True,
            "cors_must_be_explicit": True,
            "no_render": True,
        }

        write_json(DEPLOYMENT, manifest)
        return manifest

    def execute(self) -> dict[str, Any]:
        discovered = self.discover()
        interfaces = self.discover_interfaces()
        capabilities = self.map_capabilities()
        connections = self.connect()
        planning = self.run_safe_planning()

        result = {
            "timestamp": now(),
            "discovered_components": discovered,
            "interfaces": interfaces,
            "capabilities": capabilities,
            "connections": connections,
            "planning": planning,
            "identity": self.federation_identity(),
            "federation": self.probe_federation(),
            "boot": self.boot_plan(),
            "deployment": self.deployment(),
        }

        write_json(STATE / "last-run.json", result)
        event("INTEGRATION_CYCLE_FINISHED")
        return result


def main() -> int:
    control = IAOIntegrator()

    command = sys.argv[1] if len(sys.argv) > 1 else "integrate"

    if command == "integrate":
        result = control.execute()
    elif command == "status":
        result = {
            "registry": read_json(REGISTRY, {}),
            "deployment": read_json(DEPLOYMENT, {}),
            "federation": read_json(FEDERATION, {}),
        }
    elif command == "boot":
        result = control.boot_plan()
    elif command == "deploy":
        result = control.deployment()
    elif command == "federation-add":
        if len(sys.argv) != 4:
            print("Uso: federation-add https://endpoint node_id")
            return 2
        result = control.add_federation_proposal(
            sys.argv[2], sys.argv[3]
        )
    elif command == "federation-probe":
        result = control.probe_federation()
    else:
        print(
            "Comandos: integrate, status, boot, deploy, "
            "federation-add, federation-probe"
        )
        return 2

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
