"""Canonical architecture registry and contract validation for IAO.

This module defines the target architecture and maps existing implementations
to it. Inspection is read-only: it does not start workers or contact networks.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "architecture"
REPORT = STATE / "architecture-status.json"

ARCHITECTURE_ID = "IAO_DISTRIBUTED_AUTONOMOUS_V1"

SUBSYSTEMS: dict[str, dict[str, Any]] = {
    "iao_core": {
        "purpose": "Identidad, estado, memoria y coordinación global",
        "components": {
            "omega.store": ["Store"],
            "omega.autonomous_core": ["AutonomousCore"],
            "omega.autonomous_coordinator": ["AutonomousCoordinator"],
        },
    },
    "padge": {
        "purpose": "Autoprogramación, evolución y reparación del sistema completo",
        "components": {"omega.padge": ["cycle", "build", "inspect"]},
    },
    "global_discovery": {
        "purpose": "Descubrimiento de peers, servicios y nodos participantes",
        "components": {
            "omega.federation_discovery_engine": ["DiscoveryEngine"],
            "omega.federation_p2p_discovery": ["discover", "run"],
        },
    },
    "node_assimilation": {
        "purpose": "Validación e incorporación autorizada de participantes",
        "components": {
            "omega.infrastructure_assimilator": ["InfrastructureAssimilator"],
            "omega.ipfs_assimilator": ["IPFSAssimilator"],
            "omega.universal_assimilator": ["UniversalAssimilator"],
        },
    },
    "federated_identity": {
        "purpose": "Identidad criptográfica, confianza, permisos y federación",
        "components": {
            "omega.federation": ["Node", "FedServer"],
        },
    },
    "distributed_intelligence": {
        "purpose": "Enrutamiento de modelos y distribución de tareas",
        "components": {
            "omega.llm_router": ["RouterModelAdapter", "chat_with_metadata"],
            "omega.autonomous_core": ["AutonomousCore"],
        },
    },
    "distributed_memory": {
        "purpose": "Memoria persistente y conocimiento verificable",
        "components": {
            "omega.store": ["Store"],
            "omega.knowledge_store": ["ingest", "search", "status"],
        },
    },
    "replication": {
        "purpose": "Replicación íntegra de código, memoria y respaldos",
        "components": {
            "omega.store": ["Store"],
            "omega.ipfs_assimilator": ["IPFSAssimilator"],
        },
        "required_future": ["independent_replica_verification"],
    },
    "self_healing": {
        "purpose": "Detección de fallos, recuperación y rollback",
        "components": {
            "omega.padge": ["build"],
            "omega.store": ["Store"],
        },
    },
    "resource_orchestration": {
        "purpose": "Asignación de recursos voluntarios y autorizados",
        "components": {
            "omega.autonomous_core": ["AutonomousCore"],
        },
        "required_future": ["resource_lease_enforcement"],
    },
    "network_intelligence": {
        "purpose": "Topología, conectividad, capacidad y dependencias",
        "components": {
            "omega.network_intelligence": [
                "run_cycle", "discover_federation",
                "discover_infrastructure"
            ],
            "tools.iao_node_network_engine": [
                "discover", "heartbeat_all", "local_status"
            ],
            "tools.iao_p2p_autonomy_bridge": ["main"],
        },
    },
    "continuity": {
        "purpose": "Operación independiente del teléfono y continuidad federada",
        "components": {
            "tools.iao_continuity": ["cycle", "main"],
            "tools.iao_five_motor_supervisor": ["status", "run"],
        },
        "required_future": ["external_coordinator_failover"],
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _module_path(module_name: str) -> Path:
    return ROOT.joinpath(*module_name.split(".")).with_suffix(".py")


def inspect_subsystem(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    components = []
    missing = []

    for module_name, required_symbols in spec["components"].items():
        path = _module_path(module_name)
        module_result = {
            "module": module_name,
            "file_exists": path.is_file(),
            "symbols": {},
        }

        if not path.is_file():
            missing.append(module_name)
            for symbol in required_symbols:
                module_result["symbols"][symbol] = False
        else:
            try:
                source = path.read_text(encoding="utf-8")
                import ast
                tree = ast.parse(source)
                found = set()
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        found.add(node.name)
                for symbol in required_symbols:
                    ok = symbol in found
                    module_result["symbols"][symbol] = ok
                    if not ok:
                        missing.append(f"{module_name}.{symbol}")
            except Exception as exc:
                module_result["parse_error"] = repr(exc)[:500]
                missing.append(module_name)

        components.append(module_result)

    required_future = spec.get("required_future", [])
    complete = not missing and not required_future

    return {
        "name": name,
        "purpose": spec["purpose"],
        "status": (
            "IMPLEMENTED" if complete
            else "PARTIAL" if components and not all(
                not c["file_exists"] for c in components
            )
            else "MISSING"
        ),
        "components": components,
        "missing_contracts": missing,
        "future_capabilities": required_future,
    }


def inspect_architecture() -> dict[str, Any]:
    subsystems = {
        name: inspect_subsystem(name, spec)
        for name, spec in SUBSYSTEMS.items()
    }

    counts = {
        status: sum(1 for item in subsystems.values()
                    if item["status"] == status)
        for status in ("IMPLEMENTED", "PARTIAL", "MISSING")
    }

    return {
        "architecture_id": ARCHITECTURE_ID,
        "timestamp": utc_now(),
        "repository": str(ROOT),
        "mode": "READ_ONLY_CONTRACT_INSPECTION",
        "subsystems": subsystems,
        "summary": {
            "subsystem_count": len(subsystems),
            **counts,
            "external_nodes_confirmed": 0,
            "external_replicas_confirmed": 0,
            "global_autonomy_confirmed": False,
        },
    }


def save_report(report: dict[str, Any]) -> Path:
    STATE.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".architecture-", suffix=".tmp", dir=str(STATE)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, REPORT)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return REPORT


def run_inspection() -> dict[str, Any]:
    report = inspect_architecture()
    save_report(report)
    return report
