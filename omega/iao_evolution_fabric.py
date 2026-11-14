"""
IAO Evolution Fabric
Núcleo extensible de evolución autónoma y federación.

Este módulo no inicia procesos ni altera el runtime al importarse.
Las acciones se ejecutan únicamente mediante llamadas explícitas.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable


VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "evolution_fabric"
WORK = STATE / "work"
VERSIONS = STATE / "versions"
EVENTS = STATE / "events.jsonl"
NODES = STATE / "federation" / "nodes.json"
PROPOSALS = STATE / "federation" / "proposals.jsonl"

for directory in (STATE, WORK, VERSIONS, NODES.parent):
    directory.mkdir(parents=True, exist_ok=True)


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    temporary.write_bytes(data)
    os.replace(temporary, path)


def append_event(kind: str, data: dict[str, Any]) -> None:
    event = {
        "timestamp": utc(),
        "kind": kind,
        "data": data,
    }
    encoded = json.dumps(
        event, ensure_ascii=False, sort_keys=True
    ).encode("utf-8")
    with EVENTS.open("ab") as stream:
        stream.write(encoded + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


@dataclass
class Capability:
    name: str
    enabled: bool
    description: str
    adapter: str | None = None


@dataclass
class EvolutionTask:
    task_id: str
    objective: str
    operation: str
    status: str = "PROPOSED"
    created_at: str = field(default_factory=utc)
    result: dict[str, Any] = field(default_factory=dict)


class EvolutionFabric:
    """
    Control plane extensible para evolución y federación.

    No concede autoridad arbitraria al código generado.
    No ejecuta código candidato directamente.
    """

    def __init__(self, root: Path | str = ROOT):
        self.root = Path(root).resolve()
        self.state = self.root / ".state" / "evolution_fabric"
        self.work = self.state / "work"
        self.versions = self.state / "versions"
        self.events = self.state / "events.jsonl"
        self.nodes_file = self.state / "federation" / "nodes.json"
        self.proposals_file = (
            self.state / "federation" / "proposals.jsonl"
        )

        for path in (
            self.work,
            self.versions,
            self.nodes_file.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)

        self.adapters: dict[str, Callable[..., Any]] = {}
        self.capabilities = self._capability_map()

    def _event(self, kind: str, **data: Any) -> None:
        event = {
            "timestamp": utc(),
            "kind": kind,
            "data": data,
        }
        with self.events.open("ab") as stream:
            stream.write(
                json.dumps(event, sort_keys=True).encode() + b"\n"
            )
            stream.flush()
            os.fsync(stream.fileno())

    def _capability_map(self) -> dict[str, Capability]:
        return {
            "autoprogramming": Capability(
                "autoprogramming", True,
                "Planificación, generación y validación de cambios"
            ),
            "self_repair": Capability(
                "self_repair", True,
                "Preparación de reparaciones reversibles"
            ),
            "federation": Capability(
                "federation", True,
                "Identidad, descubrimiento y propuestas de pares"
            ),
            "component_coupling": Capability(
                "component_coupling", True,
                "Adaptadores explícitos para componentes IAO"
            ),
            "coordinated_boot": Capability(
                "coordinated_boot", True,
                "Planificación de arranque sin duplicar procesos"
            ),
            "internet_deployment": Capability(
                "internet_deployment", True,
                "Generación de manifiestos de despliegue"
            ),
        }

    def register_adapter(
        self, name: str, callback: Callable[..., Any]
    ) -> None:
        if not name or not callable(callback):
            raise ValueError("Adaptador inválido")
        self.adapters[name] = callback
        self._event("ADAPTER_REGISTERED", name=name)

    def inventory(self) -> dict[str, Any]:
        components = {
            "omega": self.root / "omega",
            "padge": self.root / "omega" / "padge.py",
            "supervisor": self.root / "omega" / "supervisor.py",
            "server": self.root / "omega" / "server.py",
            "tools": self.root / "tools",
            "web": self.root / "web",
        }

        result = {}
        for name, path in components.items():
            result[name] = {
                "exists": path.exists(),
                "path": str(path.relative_to(self.root)),
                "kind": "directory" if path.is_dir() else "file",
            }

        return {
            "fabric_version": VERSION,
            "components": result,
            "adapters": sorted(self.adapters),
            "capabilities": {
                key: asdict(value)
                for key, value in self.capabilities.items()
            },
        }

    def create_task(
        self, objective: str, operation: str = "research"
    ) -> EvolutionTask:
        if not objective.strip():
            raise ValueError("Objetivo vacío")

        allowed = {
            "research",
            "generate",
            "validate",
            "repair_proposal",
            "federation",
            "integration_proposal",
            "deployment_plan",
        }
        if operation not in allowed:
            raise ValueError("Operación no permitida")

        task = EvolutionTask(
            task_id=secrets.token_hex(12),
            objective=objective,
            operation=operation,
        )

        path = self.work / (task.task_id + ".json")
        atomic_write(
            path,
            json.dumps(asdict(task), indent=2).encode("utf-8"),
        )
        self._event(
            "TASK_CREATED",
            task_id=task.task_id,
            operation=operation,
        )
        return task

    def update_task(
        self, task_id: str, status: str,
        result: dict[str, Any] | None = None
    ) -> None:
        path = self.work / (task_id + ".json")
        if not path.is_file():
            raise FileNotFoundError(task_id)

        task = json.loads(path.read_text(encoding="utf-8"))
        task["status"] = status
        task["result"] = result or {}
        atomic_write(
            path,
            json.dumps(task, indent=2).encode("utf-8"),
        )
        self._event("TASK_UPDATED", task_id=task_id, status=status)

    def propose_code(
        self, relative_path: str, source: str
    ) -> dict[str, Any]:
        """
        Guarda un candidato sin modificar el archivo de producción.
        Valida sintaxis y aplica comprobaciones estáticas básicas.
        """
        target = (self.root / relative_path).resolve()

        if self.root not in target.parents:
            raise ValueError("Ruta fuera del repositorio")

        if not relative_path.endswith(".py"):
            raise ValueError("Sólo se admiten candidatos Python")

        if not isinstance(source, str) or not source.strip():
            raise ValueError("Código vacío")

        try:
            tree = ast.parse(source, filename=relative_path)
        except SyntaxError as exc:
            self._event(
                "CANDIDATE_REJECTED_SYNTAX",
                path=relative_path,
                error=str(exc),
            )
            raise

        dangerous = {
            "eval", "exec", "compile", "__import__",
        }
        found = sorted({
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in dangerous
        })

        candidate_id = secrets.token_hex(12)
        candidate_dir = self.versions / candidate_id
        candidate_dir.mkdir(parents=True, exist_ok=False)

        code_path = candidate_dir / target.name
        code_path.write_text(source, encoding="utf-8")

        report = {
            "candidate_id": candidate_id,
            "target": relative_path,
            "created_at": utc(),
            "sha256": digest(source.encode()),
            "syntax_valid": True,
            "dangerous_calls": found,
            "status": "CANDIDATE",
            "production_modified": False,
        }

        atomic_write(
            candidate_dir / "candidate.json",
            json.dumps(report, indent=2).encode(),
        )
        self._event(
            "CODE_CANDIDATE_CREATED",
            candidate_id=candidate_id,
            target=relative_path,
            dangerous_calls=found,
        )
        return report

    def validate_candidate(self, candidate_id: str) -> dict[str, Any]:
        candidate_dir = self.versions / candidate_id
        metadata = candidate_dir / "candidate.json"

        if not metadata.is_file():
            raise FileNotFoundError(candidate_id)

        report = json.loads(metadata.read_text())
        code_path = candidate_dir / Path(report["target"]).name
        source = code_path.read_text(encoding="utf-8")

        ast.parse(source)
        current_hash = digest(source.encode())
        if current_hash != report["sha256"]:
            raise ValueError("El hash del candidato cambió")

        checks = {
            "syntax": True,
            "hash": True,
            "inside_repository": True,
            "dangerous_calls_absent": not report["dangerous_calls"],
        }

        report["validation"] = checks
        report["status"] = (
            "VALIDATED"
            if all(checks.values())
            else "REQUIRES_REVIEW"
        )

        atomic_write(
            metadata,
            json.dumps(report, indent=2).encode(),
        )
        self._event(
            "CANDIDATE_VALIDATED",
            candidate_id=candidate_id,
            checks=checks,
        )
        return report

    def promote_candidate(
        self, candidate_id: str, authorized: bool = False
    ) -> dict[str, Any]:
        """
        La promoción requiere autorización explícita.
        No se ejecuta durante la generación ni validación.
        """
        if authorized is not True:
            raise PermissionError(
                "La promoción requiere autorización administrativa"
            )

        candidate_dir = self.versions / candidate_id
        metadata_path = candidate_dir / "candidate.json"
        if not metadata_path.is_file():
            raise FileNotFoundError(candidate_id)

        report = json.loads(metadata_path.read_text())
        if report.get("status") != "VALIDATED":
            raise ValueError("Candidato no validado")

        if not all(report.get("validation", {}).values()):
            raise ValueError("Validación incompleta")

        target = (self.root / report["target"]).resolve()
        if self.root not in target.parents:
            raise ValueError("Ruta fuera del repositorio")

        if target.exists():
            raise FileExistsError(
                "No se sobrescribe producción automáticamente"
            )

        source = candidate_dir / target.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

        self._event(
            "CANDIDATE_PROMOTED",
            candidate_id=candidate_id,
            target=report["target"],
        )
        return {
            "status": "PROMOTED",
            "target": report["target"],
        }

    def local_identity(self) -> dict[str, str]:
        """
        Identidad persistente. La clave privada nunca se exporta.
        """
        identity_dir = self.state / "identity"
        identity_dir.mkdir(parents=True, exist_ok=True)
        secret_file = identity_dir / "node-secret"

        if not secret_file.exists():
            atomic_write(secret_file, secrets.token_bytes(32))
            try:
                secret_file.chmod(0o600)
            except OSError:
                pass

        secret = secret_file.read_bytes()
        node_id = digest(secret)

        return {
            "node_id": node_id,
            "algorithm": "HMAC-SHA256",
            "secret_storage": "local_private_file",
        }

    def sign_message(self, payload: dict[str, Any]) -> str:
        secret_file = self.state / "identity" / "node-secret"
        if not secret_file.is_file():
            self.local_identity()

        secret = secret_file.read_bytes()
        message = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode()
        return hmac.new(secret, message, hashlib.sha256).hexdigest()

    def verify_local_message(
        self, payload: dict[str, Any], signature: str
    ) -> bool:
        expected = self.sign_message(payload)
        return hmac.compare_digest(expected, signature)

    def propose_peer(
        self, endpoint: str, peer_id: str,
        transport: str = "https"
    ) -> dict[str, Any]:
        """
        Registra una propuesta. No incorpora automáticamente el nodo.
        """
        if transport != "https":
            raise ValueError("Sólo se admiten pares HTTPS")

        from urllib.parse import urlparse
        parsed = urlparse(endpoint)

        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Endpoint HTTPS inválido")

        proposal = {
            "proposal_id": secrets.token_hex(12),
            "created_at": utc(),
            "endpoint": endpoint,
            "peer_id": peer_id,
            "transport": transport,
            "status": "PENDING_VERIFICATION",
        }

        with self.proposals_file.open("ab") as stream:
            stream.write(json.dumps(proposal).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

        self._event(
            "FEDERATION_PEER_PROPOSED",
            proposal_id=proposal["proposal_id"],
            peer_id=peer_id,
        )
        return proposal

    def approve_peer(
        self, proposal_id: str,
        verified_peer_id: str,
        authorized: bool = False
    ) -> dict[str, Any]:
        if not authorized:
            raise PermissionError(
                "La incorporación exige autorización administrativa"
            )

        proposals = []
        selected = None

        if self.proposals_file.exists():
            for line in self.proposals_file.read_text().splitlines():
                try:
                    item = json.loads(line)
                    if item["proposal_id"] == proposal_id:
                        selected = item
                    else:
                        proposals.append(item)
                except ValueError:
                    continue

        if selected is None:
            raise FileNotFoundError(proposal_id)

        if selected["peer_id"] != verified_peer_id:
            raise PermissionError("La identidad del par no coincide")

        selected["status"] = "APPROVED"
        selected["verified_at"] = utc()
        proposals.append(selected)

        registry = load_json(self.nodes_file, {"nodes": []})
        if any(
            node["peer_id"] == verified_peer_id
            for node in registry["nodes"]
        ):
            raise ValueError("El nodo ya está registrado")

        registry["nodes"].append({
            "peer_id": verified_peer_id,
            "endpoint": selected["endpoint"],
            "transport": "https",
            "approved_at": utc(),
            "status": "REGISTERED",
        })

        atomic_write(
            self.nodes_file,
            json.dumps(registry, indent=2).encode(),
        )
        self._event("FEDERATION_PEER_APPROVED", peer_id=verified_peer_id)

        return {"status": "REGISTERED", "peer_id": verified_peer_id}

    def federation_nodes(self) -> list[dict[str, Any]]:
        return load_json(self.nodes_file, {"nodes": []}).get(
            "nodes", []
        )

    def https_request(
        self, endpoint: str, payload: dict[str, Any],
        timeout: int = 15
    ) -> dict[str, Any]:
        """
        Comunicación autenticada a nivel de transporte TLS.
        La identidad de aplicación debe verificarse por el protocolo
        del nodo remoto antes de confiar en sus respuestas.
        """
        from urllib.parse import urlparse
        parsed = urlparse(endpoint)

        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Se exige endpoint HTTPS")

        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(
                request, timeout=timeout, context=context
            ) as response:
                raw = response.read(1024 * 1024)
                return {
                    "http_status": response.status,
                    "body": raw.decode("utf-8", errors="replace"),
                }
        except urllib.error.HTTPError as exc:
            return {
                "http_status": exc.code,
                "body": exc.read(4096).decode(
                    "utf-8", errors="replace"
                ),
            }

    def component_plan(self) -> dict[str, Any]:
        inventory = self.inventory()
        existing = inventory["components"]

        plan = []
        for name, item in existing.items():
            plan.append({
                "component": name,
                "present": item["exists"],
                "action": (
                    "CONNECT_THROUGH_ADAPTER"
                    if item["exists"]
                    else "MISSING_COMPONENT"
                ),
                "automatic_execution": False,
            })

        return {
            "status": "PLAN_ONLY",
            "components": plan,
            "registered_adapters": sorted(self.adapters),
        }

    def boot_plan(self) -> dict[str, Any]:
        """
        Describe dependencias sin arrancar ni reiniciar procesos.
        """
        order = [
            "identity",
            "audit",
            "database",
            "omega",
            "policy",
            "padge",
            "workers",
            "federation",
            "api",
            "web",
        ]

        return {
            "status": "PLAN_ONLY",
            "order": order,
            "restart_existing_processes": False,
            "duplicate_process_policy": "DO_NOT_START_IF_ALREADY_ACTIVE",
        }

    def deployment_manifest(self) -> dict[str, Any]:
        """
        Manifiesto neutral. No presupone proveedor ni publica servicios.
        """
        return {
            "application": "IAO",
            "version": VERSION,
            "runtime": "python",
            "entrypoint": "python -m omega.supervisor",
            "health": [
                "/health/live",
                "/health/ready",
            ],
            "network": {
                "public_transport": "HTTPS",
                "authentication_required": True,
                "cors": "EXPLICIT_ORIGINS_ONLY",
            },
            "secrets": "EXTERNAL_SECRET_STORE_OR_PRIVATE_ENVIRONMENT",
            "persistent_paths": [
                ".state",
                "~/.config/iao",
            ],
            "deployment_status": "NOT_DEPLOYED",
            "provider": None,
            "reason": (
                "Proveedor y credenciales no configurados "
                "en este manifiesto"
            ),
        }

    def autonomous_cycle(
        self, objective: str
    ) -> dict[str, Any]:
        """
        Ciclo autónomo seguro: crea una tarea y la planifica.
        No ejecuta código generado ni despliega por sí mismo.
        """
        task = self.create_task(objective, "research")
        self.update_task(
            task.task_id,
            "PLANNED",
            {
                "next_steps": [
                    "research",
                    "design",
                    "generate_candidate",
                    "validate_candidate",
                    "request_promotion_authorization",
                ]
            },
        )
        self._event(
            "AUTONOMOUS_CYCLE_PLANNED",
            task_id=task.task_id,
            objective=objective,
        )
        return {
            "task_id": task.task_id,
            "status": "PLANNED",
            "next_steps": [
                "research",
                "design",
                "generate_candidate",
                "validate_candidate",
                "request_promotion_authorization",
            ],
        }

    def status(self) -> dict[str, Any]:
        identity = self.local_identity()
        return {
            "version": VERSION,
            "identity": identity,
            "inventory": self.inventory(),
            "federation_nodes": self.federation_nodes(),
            "component_plan": self.component_plan(),
            "boot_plan": self.boot_plan(),
            "deployment": self.deployment_manifest(),
        }


def main() -> int:
    fabric = EvolutionFabric()
    if len(sys.argv) < 2:
        print(json.dumps(fabric.status(), indent=2))
        return 0

    command = sys.argv[1]

    if command == "status":
        result = fabric.status()
    elif command == "boot-plan":
        result = fabric.boot_plan()
    elif command == "component-plan":
        result = fabric.component_plan()
    elif command == "deployment":
        result = fabric.deployment_manifest()
    elif command == "cycle":
        objective = " ".join(sys.argv[2:]).strip()
        if not objective:
            print("Uso: cycle <objetivo>")
            return 2
        result = fabric.autonomous_cycle(objective)
    elif command == "identity":
        result = fabric.local_identity()
    else:
        print(
            "Comandos: status, boot-plan, component-plan, "
            "deployment, cycle, identity"
        )
        return 2

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
