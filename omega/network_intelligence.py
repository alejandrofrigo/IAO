"""Coordinador de descubrimiento de la arquitectura distribuida IAO.

Los candidatos descubiertos no se consideran nodos incorporados.
La incorporación requiere identidad, autorización y evidencia adicional.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "network-intelligence"
REPORT = STATE / "discovery-report.json"
RUNTIME = STATE / "runtime.json"
LOCK = STATE / "cycle.lock"

MIN_INTERVAL = 300
FEDERATION_TIMEOUT = 120
INFRASTRUCTURE_TIMEOUT = 150


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".iao-network-",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_runtime() -> dict[str, Any]:
    try:
        data = json.loads(RUNTIME.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def configured_bootstrap_count() -> int:
    return sum(
        1 for item in os.environ.get(
            "IAO_P2P_BOOTSTRAP_URLS", ""
        ).split(",")
        if item.strip()
    )


def discover_federation() -> dict[str, Any]:
    """Ejecuta el protocolo de descubrimiento federado configurado."""
    count = configured_bootstrap_count()

    if count == 0:
        return {
            "status": "NO_BOOTSTRAP_CONFIGURED",
            "configured_bootstraps": 0,
            "authenticated_candidates": None,
        }

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "omega.federation_p2p_discovery",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=FEDERATION_TIMEOUT,
            check=False,
        )
        return {
            "status": (
                "DISCOVERY_COMMAND_COMPLETED_UNVERIFIED"
                if result.returncode == 0
                else "DISCOVERY_INCOMPLETE_OR_REJECTED"
            ),
            "return_code": result.returncode,
            "configured_bootstraps": count,
            "authenticated_candidates": None,
            "identity_verification": "NOT_ESTABLISHED_BY_EXIT_CODE",
            "output_tail": (result.stdout or "")[-2500:],
            "error_tail": (result.stderr or "")[-1200:],
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT",
            "configured_bootstraps": count,
            "authenticated_candidates": None,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "configured_bootstraps": count,
            "authenticated_candidates": None,
        }


def discover_infrastructure() -> dict[str, Any]:
    """Busca y registra candidatos sin declararlos operativos."""
    code = (
        "from omega.infrastructure_assimilator import "
        "InfrastructureAssimilator; "
        "obj=InfrastructureAssimilator(); "
        "added=obj.assimilate(); "
        "print('CANDIDATES_ADDED=', added)"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=INFRASTRUCTURE_TIMEOUT,
            check=False,
        )
        stdout = result.stdout or ""
        match = re.search(
            r"CANDIDATES_ADDED\s*=\s*(\d+)",
            stdout,
        )
        added = int(match.group(1)) if match else None

        if result.returncode != 0:
            status = "DISCOVERY_FAILED"
        elif added is None:
            status = "OUTPUT_UNPARSEABLE"
        elif added > 0:
            status = "CANDIDATES_FOUND"
        else:
            status = "SEARCH_COMPLETED_NO_CANDIDATES"

        return {
            "status": status,
            "return_code": result.returncode,
            "candidates_added": added,
            "candidate_count_is_verified_from_output": added is not None,
            "output_tail": stdout[-2500:],
            "error_tail": (result.stderr or "")[-1200:],
            "operational_nodes_confirmed": 0,
            "enrollment_confirmed": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT",
            "operational_nodes_confirmed": 0,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "operational_nodes_confirmed": 0,
        }


def read_ipfs_evidence(max_age_seconds: int = 900) -> dict[str, Any]:
    """Lee evidencia reciente de Kubo; no ejecuta comandos de red."""
    path = ROOT / ".state" / "p2p-rollout" / "padge-p2p-bridge.json"

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"status": "INVALID_BRIDGE_REPORT"}

        if data.get("schema") != "IAO_PADGE_IPFS_P2P_BRIDGE_V1":
            return {"status": "UNRECOGNIZED_REPORT"}

        timestamp = float(data.get("timestamp", 0))
        age = max(0, time.time() - timestamp)
        if timestamp <= 0 or age > max_age_seconds:
            return {
                "status": "STALE_REPORT",
                "age_seconds": round(age, 1),
            }

        peers = data.get("connected_peer_count", 0)
        providers = data.get("external_provider_count", 0)
        if not isinstance(peers, int) or peers < 0:
            peers = 0
        if not isinstance(providers, int) or providers < 0:
            providers = 0

        sample = data.get("connected_peer_sample", [])
        if not isinstance(sample, list):
            sample = []

        return {
            "status": "FRESH_EVIDENCE",
            "age_seconds": round(age, 1),
            "local_peer_id": data.get("local_peer_id"),
            "connected_peer_count": peers,
            "connected_peer_sample": sample[:15],
            "release_cid": data.get("release_cid"),
            "release_block_available": bool(
                data.get("release_block_available")
            ),
            "release_pin_available": bool(
                data.get("release_pin_available")
            ),
            "provider_announcement": data.get(
                "recursive_provider_announcement", "UNKNOWN"
            ),
            "external_provider_observed_count": providers,
            "external_replication_confirmed": False,
            "external_transfer_confirmed": False,
            "peer_identity_as_iao_node": False,
            "evidence_rule": (
                "IPFS_PEER_OR_PROVIDER_IS_NOT_AUTHENTICATED_IAO_NODE"
            ),
        }
    except FileNotFoundError:
        return {"status": "NO_BRIDGE_REPORT"}
    except (OSError, ValueError, TypeError):
        return {"status": "INVALID_BRIDGE_REPORT"}


def run_cycle(force: bool = False) -> dict[str, Any]:
    """Un ciclo único, limitado y serializado de inteligencia de red."""
    STATE.mkdir(parents=True, exist_ok=True)

    with LOCK.open("a+", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(
                lock_handle.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            return {"status": "ALREADY_RUNNING"}

        previous = _read_runtime()
        now = time.time()
        last_run = float(previous.get("last_run", 0) or 0)

        if not force and now - last_run < MIN_INTERVAL:
            return {
                "status": "INTERVAL_NOT_REACHED",
                "seconds_remaining": max(
                    0, int(MIN_INTERVAL - (now - last_run))
                ),
            }

        # Reservar el ciclo antes de iniciar operaciones de red.
        runtime = {
            "last_run": now,
            "status": "RUNNING",
            "architecture": "IAO_DISTRIBUTED_AUTONOMOUS_V1",
        }
        _atomic_json(RUNTIME, runtime)

        report: dict[str, Any] = {
            "schema": "IAO_NETWORK_INTELLIGENCE_V1",
            "timestamp": now,
            "status": "RUNNING",
            "discovery": {},
            "evidence": {
                "discovered_candidates_are_not_nodes": True,
                "identity_verified_requires_signed_handshake": True,
                "external_enrollment_confirmed": False,
                "external_execution_confirmed": False,
                "external_replication_confirmed": False,
            },
        }

        try:
            report["discovery"]["federation"] = discover_federation()
        except Exception as exc:
            report["discovery"]["federation"] = {
                "status": "ERROR",
                "error_type": type(exc).__name__,
            }

        try:
            report["discovery"]["infrastructure"] = (
                discover_infrastructure()
            )
        except Exception as exc:
            report["discovery"]["infrastructure"] = {
                "status": "ERROR",
                "error_type": type(exc).__name__,
                "operational_nodes_confirmed": 0,
            }

        # Evidencia generada por el puente que ejecuta PADGE.
        report["discovery"]["ipfs"] = read_ipfs_evidence()

        federation = report["discovery"]["federation"]
        infrastructure = report["discovery"]["infrastructure"]
        ipfs = report["discovery"]["ipfs"]

        added = infrastructure.get("candidates_added")
        peers = ipfs.get("connected_peer_count", 0)
        providers = ipfs.get("external_provider_observed_count", 0)

        evidence_observed = (
            (isinstance(added, int) and added > 0)
            or (isinstance(peers, int) and peers > 0)
            or (isinstance(providers, int) and providers > 0)
        )

        report["evidence"].update({
            "ipfs_peer_count_is_not_iao_node_count": True,
            "provider_announcement_is_not_replica_proof": True,
            "external_provider_observed_count": providers,
            "external_replication_confirmed": False,
            "external_transfer_confirmed": False,
            "external_enrollment_confirmed": False,
            "external_execution_confirmed": False,
        })

        if evidence_observed:
            report["status"] = "NETWORK_EVIDENCE_OBSERVED"
        elif (
            federation.get("status") == "NO_BOOTSTRAP_CONFIGURED"
            and infrastructure.get("status")
                == "SEARCH_COMPLETED_NO_CANDIDATES"
        ):
            report["status"] = "NO_EXTERNAL_DISCOVERY"
        else:
            report["status"] = "DEGRADED_NO_VERIFIED_DISCOVERY"

        report["finished_at"] = time.time()
        _atomic_json(REPORT, report)

        runtime.update({
            "status": report["status"],
            "finished_at": report["finished_at"],
            "report": str(REPORT.relative_to(ROOT)),
        })
        _atomic_json(RUNTIME, runtime)

        return report


if __name__ == "__main__":
    result = run_cycle(force=True)
    print(json.dumps(result, ensure_ascii=False, indent=2))
