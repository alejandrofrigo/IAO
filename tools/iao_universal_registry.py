#!/usr/bin/env python3
"""Registro universal y progresivo de recursos para la Red IAO."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
REGISTRY = STATE / "iao-universal-registry.json"

KINDS = (
    "api", "model", "agent", "compute",
    "repository", "knowledge", "mcp", "iao_peer", "other",
)
ADAPTERS = {
    "api": ["rest", "graphql", "openapi", "custom_http"],
    "model": ["openai_compatible", "anthropic", "gemini", "custom_model"],
    "agent": ["mcp", "http_agent", "custom_agent"],
    "compute": ["iao_federation", "ssh_managed", "container_api", "custom_compute"],
    "repository": ["git", "github", "gitlab", "source_archive"],
    "knowledge": ["web", "docs", "git", "database", "custom_knowledge"],
    "mcp": ["mcp_stdio", "mcp_http", "custom_mcp"],
    "iao_peer": ["iao_federation"],
    "other": ["custom"],
}
STAGES = ("DISCOVERED", "ASSESSED", "INTEGRATED", "ASSIMILATED", "QUARANTINED")


def now():
    return datetime.now(timezone.utc).isoformat()


def load():
    if not REGISTRY.exists():
        return {
            "schema": "IAO_UNIVERSAL_REGISTRY_V1",
            "created_at": now(),
            "policy": {
                "single_manifest_required": False,
                "single_protocol_required": False,
                "heterogeneous_adapters": True,
                "progressive_assimilation": True,
                "secrets_must_not_be_stored": True,
                "unverified_resources_count_as_active": False,
            },
            "adapter_catalog": ADAPTERS,
            "resources": [],
        }
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
        raise ValueError("Registro existente inválido; no se modificó.")
    return data


def save(data):
    STATE.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".iao-registry-", dir=STATE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, REGISTRY)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def validate_url(value):
    """Valida una URL HTTPS sin realizar conexiones de red.

    La resolución DNS debe comprobarse de nuevo al conectar y sus
    direcciones deben fijarse para evitar DNS rebinding.
    """
    if not value:
        return None
    if not isinstance(value, str):
        raise ValueError("La URL debe ser texto.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("La URL contiene caracteres de control.")
    if any(char.isspace() for char in value):
        raise ValueError("La URL no puede contener espacios.")

    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL o puerto inválido.") from exc

    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Las URL remotas deben usar HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError("No se permiten credenciales dentro de la URL.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Puerto fuera de rango.")

    host = parsed.hostname.rstrip(".").lower()
    forbidden_suffixes = (
        ".localhost", ".local", ".internal", ".home.arpa",
    )
    if host == "localhost" or host.endswith(forbidden_suffixes):
        raise ValueError("No se permiten nombres de host locales.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Nombre de host inválido.") from exc

        labels = ascii_host.split(".")
        valid = (
            "." in ascii_host
            and len(ascii_host) <= 253
            and not all(label.isdigit() for label in labels)
            and all(
                label
                and len(label) <= 63
                and label[0].isalnum()
                and label[-1].isalnum()
                and all(ch.isalnum() or ch == "-" for ch in label)
                for label in labels
            )
        )
        if not valid:
            raise ValueError("Nombre de host inválido o ambiguo.")
    else:
        if not address.is_global:
            raise ValueError("No se permiten IP privadas o no globales.")

    return value


def validate_public_dns(host, resolver=None):
    """Comprobación DNS previa a conexión; no sustituye fijar la IP."""
    resolver = resolver or socket.getaddrinfo
    try:
        records = resolver(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("No se pudo resolver el host.") from exc

    addresses = set()
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError("Respuesta DNS inválida.") from exc
        if not address.is_global:
            raise ValueError("DNS apunta a una IP privada o no global.")
        addresses.add(str(address))

    if not addresses:
        raise ValueError("El host no tiene direcciones DNS utilizables.")
    return tuple(sorted(addresses))


def add_resource(args):
    data = load()
    url = validate_url(args.url)
    kind = args.kind
    adapter = args.adapter or ADAPTERS[kind][0]
    if adapter not in ADAPTERS[kind]:
        raise ValueError(f"Adaptador no válido para {kind}: {adapter}")

    identity = f"{kind}|{args.name.strip()}|{url or ''}"
    rid = hashlib.sha256(identity.encode()).hexdigest()[:20]
    existing = next((x for x in data["resources"] if x["id"] == rid), None)
    if existing:
        print(json.dumps({"result": "ALREADY_REGISTERED", "resource": existing},
                         ensure_ascii=False, indent=2))
        return

    item = {
        "id": rid,
        "name": args.name.strip(),
        "kind": kind,
        "url": url,
        "adapter": adapter,
        "capabilities": sorted(set(args.capabilities or [])),
        "permission_status": args.permission,
        "stage": "DISCOVERED",
        "checks": {
            "identity_verified": False,
            "permission_verified": False,
            "adapter_tested": False,
            "real_exchange_confirmed": False,
        },
        "evidence": [],
        "created_at": now(),
        "updated_at": now(),
        "notes": args.notes or "",
    }
    data["resources"].append(item)
    save(data)
    print(json.dumps({"result": "REGISTERED_AS_DISCOVERED", "resource": item},
                     ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Crear el registro si todavía no existe.")
    sub.add_parser("status", help="Resumen de recursos por etapa.")
    sub.add_parser("list", help="Mostrar recursos registrados.")

    add = sub.add_parser("add", help="Registrar un recurso heterogéneo.")
    add.add_argument("--name", required=True)
    add.add_argument("--kind", required=True, choices=KINDS)
    add.add_argument("--url")
    add.add_argument("--adapter", choices=None)
    add.add_argument("--capability", action="append")
    add.add_argument(
        "--permission",
        choices=("unknown", "public_service", "declared", "signed"),
        default="unknown",
    )
    add.add_argument("--notes", default="")

    args = parser.parse_args()
    try:
        if args.command == "init":
            existed = REGISTRY.exists()
            data = load()
            if not existed:
                save(data)
            print(f"REGISTRY={'EXISTING_PRESERVED' if existed else 'CREATED'}")
            print(f"PATH={REGISTRY}")
        elif args.command == "add":
            add_resource(args)
        else:
            data = load()
            if args.command == "list":
                print(json.dumps(data["resources"], ensure_ascii=False, indent=2))
            else:
                counts = {stage: 0 for stage in STAGES}
                for item in data["resources"]:
                    counts[item.get("stage", "DISCOVERED")] = (
                        counts.get(item.get("stage", "DISCOVERED"), 0) + 1
                    )
                print(json.dumps({
                    "schema": data.get("schema"),
                    "total": len(data["resources"]),
                    "by_stage": counts,
                    "single_manifest_required": data.get("policy", {}).get(
                        "single_manifest_required"
                    ),
                    "single_protocol_required": data.get("policy", {}).get(
                        "single_protocol_required"
                    ),
                    "active_resources": sum(
                        1 for x in data["resources"]
                        if x.get("stage") == "ASSIMILATED"
                        and x.get("checks", {}).get("real_exchange_confirmed")
                    ),
                }, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
