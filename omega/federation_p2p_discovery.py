"""IAO P2P: descubrimiento y autenticación de nodos externos."""

import base64
import hashlib
import json
import os
import sqlite3
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".state" / "federation"
DB = STATE / "p2p-discovery.sqlite3"

PROTOCOL = "iao-federation"
VERSION = 1
TIMEOUT = 12
MAX_RESPONSE = 65536


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode()


def initialize():
    STATE.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS peers (
            node_id TEXT PRIMARY KEY,
            endpoint TEXT NOT NULL,
            public_key TEXT NOT NULL,
            capabilities TEXT NOT NULL,
            status TEXT NOT NULL,
            last_seen INTEGER NOT NULL,
            fingerprint TEXT NOT NULL
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS discovery_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            node_id TEXT,
            event TEXT NOT NULL,
            details TEXT
        )
        """)


def record(event, node_id=None, details=None):
    with sqlite3.connect(DB) as db:
        db.execute(
            "INSERT INTO discovery_events "
            "(timestamp,node_id,event,details) VALUES (?,?,?,?)",
            (int(time.time()), node_id, event,
             json.dumps(details or {}))
        )


def fetch(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Solo se admiten endpoints HTTPS")

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "IAO-Federation/1"
        }
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise ValueError("HTTP no satisfactorio")
        data = response.read(MAX_RESPONSE + 1)

    if len(data) > MAX_RESPONSE:
        raise ValueError("Respuesta demasiado grande")

    return json.loads(data)



def validate_manifest(manifest):
    """Valida la publicación Ed25519 nativa de omega.federation.Node."""
    from math import isfinite
    from urllib.parse import urlsplit

    if not isinstance(manifest, dict):
        raise ValueError("Manifiesto inválido")

    required = {
        "protocol", "version", "node_id", "public_key",
        "endpoint", "capabilities", "issued_at",
        "lease_expires_at", "sig",
    }
    if not required.issubset(manifest):
        raise ValueError("Manifiesto incompleto")

    if manifest["protocol"] != "iao-federation-publication":
        raise ValueError("Protocolo de publicación incompatible")
    if manifest["version"] != 1:
        raise ValueError("Versión incompatible")

    endpoint = manifest["endpoint"]
    parsed = urlsplit(endpoint if isinstance(endpoint, str) else "")
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password
            or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("Endpoint público HTTPS inválido")

    try:
        key = bytes.fromhex(manifest["public_key"])
        signature = base64.b64decode(manifest["sig"], validate=True)
    except Exception as exc:
        raise ValueError("Clave o firma malformada") from exc

    if len(key) != 32 or len(signature) != 64:
        raise ValueError("Identidad Ed25519 inválida")

    short_id = hashlib.sha256(key).hexdigest()[:16]
    if manifest["node_id"] != short_id:
        raise ValueError("NODE_ID no corresponde a la clave pública")

    from cryptography.exceptions import InvalidSignature
    try:
        body = {k: v for k, v in manifest.items() if k != "sig"}
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, canonical(body)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("FIRMA_DE_PUBLICACION_INVALIDA") from exc

    issued = manifest["issued_at"]
    expires = manifest["lease_expires_at"]
    if (isinstance(issued, bool) or not isinstance(issued, (int, float))
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not isfinite(float(issued)) or not isfinite(float(expires))):
        raise ValueError("Vigencia temporal inválida")

    now = time.time()
    if float(issued) > now + 60:
        raise ValueError("Publicación emitida en el futuro")
    if float(expires) <= now or float(expires) <= float(issued):
        raise ValueError("Publicación caducada")

    caps = manifest["capabilities"]
    if (not isinstance(caps, list)
            or any(not isinstance(x, str) or not x for x in caps)):
        raise ValueError("Capacidades inválidas")

    return short_id, key


def discover(seed):
    """Descubre un FedServer, verifica publicación y prueba posesión Ed25519."""
    from urllib.parse import urlsplit
    from cryptography.hazmat.primitives import serialization
    from omega.federation import verify_identity_challenge

    seed_url = seed.rstrip("/")
    parsed_seed = urlsplit(seed_url)
    if (parsed_seed.scheme != "https" or not parsed_seed.hostname
            or parsed_seed.username or parsed_seed.password
            or parsed_seed.query or parsed_seed.fragment):
        raise ValueError("Bootstrap debe ser HTTPS")

    manifest = fetch(seed_url + "/.well-known/iao-federation.json")
    peer_id, peer_key = validate_manifest(manifest)
    endpoint = manifest["endpoint"].rstrip("/")

    # La identidad local se usa únicamente para construir el campo "from".
    local_key_path = STATE / "identity" / "private.pem"
    if not local_key_path.is_file():
        raise FileNotFoundError("No existe identidad federada local persistente")

    local_key = serialization.load_pem_private_key(
        local_key_path.read_bytes(), password=None
    )
    local_pub = local_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    requester_id = hashlib.sha256(local_pub).hexdigest()[:16]

    if requester_id == peer_id:
        raise ValueError("El bootstrap apunta a la propia identidad")

    nonce = os.urandom(32).hex()
    request_ts = float(time.time())
    challenge = {
        "v": 1,
        "from": requester_id,
        "to": peer_id,
        "nonce": nonce,
        "ts": request_ts,
    }

    req = urllib.request.Request(
        endpoint + "/fed/v1/handshake",
        data=canonical(challenge),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "IAO-Federation/1",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise ValueError("Handshake HTTP no satisfactorio")
        raw_answer = response.read(MAX_RESPONSE + 1)

    if len(raw_answer) > MAX_RESPONSE:
        raise ValueError("Respuesta de handshake demasiado grande")
    answer = json.loads(raw_answer)

    identity_doc = {
        "protocol": "iao-federation",
        "version": 1,
        "node_id": peer_id,
        "public_key": peer_key.hex(),
    }
    verified = verify_identity_challenge(
        identity_doc,
        answer,
        requester_id=requester_id,
        nonce=nonce,
        request_ts=request_ts,
        now=time.time(),
        skew=60.0,
    )
    if not verified.get("ok"):
        raise ValueError("HANDSHAKE_RECHAZADO:" + str(verified.get("error")))

    fingerprint = hashlib.sha256(peer_key).hexdigest()

    with sqlite3.connect(DB) as db:
        old = db.execute(
            "SELECT fingerprint FROM peers WHERE node_id=?", (peer_id,)
        ).fetchone()
        if old and old[0] != fingerprint:
            raise ValueError("CAMBIO DE IDENTIDAD: cuarentena")

        db.execute("""
        INSERT INTO peers
        (node_id,endpoint,public_key,capabilities,status,last_seen,fingerprint)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(node_id) DO UPDATE SET
          endpoint=excluded.endpoint,
          public_key=excluded.public_key,
          capabilities=excluded.capabilities,
          status='AUTHENTICATED_CANDIDATE',
          last_seen=excluded.last_seen,
          fingerprint=excluded.fingerprint
        """, (
            peer_id, endpoint, peer_key.hex(),
            json.dumps(manifest["capabilities"]),
            "AUTHENTICATED_CANDIDATE", int(time.time()), fingerprint
        ))

    record("AUTHENTICATED_CANDIDATE", peer_id, {
        "endpoint": endpoint,
        "fingerprint": fingerprint,
        "handshake": "ED25519_VERIFIED",
    })
    return peer_id



def run():
    initialize()
    seeds = [
        x.strip() for x in
        os.environ.get("IAO_P2P_BOOTSTRAP_URLS", "").split(",")
        if x.strip()
    ]

    if not seeds:
        print("SIN_BOOTSTRAP: configura directorios P2P participantes")
        return 2

    successes = 0
    for seed in seeds:
        try:
            identity = discover(seed)
            print("NODO AUTENTICADO:", identity)
            successes += 1
        except Exception as exc:
            record("DISCOVERY_REJECTED", details={
                "seed": seed,
                "error": str(exc)[:300]
            })
            print("RECHAZADO:", seed, str(exc)[:200])

    print("NODOS AUTENTICADOS:", successes)
    print("BASE:", DB)
    return 0 if successes else 1


if __name__ == "__main__":
    raise SystemExit(run())
