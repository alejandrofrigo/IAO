#!/usr/bin/env python3
"""
Test end-to-end del bridge Nostr <-> iao-federation.

Genera una clave Nostr (secp256k1/schnorr via chaincraft), firma un evento
kind:1 con IAO_FEDERATION_AUTHORIZE:<bridge_pubkey>, lo inyecta como candidato
en iao-external-nodes.json, y ejecuta el pipeline. Verifica:

  1. Firma Schnorr valida -> verify_nostr_event retorna True.
  2. Evento con marker correcto -> bridge lo detecta y genera ParticipationContract.
  3. authorized:true -> pipeline ENROLLED, peers.json actualizado.
  4. authorized:false -> SKIPPED_NOT_AUTHORIZED_BY_OPERATOR.
  5. Firma invalida -> verify_nostr_event retorna False, bridge descarta.
"""
import json, os, sys, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega.federation_protocols.nostr_schnorr import verify_nostr_event, nostr_event_id
from omega.federation_protocols.nostr_bridge import (
    bridge_pubkey_hex, NostrBridge, AUTHORIZE_MARKER, AUTHORIZE_TAG,
)

STATE = ROOT / ".state"
NODES = STATE / "iao-external-nodes.json"
PEERS_V2 = STATE / "iao-node-network" / "peers.json"
PEERS_V1 = STATE / "iao-node-network" / "authorized-peers.json"


def make_nostr_key():
    """Genera clave Nostr usando chaincraft (schnorr puro)."""
    from chaincraft.crypto_primitives.schnorr import SchnorrSignaturePrimitive
    prim = SchnorrSignaturePrimitive()
    prim.generate_key()
    return prim


def build_event(prim, bridge_pub: str, kind: int = 1) -> dict:
    """Construye y firma un evento kind:1 de autorizacion Nostr."""
    import time
    content = f"{AUTHORIZE_MARKER}{bridge_pub}"
    ev = {
        "pubkey": prim.pubkey_hex,
        "created_at": int(time.time()),
        "kind": kind,
        "tags": [["t", AUTHORIZE_TAG]],
        "content": content,
    }
    ev_id_hex = nostr_event_id(ev)
    ev["id"] = ev_id_hex
    sig = prim.sign(bytes.fromhex(ev_id_hex))
    ev["sig"] = sig.hex() if isinstance(sig, bytes) else sig
    return ev


def reset_stores():
    """Deja los stores limpios para que el test sea determinista."""
    for p, key in [(PEERS_V2, "peers"), (PEERS_V1, "authorized_peers")]:
        if p.exists():
            d = json.loads(p.read_text())
            d[key] = []
            p.write_text(json.dumps(d, indent=2))


def main():
    print("=== TEST BRIDGE NOSTR ===")
    bridge_pub = bridge_pubkey_hex()
    print(f"Bridge pubkey: {bridge_pub}")

    # 1. Generar clave Nostr de prueba
    prim = make_nostr_key()
    print(f"Nostr pubkey (operador de prueba): {prim.pubkey_hex}")

    # 2. Construir y firmar evento valido
    ev_valid = build_event(prim, bridge_pub)
    print(f"Evento firmado: id={ev_valid['id'][:16]}...")

    # Test A: verificacion de firma valida
    ok = verify_nostr_event(ev_valid)
    print(f"[A] verify_nostr_event (valido): {ok}")
    if not ok:
        print("FALLO: firma valida rechazada"); sys.exit(1)

    # Test B: firma invalida
    ev_bad = dict(ev_valid)
    ev_bad["sig"] = "00" * 64
    bad_ok = verify_nostr_event(ev_bad)
    print(f"[B] verify_nostr_event (invalido): {bad_ok}")
    if bad_ok:
        print("FALLO: firma invalida aceptada"); sys.exit(1)

    # Test C: bridge genera ParticipationContract
    bridge = NostrBridge()
    contract = bridge.to_participation_contract({"nostr_event": ev_valid, "endpoint": "nostr://test"})
    print(f"[C] ParticipationContract generado: peer_id={contract['peer_id']}")
    if not contract or not contract.get("peer_id"):
        print("FALLO: contrato no generado"); sys.exit(1)

    # Test D: evento sin marker -> bridge no lo procesa
    ev_nomarker = build_event(prim, "pubkey_que_no_es_el_bridge")
    contract_nomarker = bridge.to_participation_contract({"nostr_event": ev_nomarker, "endpoint": "nostr://test"})
    # to_participation_contract no mira el marker (ya se filtro en _filter_authorizations),
    # pero verificamos que el filtro lo descarta:
    from omega.federation_protocols.nostr_bridge import _filter_authorizations
    filtered = _filter_authorizations([ev_nomarker])
    print(f"[D] _filter_authorizations (sin marker): {len(filtered)} eventos")
    if len(filtered) != 0:
        print("FALLO: evento sin marker paso el filtro"); sys.exit(1)

    # Test E: pipeline ENROLLED con authorized:true (offline injection)
    reset_stores()
    nodes = json.loads(NODES.read_text()) if NODES.exists() else {"nodes": []}
    # Quitar cualquier candidato nostr previo
    nodes["nodes"] = [n for n in nodes["nodes"] if n.get("source") != "nostr_bridge"]
    nodes["nodes"].append({
        "url": f"nostr://{prim.pubkey_hex}",
        "id": None,
        "authorized": True,
        "capabilities": ["knowledge.search"],
        "source": "nostr_bridge",
        "nostr_event": ev_valid,
    })
    NODES.write_text(json.dumps(nodes, indent=2))
    print(f"[E] Candidato Nostr inyectado con authorized:true")

    # Ejecutar pipeline sin discovery (para no tocar relays en el test)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "auto", str(ROOT / "tools" / "iao_federation_autonomous.py"))
    auto = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auto)
    report = auto.run_cycle(dry_run=False, discover=False)
    print(f"[E] Pipeline resultado: {json.dumps(report['results'], indent=2)}")
    enrolled = [r for r in report["results"] if r.get("status") == "ENROLLED"]
    if not enrolled:
        print("FALLO: pipeline no enrolo el peer Nostr"); sys.exit(1)

    # Verificar stores
    peers_v2 = json.loads(PEERS_V2.read_text())
    peers_v1 = json.loads(PEERS_V1.read_text())
    peer_id = enrolled[0]["peer_id"]
    if not any(p["peer_id"] == peer_id for p in peers_v2["peers"]):
        print("FALLO: peer no en peers.json"); sys.exit(1)
    if not any(p["node_id"] == peer_id for p in peers_v1["authorized_peers"]):
        print("FALLO: peer no en authorized-peers.json"); sys.exit(1)
    print(f"[E] Stores actualizados: {peer_id} en peers.json y authorized-peers.json")

    # Test F: authorized:false -> SKIPPED
    reset_stores()
    nodes["nodes"] = [n for n in nodes["nodes"] if n.get("source") != "nostr_bridge"]
    nodes["nodes"].append({
        "url": f"nostr://{prim.pubkey_hex}",
        "id": None,
        "authorized": False,
        "capabilities": ["knowledge.search"],
        "source": "nostr_bridge",
        "nostr_event": ev_valid,
    })
    NODES.write_text(json.dumps(nodes, indent=2))
    report2 = auto.run_cycle(dry_run=False, discover=False)
    skipped = [r for r in report2["results"]
               if r.get("status") == "SKIPPED_NOT_AUTHORIZED_BY_OPERATOR"]
    print(f"[F] Pipeline authorized:false -> {len(skipped)} skipped")
    if not skipped:
        print("FALLO: pipeline enrolo sin autorizacion"); sys.exit(1)

    print("\n=== TODOS LOS TESTS PASARON ===")


if __name__ == "__main__":
    main()
