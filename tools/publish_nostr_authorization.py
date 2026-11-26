#!/usr/bin/env python3
"""
Publica un evento Nostr kind:1 de autorizacion para el bridge IAO.
El evento firma con la clave Nostr del operador y contiene:
  content: "IAO_FEDERATION_AUTHORIZE:<bridge_pubkey_hex>"
  tags:    [["t", "iao-federation"]]

Uso:
  python3 tools/publish_nostr_authorization.py --relay wss://relay.damus.io
  python3 tools/publish_nostr_authorization.py --dry-run   # solo construye, no publica
"""
import argparse, asyncio, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from omega.federation_protocols.nostr_schnorr import nostr_event_id, verify_nostr_event
from omega.federation_protocols.nostr_bridge import bridge_pubkey_hex, AUTHORIZE_MARKER, AUTHORIZE_TAG

STATE = ROOT / ".state"
PUBLISHED_DIR = STATE / "nostr-published-events"

DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]


def make_key():
    from chaincraft.crypto_primitives.schnorr import SchnorrSignaturePrimitive
    prim = SchnorrSignaturePrimitive()
    prim.generate_key()
    return prim


def build_event(prim, bridge_pub: str) -> dict:
    ev = {
        "pubkey": prim.pubkey_hex,
        "created_at": int(time.time()),
        "kind": 1,
        "tags": [["t", AUTHORIZE_TAG]],
        "content": f"{AUTHORIZE_MARKER}{bridge_pub}",
    }
    ev["id"] = nostr_event_id(ev)
    sig = prim.sign(bytes.fromhex(ev["id"]))
    ev["sig"] = sig.hex() if isinstance(sig, bytes) else sig
    return ev


async def publish_to_relay(relay: str, event: dict, timeout: float = 10.0) -> dict:
    """Publica un evento en un relay Nostr y espera OK."""
    import websockets
    result = {"relay": relay, "ok": False, "response": None}
    try:
        async with websockets.connect(relay, open_timeout=timeout, close_timeout=2) as ws:
            await ws.send(json.dumps(["EVENT", event]))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(msg, list) and len(msg) >= 3 and msg[0] == "OK":
                    result["response"] = msg
                    # msg = ["OK", event_id, true/false, ""]
                    if msg[1] == event["id"]:
                        result["ok"] = bool(msg[2])
                        break
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


async def main_async(args):
    bridge_pub = bridge_pubkey_hex()
    print(f"Bridge pubkey: {bridge_pub}")

    prim = make_key()
    print(f"Operador Nostr pubkey: {prim.pubkey_hex}")

    ev = build_event(prim, bridge_pub)
    print(f"Evento construido: id={ev['id']}")
    print(f"  content: {ev['content']}")
    print(f"  tags: {ev['tags']}")

    # Verificar localmente antes de publicar
    if not verify_nostr_event(ev):
        print("FALLO: el evento no verifica localmente"); return 1
    print("Verificacion local: OK")

    PUBLISHED_DIR.mkdir(parents=True, exist_ok=True)
    event_file = PUBLISHED_DIR / f"{ev['id']}.json"
    event_file.write_text(json.dumps(ev, indent=2))
    print(f"Evento guardado en: {event_file}")

    if args.dry_run:
        print("DRY-RUN: no se publica")
        return 0

    relays = args.relay or DEFAULT_RELAYS
    print(f"\nPublicando en {len(relays)} relays...")
    tasks = [publish_to_relay(r, ev, args.timeout) for r in relays]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    ok_count = 0
    for r in results:
        if isinstance(r, dict):
            print(f"  {r['relay']}: ok={r['ok']} response={r.get('response')}")
            if r["ok"]:
                ok_count += 1
        else:
            print(f"  error: {r}")
    print(f"\n{ok_count}/{len(relays)} relays aceptaron el evento")

    if ok_count == 0:
        print("\nNo se pudo publicar en ningun relay. Verifica tu conexion a Internet")
        print("y que los relays esten accesibles. Prueba con --relay wss://nos.lol")
        return 1

    print("\nEvento publicado. El bridge lo descubrira en el proximo ciclo del pipeline.")
    print("Para verificar:")
    print(f"  python3 tools/iao_federation_autonomous.py --dry-run")
    print("  grep discovery_nostr .state/iao-node-network/federation-audit/events.jsonl | tail -3")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay", action="append", help="relay wss:// (puede repetirse)")
    ap.add_argument("--dry-run", action="store_true", help="solo construye, no publica")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
