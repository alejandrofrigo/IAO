"""
Bridge Nostr <-> iao-federation.

Permite que un operador Nostr (que NO corre iao-federation) se federe
publicando un evento kind:1 firmado con schnorr:

    content: "IAO_FEDERATION_AUTHORIZE:<bridge_pubkey_hex>"
    tags:    [["t", "iao-federation"]]

El bridge:
  1. Descubre relays públicos y consulta eventos kind:1 con ese marker.
  2. Verifica la firma schnorr del evento (consentimiento criptografico).
  3. Genera/mantiene una clave Ed25519 propia (aislada de la identidad IAO).
  4. Traduce el consentimiento a un ParticipationContract compatible con Node.enroll.
  5. Firma el challenge Ed25519 en nombre del operador Nostr (delegacion).

NO asimila relays sin evento de autorizacion verificado.
NO toca federation.py ni padge.py.
"""
from __future__ import annotations
import asyncio, json, os, stat, tempfile, time, urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import ProtocolAdapter, register
from .nostr_schnorr import verify_nostr_event, nostr_event_id

ROOT = Path(__file__).resolve().parents[2]
BRIDGE_STATE_ROOT = Path(os.environ.get("IAO_STATE_DIR") or os.environ.get("OMEGA_STATE_DIR") or ROOT / ".state").expanduser()
BRIDGE_DIR = BRIDGE_STATE_ROOT / "federation-bridges" / "nostr"
BRIDGE_KEY = BRIDGE_DIR / "bridge.pem"

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]
AUTHORIZE_MARKER = "IAO_FEDERATION_AUTHORIZE:"
AUTHORIZE_TAG = "iao-federation"
QUERY_TIMEOUT = 10.0
REQ_TIMEOUT = 8.0


def _ensure_bridge_key() -> Ed25519PrivateKey:
    absolute = BRIDGE_DIR.absolute()
    if any(part.is_symlink() for part in (absolute, *absolute.parents)):
        raise RuntimeError("NOSTR_BRIDGE_DIRECTORY_SYMLINK_REFUSED")
    BRIDGE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BRIDGE_DIR, 0o700)
    if BRIDGE_KEY.is_symlink():
        raise RuntimeError("NOSTR_BRIDGE_KEY_SYMLINK_REFUSED")
    if BRIDGE_KEY.exists():
        if not BRIDGE_KEY.is_file():
            raise RuntimeError("NOSTR_BRIDGE_KEY_PATH_REFUSED")
        mode = stat.S_IMODE(BRIDGE_KEY.stat().st_mode)
        if mode & 0o077:
            os.chmod(BRIDGE_KEY, 0o600)
        return serialization.load_pem_private_key(BRIDGE_KEY.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd, temporary = tempfile.mkstemp(prefix=".bridge-", dir=str(BRIDGE_DIR))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, BRIDGE_KEY)
        except FileExistsError:
            if BRIDGE_KEY.is_symlink() or not BRIDGE_KEY.is_file():
                raise RuntimeError("NOSTR_BRIDGE_KEY_PATH_REFUSED")
            os.chmod(BRIDGE_KEY, 0o600)
            return serialization.load_pem_private_key(BRIDGE_KEY.read_bytes(), password=None)
        directory_fd = os.open(BRIDGE_DIR, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return key
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def bridge_pubkey_hex() -> str:
    key = _ensure_bridge_key()
    return key.public_key().public_bytes_raw().hex()


async def _query_relay(relay: str, filters: dict, timeout: float = QUERY_TIMEOUT) -> list[dict]:
    """Consulta un relay Nostr via WebSocket. Devuelve eventos kind:1."""
    try:
        import websockets
    except ImportError:
        return []
    sub_id = "iao-federation-bridge"
    events: list[dict] = []
    try:
        async with websockets.connect(relay, open_timeout=timeout, close_timeout=2) as ws:
            await ws.send(json.dumps(["REQ", sub_id, filters]))
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
                if not isinstance(msg, list) or not msg:
                    continue
                if msg[0] == "EVENT" and len(msg) == 3 and isinstance(msg[2], dict):
                    events.append(msg[2])
                elif msg[0] == "EOSE":
                    break
            try:
                await ws.send(json.dumps(["CLOSE", sub_id]))
            except Exception:
                pass
    except Exception:
        return events
    return events


def _filter_authorizations(events: list[dict]) -> list[dict]:
    """Filtra eventos que son autorizaciones validas hacia este bridge."""
    marker = AUTHORIZE_MARKER + bridge_pubkey_hex()
    out = []
    for ev in events:
        if not isinstance(ev, dict): continue
        if ev.get("kind") != 1: continue
        content = ev.get("content", "")
        if not isinstance(content, str) or not content.startswith(marker): continue
        tags = ev.get("tags", [])
        if not any(isinstance(t, list) and len(t) >= 2 and t[0] == "t" and t[1] == AUTHORIZE_TAG
                   for t in tags):
            continue
        if not verify_nostr_event(ev):
            continue
        out.append(ev)
    return out


async def discover_nostr_authorizations(relays: list[str] | None = None) -> list[dict]:
    """Descubre eventos de autorizacion Nostr hacia este bridge."""
    relays = relays or DEFAULT_RELAYS
    filters = {
        "kinds": [1],
        "#t": [AUTHORIZE_TAG],
        "limit": 100,
    }
    tasks = [_query_relay(r, filters) for r in relays]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_events: list[dict] = []
    for r in results:
        if isinstance(r, list):
            all_events.extend(r)
    valid = _filter_authorizations(all_events)
    # dedupe por id
    seen = set(); deduped = []
    for ev in valid:
        eid = ev.get("id")
        if eid and eid not in seen:
            seen.add(eid); deduped.append(ev)
    return deduped


class NostrBridge(ProtocolAdapter):
    name = "nostr"

    def probe(self, addr: str, timeout: float = 5.0):
        """Probe ligero: si el addr es un relay wss://, devuelve metadata."""
        if not isinstance(addr, str) or not addr.startswith("wss://"):
            return None
        return {"endpoint": addr, "protocol": "nostr", "kind": "relay"}

    def to_participation_contract(self, candidate: dict) -> dict | None:
        """Un relay/evento Nostr es un canal de descubrimiento, no un nodo IAO.

        No se inventa un endpoint .local ni se delega la identidad del bridge
        a un autor Nostr. El enrolamiento requiere un servicio IAO separado,
        con endpoint HTTPS propio y challenge Ed25519 verificable.
        """
        return None


def build_candidates_from_events(events: list[dict], relays: list[str]) -> list[dict]:
    """Convierte eventos de autorizacion en candidatos para el pipeline."""
    out = []
    for ev in events:
        out.append({
            "url": f"nostr://{ev.get('pubkey','')}",
            "id": None,  # se calcula en to_participation_contract
            "authorized": False,
            "capabilities": ["knowledge.search"],
            "source": "nostr_bridge",
            "nostr_event": ev,
        })
    return out


register(NostrBridge())
