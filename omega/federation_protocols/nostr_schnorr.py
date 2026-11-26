"""
Verificación BIP-340 Schnorr en Python puro (solo stdlib).
Necesario para validar firmas de eventos Nostr sin coincurve.
Referencia: BIP-340, implementación zero-dependency.
"""
import hashlib

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_Gx, _Gy)

def _tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()

def _inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)

def _point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)

def _point_mul(p, n):
    r = None
    while n:
        if n & 1: r = _point_add(r, p)
        p = _point_add(p, p)
        n >>= 1
    return r

def _lift_x(x: int):
    if x >= _P: return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq: return None
    return (x, y if y % 2 == 0 else _P - y)

def _bytes_from_int(x: int, length: int = 32) -> bytes:
    return x.to_bytes(length, "big")

def schnorr_verify(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    """Verifica firma BIP-340. message debe ser el hash sha256 del evento Nostr."""
    try:
        pubkey = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    P = _lift_x(int.from_bytes(pubkey, "big"))
    if P is None: return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N: return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + pubkey + message), "big") % _N
    R = _point_add(_point_mul(_G, s), _point_mul(P, _N - e))
    if R is None: return False
    if R[1] % 2 != 0: return False
    if R[0] != r: return False
    return True

def nostr_event_id(event: dict) -> str:
    """Calcula el id (sha256) de un evento Nostr según NIP-01."""
    import json
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(serialized.encode()).hexdigest()

def verify_nostr_event(event: dict) -> bool:
    """Verifica id y firma de un evento Nostr."""
    try:
        expected_id = nostr_event_id(event)
        if event.get("id") != expected_id:
            return False
        return schnorr_verify(event["pubkey"], bytes.fromhex(expected_id), event["sig"])
    except (KeyError, ValueError, TypeError):
        return False
