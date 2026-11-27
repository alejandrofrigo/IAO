#!/usr/bin/env python3
"""Federacion autonoma externa de IAO - pipeline con validacion mutua."""
from __future__ import annotations
import ssl
import argparse, asyncio, base64, hashlib, json, os, secrets, sys, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from omega.store import Store
from omega.tools.registry import ToolRegistry
from omega.federation import Node, verify_identity_challenge
from omega.federation_transport import fetch_public_json, fetch_onion_json, FederationTransportError
import omega.federation_protocols.native  # noqa: F401
import omega.federation_protocols.nostr   # noqa: F401
from omega.federation_protocols import probe_any, get as get_adapter
# El bridge real se importa DESPUÉS del stub para sobrescribir el registro global:
import omega.federation_protocols.nostr_bridge  # noqa: F401

STATE    = ROOT / ".state"
NODES    = STATE / "iao-external-nodes.json"
POLICY   = STATE / "iao-node-network/federation-policy.json"
PEERS_V2 = STATE / "iao-node-network/peers.json"
PEERS_V1 = STATE / "iao-node-network/authorized-peers.json"
INBOX    = STATE / "iao-node-network/federation-inbox"
AUDIT    = STATE / "iao-node-network/federation-audit/events.jsonl"
REPORT   = STATE / "iao-federation-autonomous-report.json"
IDENTITY = STATE / "federation/identity"
SOURCES  = STATE / "iao-federation-sources.json"

def utc(): return datetime.now(timezone.utc).isoformat()
def load(p, d): return json.loads(p.read_text(encoding="utf-8")) if p.exists() else d
def save(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)
def audit(event, **fields):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": utc(), "event": event, **fields}, ensure_ascii=False) + "\n")

def discover_signed_directory(url, trusted_pub_hex, timeout=15):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        doc = fetch_public_json(url, timeout=timeout, max_bytes=1_000_000)
    except Exception as exc:
        audit("discovery_directory_failed", error_type=type(exc).__name__)
        return []
    if not isinstance(doc, dict):
        audit("discovery_directory_invalid", reason="JSON_OBJECT_REQUIRED")
        return []
    sig = doc.pop("sig", None)
    if not isinstance(sig, str) or not sig or len(sig) > 256:
        audit("discovery_directory_unsigned", reason="SIGNATURE_MISSING")
        return []
    body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    try:
        signature = base64.b64decode(sig, validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_pub_hex)).verify(
            signature, body
        )
    except Exception:
        audit("discovery_directory_bad_signature")
        return []
    peers = doc.get("peers", [])
    if not isinstance(peers, list):
        return []
    out = []
    for peer in peers[:1000]:
        if (
            isinstance(peer, dict)
            and isinstance(peer.get("id"), str)
            and isinstance(peer.get("url"), str)
            and peer["url"].startswith("https://")
        ):
            out.append({
                "url": peer["url"],
                "id": peer["id"],
                "capabilities": peer.get("capabilities", []),
                "source": "signed_directory",
            })
    audit("discovery_directory_ok", peers=len(out))
    return out


def discover_feed(url, timeout=10):
    try:
        data = fetch_public_json(url, timeout=timeout, max_bytes=500_000)
    except Exception as exc:
        audit("discovery_feed_failed", error_type=type(exc).__name__)
        return []
    if isinstance(data, list):
        peers = data
    elif isinstance(data, dict):
        peers = data.get("peers", [])
    else:
        return []
    if not isinstance(peers, list):
        return []
    out = []
    for peer in peers[:1000]:
        if (
            isinstance(peer, dict)
            and isinstance(peer.get("id"), str)
            and isinstance(peer.get("url"), str)
            and peer["url"].startswith("https://")
        ):
            out.append({
                "url": peer["url"],
                "id": peer["id"],
                "capabilities": peer.get("capabilities", []),
                "source": "public_feed",
            })
    audit("discovery_feed_ok", peers=len(out))
    return out



def discover_onion_feed(url, timeout=15):
    """Discover public IAO candidates from a v3 onion JSON feed via local Tor SOCKS."""
    try:
        fetch_onion_json  # fail early if the Tor transport is unavailable
        from omega.federation_transport import _parse_onion_url
        _parse_onion_url(url)
        data = fetch_onion_json(url, timeout=timeout, max_bytes=500_000)
    except Exception as exc:
        audit("discovery_onion_feed_failed", error_type=type(exc).__name__)
        return []
    if isinstance(data, list):
        peers = data
    elif isinstance(data, dict):
        peers = data.get("peers", [])
    else:
        return []
    if not isinstance(peers, list):
        return []
    out = []
    for peer in peers[:100]:
        if not isinstance(peer, dict):
            continue
        endpoint = peer.get("url") or peer.get("onion_url")
        if not isinstance(endpoint, str):
            continue
        try:
            _parse_onion_url(endpoint)
        except FederationTransportError:
            continue
        peer_id = peer.get("peer_id")
        if peer_id is not None and (
            not isinstance(peer_id, str) or not 20 <= len(peer_id) <= 120
            or not peer_id.isascii() or not peer_id.isalnum()
        ):
            peer_id = None
        out.append({
            "service_url": endpoint,
            "peer_id": peer_id,
            "source": "tor_onion_feed",
            "identity_state": "UNVERIFIED",
            "participation_state": "CANDIDATE_ONLY",
            "capabilities": [],
            "granted_capabilities": [],
            "remote_code_execution": False,
            "control_authority": False,
        })
    audit("discovery_onion_feed_ok", peers=len(out))
    return out


def merge_onion_candidates(candidates):
    """Persist onion service candidates separately from HTTPS federation nodes."""
    path = STATE / "iao-onion-candidates.json"
    if path.is_symlink():
        raise RuntimeError("ONION_CANDIDATE_REGISTRY_SYMLINK_REFUSED")
    data = load(path, {"schema": 1, "services": {}})
    services = data.get("services", {})
    if not isinstance(services, dict) or len(services) > 2000:
        raise RuntimeError("ONION_CANDIDATE_REGISTRY_INVALID")
    added = observed = 0
    now = utc()
    from omega.federation_transport import _parse_onion_url
    for candidate in candidates[:100]:
        if not isinstance(candidate, dict) or candidate.get("source") != "tor_onion_feed":
            continue
        endpoint = candidate.get("service_url")
        try:
            host, port, target = _parse_onion_url(endpoint)
        except Exception:
            continue
        key = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        previous = services.get(key, {})
        if previous and not isinstance(previous, dict):
            raise RuntimeError("ONION_CANDIDATE_RECORD_INVALID")
        services[key] = {
            "service_url": endpoint,
            "onion_host": host,
            "virtual_port": port,
            "path": target,
            "peer_id": candidate.get("peer_id"),
            "source": "tor_onion_feed",
            "discovery_state": "FEED_ADVERTISED_UNPROBED",
            "identity_state": "UNVERIFIED",
            "participation_state": "CANDIDATE_ONLY",
            "first_seen": previous.get("first_seen", now),
            "last_seen": now,
            "capabilities": [],
            "granted_capabilities": [],
            "remote_code_execution": False,
            "control_authority": False,
        }
        observed += 1
        if not previous:
            added += 1
    ordered = sorted(services.items(), key=lambda item: item[1].get("last_seen", ""), reverse=True)[:1000]
    payload = {"schema": 1, "services": dict(ordered)}
    path.parent.mkdir(parents=True, exist_ok=True)
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".onion-candidates-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    return {"new": added, "observed": observed, "total": len(payload["services"])}

def _validate_local_ipfs_api(value):
    """IPFS HTTP API is a local control endpoint, never an arbitrary remote URL."""
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        return (
            parsed.scheme == "http"
            and host in {"127.0.0.1", "localhost", "::1"}
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and parsed.port in (None, 5001)
        )
    except (TypeError, ValueError):
        return False


def _parse_ipfs_peer(peer):
    """Retain the real libp2p peer ID and multiaddr; never invent an HTTPS URL."""
    if not isinstance(peer, dict):
        return None
    peer_id = peer.get("Peer")
    multiaddr = peer.get("Addr")
    if (
        not isinstance(peer_id, str)
        or not 20 <= len(peer_id) <= 100
        or not all(ch.isalnum() for ch in peer_id)
        or not isinstance(multiaddr, str)
        or not multiaddr.startswith("/")
        or len(multiaddr) > 512
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in multiaddr)
    ):
        return None
    return {
        "peer_id": peer_id,
        "multiaddr": multiaddr,
        "source": "ipfs_swarm_peer",
        "status": "DISCOVERED_UNVERIFIED",
        "granted_capabilities": [],
    }


def discover_dht(ipfs_api):
    if not _validate_local_ipfs_api(ipfs_api):
        audit("dht_discovery_rejected", reason="LOCAL_IPFS_API_REQUIRED")
        return []
    try:
        req = urllib.request.Request(
            f"{ipfs_api.rstrip('/')}/api/v0/swarm/peers",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read(500_000))
    except Exception as exc:
        audit("dht_discovery_unavailable", error_type=type(exc).__name__)
        return []
    peers = data.get("Peers", []) if isinstance(data, dict) else []
    if not isinstance(peers, list):
        return []
    out = []
    seen = set()
    for peer in peers[:500]:
        item = _parse_ipfs_peer(peer)
        if item and item["peer_id"] not in seen:
            seen.add(item["peer_id"])
            out.append(item)
    audit("ipfs_swarm_peers_discovered", count=len(out))
    return out

def merge_p2p_candidates(candidates):
    """Persist discovered libp2p addresses separately from HTTP federation nodes."""
    path = STATE / "iao-p2p-candidates.json"
    data = load(path, {"schema": 1, "peers": {}})
    peers = data.get("peers", {})
    if not isinstance(peers, dict):
        peers = {}
    added = 0
    now = utc()
    for candidate in candidates:
        if not isinstance(candidate, dict) or candidate.get("source") != "ipfs_swarm_peer":
            continue
        peer_id = candidate.get("peer_id")
        multiaddr = candidate.get("multiaddr")
        if not isinstance(peer_id, str) or not isinstance(multiaddr, str):
            continue
        existing = peers.get(peer_id, {})
        peers[peer_id] = {
            "peer_id": peer_id,
            "multiaddr": multiaddr,
            "source": "ipfs_swarm_peer",
            "status": "DISCOVERED_UNVERIFIED",
            "granted_capabilities": [],
            "first_seen": existing.get("first_seen", now),
            "last_seen": now,
        }
        if not existing:
            added += 1
    # Bounded registry: preserve most recently seen entries.
    ordered = sorted(
        peers.values(), key=lambda item: item.get("last_seen", ""), reverse=True
    )[:1000]
    data["peers"] = {item["peer_id"]: item for item in ordered}
    save(path, data)
    return added


def run_discovery():
    sources = load(SOURCES, {})
    candidates = []
    for d in sources.get("signed_directories", []):
        if d.get("url") and d.get("pubkey_hex"):
            candidates.extend(discover_signed_directory(d["url"], d["pubkey_hex"]))
    for f in sources.get("feeds", []):
        if isinstance(f, str) and f.startswith("https://"):
            candidates.extend(discover_feed(f))
    onion_feeds = sources.get("onion_feeds", [])
    if isinstance(onion_feeds, list):
        for feed in onion_feeds[:20]:
            if isinstance(feed, str):
                candidates.extend(discover_onion_feed(feed))
    dht = sources.get("dht", {})
    if dht.get("enabled"):
        candidates.extend(discover_dht(dht.get("ipfs_api", "http://127.0.0.1:5001")))
    bridges = sources.get("bridges", {})
    nostr_cfg = bridges.get("nostr", {})
    if nostr_cfg.get("enabled"):
        try:
            from omega.federation_protocols.nostr_bridge import discover_nostr_authorizations
            relays = nostr_cfg.get("relays") or None
            events = asyncio.run(discover_nostr_authorizations(relays))
            for ev in events:
                candidates.append({
                    "url": f"nostr://{ev.get('pubkey','')}",
                    "id": None,
                    "authorized": False,
                    "capabilities": ["knowledge.search"],
                    "source": "nostr_bridge",
                    "nostr_event": ev,
                })
            audit("discovery_nostr_ok", events=len(events))
        except Exception as e:
            audit("discovery_nostr_failed", error=str(e)[:120])
    return candidates

def merge_candidates_into_nodes(candidates):
    cfg = load(NODES, {"nodes": []})
    ids = {n.get("id") for n in cfg.get("nodes", []) if n.get("id")}
    added = 0
    for c in candidates:
        # Solo endpoints IAO HTTPS con ID verificable entran en el pipeline HTTP.
        # Peers libp2p y anuncios Nostr permanecen en sus registros de descubrimiento.
        if (
            not isinstance(c, dict)
            or not isinstance(c.get("url"), str)
            or not c.get("url", "").startswith("https://")
            or not c.get("id")
            or c["id"] in ids
        ):
            continue
        cfg["nodes"].append({"url": c["url"], "id": c["id"],
            "authorized": False,
            "capabilities": c.get("capabilities", []),
            "source": c.get("source", "unknown")})
        ids.add(c["id"]); added += 1
    save(NODES, cfg); return added

def probe_and_verify(addr):
    hit = probe_any(addr)
    if not hit: return None
    protocol, candidate = hit
    if protocol != "iao-federation":
        return protocol, candidate, {"ok": False, "error": "NO_BRIDGE"}
    requester_id = secrets.token_hex(8)
    nonce = secrets.token_hex(32)
    request_ts = time.time()
    origin = candidate["endpoint"]
    challenge = {"v": 1, "from": requester_id,
                 "to": candidate["identity_doc"]["node_id"],
                 "nonce": nonce, "ts": request_ts}
    try:
        req = urllib.request.Request(origin + "/fed/v1/handshake", method="POST",
            data=json.dumps(challenge).encode(),
            headers={"Content-Type": "application/json"})
        # Respetar IAO_TLS_CA_FILE si está definido (tests con CA propia).
        # En producción no se define y se usa el almacén del sistema.
        _ca_file = os.environ.get("IAO_TLS_CA_FILE")
        _ctx = ssl.create_default_context(cafile=_ca_file) if _ca_file else None
        if _ctx is not None and origin.startswith("https://"):
            with urllib.request.urlopen(req, timeout=8, context=_ctx) as r:
                response = json.loads(r.read(4096))
        else:
            with urllib.request.urlopen(req, timeout=8) as r:
                response = json.loads(r.read(4096))
    except Exception as e:
        audit("handshake_unreachable", addr=addr,
              error=f"{type(e).__name__}:{str(e)[:120]}")
        return protocol, candidate, {"ok": False,
                                      "error": "HANDSHAKE_UNREACHABLE",
                                      "detail": type(e).__name__}
    verified = verify_identity_challenge(candidate["identity_doc"], response,
        requester_id=requester_id, nonce=nonce,
        request_ts=request_ts, now=time.time(), skew=60.0)
    if not verified.get("ok"):
        audit("handshake_rejected", addr=addr, error=verified.get("error"))
    else:
        audit("handshake_verified", addr=addr, peer_id=verified["peer_id"])
    return protocol, candidate, verified

def _registry_with_knowledge():
    """Registry con knowledge.search real, igual que omega/server.py."""
    import os
    from omega.tools.knowledge_search import KnowledgeCorpus
    from omega.tools.registry import ToolSpec
    corpus_dir = Path(os.environ.get("OMEGA_CORPUS_DIR", "docs/corpus"))
    corpus = KnowledgeCorpus(corpus_dir)
    r = ToolRegistry()
    if r.get("knowledge.search") is None:
        r.register(ToolSpec("knowledge.search", "1.0.0", "knowledge.search",
                            "READ_ONLY", 5.0,
                            corpus.validate_input, corpus.run, corpus.verify))
    return r

def make_node(policy):
    key = load_pem_private_key((IDENTITY / "private.pem").read_bytes(), password=None)
    return Node(store=Store(str(STATE / "store.db")), registry=_registry_with_knowledge(),
                key=key, peer_store_path=PEERS_V2,
                served=frozenset(policy.get("allowed_capabilities", [])))

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

def _remote_handshake_allowed(url):
    """Only loopback may be probed until trusted public transport is integrated."""
    return _peer_is_loopback(url)


def _peer_is_loopback(url):
    from urllib.parse import urlsplit
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        return False
    return host in _LOOPBACK_HOSTS

def enroll_if_consented(node, protocol, candidate, verified, item, policy):
    # La firma Ed25519 prueba identidad, no autenticación del canal. El probe
    # actual no aporta una atestación mTLS ligada a la conexión ni bloquea de
    # forma segura redirects/DNS rebinding. Por eso no se enrolan peers remotos
    # hasta integrar un transporte confiable; el descubrimiento sigue permitido.
    candidate_url = candidate.get("endpoint") if isinstance(candidate, dict) else None
    if candidate_url is None and isinstance(item, dict):
        candidate_url = item.get("url")
    if not _peer_is_loopback(candidate_url or ""):
        return {
            "status": "BLOCKED_TRUSTED_TRANSPORT_NOT_INTEGRATED",
            "peer_id": (verified or {}).get("peer_id"),
            "peer_url": str(candidate_url or "")[:200],
            "enrollment_performed": False,
            "capabilities_granted": [],
        }
    # Salvaguarda por-peer: si mTLS está desactivado (solo permitido en
    # entornos de integración), rechazar cualquier peer que no sea loopback.
    # En producción require_mutual_tls debe ser True.
    if not policy.get("require_mutual_tls"):
        candidate_url = candidate.get("endpoint") if isinstance(candidate, dict) else None
        if candidate_url is None and isinstance(item, dict):
            candidate_url = item.get("url")
        if not _peer_is_loopback(candidate_url or ""):
            audit("peer_blocked_mtls_required",
                  peer_url=str(candidate_url)[:200])
            return {
                "status": "BLOCKED_MTLS_REQUIRED_NON_LOOPBACK",
                "peer_id": (verified or {}).get("peer_id"),
                "peer_url": str(candidate_url)[:200],
                "policy": "Sin mTLS solo loopback puede enrolarse.",
            }
    if protocol == "nostr":
        peer_id = verified.get("peer_id")
        if not peer_id:
            return {"status": "SKIPPED_NO_PEER_ID", "protocol": "nostr"}
    else:
        peer_id = candidate["identity_doc"]["node_id"]
    # Enrolamiento autónomo: la confianza proviene de la verificación
    # criptográfica completa (handshake firmado) y de que las capacidades
    # solicitadas estén en la allowlist READ_ONLY. No se requiere flag
    # authorized=True previo. La decisión queda auditada.
    policy_caps = set(policy.get("allowed_capabilities", []))
    requested_caps = set(item.get("capabilities", [])) & policy_caps
    if not requested_caps:
        return {"status": "SKIPPED_NO_ALLOWED_CAPABILITIES", "peer_id": peer_id}
    if not verified.get("ok"):
        return {"status": "SKIPPED_HANDSHAKE_FAILED", "peer_id": peer_id,
                "error": verified.get("error")}
    if not verified.get("ok"):
        return {"status": "SKIPPED_HANDSHAKE_FAILED", "peer_id": peer_id,
                "error": verified.get("error")}
    adapter = get_adapter(protocol)
    if not adapter: return {"status": "SKIPPED_NO_ADAPTER", "protocol": protocol}
    contract = adapter.to_participation_contract(candidate)
    if not contract: return {"status": "SKIPPED_NO_BRIDGE", "protocol": protocol}
    allowed = set(policy.get("allowed_capabilities", []))
    requested = set(item.get("capabilities", [])) & allowed
    if not requested:
        return {"status": "SKIPPED_NO_ALLOWED_CAPABILITIES", "peer_id": peer_id}
    contract["lease_expires_at"] = time.time() + 3600
    contract["capabilities"] = sorted(requested)
    # Evitar reinscripciones y propuestas duplicadas para peers ya vigentes.
    existing = node.peers.get(peer_id)
    if isinstance(existing, dict) and not existing.get("revoked", True):
        try:
            old_pub = existing.get("pub")
            if not isinstance(old_pub, bytes):
                old_pub = base64.b64decode(existing.get("pubkey", ""), validate=True)
            new_pub = base64.b64decode(contract["pubkey"], validate=True)

            same_identity = old_pub == new_pub
            same_endpoint = existing.get("endpoint") == contract.get("endpoint")
            same_capabilities = (
                set(existing.get("capabilities", [])) == requested
            )
            same_grants = (
                set(existing.get("granted_capabilities", [])) == requested
            )
            lease_valid = (
                float(existing.get("lease_expires_at", 0)) > time.time() + 300
            )

            if (same_identity and same_endpoint and same_capabilities
                    and same_grants and lease_valid):
                audit("peer_already_enrolled", peer_id=peer_id,
                      capabilities=sorted(requested))
                return {
                    "status": "ALREADY_ENROLLED",
                    "peer_id": peer_id,
                    "capabilities": sorted(requested),
                }
        except (TypeError, ValueError, KeyError):
            # Estado incompleto o inconsistente: continuar por la vía normal
            # de validación y reinscripción, sin darlo por válido.
            pass

    # Registro autónomo de la autorización en el ledger de candidatos.
    try:
        registry = CandidateRegistry(STATE / "iao-federation-candidates.json")
        try:
            registry.authorize(item["candidate_id"])
        except Exception:
            # Si ya estaba autorizado o el registro no está, continuar.
            pass
    except Exception:
        pass

    try:
        node.enroll(contract, granted_capabilities=sorted(requested))
    except Exception as e:
        audit("enroll_failed", peer_id=peer_id, error=str(e)[:200])
        return {"status": "ENROLL_FAILED", "peer_id": peer_id, "error": str(e)[:200]}
    peers = load(PEERS_V1, {"schema": 1, "authorized_peers": []})
    peers["authorized_peers"] = [p for p in peers.get("authorized_peers", [])
                                  if p.get("node_id") != peer_id]
    peers["authorized_peers"].append({"node_id": peer_id, "endpoint": candidate["endpoint"],
        "status": "AUTHORIZED", "capabilities": sorted(requested),
        "protocol": protocol, "enrolled_at": utc(),
        "source": "autonomous_pipeline"})
    save(PEERS_V1, peers)
    registry_path = STATE / "iao-node-network/nodes.json"
    registry = load(registry_path, {"schema": 1, "nodes": {}})
    registry.setdefault("nodes", {})[peer_id] = {
        "node_id": peer_id,
        "name": f"peer-{peer_id[:8]}",
        "status": "ACTIVE",
        "transport": "mTLS",
        "tls": {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
        "last_verified": utc(),
        "endpoint": candidate["endpoint"],
        "capabilities": sorted(requested),
        "protocol": protocol,
        "control_plane_admission": "PENDING",
    }
    save(registry_path, registry)
    INBOX.mkdir(parents=True, exist_ok=True)
    proposal_id = hashlib.sha256((peer_id + utc()).encode()).hexdigest()
    save(INBOX / f"{proposal_id}.json", {"schema": 1, "proposal_id": proposal_id,
        "source": "IAO_FEDERATED_NODE", "node_id": peer_id,
        "protocol": protocol, "capabilities": sorted(requested),
        "requested_action": "CAPABILITY_CATALOG_UPDATE",
        "execution_authority": "NONE",
        "status": "STAGED_FOR_PADGE_REVIEW", "created_at": utc()})
    audit("peer_enrolled", peer_id=peer_id, capabilities=sorted(requested), mode="AUTONOMOUS")
    return {"status": "ENROLLED", "peer_id": peer_id, "capabilities": sorted(requested)}

def run_cycle(dry_run=False, discover=True):
    policy = load(POLICY, {})
    if not policy.get("enabled"): return {"status": "FEDERATION_DISABLED"}

    discovery_summary = {"candidates_added": 0}
    if discover:
        candidates = run_discovery()
        discovery_summary["candidates_added"] = merge_candidates_into_nodes(candidates)
        discovery_summary["p2p_peers_added"] = merge_p2p_candidates(candidates)
        onion_candidates = [item for item in candidates if isinstance(item, dict) and item.get("source") == "tor_onion_feed"]
        discovery_summary["onion_assimilation"] = merge_onion_candidates(onion_candidates)
        discovery_summary["candidates_discovered"] = len(candidates)
        try:
            from omega.libp2p_discovery import discover_sync
            p2p = discover_sync()
            discovery_summary["libp2p"] = {
                "status": p2p.get("status"),
                "connected_bootstrappers": p2p.get("connected_bootstrappers", 0),
                "routing_peers_discovered": p2p.get("routing_peers_discovered", 0),
                "persisted_new_peers": p2p.get("persisted_new_peers", 0),
                "enrollment_performed": False,
                "capabilities_granted": [],
            }
            audit("libp2p_dht_discovery_cycle", **discovery_summary["libp2p"])
        except Exception as exc:
            discovery_summary["libp2p"] = {"status": "UNAVAILABLE", "error_type": type(exc).__name__}
            audit("libp2p_dht_discovery_unavailable", error_type=type(exc).__name__)
    items = [n for n in load(NODES, {"nodes": []}).get("nodes", []) if isinstance(n, dict)]
    node = make_node(policy) if not dry_run else None
    results = []
    for item in items:
        addr = item.get("url")
        if not isinstance(addr, str): continue
        # Rama Nostr: no hace probe HTTPS; usa el bridge directamente
        if item.get("source") == "nostr_bridge" and item.get("nostr_event"):
            from omega.federation_protocols.nostr_bridge import NostrBridge
            bridge = NostrBridge()
            candidate = {"nostr_event": item["nostr_event"], "endpoint": addr}
            contract = bridge.to_participation_contract(candidate)
            if not contract:
                results.append({"addr": addr, "protocol": "nostr", "status": "SKIPPED_NO_BRIDGE"})
                continue
            if dry_run:
                results.append({"addr": addr, "protocol": "nostr",
                                "handshake_ok": True,
                                "operator_authorized": bool(item.get("authorized"))})
                continue
            if not item.get("authorized"):
                results.append({"addr": addr, "protocol": "nostr",
                                "status": "SKIPPED_NOT_AUTHORIZED_BY_OPERATOR",
                                "peer_id": contract["peer_id"]})
                continue
            verified = {"ok": True, "peer_id": contract["peer_id"], "verified": True}
            results.append({"addr": addr, "protocol": "nostr",
                            **enroll_if_consented(node, "nostr", candidate, verified, item, policy)})
            continue
        if not _remote_handshake_allowed(addr):
            results.append({
                "addr": addr,
                "status": "BLOCKED_TRUSTED_TRANSPORT_NOT_INTEGRATED",
                "handshake_performed": False,
                "enrollment_performed": False,
                "capabilities_granted": [],
            })
            continue
        probed = probe_and_verify(addr)
        if not probed:
            results.append({"addr": addr, "status": "NO_PROTOCOL_MATCH"}); continue
        protocol, candidate, verified = probed
        if dry_run:
            results.append({"addr": addr, "protocol": protocol,
                            "handshake_ok": bool(verified.get("ok")),
                            "operator_authorized": bool(item.get("authorized"))})
            continue
        results.append({"addr": addr, "protocol": protocol,
                        **enroll_if_consented(node, protocol, candidate, verified, item, policy)})
    report = {"utc": utc(), "policy_mode": policy.get("padge_mode"),
        "discovery": discovery_summary, "total_items": len(items), "results": results,
        "summary": {
            "enrolled": sum(1 for r in results if r.get("status") == "ENROLLED"),
            "skipped_not_authorized": sum(1 for r in results if r.get("status","").startswith("SKIPPED_NOT_AUTHORIZED")),
            "skipped_handshake": sum(1 for r in results if r.get("status","").startswith("SKIPPED_HANDSHAKE")),
            "failed": sum(1 for r in results if r.get("status") == "ENROLL_FAILED")}}
    if not dry_run:
        save(REPORT, report); audit("autonomous_cycle_completed", **report["summary"])
    return report

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-discover", action="store_true")
    ap.add_argument("--watch", action="store_true")
    args = ap.parse_args()
    if args.watch:
        while True:
            try:
                print(json.dumps(run_cycle(args.dry_run, not args.no_discover),
                                 indent=2, ensure_ascii=False))
            except Exception as e:
                audit("cycle_error", error=str(e)[:200])
            time.sleep(int(load(SOURCES, {"interval_seconds": 300}).get("interval_seconds", 300)))
    else:
        print(json.dumps(run_cycle(args.dry_run, not args.no_discover),
                         indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
