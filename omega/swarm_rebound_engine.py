#!/usr/bin/env python3
"""Motor de enjambre con revote continuo para candidatos/nodos IAO verificables."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
LOG_DIR = ROOT / "logs"
STATE_FILE = STATE_DIR / "swarm-rebound-state.json"
AUDIT_LOG = LOG_DIR / "swarm-rebound.jsonl"

STOP = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _handle_sig(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True


def _valid_hex(val: Any, length: int) -> bool:
    if not isinstance(val, str) or len(val) != length:
        return False
    return all(c in "0123456789abcdef" for c in val)


def _expected_node_id(pub_hex: str) -> str:
    pub_bytes = bytes.fromhex(pub_hex)
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def _normalize_base_url(raw: str) -> str | None:
    if not isinstance(raw, str):
        return None
    u = raw.strip().rstrip("/")
    if not (u.startswith("http://") or u.startswith("https://")):
        return None
    for suffix in ("/fed/v1/message", "/fed/v1/identity", "/fed/v1/handshake"):
        if u.endswith(suffix):
            u = u[: -len(suffix)]
    return u or None


def collect_candidate_urls(extra_urls: list[str] | None = None) -> list[str]:
    """Recolecta URLs candidatas configuradas o locales reales (sin inventar hosts)."""
    candidates: list[str] = []

    # 1. Nodo local IAO en 127.0.0.1:8080 si está configurado
    local_port = os.environ.get("IAO_LOCAL_HTTP_PORT", "8080").strip()
    if local_port.isdigit():
        candidates.append(f"http://127.0.0.1:{local_port}")

    # 2. Fuentes en .state/ si existen
    pub_ep = STATE_DIR / "iao-federation-public-endpoint.json"
    if pub_ep.exists():
        try:
            data = json.loads(pub_ep.read_text(encoding="utf-8"))
            for key in ("endpoint", "identity_url", "url"):
                norm = _normalize_base_url(data.get(key, ""))
                if norm:
                    candidates.append(norm)
        except Exception:
            pass

    directory = STATE_DIR / "my-federation-directory.json"
    if directory.exists():
        try:
            data = json.loads(directory.read_text(encoding="utf-8"))
            for peer in data.get("peers", []):
                if isinstance(peer, dict):
                    norm = _normalize_base_url(peer.get("url", ""))
                    if norm:
                        candidates.append(norm)
        except Exception:
            pass

    # 2c. Endpoints anunciados dentro del manifiesto publicado en IPFS
    candidates.extend(collect_ipfs_manifest_urls())

    # 3. URLs adicionales explícitas por entorno o CLI
    env_extra = os.environ.get("IAO_SWARM_CANDIDATE_URLS", "")
    for item in env_extra.split(","):
        norm = _normalize_base_url(item)
        if norm:
            candidates.append(norm)

    for item in extra_urls or []:
        norm = _normalize_base_url(item)
        if norm:
            candidates.append(norm)

    # Deduplicar preservando orden
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def probe_candidate(base_url: str, timeout: float = 4.0) -> dict[str, Any]:
    """Sondea /fed/v1/identity o raíz del candidato y mide latencia y validez."""
    t0 = time.monotonic()
    identity_url = f"{base_url}/fed/v1/identity"
    probe_result: dict[str, Any] = {
        "url": base_url,
        "identity_url": identity_url,
        "probed_at": utc_now(),
        "reachable": False,
        "protocol_valid": False,
        "node_id": None,
        "public_key_prefix": None,
        "http_status": None,
        "latency_ms": None,
        "error": None,
    }

    req = urllib.request.Request(
        identity_url,
        headers={"User-Agent": "IAO-Swarm-Rebound/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
            probe_result["http_status"] = resp.status
            probe_result["latency_ms"] = latency_ms
            probe_result["reachable"] = 200 <= resp.status < 500
            raw_body = resp.read(8192).decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw_body)
            except Exception:
                payload = None

            if isinstance(payload, dict):
                proto = payload.get("protocol")
                ver = payload.get("version")
                nid = payload.get("node_id")
                pub = payload.get("public_key")
                if proto == "iao-federation" and ver == 1 and _valid_hex(nid, 16) and _valid_hex(pub, 64):
                    expected = _expected_node_id(pub)
                    if expected == nid:
                        probe_result["protocol_valid"] = True
                        probe_result["node_id"] = nid
                        probe_result["public_key_prefix"] = pub[:12] + "..."
                    else:
                        probe_result["error"] = "NODE_ID_KEY_MISMATCH"
                else:
                    probe_result["error"] = "NON_FEDERATION_OR_PARTIAL_IDENTITY"
            else:
                probe_result["error"] = "INVALID_JSON_IDENTITY"
    except urllib.error.HTTPError as exc:
        probe_result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        probe_result["http_status"] = exc.code
        probe_result["reachable"] = True
        probe_result["error"] = f"HTTP_{exc.code}"
    except Exception as exc:
        probe_result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        probe_result["error"] = f"{type(exc).__name__}:{exc}"

    return probe_result



def collect_p2p_peer_urls() -> list[str]:
    """Recolecta URLs de pares P2P descubiertos o anunciados en archivos de estado."""
    discovered: list[str] = []
    p2p_file_env = os.environ.get("IAO_P2P_PEERS_FILE", "").strip()
    peer_files = [Path(p2p_file_env)] if p2p_file_env else []
    peer_files.extend([
        STATE_DIR / "p2p-peers.json",
        STATE_DIR / "dht-discovered-peers.json",
    ])

    for pf in peer_files:
        if not pf.exists():
            continue
        try:
            raw = json.loads(pf.read_text(encoding="utf-8"))
            items = raw.get("peers", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
            for item in items:
                if isinstance(item, str):
                    norm = _normalize_base_url(item)
                    if norm:
                        discovered.append(norm)
                elif isinstance(item, dict):
                    for key in ("url", "endpoint", "http_url", "identity_url"):
                        norm = _normalize_base_url(item.get(key, ""))
                        if norm:
                            discovered.append(norm)
                            break
        except Exception:
            pass
    return discovered


def register_verified_peer(url: str, probe: dict[str, Any]) -> None:
    """Persiste nodos con protocolo válido en .state/my-federation-directory.json."""
    if not probe.get("protocol_valid"):
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    dir_path = STATE_DIR / "my-federation-directory.json"
    data: dict[str, Any] = {"schema": "IAO_FEDERATION_DIRECTORY_V1", "peers": []}
    if dir_path.exists():
        try:
            loaded = json.loads(dir_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("peers"), list):
                data = loaded
        except Exception:
            pass
    peers = [p for p in data["peers"] if isinstance(p, dict) and p.get("url") != url]
    peers.append({
        "url": url,
        "node_id": probe.get("node_id"),
        "public_key_prefix": probe.get("public_key_prefix"),
        "last_seen_utc": probe.get("probed_at"),
        "latency_ms": probe.get("latency_ms"),
        "status": "VERIFIED",
    })
    data["peers"] = peers
    data["updated_at"] = utc_now()
    dir_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")



def _read_manifest_by_cid(cid: str, timeout_sec: float = 3.0) -> list[str]:
    proc = subprocess.run(
        ["ipfs", "cat", cid.strip()],
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    manifest = json.loads(proc.stdout)
    if not isinstance(manifest, dict):
        return []
    found: list[str] = []
    for ep in manifest.get("endpoints", []):
        if isinstance(ep, str):
            norm = _normalize_base_url(ep)
            if norm:
                found.append(norm)
    for peer in manifest.get("peers", []):
        if isinstance(peer, dict):
            norm = _normalize_base_url(peer.get("url", ""))
            if norm:
                found.append(norm)
    return found


def collect_ipfs_manifest_urls(timeout_sec: float = 3.0) -> list[str]:
    """Lee manifiestos IAO referenciados por CID en .state/ipfs-swarm-manifest.json e ipfs-swarm-index.json."""
    cids: list[str] = []
    ref_path = STATE_DIR / "ipfs-swarm-manifest.json"
    if ref_path.exists():
        try:
            ref = json.loads(ref_path.read_text(encoding="utf-8"))
            cid = ref.get("cid") if isinstance(ref, dict) else None
            if isinstance(cid, str) and cid.strip():
                cids.append(cid.strip())
        except Exception:
            pass

    idx_path = STATE_DIR / "ipfs-swarm-index.json"
    if idx_path.exists():
        try:
            idx = json.loads(idx_path.read_text(encoding="utf-8"))
            raw_cids = idx.get("cids", []) if isinstance(idx, dict) else (idx if isinstance(idx, list) else [])
            for item in raw_cids:
                if isinstance(item, str) and item.strip():
                    cids.append(item.strip())
                elif isinstance(item, dict) and isinstance(item.get("cid"), str) and item["cid"].strip():
                    cids.append(item["cid"].strip())
        except Exception:
            pass

    urls: list[str] = []
    seen_cids: set[str] = set()
    for cid in cids:
        if cid in seen_cids:
            continue
        seen_cids.add(cid)
        try:
            urls.extend(_read_manifest_by_cid(cid, timeout_sec=timeout_sec))
        except Exception:
            continue
    return urls


def trigger_constant_p2p_assimilation(timeout_sec: float = 4.0) -> None:
    """Ejecuta la asimilación periódica de peers abiertos de la red P2P sin bloquear el ciclo."""
    script_path = ROOT / "logs" / "assimilate-open-p2p.sh"
    if not script_path.exists():
        return
    try:
        subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except Exception:
        pass


def trigger_periodic_ipfs_publish(cycle_num: int, every_n_cycles: int = 3, timeout_sec: float = 5.0) -> None:
    """Publica/actualiza el manifiesto y el índice CID en IPFS cada N ciclos sin bloquear el motor."""
    if cycle_num <= 0 or cycle_num % max(1, every_n_cycles) != 0:
        return
    script_path = ROOT / "logs" / "publish-ipfs-swarm.sh"
    if not script_path.exists():
        return
    try:
        subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except Exception:
        pass


def compute_score(probe: dict[str, Any], consecutive_ok: int) -> float:
    if not probe.get("reachable"):
        return 0.0
    score = 40.0
    if probe.get("protocol_valid"):
        score += 40.0
    latency = probe.get("latency_ms")
    if isinstance(latency, (int, float)) and latency >= 0:
        # Bonificación por baja latencia (hasta +15 pts)
        score += max(0.0, 15.0 - min(latency / 40.0, 15.0))
    score += min(consecutive_ok * 1.5, 5.0)
    return round(score, 2)


class SwarmReboundEngine:
    def __init__(self, extra_urls: list[str] | None = None, hysteresis_margin: float = 5.0) -> None:
        self.extra_urls = extra_urls or []
        self.hysteresis_margin = hysteresis_margin
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    data.setdefault("cycle", 0)
                    data.setdefault("leader_url", None)
                    data.setdefault("candidates", {})
                    data.setdefault("rebound_history", [])
                    return data
            except Exception:
                pass
        return {
            "schema": "IAO_SWARM_REBOUND_V1",
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "cycle": 0,
            "leader_url": None,
            "candidates": {},
            "rebound_history": [],
        }

    def _save_state(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.state["updated_at"] = utc_now()
        STATE_FILE.write_text(
            json.dumps(self.state, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _append_audit(self, entry: dict[str, Any]) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def run_cycle(self) -> dict[str, Any]:
        trigger_constant_p2p_assimilation()
        now_ts = time.time()
        self.state["cycle"] = int(self.state.get("cycle", 0)) + 1
        cycle_num = self.state["cycle"]

        urls = collect_candidate_urls(self.extra_urls)
        cand_map: dict[str, dict[str, Any]] = self.state.setdefault("candidates", {})

        # Asegurar que URLs previas sigan rastreadas si existían
        for prev_url in list(cand_map.keys()):
            if prev_url not in urls:
                urls.append(prev_url)

        evaluations: list[dict[str, Any]] = []
        for url in urls:
            entry = cand_map.setdefault(
                url,
                {
                    "url": url,
                    "consecutive_ok": 0,
                    "consecutive_fail": 0,
                    "backoff_until": 0.0,
                    "score": 0.0,
                    "last_probe": None,
                },
            )

            backoff_until = float(entry.get("backoff_until", 0.0))
            if now_ts < backoff_until:
                remaining = round(backoff_until - now_ts, 1)
                evaluations.append(
                    {
                        "url": url,
                        "skipped_backoff_sec": remaining,
                        "score": entry.get("score", 0.0),
                        "protocol_valid": bool((entry.get("last_probe") or {}).get("protocol_valid")),
                    }
                )
                continue

            probe = probe_candidate(url)
            entry["last_probe"] = probe

            if probe.get("reachable"):
                entry["consecutive_ok"] = int(entry.get("consecutive_ok", 0)) + 1
                entry["consecutive_fail"] = 0
                entry["backoff_until"] = 0.0
            else:
                entry["consecutive_ok"] = 0
                entry["consecutive_fail"] = int(entry.get("consecutive_fail", 0)) + 1
                backoff_sec = min(15.0 * (2 ** min(entry["consecutive_fail"] - 1, 5)), 300.0)
                entry["backoff_until"] = now_ts + backoff_sec

            if probe.get("protocol_valid"):
                register_verified_peer(url, probe)
            score = compute_score(probe, entry["consecutive_ok"])
            entry["score"] = score
            evaluations.append(
                {
                    "url": url,
                    "reachable": probe.get("reachable"),
                    "protocol_valid": probe.get("protocol_valid"),
                    "node_id": probe.get("node_id"),
                    "latency_ms": probe.get("latency_ms"),
                    "score": score,
                    "error": probe.get("error"),
                }
            )

        # Revotación con histéresis para evitar cambios por micro-oscilaciones
        eligible = [ev for ev in evaluations if ev.get("score", 0.0) > 0.0]
        eligible.sort(key=lambda x: (-x["score"], x.get("latency_ms") if x.get("latency_ms") is not None else 999999.0))

        prev_leader = self.state.get("leader_url")
        new_leader = prev_leader
        rebound_reason = "NO_CHANGE"

        prev_eval = next((e for e in eligible if e["url"] == prev_leader), None)
        best_eval = eligible[0] if eligible else None

        if best_eval is None:
            new_leader = None
            rebound_reason = "NO_REACHABLE_CANDIDATES"
        elif prev_eval is None:
            new_leader = best_eval["url"]
            rebound_reason = "INITIAL_OR_PREV_LEADER_UNAVAILABLE"
        elif best_eval["url"] != prev_leader:
            if best_eval["score"] >= prev_eval["score"] + self.hysteresis_margin:
                new_leader = best_eval["url"]
                rebound_reason = f"SCORE_SURPASSED_HYSTERESIS({best_eval['score']}>{prev_eval['score']}+{self.hysteresis_margin})"
            else:
                rebound_reason = "HELD_BY_HYSTERESIS"
        else:
            rebound_reason = "LEADER_CONFIRMED"

        rebound_occurred = new_leader != prev_leader
        self.state["leader_url"] = new_leader

        summary = {
            "cycle": cycle_num,
            "utc": utc_now(),
            "leader_url": new_leader,
            "rebound_occurred": rebound_occurred,
            "rebound_reason": rebound_reason,
            "reachable_count": len(eligible),
            "total_tracked": len(evaluations),
            "evaluations": evaluations,
        }

        hist = self.state.setdefault("rebound_history", [])
        hist.append(
            {
                "cycle": cycle_num,
                "utc": summary["utc"],
                "leader_url": new_leader,
                "rebound_occurred": rebound_occurred,
                "rebound_reason": rebound_reason,
                "reachable_count": len(eligible),
            }
        )
        self.state["rebound_history"] = hist[-50:]

        self._save_state()
        self._append_audit(summary)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="IAO Swarm Rebound Engine")
    parser.add_argument("--once", action="store_true", help="Ejecuta un solo ciclo de revote")
    parser.add_argument("--loop", action="store_true", help="Ejecuta en bucle continuo")
    parser.add_argument("--interval", type=int, default=30, help="Segundos entre ciclos en --loop")
    parser.add_argument("--url", action="append", default=[], help="URL base candidata adicional")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    engine = SwarmReboundEngine(extra_urls=args.url)
    if args.once or not args.loop:
        res = engine.run_cycle()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    interval = max(5, int(args.interval))
    while not STOP:
        res = engine.run_cycle()
        print(
            f"[{res['utc']}] cycle={res['cycle']} leader={res['leader_url']} "
            f"reachable={res['reachable_count']}/{res['total_tracked']} reason={res['rebound_reason']}",
            flush=True,
        )
        for _ in range(interval):
            if STOP:
                break
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
