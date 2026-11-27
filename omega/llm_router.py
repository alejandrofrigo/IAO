"""IAO automatic multi-provider router; Python standard library only."""
from __future__ import annotations

import json
import math
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".config" / "iao" / "llm-providers.json"
STATE = Path.home() / ".local" / "share" / "iao" / "llm-health.json"
LOCK = threading.Lock()

def _secret_value(name):
    """Resolve a provider secret without logging or persisting its value."""
    value = os.environ.get(name, "")
    if value:
        return value
    if name != "MODEL_API_KEY":
        return ""
    env_file = Path.cwd() / ".env"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw = line.split("=", 1)
            if key.strip() == name:
                raw = raw.strip()
                if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
                    raw = raw[1:-1]
                return raw
    except OSError:
        pass
    return ""



def _read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def providers():
    """Read configured HTTPS gateways; never load secret values into provider metadata."""
    data = _read_json(CONFIG, {"providers": []})
    configured = data.get("providers", []) if isinstance(data, dict) else []
    result = []
    for provider in configured:
        if not isinstance(provider, dict) or not provider.get("enabled", True):
            continue
        ident = provider.get("id")
        if (
            not isinstance(ident, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", ident)
            or not isinstance(provider.get("url"), str)
            or not provider["url"].startswith("https://")
            or not isinstance(provider.get("model"), str)
            or not provider["model"].strip()
        ):
            continue
        result.append(provider)
    return result


def _route_requirements(value):
    """Validate caller constraints; missing provider metadata never satisfies a constraint."""
    if value is None:
        return {"capabilities": [], "modalities": [], "max_cost_per_1k_tokens": None}
    if not isinstance(value, dict) or set(value) - {
        "capabilities", "modalities", "max_cost_per_1k_tokens"
    }:
        raise ValueError("INVALID_ROUTE_REQUIREMENTS")
    normalized = {}
    for field in ("capabilities", "modalities"):
        items = value.get(field, [])
        if (
            not isinstance(items, list)
            or any(not isinstance(item, str) or not re.fullmatch(
                r"[a-z][a-z0-9_.-]{0,63}", item
            ) for item in items)
            or len(items) != len(set(items))
        ):
            raise ValueError("INVALID_ROUTE_REQUIREMENTS")
        normalized[field] = items
    ceiling = value.get("max_cost_per_1k_tokens")
    if ceiling is not None and (
        isinstance(ceiling, bool)
        or not isinstance(ceiling, (int, float))
        or not math.isfinite(float(ceiling))
        or ceiling < 0
    ):
        raise ValueError("INVALID_ROUTE_REQUIREMENTS")
    normalized["max_cost_per_1k_tokens"] = (
        float(ceiling) if ceiling is not None else None
    )
    return normalized


def _compatible(provider, requirements):
    capabilities = provider.get("capabilities", ["chat.completion"])
    modalities = provider.get("modalities", ["text"])
    if (
        not isinstance(capabilities, list)
        or not all(isinstance(item, str) for item in capabilities)
        or not isinstance(modalities, list)
        or not all(isinstance(item, str) for item in modalities)
        or not set(requirements["capabilities"]).issubset(capabilities)
        or not set(requirements["modalities"]).issubset(modalities)
    ):
        return False
    ceiling = requirements["max_cost_per_1k_tokens"]
    if ceiling is not None:
        cost = provider.get("cost_per_1k_tokens")
        if (
            isinstance(cost, bool)
            or not isinstance(cost, (int, float))
            or not math.isfinite(float(cost))
            or cost < 0
            or float(cost) > ceiling
        ):
            return False
    return True


def _ordered_candidates(configured, states, requirements, now):
    compatible = [p for p in configured if _compatible(p, requirements)]
    if not compatible:
        raise RuntimeError("IAO_NO_COMPATIBLE_PROVIDERS")
    ready = [
        p for p in compatible
        if float(states.get(p["id"], {}).get("retry_after", 0) or 0) <= now
    ]
    candidates = ready or compatible
    return sorted(candidates, key=lambda p: (
        min(int(states.get(p["id"], {}).get("failures", 0) or 0), 1000),
        float(p.get("cost_per_1k_tokens"))
        if isinstance(p.get("cost_per_1k_tokens"), (int, float))
        and not isinstance(p.get("cost_per_1k_tokens"), bool)
        and math.isfinite(float(p["cost_per_1k_tokens"]))
        and p["cost_per_1k_tokens"] >= 0 else float("inf"),
        float(states.get(p["id"], {}).get("latency_ewma_ms", float("inf")) or float("inf")),
        int(p.get("priority", 100)) if isinstance(p.get("priority", 100), int)
        and not isinstance(p.get("priority", 100), bool) else 100,
        p["id"],
    ))


def health():
    return _read_json(STATE, {})


def _request(provider, messages, timeout):
    url = provider["url"].rstrip("/") + "/chat/completions"
    key_env = provider.get("key_env", "")
    key = _secret_value(key_env) if key_env else ""
    payload = {
        "model": provider["model"],
        "messages": messages,
        "stream": False,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            **({"Authorization": "Bearer " + key} if key else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        data = json.loads(response.read(2_000_000).decode("utf-8"))
    answer = data["choices"][0]["message"]["content"]
    if not isinstance(answer, str) or not answer.strip():
        raise ValueError("empty response")
    upstream_model = data.get("model")
    if not isinstance(upstream_model, str) or not upstream_model.strip():
        upstream_model = None
    else:
        upstream_model = upstream_model.strip()[:120]
    return answer.strip(), upstream_model


def chat_with_metadata(messages, timeout=25, requirements=None):
    """Route by declared capability, modality, configured cost, health and priority."""
    configured = providers()
    if not configured:
        raise RuntimeError(
            "IAO_NO_PROVIDERS: configure HTTPS OpenAI-compatible gateways "
            "in ~/.config/iao/llm-providers.json"
        )
    route = _route_requirements(requirements)
    states = health()
    if not isinstance(states, dict):
        states = {}
    candidates = _ordered_candidates(configured, states, route, time.time())

    errors = []
    for p in candidates:
        ident = p["id"]
        started = time.monotonic()
        provider_timeout = p.get("timeout_seconds", timeout)
        if (
            isinstance(provider_timeout, bool)
            or not isinstance(provider_timeout, (int, float))
            or not math.isfinite(float(provider_timeout))
            or provider_timeout <= 0
        ):
            errors.append(f"{ident}:InvalidTimeout")
            continue
        effective_timeout = min(float(timeout), float(provider_timeout))
        try:
            answer, upstream_model = _request(p, messages, effective_timeout)
            latency_ms = max(0.0, (time.monotonic() - started) * 1000.0)
            with LOCK:
                states = health()
                if not isinstance(states, dict):
                    states = {}
                previous = states.get(ident, {})
                old_latency = previous.get("latency_ewma_ms")
                latency_ewma = (
                    latency_ms if not isinstance(old_latency, (int, float))
                    or isinstance(old_latency, bool)
                    else (0.7 * float(old_latency) + 0.3 * latency_ms)
                )
                states[ident] = {
                    "failures": 0,
                    "last_success": int(time.time()),
                    "last_latency_ms": round(latency_ms, 2),
                    "latency_ewma_ms": round(latency_ewma, 2),
                    "retry_after": 0,
                }
                _write_json(STATE, states)
            return {
                "reply": answer,
                "model_identity": {
                    "provider_id": str(ident)[:120],
                    "configured_model": str(p["model"])[:120],
                    "upstream_model": upstream_model,
                    "identity_status": (
                        "upstream_model_reported"
                        if upstream_model else "configured_model_only"
                    ),
                },
            }
        except Exception as exc:
            # Record only a generic error class; never save keys or request text.
            errors.append(f"{ident}:{type(exc).__name__}")
            latency_ms = max(0.0, (time.monotonic() - started) * 1000.0)
            with LOCK:
                states = health()
                if not isinstance(states, dict):
                    states = {}
                previous = states.get(ident, {})
                failures = min(int(previous.get("failures", 0)) + 1, 12)
                delay = min(90 * (2 ** min(failures - 1, 5)), 3600)
                old_latency = previous.get("latency_ewma_ms")
                latency_ewma = (
                    latency_ms if not isinstance(old_latency, (int, float))
                    or isinstance(old_latency, bool)
                    else (0.7 * float(old_latency) + 0.3 * latency_ms)
                )
                states[ident] = {
                    "failures": failures,
                    "last_error": type(exc).__name__,
                    "last_latency_ms": round(latency_ms, 2),
                    "latency_ewma_ms": round(latency_ewma, 2),
                    "retry_after": int(time.time() + delay + random.randint(0, 15)),
                }
                _write_json(STATE, states)

    raise RuntimeError("IAO_ALL_PROVIDERS_FAILED: " + ", ".join(errors))


def chat(messages, timeout=25, requirements=None):
    """Backward-compatible text-only router interface with optional route constraints."""
    return chat_with_metadata(messages, timeout, requirements)["reply"]


def status():
    configured = providers()
    states = health()
    return {
        "configured": len(configured),
        "providers": [
            {
                "id": p.get("id", "unnamed"),
                "model": p["model"],
                "failures": states.get(p.get("id", ""), {}).get("failures", 0),
                "last_success": states.get(p.get("id", ""), {}).get("last_success"),
            }
            for p in configured
        ],
    }


class RouterModelAdapter:
    """Adapter compatible with the IAO chat service contract."""

    def _prepare(self, messages):
        from omega.adapters.model import ModelError, SYSTEM_PROMPT

        prepared = list(messages)
        if not prepared or prepared[-1].get("role") != "user":
            raise ModelError("INVALID_PROMPT", 400)

        if not any(m.get("role") == "system" for m in prepared):
            prepared.insert(0, {
                "role": "system",
                "content": SYSTEM_PROMPT,
            })
        return prepared

    def chat(self, messages):
        """Backward-compatible text-only adapter interface."""
        return self.chat_with_metadata(messages)["reply"]

    def chat_with_metadata(self, messages, requirements=None):
        from omega.adapters.model import ModelError

        prepared = self._prepare(messages)
        try:
            return chat_with_metadata(prepared, requirements=requirements)
        except Exception:
            # Never pass provider response bodies, credentials, or prompts
            # into service errors or audit records.
            raise ModelError("PROVIDER_UNAVAILABLE", 503) from None
