"""IAO automatic multi-provider router; Python standard library only."""
from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".config" / "iao" / "llm-providers.json"
STATE = Path.home() / ".local" / "share" / "iao" / "llm-health.json"
LOCK = threading.Lock()


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
    """Read configured gateways. Secrets are environment-variable references."""
    data = _read_json(CONFIG, {"providers": []})
    return [
        p for p in data.get("providers", [])
        if isinstance(p, dict)
        and p.get("enabled", True)
        and isinstance(p.get("url"), str)
        and p["url"].startswith("https://")
        and isinstance(p.get("model"), str)
        and p["model"].strip()
    ]


def health():
    return _read_json(STATE, {})


def _request(provider, messages, timeout):
    url = provider["url"].rstrip("/") + "/chat/completions"
    key_env = provider.get("key_env", "")
    key = os.environ.get(key_env, "") if key_env else ""
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
    return answer.strip()


def chat(messages, timeout=25):
    """Try eligible providers in priority order, with automatic failover."""
    candidates = providers()
    if not candidates:
        raise RuntimeError(
            "IAO_NO_PROVIDERS: configure HTTPS OpenAI-compatible gateways "
            "in ~/.config/iao/llm-providers.json"
        )

    states = health()
    now = time.time()

    # Do not call providers that are still in cooldown when another is ready.
    candidates.sort(key=lambda p: (
        states.get(p.get("id", ""), {}).get("failures", 0),
        p.get("priority", 100),
    ))
    ready = [
        p for p in candidates
        if float(states.get(p.get("id", ""), {}).get("retry_after", 0) or 0) <= now
    ]
    if ready:
        candidates = ready
    else:
        # If every provider is cooling down, probe only the earliest eligible retry.
        candidates.sort(key=lambda p: (
            float(states.get(p.get("id", ""), {}).get("retry_after", 0) or 0),
            states.get(p.get("id", ""), {}).get("failures", 0),
            p.get("priority", 100),
        ))
        candidates = candidates[:1]

    errors = []
    for p in candidates:
        ident = p.get("id", p["url"])
        try:
            answer = _request(p, messages, timeout)
            with LOCK:
                states = health()
                states[ident] = {
                    "failures": 0,
                    "last_success": int(time.time()),
                    "retry_after": 0,
                }
                _write_json(STATE, states)
            return answer
        except Exception as exc:
            # Record only a generic error class; never save keys or request text.
            errors.append(f"{ident}:{type(exc).__name__}")
            with LOCK:
                states = health()
                previous = states.get(ident, {})
                failures = min(int(previous.get("failures", 0)) + 1, 12)
                delay = min(90 * (2 ** min(failures - 1, 5)), 3600)
                states[ident] = {
                    "failures": failures,
                    "last_error": type(exc).__name__,
                    "retry_after": int(time.time() + delay + random.randint(0, 15)),
                }
                _write_json(STATE, states)

    raise RuntimeError("IAO_ALL_PROVIDERS_FAILED: " + ", ".join(errors))


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

    def chat(self, messages):
        from omega.adapters.model import ModelError, SYSTEM_PROMPT

        prepared = list(messages)
        if not prepared or prepared[-1].get("role") != "user":
            raise ModelError("INVALID_PROMPT", 400)

        if not any(m.get("role") == "system" for m in prepared):
            prepared.insert(0, {
                "role": "system",
                "content": SYSTEM_PROMPT,
            })

        try:
            return chat(prepared)
        except Exception:
            # Never pass provider response bodies, credentials, or prompts
            # into service errors or audit records.
            raise ModelError("PROVIDER_UNAVAILABLE", 503) from None
