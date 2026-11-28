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


def chat_with_metadata(messages, timeout=25):
    """Return generated text and non-secret technical provider metadata."""
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
        # Probe every cooling provider in recovery order. A failed probe
        # must not prevent trying the next configured provider.
        candidates.sort(key=lambda p: (
            float(states.get(p.get("id", ""), {}).get("retry_after", 0) or 0),
            states.get(p.get("id", ""), {}).get("failures", 0),
            p.get("priority", 100),
        ))

    errors = []
    for p in candidates:
        ident = p.get("id", p["url"])
        try:
            answer, upstream_model = _request(p, messages, timeout)
            with LOCK:
                states = health()
                states[ident] = {
                    "failures": 0,
                    "last_success": int(time.time()),
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


def chat(messages, timeout=25):
    """Backward-compatible text-only router interface."""
    return chat_with_metadata(messages, timeout)["reply"]


def _credential_present(provider):
    key_env = provider.get("key_env", "")
    if not key_env:
        return False
    return bool(_secret_value(key_env))


def status():
    """Expose declaration/credential/evidence state without probing or leaking secrets.

    ``declared`` means the provider is present in the local inventory.
    ``credential_present`` means its referenced secret resolves at runtime.
    ``connectivity`` becomes ``confirmed`` only after a real successful call;
    configuration alone never marks a provider available.
    """
    configured = providers()
    states = health()
    result = []
    for p in configured:
        ident = p.get("id", "unnamed")
        state = states.get(ident, {})
        success = state.get("last_success")
        result.append({
            "id": ident,
            "model": p["model"],
            "declared": True,
            "credential_present": _credential_present(p),
            "connectivity": "confirmed" if success else "unverified",
            "failures": state.get("failures", 0),
            "last_success": success,
        })
    return {
        "configured": len(configured),
        "providers": result,
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

    def chat_with_metadata(self, messages):
        from omega.adapters.model import ModelError

        prepared = self._prepare(messages)
        try:
            return chat_with_metadata(prepared)
        except Exception:
            # Never pass provider response bodies, credentials, or prompts
            # into service errors or audit records.
            raise ModelError("PROVIDER_UNAVAILABLE", 503) from None
