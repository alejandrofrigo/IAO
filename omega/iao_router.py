"""Enrutador IAO: proveedores configurados, fallback y secretos locales."""
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILES = (ROOT / ".env", Path.home() / ".iao-runtime.env")

def _load_local_env():
    # Lee configuración local sin imprimir ni exportar secretos a logs.
    for path in ENV_FILES:
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k.replace("_", "").isalnum():
                    os.environ.setdefault(k, v)
        except (OSError, UnicodeError):
            pass

def _messages(history):
    if isinstance(history, list):
        out = []
        for item in history:
            if isinstance(item, dict) and "content" in item:
                role = item.get("role", "user")
                if role not in ("system", "user", "assistant"):
                    role = "user"
                content = item.get("content", "")
                if isinstance(content, str):
                    out.append({"role": role, "content": content})
                else:
                    out.append({"role": role, "content": json.dumps(content, ensure_ascii=False)})
            else:
                out.append({"role": "user", "content": str(item)})
        return out
    return [{"role": "user", "content": str(history)}]

def _post(url, headers, payload, timeout=35):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(4_000_000)
        obj = json.loads(raw.decode("utf-8"))
    return obj

def _openai_compatible(name, key, base, model, messages):
    obj = _post(
        base.rstrip("/") + "/chat/completions",
        {"Authorization": "Bearer " + key, "Content-Type": "application/json",
         "User-Agent": "IAO/1.0"},
        {"model": model, "messages": messages, "stream": False},
    )
    return obj["choices"][0]["message"]["content"]

def _gemini(key, model, messages):
    # Gemini REST API; el contenido se transforma a su esquema nativo.
    contents = []
    system_parts = []
    for m in messages:
        if m["role"] == "system":
            system_parts.append(m["content"])
        else:
            contents.append({
                "role": "model" if m["role"] == "assistant" else "user",
                "parts": [{"text": m["content"]}]
            })
    payload = {"contents": contents}
    if system_parts:
        payload["systemInstruction"] = {"parts": [{"text": "\n".join(system_parts)}]}
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           + model + ":generateContent?key=" + key)
    obj = _post(url, {"Content-Type": "application/json"}, payload)
    return "".join(p.get("text", "") for p in
                   obj["candidates"][0]["content"]["parts"])

def _providers():
    _load_local_env()
    # Se intenta únicamente con claves que existan en la configuración local.
    specs = [
        ("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1",
         "GROQ_MODEL", "llama-3.3-70b-versatile"),
        ("cerebras", "CEREBRAS_API_KEY", "https://api.cerebras.ai/v1",
         "CEREBRAS_MODEL", "llama-3.3-70b"),
        ("openrouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1",
         "OPENROUTER_MODEL", "openrouter/auto"),
        ("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1",
         "MISTRAL_MODEL", "mistral-small-latest"),
        ("deepseek", "DEEPSEEK_API_KEY", "https://api.deepseek.com",
         "DEEPSEEK_MODEL", "deepseek-chat"),
        ("together", "TOGETHER_API_KEY", "https://api.together.xyz/v1",
         "TOGETHER_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
        ("sambanova", "SAMBANOVA_API_KEY", "https://api.sambanova.ai/v1",
         "SAMBANOVA_MODEL", "Meta-Llama-3.3-70B-Instruct"),
        ("nvidia", "NVIDIA_API_KEY", "https://integrate.api.nvidia.com/v1",
         "NVIDIA_MODEL", "meta/llama-3.3-70b-instruct"),
        ("fireworks", "FIREWORKS_API_KEY", "https://api.fireworks.ai/inference/v1",
         "FIREWORKS_MODEL", "accounts/fireworks/models/llama-v3p3-70b-instruct"),
    ]
    configured = []
    for name, keyvar, base, modelvar, default_model in specs:
        key = os.environ.get(keyvar, "").strip()
        if key:
            configured.append((name, key, base,
                               os.environ.get(modelvar, default_model).strip()))
    # También admite la configuración existente MODEL_PROVIDER/MODEL_API_KEY.
    provider = os.environ.get("MODEL_PROVIDER", "").strip().lower()
    key = os.environ.get("MODEL_API_KEY", "").strip()
    if key and provider in ("groq", "cerebras", "openrouter", "mistral",
                            "deepseek", "together", "sambanova", "nvidia",
                            "fireworks"):
        lookup = {x[0]: x for x in specs}
        spec = lookup.get(provider)
        if spec and not any(p[0] == provider for p in configured):
            configured.append((
                provider, key, spec[2],
                os.environ.get("MODEL_ID", spec[4]).strip()
            ))
    gkey = os.environ.get("GEMINI_API_KEY", "").strip()
    if gkey:
        configured.append((
            "gemini", gkey, "",
            os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip()
        ))
    # Orden opcional explícito; no se presume que una API sea gratuita.
    order = [x.strip().lower() for x in
             os.environ.get("IAO_PROVIDER_ORDER", "").split(",") if x.strip()]
    if order:
        rank = {name: i for i, name in enumerate(order)}
        configured.sort(key=lambda p: rank.get(p[0], len(rank)))
    return configured

def _provider_call(p, messages):
    name, key, base, model = p
    if name == "gemini":
        return _gemini(key, model, messages)
    return _openai_compatible(name, key, base, model, messages)

def chat_with_fallback(existing_model, history):
    """Intenta proveedores configurados; usa el adaptador original como fallback."""
    messages = _messages(history)
    failures = []
    for p in _providers():
        try:
            answer = _provider_call(p, messages)
            if isinstance(answer, str) and answer.strip():
                return answer
            failures.append(p[0] + ":respuesta vacía")
        except Exception as exc:
            # No guardar mensajes, tokens, claves ni cuerpos de peticiones.
            failures.append(p[0] + ":" + type(exc).__name__)
    if existing_model is not None and hasattr(existing_model, "chat"):
        try:
            return existing_model.chat(history)
        except Exception:
            # No ocultar el error final real del adaptador.
            raise
    raise RuntimeError(
        "No hay proveedor de IA operativo. Fallos de proveedores: "
        + ", ".join(failures or ["ninguna credencial configurada"])
    )
