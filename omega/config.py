"""Typed, stdlib-only configuration. Secrets come from the environment / secret broker."""
import os
from dataclasses import dataclass

_ENVS = {"development", "test", "staging", "production"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    host: str
    port: int
    model_adapter: str
    public_base_url: str

    def __repr__(self) -> str:  # never leak secrets via repr
        return f"Settings(app_env={self.app_env!r}, port={self.port})"


def load_settings(env: dict[str, str] | None = None) -> Settings:
    e = dict(os.environ) if env is None else env
    app_env = e.get("APP_ENV", "development")
    if app_env not in _ENVS:
        raise ValueError(f"APP_ENV must be one of {sorted(_ENVS)}")
    port = int(e.get("PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT out of range")
    model_adapter = e.get(
        "MODEL_ADAPTER", e.get("MODEL_PROVIDER", "disabled")
    ).strip().lower()
    allowed_adapters = {"disabled", "anthropic", "gemini", "groq"}
    if model_adapter not in allowed_adapters:
        raise ValueError("MODEL_ADAPTER must be disabled, anthropic, gemini, or groq")
    provider = e.get("MODEL_PROVIDER", "").strip().lower()
    if model_adapter != "disabled" and provider and provider != model_adapter:
        raise ValueError("MODEL_ADAPTER and MODEL_PROVIDER must match")
    return Settings(
        app_env=app_env,
        host=e.get("HOST", "127.0.0.1"),
        port=port,
        model_adapter=model_adapter,
        public_base_url=e.get("PUBLIC_BASE_URL", "http://localhost:8080"),
    )
