"""Typed, stdlib-only configuration. Secrets come from the environment / secret broker."""
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

_ENVS = {"development", "test", "staging", "production"}
_ALLOWED_ADAPTERS = {"disabled", "anthropic", "gemini", "groq"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    host: str
    port: int
    model_adapter: str
    public_base_url: str

    def __repr__(self) -> str:  # never leak secrets via repr
        return f"Settings(app_env={self.app_env!r}, port={self.port})"


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("PORT out of range")
    return port


def _validate_host(host: str) -> str:
    if not host or host != host.strip() or any(
        character.isspace() or ord(character) < 32 for character in host
    ):
        raise ValueError("HOST must be a non-empty host without whitespace")
    return host


def _validate_public_base_url(value: str) -> str:
    if not value or value != value.strip():
        raise ValueError("PUBLIC_BASE_URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port  # Forces validation of malformed/out-of-range ports.
    except ValueError as exc:
        raise ValueError("PUBLIC_BASE_URL is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("PUBLIC_BASE_URL must be an HTTP(S) URL without credentials, query or fragment")
    return value.rstrip("/")


def load_settings(env: dict[str, str] | None = None) -> Settings:
    e = dict(os.environ) if env is None else env
    app_env = e.get("APP_ENV", "development")
    if app_env not in _ENVS:
        raise ValueError(f"APP_ENV must be one of {sorted(_ENVS)}")
    port = _parse_port(e.get("PORT", "8080"))
    host = _validate_host(e.get("HOST", "127.0.0.1"))
    model_adapter = e.get(
        "MODEL_ADAPTER", e.get("MODEL_PROVIDER", "disabled")
    ).strip().lower()
    if model_adapter not in _ALLOWED_ADAPTERS:
        raise ValueError("MODEL_ADAPTER must be disabled, anthropic, gemini, or groq")
    provider = e.get("MODEL_PROVIDER", "").strip().lower()
    if model_adapter != "disabled" and provider and provider != model_adapter:
        raise ValueError("MODEL_ADAPTER and MODEL_PROVIDER must match")
    public_base_url = _validate_public_base_url(
        e.get("PUBLIC_BASE_URL", "http://localhost:8080")
    )
    return Settings(
        app_env=app_env,
        host=host,
        port=port,
        model_adapter=model_adapter,
        public_base_url=public_base_url,
    )
