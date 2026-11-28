"""Contract tests for the hardened, persistent single-host production package."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_production_compose_is_private_and_persistent():
    compose = (ROOT / "compose.production.yaml").read_text(encoding="utf-8")
    assert 'APP_ENV: production' in compose
    assert '"127.0.0.1:8080:8080"' in compose
    assert 'OMEGA_TOKEN_SIGNING_KEY: ${OMEGA_TOKEN_SIGNING_KEY:?Set OMEGA_TOKEN_SIGNING_KEY}' in compose
    assert 'AUDIT_HMAC_KEY: ${AUDIT_HMAC_KEY:?Set AUDIT_HMAC_KEY}' in compose
    assert 'IAO_CORS_ORIGINS: ${IAO_CORS_ORIGINS:?Set IAO_CORS_ORIGINS' in compose
    assert 'iao-state:/var/lib/iao' in compose
    assert 'restart: unless-stopped' in compose
    assert 'read_only: true' in compose
    assert 'no-new-privileges:true' in compose
    assert 'cap_drop:' in compose and '      - ALL' in compose


def test_production_compose_does_not_enable_unconfigured_paid_or_llm_provider():
    compose = (ROOT / "compose.production.yaml").read_text(encoding="utf-8")
    assert "IAO_LLM_ROUTER" not in compose
    assert "ANTHROPIC_API_KEY" not in compose
    assert "GEMINI_API_KEY" not in compose
    assert "GROQ_API_KEY" not in compose


def test_production_docs_state_single_instance_and_unverified_infrastructure():
    docs = (ROOT / "docs" / "production-host.md").read_text(encoding="utf-8")
    assert "single API instance" in docs
    assert "Do not scale replicas" in docs
    assert "does not establish global P2P connectivity" in docs
    assert "does not" in docs and "24/7 service" in docs
