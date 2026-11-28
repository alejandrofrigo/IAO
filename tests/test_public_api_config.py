from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_frontend_does_not_pin_an_ephemeral_api_tunnel():
    config = (ROOT / "web" / "api-config.js").read_text(encoding="utf-8")
    assert "trycloudflare.com" not in config
    assert 'window.IAO_API_BASE = "";' in config
    assert 'IAO_API_ENDPOINT_NOT_CONFIGURED' in config
    assert 'origin.protocol !== "https:"' in config


def test_pages_build_uses_explicit_provider_neutral_api_origin():
    workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(
        encoding="utf-8"
    )
    assert "vars.IAO_API_BASE_URL" in workflow
    assert "IAO_API_BASE_URL must be an HTTPS origin" in workflow
    assert "IAO_API_ENDPOINT_NOT_CONFIGURED" in workflow
