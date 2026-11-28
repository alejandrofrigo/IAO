"""The container contract must stay non-root, persistent and probeable."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_declares_non_root_persistent_runtime_and_healthcheck():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER iao" in dockerfile
    assert 'VOLUME ["/var/lib/iao"]' in dockerfile
    assert "HEALTHCHECK --interval=30s --timeout=5s" in dockerfile
    assert "http://127.0.0.1:8080/health/live" in dockerfile
    assert "--no-access-log" in dockerfile
    assert "COPY .env" not in dockerfile
    assert "ARG OMEGA_DEV_TOKEN_KEY" not in dockerfile
    assert "ENV OMEGA_DEV_TOKEN_KEY" not in dockerfile
    deploy_dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    assert 'VOLUME ["/var/lib/iao"]' in deploy_dockerfile
    assert "OMEGA_STATE_DIR=/var/lib/iao" in deploy_dockerfile
    assert "HOME=/var/lib/iao/home" in deploy_dockerfile
    assert "IAO_STATE_DIR=/var/lib/iao" in deploy_dockerfile
    assert "OMEGA_CORPUS_DIR=/app/docs/corpus" in deploy_dockerfile
    assert "PORT=8080" in deploy_dockerfile
    assert "COPY .env" not in deploy_dockerfile
