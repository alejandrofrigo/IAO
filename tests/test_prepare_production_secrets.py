from __future__ import annotations

import stat

import pytest

from tools.iao_prepare_production_secrets import write_production_secrets


def test_production_secrets_are_private_and_never_overwritten(tmp_path):
    target = tmp_path / ".env.production"
    result = write_production_secrets(target, now=1_000)
    assert result == target
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    content = target.read_text(encoding="utf-8")
    assert "APP_ENV=production" in content
    assert "IAO_SESSION_SIGNING_KEY=" in content
    assert "AUDIT_HMAC_KEY=" in content
    assert "IAO_DEVICE_ENROLLMENT_CODE=" in content
    assert "IAO_OPERATOR_BOOTSTRAP_CODE=" in content
    assert "IAO_OPERATOR_BOOTSTRAP_EXPIRES_AT=1900" in content
    assert "PUBLIC_BASE_URL=CHANGE_ME_HTTPS_ORIGIN" in content
    with pytest.raises(FileExistsError, match="PRODUCTION_ENV_ALREADY_EXISTS"):
        write_production_secrets(target, now=1_001)


def test_generated_session_and_audit_keys_are_distinct(tmp_path):
    target = write_production_secrets(tmp_path / ".env.production", now=1_000)
    values = dict(
        line.split("=", 1)
        for line in target.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert values["IAO_SESSION_SIGNING_KEY"] != values["AUDIT_HMAC_KEY"]
    assert len(values["IAO_SESSION_SIGNING_KEY"]) >= 32
    assert len(values["AUDIT_HMAC_KEY"]) >= 32
