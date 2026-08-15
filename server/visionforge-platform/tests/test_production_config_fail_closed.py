from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-production-config")

from app.config import Config, _is_https_origin


def test_https_origin_normalizes_outer_whitespace() -> None:
    assert _is_https_origin("  https://visionforge.example  ")
    assert not _is_https_origin("https://visionforge.example/path")
    assert not _is_https_origin("http://visionforge.example")


def test_production_configuration_cannot_disable_runtime_boundaries(monkeypatch) -> None:
    monkeypatch.setattr(Config, "ENVIRONMENT", "production")
    monkeypatch.setattr(Config, "SITE_URL", " https://visionforge.example ")
    monkeypatch.setattr(Config, "REQUIRE_RUNTIME_INTEGRITY", False)
    monkeypatch.setattr(Config, "REQUIRE_RUNTIME_INSTANCE_ID", False)
    monkeypatch.setattr(Config, "ALLOW_INSECURE_RUNTIME_LEASE_HMAC", True)
    monkeypatch.setattr(Config, "COOKIE_SECURE", False)

    errors = Config.validate()

    assert "REQUIRE_RUNTIME_INTEGRITY must remain enabled for HTTPS production" in errors
    assert "production requires REQUIRE_RUNTIME_INTEGRITY=1" in errors
    assert "production requires REQUIRE_RUNTIME_INSTANCE_ID=1" in errors
    assert "production forbids ALLOW_INSECURE_RUNTIME_LEASE_HMAC" in errors
    assert "production requires COOKIE_SECURE=1" in errors


def test_production_configuration_requires_https_origin(monkeypatch) -> None:
    monkeypatch.setattr(Config, "ENVIRONMENT", "production")
    monkeypatch.setattr(Config, "SITE_URL", "http://visionforge.example")
    monkeypatch.setattr(Config, "REQUIRE_RUNTIME_INTEGRITY", True)
    monkeypatch.setattr(Config, "REQUIRE_RUNTIME_INSTANCE_ID", True)
    monkeypatch.setattr(Config, "ALLOW_INSECURE_RUNTIME_LEASE_HMAC", False)
    monkeypatch.setattr(Config, "COOKIE_SECURE", True)

    assert "production SITE_URL must be an origin-only HTTPS URL" in Config.validate()
