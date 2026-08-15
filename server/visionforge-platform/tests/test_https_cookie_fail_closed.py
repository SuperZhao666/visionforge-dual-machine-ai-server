from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-https-cookie-policy")

from app.config import Config  # noqa: E402


def test_https_site_cannot_disable_secure_cookies(monkeypatch) -> None:
    monkeypatch.setattr(Config, "SITE_URL", "https://visionforge.example")
    monkeypatch.setattr(Config, "COOKIE_SECURE", False)

    assert "HTTPS SITE_URL requires COOKIE_SECURE=1" in Config.validate()
