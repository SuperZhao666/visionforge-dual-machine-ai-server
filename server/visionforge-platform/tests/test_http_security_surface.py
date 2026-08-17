from __future__ import annotations

import importlib
import os
import re
from pathlib import Path

import pytest


_SERVER_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_ROOT = _SERVER_ROOT / "app" / "templates"
_MAIN_SOURCE = _SERVER_ROOT / "app" / "main.py"
_NGINX_CONFIG = _SERVER_ROOT / "deploy" / "nginx.conf"
_HARDENED_NGINX_CONFIG = (
    _SERVER_ROOT.parents[1] / "security-defense" / "config" / "nginx" / "vf-site.conf"
)
_XIANYU_REPLY_SERVER = (
    _SERVER_ROOT / "deploy" / "xianyu-fulfillment" / "upstream" / "reply_server.py"
)


def test_application_source_builds_nonce_bound_script_policy() -> None:
    source = _MAIN_SOURCE.read_text(encoding="utf-8")
    assert "secrets.token_urlsafe(24)" in source
    assert 'f"script-src \'self\' \'nonce-{csp_nonce}\'; "' in source
    assert "script-src 'self' 'unsafe-inline'" not in source
    assert 'f"style-src-elem \'self\' \'nonce-{csp_nonce}\'; "' in source
    assert '"style-src-attr \'unsafe-inline\'; "' in source
    assert '"style-src \'self\'; "' in source
    assert "style-src 'self' 'unsafe-inline'" not in source
    assert "RotatingFileHandler" in source
    assert '"object-src \'none\'"' in source


def test_html_response_uses_nonce_bound_script_policy_when_runtime_deps_exist() -> None:
    # This integration check needs the locked server environment. Keep the
    # source-contract tests runnable in minimal/offline repair environments.
    pytest.importorskip("bcrypt")
    pytest.importorskip("slowapi")
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")

    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-http-security-surface")
    main = importlib.import_module("app.main")
    from fastapi.testclient import TestClient

    response = TestClient(main.app).get("/login")
    assert response.status_code == 200
    policy = response.headers["content-security-policy"]
    match = re.search(r"script-src 'self' 'nonce-([^']+)'", policy)
    assert match is not None
    assert "script-src 'self' 'unsafe-inline'" not in policy
    assert "object-src 'none'" in policy
    assert f"style-src-elem 'self' 'nonce-{match.group(1)}'" in policy
    assert "style-src-attr 'unsafe-inline'" in policy
    assert "style-src 'self' 'unsafe-inline'" not in policy
    assert f'nonce="{match.group(1)}"' in response.text


def test_templates_have_no_inline_event_handlers_or_nonce_less_inline_scripts() -> None:
    event_handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
    script_tag = re.compile(r"<script(?P<attrs>[^>]*)>", re.IGNORECASE)
    style_tag = re.compile(r"<style(?P<attrs>[^>]*)>", re.IGNORECASE)
    failures: list[str] = []
    for path in sorted(_TEMPLATE_ROOT.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        if event_handler.search(text):
            failures.append(f"inline event handler: {path}")
        for match in script_tag.finditer(text):
            attributes = match.group("attrs").lower()
            if "src=" not in attributes and "nonce=" not in attributes:
                failures.append(f"nonce-less inline script: {path}")
        for match in style_tag.finditer(text):
            if "nonce=" not in match.group("attrs").lower():
                failures.append(f"nonce-less inline style element: {path}")
    assert failures == []


def test_nginx_does_not_override_application_nonce_policy() -> None:
    for path in (_NGINX_CONFIG, _HARDENED_NGINX_CONFIG):
        nginx = path.read_text(encoding="utf-8")
        assert "script-src 'self' 'unsafe-inline'" not in nginx
        assert "add_header Content-Security-Policy" not in nginx
        assert "HTML CSP is emitted by FastAPI with a fresh per-request" in nginx


def test_nginx_port_80_has_explicit_https_redirect() -> None:
    nginx = _NGINX_CONFIG.read_text(encoding="utf-8")
    port_80 = re.search(
        r"server\s*\{(?P<body>.*?\blisten\s+80\s*;.*?)\}",
        nginx,
        re.DOTALL,
    )
    assert port_80 is not None
    body = port_80.group("body")
    assert "return 301 https://www.visionforge.cloud$request_uri;" in body


def test_xianyu_management_api_has_no_anonymous_docs_surface() -> None:
    if not _XIANYU_REPLY_SERVER.is_file():
        pytest.skip("optional Xianyu upstream source is not part of this checkout")
    source = _XIANYU_REPLY_SERVER.read_text(encoding="utf-8")
    fastapi_block = re.search(
        r"app\s*=\s*FastAPI\((?P<body>.*?)\n\)",
        source,
        re.DOTALL,
    )
    assert fastapi_block is not None
    body = fastapi_block.group("body")
    assert "docs_url=None" in body
    assert "redoc_url=None" in body
    assert "openapi_url=None" in body
    assert 'docs_url="/docs"' not in body
