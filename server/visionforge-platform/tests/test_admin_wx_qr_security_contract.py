from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_privileged_wechat_qr_route_is_not_mounted() -> None:
    admin_source = (ROOT / "app" / "routes" / "admin.py").read_text(
        encoding="utf-8"
    )

    assert '@router.get("/admin/wx-qr"' not in admin_source
    assert "api.qrserver.com" not in admin_source
    assert "wx_login_qr.png" not in admin_source


def test_nginx_denies_the_legacy_public_wechat_qr_path() -> None:
    nginx_config = (
        ROOT.parents[1] / "security-defense" / "config" / "nginx" / "vf-site.conf"
    ).read_text(encoding="utf-8")
    match = re.search(
        r"location\s*=\s*/static/img/wx_login_qr\.png\s*\{(?P<body>.*?)\}",
        nginx_config,
        flags=re.DOTALL,
    )

    assert match is not None
    body = match.group("body")
    assert "return 404;" in body
    assert 'Cache-Control "no-store, private, max-age=0" always;' in body
