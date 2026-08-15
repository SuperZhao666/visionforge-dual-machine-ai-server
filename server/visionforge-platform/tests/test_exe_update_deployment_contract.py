from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from deploy import validate_single_server_env as env_validator
from deploy.validate_single_server_env import validate_single_server_env


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parents[1]


def _read(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def test_production_nginx_serves_only_content_addressed_release_files() -> None:
    deploy_nginx = _read("deploy/nginx.conf")
    hardened_nginx = (
        WORKSPACE_ROOT / "security-defense" / "config" / "nginx" / "vf-site.conf"
    ).read_text(encoding="utf-8")

    for nginx in (deploy_nginx, hardened_nginx):
        assert "server_name visionforge.cloud www.visionforge.cloud;" in nginx
        assert "listen 443 ssl http2;" in nginx
        assert "https://www.visionforge.cloud$request_uri" in nginx
        assert "[0-9a-f]{64}\\.(?:exe|vfdiff)" in nginx
        assert "alias /home/ubuntu/vf-platform/app/static/releases/$release_artifact;" in nginx
        assert "max_ranges 1;" in nginx
        assert "location /static/releases/" in nginx
        assert "return 404;" in nginx
        assert "[0-9a-f]{64}\\.zip" in nginx
        assert "location /_runtime_artifacts/" in nginx
        assert "alias /home/ubuntu/vf-platform/runtime_artifacts/$runtime_artifact;" in nginx
        assert "internal;" in nginx
        assert "sendfile on;" in nginx
        assert "location = /appPush" in nginx
        assert "Content-Security-Policy" in nginx
        assert "server_name _;" not in nginx
        assert "your-domain.com" not in nginx

    assert '"public, max-age=31536000, immutable"' in deploy_nginx
    assert "add_header Cache-Control $vf_deploy_release_cache_control;" in deploy_nginx
    assert 'add_header Cache-Control "public, max-age=31536000, immutable"' not in deploy_nginx
    assert "add_header Accept-Ranges" not in deploy_nginx
    assert "vf_deploy_sanitized" in deploy_nginx


def test_deployment_scripts_keep_exe_updates_on_the_existing_server() -> None:
    setup = _read("deploy/server_setup.sh")
    env_creator = _read("deploy/create_single_server_env.py")
    final_setup = _read("deploy/final_setup.sh")
    service = _read("deploy/vf.service")
    legacy_deploy = _read("deploy/full_deploy.py")
    legacy_setup = _read("deploy/setup.py")
    combined = "\n".join(
        (setup, env_creator, final_setup, legacy_deploy, legacy_setup)
    )

    assert "github.com/SuperZhao666/VisionForge/releases" not in combined
    assert '"SITE_URL": CANONICAL_SITE_URL' in env_creator
    assert '"DOWNLOAD_URL": CANONICAL_DOWNLOAD_URL' in env_creator
    assert "Existing .env preserved" in setup
    assert "validate_single_server_env.py .env" in setup
    assert "create_single_server_env.py .env" in setup
    assert "cat > .env" not in setup
    assert "[[ -e .env || -L .env ]]" in setup
    assert "--no-access-log" in service
    assert "validate_single_server_env.py" in final_setup
    assert final_setup.index("validate_single_server_env.py") < final_setup.index(
        'sudo install -m 0644 "${APP_ROOT}/deploy/vf.service"'
    )
    assert "app/static/releases" in final_setup
    assert "nginx -t" in final_setup
    assert "Restoring the previous Nginx site" in final_setup
    assert "http://81.70.189.154" not in combined
    assert "rm -rf /home/ubuntu/vf-platform" not in legacy_deploy
    assert "AutoAddPolicy" not in legacy_deploy
    assert "PRIVATE_KEY_PASSWORD=" not in legacy_deploy
    assert "is retired because it was destructive" in legacy_deploy
    assert "git clone" not in legacy_setup
    assert "AutoAddPolicy" not in legacy_setup
    assert "is retired" in legacy_setup


def test_existing_env_validation_uses_effective_values_and_rejects_duplicates(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "SITE_URL=https://www.visionforge.cloud\n"
        "DOWNLOAD_URL=https://www.visionforge.cloud/download\n",
        encoding="utf-8",
    )
    assert validate_single_server_env(env_path) == ()

    env_path.write_text(
        "SITE_URL=https://www.visionforge.cloud\n"
        "SITE_URL=https://evil.example\n"
        "DOWNLOAD_URL=https://www.visionforge.cloud/download\n",
        encoding="utf-8",
    )
    errors = validate_single_server_env(env_path)
    assert "SITE_URL must be defined exactly once" in errors
    assert "SITE_URL must equal https://www.visionforge.cloud" in errors


def test_env_validation_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "real.env"
    target.write_text(
        "SITE_URL=https://www.visionforge.cloud\n"
        "DOWNLOAD_URL=https://www.visionforge.cloud/download\n",
        encoding="utf-8",
    )
    env_path = tmp_path / ".env"
    try:
        env_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    assert validate_single_server_env(env_path) == (
        "environment file must not be a symbolic link",
    )


def test_env_metadata_policy_requires_owner_and_exact_mode() -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=1001)

    errors = env_validator._validate_env_file_metadata(
        metadata,
        expected_uid=1000,
        required_mode=0o600,
    )

    assert "environment file owner uid must be 1000, got 1001" in errors
    assert "environment file mode must be 0600, got 0640" in errors
