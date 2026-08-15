from __future__ import annotations

from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[2]


def _text(relative_path: str) -> str:
    return (SERVER_ROOT / relative_path).read_text(encoding="utf-8")


def test_sidecar_systemd_unit_is_independent_and_hardened() -> None:
    unit = _text("deploy/vf-dual-machine.service")

    assert "User=vf-dual-machine" in unit
    assert "EnvironmentFile=/etc/visionforge-dual-machine/service.env" in unit
    assert "python -m dual_machine_service.run" in unit
    assert "StateDirectory=visionforge-dual-machine" in unit
    assert "NoNewPrivileges=true" in unit
    assert "UMask=0077" in unit
    assert "app.main" not in unit
    assert "--port 8000" not in unit
    runner = _text("dual_machine_service/run.py")
    assert "proxy_headers=False" in runner
    assert "forwarded_allow_ips" not in runner


def test_sidecar_limiter_does_not_read_single_machine_dotenv() -> None:
    routes = _text("dual_machine_service/routes.py")

    assert "config_filename=os.devnull" in routes


def test_sidecar_environment_uses_independent_database_and_keys() -> None:
    environment = _text("deploy/vf-dual-machine.env.example")

    required = (
        "DUAL_MACHINE_DATABASE_PATH=",
        "DUAL_MACHINE_LICENSE_CODE_SECRET=",
        "DUAL_MACHINE_TOKEN_SECRET=",
        "DUAL_MACHINE_LICENSE_CODE_KEY_VERSION=",
        "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON=",
        "DUAL_MACHINE_MIN_HOST_CLIENT_VERSION=",
        "DUAL_MACHINE_MIN_ANDROID_CLIENT_VERSION=",
        "DUAL_MACHINE_TICKET_PRIVATE_KEY_PATH=",
        "DUAL_MACHINE_TICKET_PUBLIC_KEY_PATH=",
        "DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON=",
        "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH=",
        "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH=",
        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON=[]",
        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON=[]",
        "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PASSWORD=",
        "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS=15",
        "DUAL_MACHINE_USAGE_LEASE_TTL_SECONDS=5",
        "DUAL_MACHINE_USAGE_RENEWAL_WINDOW_SECONDS=2",
    )
    assert all(item in environment for item in required)
    assert "vf_dual_machine.db" in environment
    assert "/vf.db" not in environment
    assert "SECRET_KEY=" not in environment
    assert "PAYMENT" not in environment


def test_bootstrap_generates_independent_pair_credential_keypair() -> None:
    bootstrap = _text("deploy/bootstrap_dual_machine_sidecar.sh")

    assert bootstrap.count(
        "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072"
    ) == 2
    assert 'ticket_private_key="${config_dir}/usage-ticket-private.pem"' in bootstrap
    assert 'ticket_public_key="${config_dir}/usage-ticket-public.pem"' in bootstrap
    assert (
        'pair_credential_private_key="${config_dir}/pair-credential-private.pem"'
        in bootstrap
    )
    assert (
        'pair_credential_public_key="${config_dir}/pair-credential-public.pem"'
        in bootstrap
    )
    assert 'openssl pkey -in "${ticket_private_key}" -pubout' in bootstrap
    assert (
        'openssl pkey -in "${pair_credential_private_key}" -pubout'
        in bootstrap
    )
    assert '"${ticket_private_key}" "${ticket_public_key}" \\' in bootstrap
    assert (
        '"${pair_credential_private_key}" "${pair_credential_public_key}"'
        in bootstrap
    )
    assert "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS=15" in bootstrap
    assert "sha256sum \"${ticket_public_key}\"" in bootstrap
    assert "sha256sum \"${pair_credential_public_key}\"" in bootstrap


def test_nginx_contract_overwrites_forwarding_and_only_routes_v1() -> None:
    location = _text(
        "deploy/nginx/dual_machine_api_location.conf.example",
    )
    http = _text("deploy/nginx/dual_machine_http.conf.example")

    assert "zone=vf_dual_machine" in http
    assert "location ^~ /api/dual-machine/v1/" in location
    assert "proxy_pass http://127.0.0.1:8010;" in location
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in location
    assert "$proxy_add_x_forwarded_for" not in location
    assert "client_max_body_size 16k;" in location
    assert (
        'add_header Strict-Transport-Security "max-age=31536000; '
        'includeSubDomains" always;'
    ) in location
    assert 'add_header X-Content-Type-Options "nosniff" always;' in location
    assert 'add_header X-Frame-Options "DENY" always;' in location
    assert 'add_header Referrer-Policy "no-referrer" always;' in location
    assert (
        'add_header Cross-Origin-Resource-Policy "same-site" always;'
    ) in location
    assert (
        'add_header Permissions-Policy "camera=(), geolocation=(), '
        'microphone=()" always;'
    ) in location
    assert 'add_header Cache-Control "no-store" always;' in location
    assert (
        'add_header Content-Security-Policy "default-src \'none\'; '
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'\" "
        "always;"
    ) in location
    assert "add_header X-Request-ID $request_id always;" in location
    assert "/healthz" not in location
    assert "127.0.0.1:8000" not in location
