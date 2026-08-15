from __future__ import annotations

import secrets
import time
from pathlib import Path

import pytest

from dual_machine_service.admin_bridge_auth import (
    AUTHORIZATION_SCHEME,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign_admin_request,
    verify_admin_request,
)
from dual_machine_service.database import initialize_database
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.settings import DualMachineSettings


def _settings(tmp_path: Path) -> DualMachineSettings:
    settings = DualMachineSettings(
        database_path=tmp_path / "dual-machine-admin.db",
        license_code_secret=b"license-code-secret-for-admin-bridge-tests",
        token_secret=b"token-secret-for-admin-bridge-tests-minimum",
        minimum_host_client_version="17.8.81",
        minimum_android_client_version="1.0.0",
        admin_bridge_secret=b"independent-admin-bridge-secret-for-tests",
        admin_bridge_max_skew_seconds=30,
    )
    initialize_database(settings)
    return settings


def _signed_headers(
    settings: DualMachineSettings,
    *,
    method: str,
    target: str,
    body: bytes,
    timestamp: int,
    nonce: str | None = None,
) -> dict[str, str]:
    request_nonce = nonce or secrets.token_hex(16)
    signature = sign_admin_request(
        settings.admin_bridge_secret,
        method=method,
        request_target=target,
        timestamp=timestamp,
        nonce=request_nonce,
        body=body,
    )
    return {
        "authorization": AUTHORIZATION_SCHEME,
        TIMESTAMP_HEADER.lower(): str(timestamp),
        NONCE_HEADER.lower(): request_nonce,
        SIGNATURE_HEADER.lower(): signature,
    }


def test_admin_bridge_accepts_one_fresh_loopback_request(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    now = int(time.time())
    target = "/internal/dual-machine-admin/v1/batches?limit=25"
    headers = _signed_headers(
        settings,
        method="GET",
        target=target,
        body=b"",
        timestamp=now,
    )

    verify_admin_request(
        settings,
        method="GET",
        request_target=target,
        headers=headers,
        client_host="127.0.0.1",
        body=b"",
        now_epoch=now,
    )


def test_admin_bridge_rejects_replay_body_tampering_and_remote_clients(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    now = int(time.time())
    target = "/internal/dual-machine-admin/v1/batches"
    body = b'{"product_key":"day","quantity":1}'
    headers = _signed_headers(
        settings,
        method="POST",
        target=target,
        body=body,
        timestamp=now,
    )

    verify_admin_request(
        settings,
        method="POST",
        request_target=target,
        headers=headers,
        client_host="::1",
        body=body,
        now_epoch=now,
    )
    with pytest.raises(DualMachineServiceError) as replay:
        verify_admin_request(
            settings,
            method="POST",
            request_target=target,
            headers=headers,
            client_host="127.0.0.1",
            body=body,
            now_epoch=now,
        )
    assert replay.value.code == "dual_machine_admin_request_replayed"

    tampered_headers = _signed_headers(
        settings,
        method="POST",
        target=target,
        body=body,
        timestamp=now,
    )
    with pytest.raises(DualMachineServiceError) as tampered:
        verify_admin_request(
            settings,
            method="POST",
            request_target=target,
            headers=tampered_headers,
            client_host="127.0.0.1",
            body=body + b" ",
            now_epoch=now,
        )
    assert tampered.value.code == "dual_machine_admin_auth_invalid"

    remote_headers = _signed_headers(
        settings,
        method="GET",
        target=target,
        body=b"",
        timestamp=now,
    )
    with pytest.raises(DualMachineServiceError) as remote:
        verify_admin_request(
            settings,
            method="GET",
            request_target=target,
            headers=remote_headers,
            client_host="203.0.113.10",
            body=b"",
            now_epoch=now,
        )
    assert remote.value.code == "dual_machine_admin_loopback_required"


def test_admin_bridge_rejects_stale_or_unconfigured_requests(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    now = int(time.time())
    target = "/internal/dual-machine-admin/v1/products"
    stale_headers = _signed_headers(
        settings,
        method="GET",
        target=target,
        body=b"",
        timestamp=now - settings.admin_bridge_max_skew_seconds - 1,
    )
    with pytest.raises(DualMachineServiceError) as stale:
        verify_admin_request(
            settings,
            method="GET",
            request_target=target,
            headers=stale_headers,
            client_host="127.0.0.1",
            body=b"",
            now_epoch=now,
        )
    assert stale.value.code == "dual_machine_admin_request_stale"

    unavailable = DualMachineSettings(
        database_path=tmp_path / "unavailable.db",
        license_code_secret=settings.license_code_secret,
        token_secret=settings.token_secret,
        minimum_host_client_version="17.8.81",
        minimum_android_client_version="1.0.0",
    )
    with pytest.raises(DualMachineServiceError) as missing:
        verify_admin_request(
            unavailable,
            method="GET",
            request_target=target,
            headers={},
            client_host="127.0.0.1",
            body=b"",
            now_epoch=now,
        )
    assert missing.value.code == "dual_machine_admin_bridge_unavailable"
