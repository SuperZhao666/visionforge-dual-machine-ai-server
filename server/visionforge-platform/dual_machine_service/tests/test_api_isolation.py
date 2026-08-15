from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dual_machine_service.card_service import CardIssuanceService
from dual_machine_service.contracts import (
    entitlement_status_payload,
    usage_heartbeat_payload,
    usage_start_cancel_payload,
    usage_start_challenge_payload,
    usage_start_payload,
    usage_stop_payload,
)
from dual_machine_service.database import connect_database, initialize_database
from dual_machine_service.identity import canonical_base64
from dual_machine_service.internal_admin_routes import (
    IssueBatchRequest,
    RevokeBatchRequest,
)
from dual_machine_service.main import create_app
from dual_machine_service.routes import (
    ActivationChallengeRequest,
    AndroidDeviceProfile,
    UsageStartRequest,
    UsageStartChallengeRequest,
)
from dual_machine_service.settings import DualMachineSettings
from dual_machine_service import usage_service as usage_service_module


def _settings(tmp_path: Path) -> DualMachineSettings:
    ticket_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    private_path = tmp_path / "ticket-private.pem"
    public_path = tmp_path / "ticket-public.pem"
    private_path.write_bytes(ticket_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(ticket_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    pair_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    pair_private_path = tmp_path / "pair-credential-private.pem"
    pair_public_path = tmp_path / "pair-credential-public.pem"
    pair_private_path.write_bytes(pair_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pair_public_path.write_bytes(pair_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    settings = DualMachineSettings(
        database_path=tmp_path / "dual.db",
        license_code_secret=(
            b"test-dual-machine-license-code-secret-32-bytes"
        ),
        token_secret=b"test-dual-machine-token-secret-32-bytes-min",
        minimum_host_client_version="17.8.81",
        minimum_android_client_version="1.0.0",
        ticket_private_key_path=private_path,
        ticket_public_key_path=public_path,
        pair_credential_private_key_path=pair_private_path,
        pair_credential_public_key_path=pair_public_path,
    )
    initialize_database(settings)
    return settings


def _identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, canonical_base64(public_der)


def _signature(
    private_key: ec.EllipticCurvePrivateKey,
    payload: bytes,
) -> str:
    return base64.b64encode(
        private_key.sign(payload, ec.ECDSA(hashes.SHA256())),
    ).decode("ascii")


def _signed_status(
    activated: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    request_nonce: str,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_nonce": request_nonce,
    }
    return _with_usage_signatures(command, host_private, android_private)


def _signed_start_challenge(
    activated: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": channel_binding_sha256,
    }
    payload = usage_start_challenge_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _signed_start_usage(
    activated: dict,
    challenge: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": channel_binding_sha256,
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "host_frames_total": 0,
        "android_frames_total": 0,
        "start_challenge_id": challenge["challenge_id"],
        "start_challenge_token": challenge["challenge_token"],
    }
    payload = usage_start_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _signed_heartbeat(
    activated: dict,
    previous: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str,
    sequence: int,
    host_frames_total: int,
    android_frames_total: int,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "session_id": previous["session_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": channel_binding_sha256,
        "sequence": sequence,
        "host_frames_total": host_frames_total,
        "android_frames_total": android_frames_total,
        "previous_lease": previous["usage_lease"],
    }
    payload = usage_heartbeat_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _signed_start_cancel(
    activated: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    start_request_id: str,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "start_request_id": start_request_id,
        "channel_binding_sha256": channel_binding_sha256,
    }
    payload = usage_start_cancel_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _signed_stop(
    activated: dict,
    previous: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str,
) -> dict:
    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "session_id": previous["session_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": channel_binding_sha256,
        "previous_lease": previous["usage_lease"],
    }
    payload = usage_stop_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _with_usage_signatures(
    command: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
) -> dict:
    payload = entitlement_status_payload(command)
    return {
        **command,
        "host_signature_b64": _signature(host_private, payload),
        "android_signature_b64": _signature(android_private, payload),
    }


def _assert_no_usage_billing(settings: DualMachineSettings) -> None:
    connection = connect_database(settings)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
        entitlement = connection.execute(
            "SELECT remaining_seconds, total_consumed_seconds "
            "FROM dm_entitlements",
        ).fetchone()
        assert tuple(entitlement) == (86_400, 0)
    finally:
        connection.close()


def test_public_api_has_no_username_or_password_contract(
    tmp_path: Path,
) -> None:
    application = create_app(_settings(tmp_path))
    schema = application.openapi()
    serialized = json.dumps(schema, sort_keys=True)

    assert all(
        path.startswith("/api/dual-machine/v1/")
        for path in schema["paths"]
    )
    assert '"username"' not in serialized
    assert '"password"' not in serialized
    assert "card_code" in serialized


def test_card_activation_requires_no_account_or_authorization_header(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    issued = CardIssuanceService(settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=1,
        channel="test",
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    application = create_app(settings)
    with TestClient(application) as client:
        challenge_response = client.post(
            "/api/dual-machine/v1/license-activations/challenges",
            json={
                "request_id": "2" * 32,
                "pair_id": "3" * 32,
                "protocol_version": 2,
                "card_code": issued.codes[0],
                "host": {
                    "device_code": "HOST-1",
                    "client_version": "17.8.81",
                    "identity_public_key_b64": host_public,
                },
                "android": {
                    "device_code": "ANDROID-1",
                    "client_version": "1.0.0",
                    "identity_public_key_b64": android_public,
                },
            },
        )
        assert challenge_response.status_code == 200
        assert "authorization" not in {
            key.lower()
            for key in challenge_response.request.headers
        }
        challenge = challenge_response.json()
        proof = base64.b64decode(
            challenge["proof_payload_b64"],
            validate=True,
        )
        activated_response = client.post(
            "/api/dual-machine/v1/license-activations/confirm",
            json={
                "challenge_id": challenge["challenge_id"],
                "challenge_token": challenge["challenge_token"],
                "host_signature_b64": _signature(host_private, proof),
                "android_signature_b64": _signature(
                    android_private,
                    proof,
                ),
            },
        )
        assert activated_response.status_code == 200
        activated = activated_response.json()
        assert activated["remaining_seconds"] == 86_400
        assert activated["total_consumed_seconds"] == 0
        assert activated["billing_started"] is False
        assert activated_response.headers["Cache-Control"] == "no-store"
        assert activated_response.headers[
            "Strict-Transport-Security"
        ] == "max-age=31536000; includeSubDomains"
        assert activated_response.headers[
            "Cross-Origin-Resource-Policy"
        ] == "same-site"
        assert activated_response.headers["Permissions-Policy"] == (
            "camera=(), geolocation=(), microphone=()"
        )
        assert activated_response.headers["X-Trace-Id"]


def test_http_billing_starts_only_after_explicit_formal_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    clock = {"now": 1_700_000_000}
    monkeypatch.setattr(
        usage_service_module.time,
        "time",
        lambda: clock["now"],
    )
    issued = CardIssuanceService(settings).issue_batch(
        request_id="5" * 32,
        product_key="day",
        quantity=1,
        channel="test",
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    channel_binding_sha256 = "f" * 64
    application = create_app(settings)
    with TestClient(application) as client:
        challenge_response = client.post(
            "/api/dual-machine/v1/license-activations/challenges",
            json={
                "request_id": "6" * 32,
                "pair_id": "7" * 32,
                "protocol_version": 2,
                "card_code": issued.codes[0],
                "host": {
                    "device_code": "HOST-1",
                    "client_version": "17.8.81",
                    "identity_public_key_b64": host_public,
                },
                "android": {
                    "device_code": "ANDROID-1",
                    "client_version": "1.0.0",
                    "identity_public_key_b64": android_public,
                },
            },
        )
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()
        proof = base64.b64decode(
            challenge["proof_payload_b64"],
            validate=True,
        )
        activated_response = client.post(
            "/api/dual-machine/v1/license-activations/confirm",
            json={
                "challenge_id": challenge["challenge_id"],
                "challenge_token": challenge["challenge_token"],
                "host_signature_b64": _signature(host_private, proof),
                "android_signature_b64": _signature(
                    android_private,
                    proof,
                ),
            },
        )
        assert activated_response.status_code == 200
        activated = activated_response.json()
        assert activated["billing_started"] is False
        _assert_no_usage_billing(settings)

        status_payload = _signed_status(
            activated,
            host_private,
            android_private,
            request_nonce="8" * 32,
        )
        status_response = client.post(
            "/api/dual-machine/v1/entitlements/"
            f"{activated['entitlement_id']}/status",
            json=status_payload,
        )
        assert status_response.status_code == 200
        assert status_response.json()["usage_session_status"] == ""
        _assert_no_usage_billing(settings)

        replayed_status_response = client.post(
            "/api/dual-machine/v1/entitlements/"
            f"{activated['entitlement_id']}/status",
            json=status_payload,
        )
        assert replayed_status_response.status_code == 409
        assert replayed_status_response.json()["error"] == (
            "usage_request_replayed"
        )
        _assert_no_usage_billing(settings)

        start_challenge_response = client.post(
            "/api/dual-machine/v1/usage-sessions/start-challenges",
            json=_signed_start_challenge(
                activated,
                host_private,
                android_private,
                request_id="9" * 32,
                request_nonce="a" * 32,
                channel_binding_sha256=channel_binding_sha256,
            ),
        )
        assert start_challenge_response.status_code == 200
        start_challenge = start_challenge_response.json()
        assert start_challenge["billing_started"] is False
        _assert_no_usage_billing(settings)

        cancelled_start_request_id = "b" * 32
        cancel_command = _signed_start_cancel(
            activated,
            host_private,
            android_private,
            start_request_id=cancelled_start_request_id,
            request_id="ab" * 16,
            request_nonce="ac" * 16,
            channel_binding_sha256=channel_binding_sha256,
        )
        cancel_response = client.post(
            "/api/dual-machine/v1/usage-sessions/start-cancellations",
            json=cancel_command,
        )
        repeated_cancel_response = client.post(
            "/api/dual-machine/v1/usage-sessions/start-cancellations",
            json=cancel_command,
        )
        assert cancel_response.status_code == 200
        assert repeated_cancel_response.status_code == 200
        assert repeated_cancel_response.json() == cancel_response.json()
        assert cancel_response.json()["session_id"] == ""
        assert cancel_response.json()["session_status"] == "not_started"
        assert cancel_response.json()["charged_seconds"] == 0
        assert cancel_response.json()["billing_started"] is False

        cancelled_start_response = client.post(
            "/api/dual-machine/v1/usage-sessions/start",
            json=_signed_start_usage(
                activated,
                start_challenge,
                host_private,
                android_private,
                request_id=cancelled_start_request_id,
                request_nonce="c" * 32,
                channel_binding_sha256=channel_binding_sha256,
            ),
        )
        assert cancelled_start_response.status_code == 409
        assert cancelled_start_response.json()["error"] == (
            "usage_start_cancelled"
        )
        _assert_no_usage_billing(settings)

        start_response = client.post(
            "/api/dual-machine/v1/usage-sessions/start",
            json=_signed_start_usage(
                activated,
                start_challenge,
                host_private,
                android_private,
                request_id="1b" * 16,
                request_nonce="c" * 32,
                channel_binding_sha256=channel_binding_sha256,
            ),
        )
        assert start_response.status_code == 200
        started = start_response.json()
        assert started["billing_started"] is True
        assert started["charged_seconds"] == settings.usage_lease_ttl_seconds
        assert started["remaining_seconds"] == (
            86_400 - settings.usage_lease_ttl_seconds
        )
        assert started["total_consumed_seconds"] == (
            settings.usage_lease_ttl_seconds
        )

        clock["now"] += (
            settings.usage_lease_ttl_seconds
            - settings.usage_renewal_window_seconds
        )
        heartbeat_response = client.post(
            "/api/dual-machine/v1/usage-sessions/"
            f"{started['session_id']}/heartbeat",
            json=_signed_heartbeat(
                activated,
                started,
                host_private,
                android_private,
                request_id="d" * 32,
                request_nonce="e" * 32,
                channel_binding_sha256=channel_binding_sha256,
                sequence=1,
                host_frames_total=1,
                android_frames_total=1,
            ),
        )
        assert heartbeat_response.status_code == 200
        renewed = heartbeat_response.json()
        assert renewed["billing_started"] is True
        assert renewed["charged_seconds"] == (
            settings.usage_lease_ttl_seconds
        )
        assert renewed["remaining_seconds"] == (
            86_400 - settings.usage_lease_ttl_seconds * 2
        )
        assert renewed["total_consumed_seconds"] == (
            settings.usage_lease_ttl_seconds * 2
        )
        assert renewed["sequence"] == 1

        clock["now"] += 1
        stop_response = client.post(
            "/api/dual-machine/v1/usage-sessions/"
            f"{renewed['session_id']}/stop",
            json=_signed_stop(
                activated,
                renewed,
                host_private,
                android_private,
                request_id="f" * 32,
                request_nonce="1a" * 16,
                channel_binding_sha256=channel_binding_sha256,
            ),
        )
        assert stop_response.status_code == 200
        stopped = stop_response.json()
        assert stopped["status"] == "ended"
        assert stopped["charged_seconds"] == 0
        assert stopped["remaining_seconds"] == renewed["remaining_seconds"]

    connection = connect_database(settings)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        assert tuple(connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchone()) == ("ended", "user_stopped")
    finally:
        connection.close()


def test_extra_username_field_is_rejected(
    tmp_path: Path,
) -> None:
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        response = client.post(
            "/api/dual-machine/v1/license-activations/challenges",
            json={
                "request_id": "4" * 32,
                "pair_id": "5" * 32,
                "protocol_version": 2,
                "card_code": "VFD2-INVALID",
                "host": {},
                "android": {},
                "username": "must-not-be-supported",
            },
        )
    assert response.status_code == 422


def test_public_request_models_reject_all_zero_ids_and_digests() -> None:
    _, public_key = _identity()
    peer = {
        "device_code": "TEST-DEVICE",
        "client_version": "17.8.81",
        "identity_public_key_b64": public_key,
    }
    activation = {
        "request_id": "1" * 32,
        "pair_id": "2" * 32,
        "protocol_version": 2,
        "card_code": "VFD2-TEST-PLACEHOLDER-CARD",
        "host": peer,
        "android": peer,
    }
    for field_name in ("request_id", "pair_id"):
        invalid = dict(activation)
        invalid[field_name] = "0" * 32
        with pytest.raises(ValidationError):
            ActivationChallengeRequest.model_validate(invalid)

    invalid_profile = dict(activation)
    invalid_profile["android_device_profile"] = {
        "device_fingerprint": "0" * 64,
    }
    with pytest.raises(ValidationError):
        ActivationChallengeRequest.model_validate(invalid_profile)

    signature = base64.b64encode(b"12345678").decode("ascii")
    start_challenge = {
        "entitlement_id": "3" * 32,
        "pair_id": "4" * 32,
        "protocol_version": 2,
        "revocation_version": 1,
        "host_signature_b64": signature,
        "android_signature_b64": signature,
        "request_id": "5" * 32,
        "request_nonce": "6" * 32,
        "channel_binding_sha256": "7" * 64,
    }
    for field_name in (
        "entitlement_id",
        "pair_id",
        "request_id",
        "request_nonce",
    ):
        invalid = dict(start_challenge)
        invalid[field_name] = "0" * 32
        with pytest.raises(ValidationError):
            UsageStartChallengeRequest.model_validate(invalid)
    invalid_digest = dict(start_challenge)
    invalid_digest["channel_binding_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        UsageStartChallengeRequest.model_validate(invalid_digest)


@pytest.mark.parametrize(
    ("field_name", "coerced_value"),
    (
        ("revocation_version", True),
        ("revocation_version", "1"),
        ("host_frames_total", True),
        ("host_frames_total", "1"),
        ("host_frames_total", 1.0),
        ("android_frames_total", True),
        ("android_frames_total", "1"),
        ("protocol_version", 2.0),
        ("host_runtime_ready", 1),
        ("host_runtime_ready", False),
        ("android_runtime_ready", 1),
        ("android_runtime_ready", False),
    ),
)
def test_public_usage_requests_reject_type_coercion(
    field_name: str,
    coerced_value: object,
) -> None:
    signature = base64.b64encode(b"12345678").decode("ascii")
    request = {
        "entitlement_id": "1" * 32,
        "pair_id": "2" * 32,
        "protocol_version": 2,
        "revocation_version": 1,
        "host_signature_b64": signature,
        "android_signature_b64": signature,
        "request_id": "3" * 32,
        "request_nonce": "4" * 32,
        "channel_binding_sha256": "5" * 64,
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "host_frames_total": 0,
        "android_frames_total": 0,
        "start_challenge_id": "6" * 32,
        "start_challenge_token": "A" * 43,
    }
    request[field_name] = coerced_value
    with pytest.raises(ValidationError):
        UsageStartRequest.model_validate(request)


@pytest.mark.parametrize("coerced_value", (True, "35", 35.0))
def test_android_profile_rejects_coerced_sdk_integer(
    coerced_value: object,
) -> None:
    with pytest.raises(ValidationError):
        AndroidDeviceProfile.model_validate({"sdk_int": coerced_value})


def test_internal_admin_request_bodies_reject_type_coercion() -> None:
    with pytest.raises(ValidationError):
        IssueBatchRequest.model_validate({
            "product_key": "day",
            "quantity": "1",
        })
    with pytest.raises(ValidationError):
        RevokeBatchRequest.model_validate({
            "reason": "security incident",
            "revoke_activated_entitlements": 1,
        })


def test_single_machine_init_creates_no_dual_tables_or_routes(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "single.db"
    script = (
        "import json, sqlite3;"
        "from app.database import init_db;"
        "from app.main import app;"
        "init_db();"
        f"c=sqlite3.connect({str(database_path)!r});"
        "tables=[r[0] for r in c.execute("
        "\"SELECT name FROM sqlite_master WHERE name LIKE 'dm_%'\")];"
        "paths=[getattr(r,'path','') for r in app.routes "
        "if getattr(r,'path','')];"
        "print(json.dumps({'tables':tables,'paths':paths}))"
    )
    environment = os.environ.copy()
    environment["SECRET_KEY"] = "test-secret-key-" + "x" * 48
    environment["DATABASE_PATH"] = str(database_path)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    evidence = json.loads(result.stdout.strip().splitlines()[-1])
    assert evidence["tables"] == []
    assert not any(
        path.startswith("/api/dual-machine/")
        for path in evidence["paths"]
    )


def test_sidecar_refuses_any_database_with_non_dual_tables(
    tmp_path: Path,
) -> None:
    disguised_core_database = tmp_path / "renamed.sqlite3"
    connection = sqlite3.connect(disguised_core_database)
    try:
        connection.execute(
            "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT)",
        )
        connection.commit()
    finally:
        connection.close()

    settings_root = tmp_path / "sidecar-settings"
    settings_root.mkdir()
    settings = _settings(settings_root)
    rejected_settings = DualMachineSettings(
        database_path=disguised_core_database,
        license_code_secret=settings.license_code_secret,
        token_secret=settings.token_secret,
        minimum_host_client_version=settings.minimum_host_client_version,
        minimum_android_client_version=(
            settings.minimum_android_client_version
        ),
        ticket_private_key_path=settings.ticket_private_key_path,
        ticket_public_key_path=settings.ticket_public_key_path,
    )
    with pytest.raises(
        ValueError,
        match="contains non-sidecar tables",
    ):
        initialize_database(rejected_settings)

    connection = sqlite3.connect(disguised_core_database)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
            )
        }
    finally:
        connection.close()
    assert tables == {"users"}
