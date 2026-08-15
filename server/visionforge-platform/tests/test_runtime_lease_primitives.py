import hashlib
import hmac
import json
import os
import time

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-runtime-lease-primitives")

from app.services import lease_service

VALID_MANIFEST_HASH = "a" * 64


@pytest.fixture(autouse=True)
def _allow_test_hmac(monkeypatch):
    monkeypatch.setattr(lease_service.config, "ALLOW_INSECURE_RUNTIME_LEASE_HMAC", True)


def _verify(token: str, **overrides):
    expected = {
        "user_id": 7,
        "session_id": 11,
        "auth_version": 3,
        "device_code": "DEVICE-A",
        "login_instance_id": "login-a",
        "expected_runtime_instance_id": "runtime-a",
        "expected_client_version": "v-test",
        "expected_manifest_hash": VALID_MANIFEST_HASH,
    }
    expected.update(overrides)
    return lease_service.verify_runtime_lease(token, **expected)


def _resign_hmac_token(
    token: str,
    *,
    payload_changes: dict[str, object] | None = None,
    header_changes: dict[str, object] | None = None,
) -> str:
    header_b64, payload_b64, _signature_b64 = token.split(".", 2)
    header = json.loads(lease_service._b64u_decode(header_b64))
    payload = json.loads(lease_service._b64u_decode(payload_b64))
    header.update(header_changes or {})
    payload.update(payload_changes or {})
    signing_input = (
        lease_service._b64u(lease_service.canonical_json(header))
        + "."
        + lease_service._b64u(lease_service.canonical_json(payload))
    )
    secret = (lease_service.config.SECRET_KEY or "dev-runtime-lease").encode("utf-8")
    signature = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + lease_service._b64u(signature)


def test_explicit_future_window_and_runtime_instance_support_safe_renewal(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    now = int(time.time())
    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v-test",
        manifest_hash=VALID_MANIFEST_HASH,
        auth_version=3,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
        not_before_epoch=now + 1,
        expires_at_epoch=now + 6,
    )

    payload = signed["lease_payload"]
    assert payload["nbf"] == now + 1
    assert payload["exp"] == now + 6
    assert payload["ttl"] == 5
    assert payload["rid"] == "runtime-a"
    assert signed["lease_ttl_seconds"] == 5

    strict_ok, strict_reason, _ = _verify(signed["lease_token"])
    renewal_ok, renewal_reason, _ = _verify(
        signed["lease_token"],
        allow_future_for_renewal=True,
    )
    wrong_runtime_ok, wrong_runtime_reason, _ = _verify(
        signed["lease_token"],
        expected_runtime_instance_id="runtime-b",
        allow_future_for_renewal=True,
    )

    assert strict_ok is False
    assert strict_reason == "not_yet_valid"
    assert renewal_ok is True
    assert renewal_reason == "ok"
    assert wrong_runtime_ok is False
    assert wrong_runtime_reason == "claim_mismatch"


def test_explicit_window_rejects_empty_or_oversized_segments(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    now = int(time.time())
    common = {
        "user_id": 7,
        "session_id": 11,
        "device_code": "DEVICE-A",
        "client_version": "v-test",
        "manifest_hash": VALID_MANIFEST_HASH,
        "auth_version": 3,
        "login_instance_id": "login-a",
        "runtime_instance_id": "runtime-a",
    }

    with pytest.raises(ValueError):
        lease_service.sign_runtime_lease(
            **common,
            not_before_epoch=now,
            expires_at_epoch=now,
        )
    with pytest.raises(ValueError):
        lease_service.sign_runtime_lease(
            **common,
            not_before_epoch=now,
            expires_at_epoch=now + lease_service.MAX_LEASE_TTL_SECONDS + 1,
        )


def test_verifier_binds_signed_version_and_integrity_claims(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    manifest_hash = "a" * 64
    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v20.0.0",
        manifest_hash=manifest_hash,
        auth_version=3,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
    )

    assert _verify(
        signed["lease_token"],
        expected_client_version="v20.0.0",
        expected_manifest_hash=manifest_hash,
    )[:2] == (True, "ok")
    assert _verify(
        signed["lease_token"],
        expected_client_version="v20.0.1",
        expected_manifest_hash=manifest_hash,
    )[:2] == (False, "claim_mismatch")
    assert _verify(
        signed["lease_token"],
        expected_client_version="v20.0.0",
        expected_manifest_hash="b" * 64,
    )[:2] == (False, "claim_mismatch")


def test_signing_rejects_overlong_identity_claims_instead_of_truncating(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    common = {
        "user_id": 7,
        "session_id": 11,
        "device_code": "D" * lease_service.MAX_DEVICE_CODE_LENGTH,
        "client_version": "v-test",
        "manifest_hash": VALID_MANIFEST_HASH,
        "auth_version": 3,
        "login_instance_id": "L" * lease_service.MAX_LOGIN_INSTANCE_ID_LENGTH,
        "runtime_instance_id": "R" * lease_service.MAX_RUNTIME_INSTANCE_ID_LENGTH,
    }

    signed = lease_service.sign_runtime_lease(**common)
    payload = signed["lease_payload"]

    assert payload["did"] == common["device_code"]
    assert payload["lid"] == common["login_instance_id"]
    assert payload["rid"] == common["runtime_instance_id"]
    assert payload["manifest_hash"] == common["manifest_hash"]

    for field_name, oversized in (
        ("device_code", "D" * (lease_service.MAX_DEVICE_CODE_LENGTH + 1)),
        ("login_instance_id", "L" * (lease_service.MAX_LOGIN_INSTANCE_ID_LENGTH + 1)),
        ("runtime_instance_id", "R" * (lease_service.MAX_RUNTIME_INSTANCE_ID_LENGTH + 1)),
        ("client_version", "v" * (lease_service.MAX_CLIENT_VERSION_LENGTH + 1)),
        ("manifest_hash", "a" * (lease_service.MAX_MANIFEST_HASH_LENGTH + 1)),
    ):
        with pytest.raises(ValueError, match=field_name):
            lease_service.sign_runtime_lease(**{**common, field_name: oversized})


def test_default_window_starts_at_signed_issue_time_and_expires_on_charged_ttl(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    monkeypatch.setattr(lease_service.time, "time", lambda: 1_000.0)

    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v-test",
        manifest_hash=VALID_MANIFEST_HASH,
        auth_version=3,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
        ttl_seconds=15,
    )

    payload = signed["lease_payload"]
    assert payload["nbf"] == 1_000
    assert payload["exp"] == 1_015
    assert payload["exp"] - payload["nbf"] == signed["lease_ttl_seconds"]

    monkeypatch.setattr(lease_service.time, "time", lambda: 999.0)
    assert _verify(signed["lease_token"])[:2] == (False, "not_yet_valid")


def test_signer_rejects_invalid_required_v2_claims(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    common = {
        "user_id": 7,
        "session_id": 11,
        "device_code": "DEVICE-A",
        "client_version": "v-test",
        "manifest_hash": VALID_MANIFEST_HASH,
        "auth_version": 0,
        "login_instance_id": "login-a",
        "runtime_instance_id": "runtime-a",
    }
    invalid_values = {
        "user_id": 0,
        "session_id": 0,
        "auth_version": -1,
        "device_code": "",
        "login_instance_id": "",
        "runtime_instance_id": "",
        "client_version": "",
        "manifest_hash": "not-a-sha256",
    }

    for field_name, invalid_value in invalid_values.items():
        with pytest.raises(ValueError, match=field_name):
            lease_service.sign_runtime_lease(
                **{**common, field_name: invalid_value}
            )


def test_verifier_enforces_v2_header_claim_types_and_windows(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    monkeypatch.setattr(lease_service.time, "time", lambda: 1_000.0)
    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v-test",
        manifest_hash=VALID_MANIFEST_HASH,
        auth_version=3,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
    )
    token = signed["lease_token"]

    cases = (
        ({"iss": "wrong"}, None, "wrong_lease_schema"),
        ({"sub": "7"}, None, "invalid_claims"),
        ({"sid": 0}, None, "invalid_identity_claims"),
        ({"av": -1}, None, "invalid_identity_claims"),
        ({"did": ""}, None, "invalid_did_claim"),
        ({"lid": ""}, None, "invalid_lid_claim"),
        ({"rid": ""}, None, "invalid_rid_claim"),
        ({"ver": ""}, None, "invalid_ver_claim"),
        ({"nonce": ""}, None, "invalid_nonce_claim"),
        ({"manifest_hash": "f" * 63}, None, "invalid_integrity_manifest"),
        ({"ttl": 16}, None, "invalid_ttl"),
        ({"nbf": 600}, None, "invalid_window"),
        ({"exp": 1_014}, None, "invalid_window"),
        (None, {"typ": "NOT-JWT"}, "bad_header"),
        (None, {"kid": "wrong"}, "key_id_mismatch"),
    )
    for payload_changes, header_changes, expected_reason in cases:
        forged = _resign_hmac_token(
            token,
            payload_changes=payload_changes,
            header_changes=header_changes,
        )
        assert _verify(forged)[:2] == (False, expected_reason)


def test_auth_version_zero_is_a_strict_binding(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v-test",
        manifest_hash=VALID_MANIFEST_HASH,
        auth_version=0,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
    )

    assert _verify(signed["lease_token"], auth_version=0)[:2] == (True, "ok")
    assert _verify(signed["lease_token"], auth_version=1)[:2] == (
        False,
        "claim_mismatch",
    )


def test_explicit_past_window_is_shifted_to_signed_issue_time(monkeypatch) -> None:
    monkeypatch.setattr(lease_service, "_load_private_key_or_none", lambda: None)
    monkeypatch.setattr(lease_service.time, "time", lambda: 1_000.0)
    signed = lease_service.sign_runtime_lease(
        user_id=7,
        session_id=11,
        device_code="DEVICE-A",
        client_version="v-test",
        manifest_hash=VALID_MANIFEST_HASH,
        auth_version=3,
        login_instance_id="login-a",
        runtime_instance_id="runtime-a",
        not_before_epoch=986,
        expires_at_epoch=1_001,
    )

    payload = signed["lease_payload"]
    assert payload["iat"] == 1_000
    assert payload["nbf"] == 1_000
    assert payload["exp"] == 1_015
    assert payload["ttl"] == 15
    assert _verify(signed["lease_token"])[:2] == (True, "ok")
