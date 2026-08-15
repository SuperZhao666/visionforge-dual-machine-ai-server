from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dual_machine_service.contracts import (
    activation_confirmation_payload,
    entitlement_status_payload,
    usage_heartbeat_payload,
    usage_start_cancel_payload,
    usage_start_challenge_payload,
    usage_start_payload,
    usage_stop_payload,
)
from dual_machine_service.identity import (
    canonical_json,
    canonical_base64,
    parse_p256_identity,
    verify_p256_signature,
)
from dual_machine_service.license_codes import (
    card_code_digest,
    derive_card_code,
    is_valid_card_code,
    normalize_card_code,
)
from dual_machine_service.token_service import (
    RsaTokenCodec,
    TokenInvalid,
    TokenSigningUnavailable,
)


def _identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, canonical_base64(public_der)


def test_card_codes_are_high_entropy_deterministic_and_digest_only() -> None:
    secret = b"dual-machine-card-test-secret-32-bytes-minimum"
    first = derive_card_code(secret, "batch:1:item:1:product:1h")
    repeated = derive_card_code(secret, "batch:1:item:1:product:1h")
    second = derive_card_code(secret, "batch:1:item:2:product:1h")

    assert first == repeated
    assert first != second
    assert first.startswith("VFD2-")
    assert is_valid_card_code(first)
    assert normalize_card_code(first).startswith("VFD2")
    assert card_code_digest(secret, first).startswith("hmac-sha256:v1:")

    tampered = first[:-1] + ("2" if first[-1] != "2" else "3")
    assert not is_valid_card_code(tampered)
    assert card_code_digest(secret, first) != card_code_digest(secret, second)


def test_p256_identity_and_signature_are_strict_and_canonical() -> None:
    private_key, public_key_b64 = _identity()
    identity = parse_p256_identity(public_key_b64)
    payload = b"dual-machine-device-proof"
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature).decode("ascii")

    verify_p256_signature(identity, signature_b64, payload)
    with pytest.raises(ValueError, match="identity_signature_invalid"):
        verify_p256_signature(identity, signature_b64, payload + b"!")
    with pytest.raises(ValueError, match="identity_public_key_invalid"):
        parse_p256_identity(public_key_b64.rstrip("="))


def test_activation_and_heartbeat_payloads_bind_security_context() -> None:
    challenge = {
        "challenge_id": "1" * 32,
        "request_id": "2" * 32,
        "pair_id": "3" * 32,
        "protocol_version": 2,
        "host_device_code": "HOST-1",
        "host_client_version": "1.0",
        "host_key_sha256": "4" * 64,
        "android_device_code": "ANDROID-1",
        "android_client_version": "1.0",
        "android_key_sha256": "5" * 64,
    }
    activation = activation_confirmation_payload(
        challenge,
        challenge_token="activation-token",
    )
    assert b"activation-token" not in activation
    assert b"challenge_token_sha256" in activation

    heartbeat = usage_heartbeat_payload({
        "entitlement_id": "6" * 32,
        "pair_id": "3" * 32,
        "session_id": "7" * 32,
        "protocol_version": 2,
        "revocation_version": 1,
        "request_id": "8" * 32,
        "request_nonce": "9" * 32,
        "sequence": 1,
        "host_frames_total": 10,
        "android_frames_total": 9,
        "channel_binding_sha256": "a" * 64,
        "previous_lease": "secret-signed-lease",
    })
    assert b"secret-signed-lease" not in heartbeat
    assert b"previous_lease_sha256" in heartbeat


def test_signature_payload_golden_vectors_match_native_clients() -> None:
    h1 = "1" * 32
    h2 = "2" * 32
    h3 = "3" * 32
    h4 = "4" * 32
    s5 = "5" * 64
    s7 = "7" * 64
    activation_token_sha256 = (
        "d066a4f4c1bea1ab8d47372ded551bc3"
        "f1d06dcba0608d179c4a6d2844fec548"
    )
    empty_device_profile_sha256 = (
        "44136fa355b3678a1146ad16f7e8649e"
        "94fb4fc21fe77e8310c060f61caaff8a"
    )
    start_token_sha256 = (
        "e2ae1865c75fe404f1e7b3049aab3c729"
        "bc5114998665ea2ff7aaa68cb0e9381"
    )
    previous_lease_sha256 = (
        "292c06e5943f1f0f623acbb683d00c6b"
        "5b6ecd5359336fdf7f0f124f1f387434"
    )

    activation = activation_confirmation_payload(
        {
            "android_client_version": "1.0.0",
            "android_device_code": "ANDROID-ABC",
            "android_key_sha256": s5,
            "challenge_id": h1,
            "host_client_version": "17.8.81",
            "host_device_code": "HOST-XYZ",
            "host_key_sha256": s7,
            "pair_id": h2,
            "protocol_version": 2,
            "request_id": h3,
        },
        challenge_token="activation-token",
    )
    assert activation.decode("ascii") == (
        '{"activation_mode":"activate",'
        '"android_client_version":"1.0.0",'
        '"android_device_code":"ANDROID-ABC",'
        '"android_device_profile_sha256":'
        f'"{empty_device_profile_sha256}",'
        f'"android_key_sha256":"{s5}","challenge_id":"{h1}",'
        f'"challenge_token_sha256":"{activation_token_sha256}",'
        '"domain":"visionforge-dual-machine-card-activate-v1",'
        '"host_client_version":"17.8.81",'
        '"host_device_code":"HOST-XYZ",'
        f'"host_key_sha256":"{s7}","pair_id":"{h2}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        '"target_entitlement_id":""'
        "}"
    )

    start_challenge = usage_start_challenge_payload({
        "channel_binding_sha256": s5,
        "entitlement_id": h1,
        "pair_id": h2,
        "protocol_version": 2,
        "request_id": h3,
        "request_nonce": h4,
        "revocation_version": 9,
    })
    assert start_challenge.decode("ascii") == (
        f'{{"channel_binding_sha256":"{s5}",'
        '"domain":"visionforge-dual-machine-usage-start-challenge-v1",'
        f'"entitlement_id":"{h1}","pair_id":"{h2}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        f'"request_nonce":"{h4}","revocation_version":9}}'
    )

    start = usage_start_payload({
        "android_frames_total": 11,
        "android_runtime_ready": True,
        "channel_binding_sha256": s5,
        "entitlement_id": h1,
        "host_frames_total": 12,
        "host_runtime_ready": True,
        "pair_id": h2,
        "protocol_version": 2,
        "request_id": h3,
        "request_nonce": h4,
        "revocation_version": 9,
        "start_challenge_id": h4,
        "start_challenge_token": "start-token",
    })
    assert start.decode("ascii") == (
        '{"android_frames_total":11,"android_runtime_ready":true,'
        f'"channel_binding_sha256":"{s5}",'
        '"domain":"visionforge-dual-machine-usage-start-v1",'
        f'"entitlement_id":"{h1}","host_frames_total":12,'
        f'"host_runtime_ready":true,"pair_id":"{h2}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        f'"request_nonce":"{h4}","revocation_version":9,'
        f'"start_challenge_id":"{h4}",'
        f'"start_challenge_token_sha256":"{start_token_sha256}"'
        "}"
    )

    start_cancel = usage_start_cancel_payload({
        "channel_binding_sha256": s5,
        "entitlement_id": h1,
        "pair_id": h2,
        "protocol_version": 2,
        "request_id": h3,
        "request_nonce": h4,
        "revocation_version": 9,
        "start_request_id": h4,
    })
    assert start_cancel.decode("ascii") == (
        f'{{"channel_binding_sha256":"{s5}",'
        '"domain":"visionforge-dual-machine-usage-start-cancel-v1",'
        f'"entitlement_id":"{h1}","pair_id":"{h2}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        f'"request_nonce":"{h4}","revocation_version":9,'
        f'"start_request_id":"{h4}"}}'
    )

    heartbeat = usage_heartbeat_payload({
        "android_frames_total": 21,
        "channel_binding_sha256": s5,
        "entitlement_id": h1,
        "host_frames_total": 22,
        "pair_id": h2,
        "previous_lease": "secret-signed-lease",
        "protocol_version": 2,
        "request_id": h3,
        "request_nonce": h4,
        "revocation_version": 9,
        "sequence": 1,
        "session_id": h4,
    })
    assert heartbeat.decode("ascii") == (
        f'{{"android_frames_total":21,"channel_binding_sha256":"{s5}",'
        '"domain":"visionforge-dual-machine-usage-heartbeat-v1",'
        f'"entitlement_id":"{h1}","host_frames_total":22,'
        f'"pair_id":"{h2}",'
        f'"previous_lease_sha256":"{previous_lease_sha256}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        f'"request_nonce":"{h4}","revocation_version":9,'
        f'"sequence":1,"session_id":"{h4}"}}'
    )

    stop = usage_stop_payload({
        "channel_binding_sha256": s5,
        "entitlement_id": h1,
        "pair_id": h2,
        "previous_lease": "secret-signed-lease",
        "protocol_version": 2,
        "request_id": h3,
        "request_nonce": h4,
        "revocation_version": 9,
        "session_id": h4,
    })
    assert stop.decode("ascii") == (
        f'{{"channel_binding_sha256":"{s5}",'
        '"domain":"visionforge-dual-machine-usage-stop-v1",'
        f'"entitlement_id":"{h1}","pair_id":"{h2}",'
        f'"previous_lease_sha256":"{previous_lease_sha256}",'
        f'"protocol_version":2,"request_id":"{h3}",'
        f'"request_nonce":"{h4}","revocation_version":9,'
        f'"session_id":"{h4}"}}'
    )

    status = entitlement_status_payload({
        "entitlement_id": h1,
        "pair_id": h2,
        "protocol_version": 2,
        "request_nonce": h4,
        "revocation_version": 9,
    })
    assert status.decode("ascii") == (
        '{"domain":"visionforge-dual-machine-entitlement-status-v1",'
        f'"entitlement_id":"{h1}","pair_id":"{h2}",'
        f'"protocol_version":2,"request_nonce":"{h4}",'
        '"revocation_version":9}'
    )


def test_signature_payload_contract_rejects_zero_and_type_coercion() -> None:
    activation = {
        "activation_mode": "activate",
        "android_client_version": "1.0.0",
        "android_device_code": "ANDROID-1",
        "android_key_sha256": "1" * 64,
        "challenge_id": "2" * 32,
        "host_client_version": "17.8.81",
        "host_device_code": "HOST-1",
        "host_key_sha256": "3" * 64,
        "pair_id": "4" * 32,
        "protocol_version": 2,
        "request_id": "5" * 32,
    }
    for field_name, length in (
        ("android_key_sha256", 64),
        ("challenge_id", 32),
        ("host_key_sha256", 64),
        ("pair_id", 32),
        ("request_id", 32),
    ):
        invalid = dict(activation)
        invalid[field_name] = "0" * length
        with pytest.raises(
            ValueError,
            match="dual_machine_signed_payload_invalid",
        ):
            activation_confirmation_payload(
                invalid,
                challenge_token="activation-token",
            )
    invalid_protocol = dict(activation)
    invalid_protocol["protocol_version"] = "2"
    with pytest.raises(
        ValueError,
        match="dual_machine_signed_payload_invalid",
    ):
        activation_confirmation_payload(
            invalid_protocol,
            challenge_token="activation-token",
        )
    reactivation = {
        **activation,
        "activation_mode": "reactivate",
        "target_entitlement_id": "6" * 32,
    }
    reactivation_payload = activation_confirmation_payload(
        reactivation,
        challenge_token="activation-token",
    )
    assert b'"activation_mode":"reactivate"' in reactivation_payload
    assert b'"target_entitlement_id":"' + b"6" * 32 in reactivation_payload

    for activation_mode, target_entitlement_id in (
        ("activate", "6" * 32),
        ("reactivate", ""),
        ("reactivate", "0" * 32),
        ("bind_device", ""),
        ("bind_device", "0" * 32),
        ("unsupported", ""),
    ):
        invalid_mode_target = {
            **activation,
            "activation_mode": activation_mode,
            "target_entitlement_id": target_entitlement_id,
        }
        with pytest.raises(
            ValueError,
            match="dual_machine_signed_payload_invalid",
        ):
            activation_confirmation_payload(
                invalid_mode_target,
                challenge_token="activation-token",
            )

    start_challenge = {
        "channel_binding_sha256": "6" * 64,
        "entitlement_id": "7" * 32,
        "pair_id": "8" * 32,
        "protocol_version": 2,
        "request_id": "9" * 32,
        "request_nonce": "a" * 32,
        "revocation_version": 1,
    }
    for field_name, length in (
        ("channel_binding_sha256", 64),
        ("entitlement_id", 32),
        ("pair_id", 32),
        ("request_id", 32),
        ("request_nonce", 32),
    ):
        invalid = dict(start_challenge)
        invalid[field_name] = "0" * length
        with pytest.raises(
            ValueError,
            match="dual_machine_signed_payload_invalid",
        ):
            usage_start_challenge_payload(invalid)

    start = {
        **start_challenge,
        "android_frames_total": 0,
        "android_runtime_ready": True,
        "host_frames_total": 0,
        "host_runtime_ready": True,
        "start_challenge_id": "b" * 32,
        "start_challenge_token": "start-token",
    }
    for field_name, invalid_value in (
        ("android_frames_total", "0"),
        ("android_runtime_ready", 1),
        ("host_frames_total", False),
        ("host_runtime_ready", "true"),
        ("start_challenge_id", "0" * 32),
    ):
        invalid = dict(start)
        invalid[field_name] = invalid_value
        with pytest.raises(
            ValueError,
            match="dual_machine_signed_payload_invalid",
        ):
            usage_start_payload(invalid)

    heartbeat = {
        **start_challenge,
        "android_frames_total": 1,
        "host_frames_total": 1,
        "previous_lease": "signed-lease",
        "sequence": 1,
        "session_id": "c" * 32,
    }
    for field_name, invalid_value in (
        ("android_frames_total", -1),
        ("host_frames_total", 1.0),
        ("previous_lease", ""),
        ("sequence", True),
        ("session_id", "0" * 32),
    ):
        invalid = dict(heartbeat)
        invalid[field_name] = invalid_value
        with pytest.raises(
            ValueError,
            match="dual_machine_signed_payload_invalid",
        ):
            usage_heartbeat_payload(invalid)


def test_usage_lease_is_dedicated_strict_and_tamper_evident() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    codec = RsaTokenCodec(
        private_key=private_key,
        public_key=private_key.public_key(),
    )
    entitlement = {
        "entitlement_id": "a" * 32,
        "pair_id": "b" * 32,
        "protocol_version": 2,
        "revocation_version": 1,
        "host_key_sha256": "c" * 64,
        "android_key_sha256": "d" * 64,
        "remaining_seconds": 3600,
        "status": "active",
    }
    session = {
        "session_id": "e" * 32,
        "channel_binding_sha256": "f" * 64,
    }
    issued = codec.issue_usage_lease(
        entitlement,
        session,
        sequence=0,
        phase="active",
        lease_duration_seconds=5,
        previous_lease_sha256="0" * 64,
        now_epoch=1_700_000_000,
    )
    payload = codec.verify_usage_lease(
        issued["usage_lease"],
        now_epoch=1_700_000_001,
    )
    assert payload["sub"] == entitlement["entitlement_id"]
    assert payload["sid"] == session["session_id"]
    assert payload["phase"] == "active"
    assert payload["cbh"] == session["channel_binding_sha256"]
    assert payload["pth"] == "0" * 64
    assert payload["exp"] - payload["nbf"] == 5

    header, body, signature = issued["usage_lease"].split(".")
    tampered_body = ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(TokenInvalid):
        codec.verify_usage_lease(
            f"{header}.{tampered_body}.{signature}",
            now_epoch=1_700_000_001,
        )
    with pytest.raises(TokenInvalid):
        codec.verify_usage_lease(
            issued["usage_lease"],
            now_epoch=1_700_000_005,
        )

    future = codec.issue_usage_lease(
        entitlement,
        session,
        sequence=1,
        phase="active",
        lease_duration_seconds=5,
        previous_lease_sha256=issued["usage_lease_sha256"],
        now_epoch=1_700_000_003,
        not_before_epoch=1_700_000_005,
    )
    with pytest.raises(TokenInvalid):
        codec.verify_usage_lease(
            future["usage_lease"],
            now_epoch=1_700_000_003,
        )
    verified_future = codec.verify_usage_lease(
        future["usage_lease"],
        now_epoch=1_700_000_003,
        not_before_grace_seconds=2,
    )
    assert verified_future["nbf"] == 1_700_000_005

    for field_name in (
        "entitlement_id",
        "pair_id",
        "host_key_sha256",
        "android_key_sha256",
    ):
        invalid_entitlement = dict(entitlement)
        invalid_entitlement[field_name] = "0" * (
            32 if field_name in {"entitlement_id", "pair_id"} else 64
        )
        with pytest.raises(
            ValueError,
            match="dual_machine_usage_lease_binding_invalid",
        ):
            codec.issue_usage_lease(
                invalid_entitlement,
                session,
                sequence=0,
                phase="active",
                lease_duration_seconds=5,
                previous_lease_sha256="0" * 64,
                now_epoch=1_700_000_000,
            )

    for field_name, length in (
        ("session_id", 32),
        ("channel_binding_sha256", 64),
    ):
        invalid_session = dict(session)
        invalid_session[field_name] = "0" * length
        with pytest.raises(
            ValueError,
            match="dual_machine_usage_lease_binding_invalid",
        ):
            codec.issue_usage_lease(
                entitlement,
                invalid_session,
                sequence=0,
                phase="active",
                lease_duration_seconds=5,
                previous_lease_sha256="0" * 64,
                now_epoch=1_700_000_000,
            )

    with pytest.raises(
        ValueError,
        match="dual_machine_usage_lease_binding_invalid",
    ):
        codec.issue_usage_lease(
            entitlement,
            session,
            sequence=1,
            phase="active",
            lease_duration_seconds=5,
            previous_lease_sha256="0" * 64,
            now_epoch=1_700_000_000,
        )

    _assert_zero_claims_are_rejected(
        codec,
        payload,
        verified_future,
    )


def _assert_zero_claims_are_rejected(
    codec: RsaTokenCodec,
    initial_claims: dict[str, object],
    renewal_claims: dict[str, object],
) -> None:
    for claim_name, length in (
        ("sub", 32),
        ("pid", 32),
        ("sid", 32),
        ("hkh", 64),
        ("akh", 64),
        ("cbh", 64),
    ):
        invalid = dict(initial_claims)
        invalid[claim_name] = "0" * length
        _refresh_usage_jti(invalid)
        with pytest.raises(TokenInvalid):
            codec.verify_usage_lease(
                codec._sign_payload(invalid),
                now_epoch=1_700_000_001,
            )

    zero_jti = dict(initial_claims)
    zero_jti["jti"] = "0" * 32
    with pytest.raises(TokenInvalid):
        codec.verify_usage_lease(
            codec._sign_payload(zero_jti),
            now_epoch=1_700_000_001,
        )

    zero_previous = dict(renewal_claims)
    zero_previous["pth"] = "0" * 64
    _refresh_usage_jti(zero_previous)
    with pytest.raises(TokenInvalid):
        codec.verify_usage_lease(
            codec._sign_payload(zero_previous),
            now_epoch=1_700_000_005,
        )

    for claim_name, invalid_value in (
        ("seq", "0"),
        ("rv", True),
        ("remaining", False),
        ("iat", 1_700_000_000.0),
    ):
        invalid = dict(initial_claims)
        invalid[claim_name] = invalid_value
        _refresh_usage_jti(invalid)
        with pytest.raises(TokenInvalid):
            codec.verify_usage_lease(
                codec._sign_payload(invalid),
                now_epoch=1_700_000_001,
            )


def _refresh_usage_jti(claims: dict[str, object]) -> None:
    claims_without_jti = {
        key: value
        for key, value in claims.items()
        if key != "jti"
    }
    claims["jti"] = hashlib.sha256(
        canonical_json(claims_without_jti),
    ).hexdigest()[:32]


def test_usage_lease_key_rotation_accepts_only_bounded_known_public_keys(
    tmp_path,
) -> None:
    previous_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    current_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    unknown_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    previous_codec = RsaTokenCodec(
        private_key=previous_private_key,
        public_key=previous_private_key.public_key(),
    )
    entitlement = {
        "entitlement_id": "a" * 32,
        "pair_id": "b" * 32,
        "protocol_version": 2,
        "revocation_version": 1,
        "host_key_sha256": "c" * 64,
        "android_key_sha256": "d" * 64,
        "remaining_seconds": 3600,
        "status": "active",
    }
    session = {
        "session_id": "e" * 32,
        "channel_binding_sha256": "f" * 64,
    }
    previous_ticket = previous_codec.issue_usage_lease(
        entitlement,
        session,
        sequence=0,
        phase="active",
        lease_duration_seconds=5,
        previous_lease_sha256="0" * 64,
        now_epoch=1_700_000_000,
    )

    current_private_path = tmp_path / "current-private.pem"
    current_public_path = tmp_path / "current-public.pem"
    previous_public_path = tmp_path / "previous-public.pem"
    current_private_path.write_bytes(
        current_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    current_public_path.write_bytes(
        current_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    previous_public_path.write_bytes(
        previous_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    rotated_codec = RsaTokenCodec.from_pem_files(
        private_key_path=current_private_path,
        public_key_path=current_public_path,
        previous_public_key_paths=(previous_public_path,),
    )

    old_claims = rotated_codec.verify_usage_lease(
        previous_ticket["usage_lease"],
        now_epoch=1_700_000_001,
    )
    assert old_claims["seq"] == 0
    current_ticket = rotated_codec.issue_usage_lease(
        entitlement,
        session,
        sequence=1,
        phase="active",
        lease_duration_seconds=5,
        previous_lease_sha256=previous_ticket["usage_lease_sha256"],
        now_epoch=1_700_000_001,
    )
    assert rotated_codec.verify_usage_lease(
        current_ticket["usage_lease"],
        now_epoch=1_700_000_002,
    )["seq"] == 1

    unknown_codec = RsaTokenCodec(
        private_key=unknown_private_key,
        public_key=unknown_private_key.public_key(),
    )
    unknown_ticket = unknown_codec.issue_usage_lease(
        entitlement,
        session,
        sequence=0,
        phase="active",
        lease_duration_seconds=5,
        previous_lease_sha256="0" * 64,
        now_epoch=1_700_000_000,
    )
    with pytest.raises(TokenInvalid):
        rotated_codec.verify_usage_lease(
            unknown_ticket["usage_lease"],
            now_epoch=1_700_000_001,
        )

    with pytest.raises(TokenSigningUnavailable):
        RsaTokenCodec(
            private_key=current_private_key,
            public_key=current_private_key.public_key(),
            verification_public_keys=(current_private_key.public_key(),),
        )
    weak_previous_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    ).public_key()
    with pytest.raises(TokenSigningUnavailable):
        RsaTokenCodec(
            private_key=current_private_key,
            public_key=current_private_key.public_key(),
            verification_public_keys=(weak_previous_key,),
        )
