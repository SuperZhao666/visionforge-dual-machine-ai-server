from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dual_machine_service.admin_service import DualMachineAdminService
from dual_machine_service.card_service import (
    CardActivationService,
    CardIssuanceService,
)
from dual_machine_service.contracts import entitlement_status_payload
from dual_machine_service.database import (
    connect_database,
    initialize_database,
)
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.identity import canonical_base64
from dual_machine_service.settings import DualMachineSettings
from dual_machine_service.usage_service import UsageService


@pytest.fixture()
def activated_pair(tmp_path: Path) -> dict:
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
    )
    initialize_database(settings)
    issued = CardIssuanceService(settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation = CardActivationService(settings)
    challenge = activation.create_challenge(
        {
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
        client_ip="127.0.0.1",
        now_epoch=1_700_000_001,
    )
    proof = base64.b64decode(challenge["proof_payload_b64"], validate=True)
    activated = activation.confirm_activation(
        {
            "challenge_id": challenge["challenge_id"],
            "challenge_token": challenge["challenge_token"],
            "host_signature_b64": _sign(host_private, proof),
            "android_signature_b64": _sign(android_private, proof),
        },
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )
    return {
        "settings": settings,
        "host_private": host_private,
        "android_private": android_private,
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "revocation_version": activated["revocation_version"],
    }


def _identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, canonical_base64(public_der)


def _sign(
    private_key: ec.EllipticCurvePrivateKey,
    payload: bytes,
) -> str:
    return base64.b64encode(
        private_key.sign(payload, ec.ECDSA(hashes.SHA256())),
    ).decode("ascii")


def _signed_status(
    pair: dict,
    *,
    request_nonce: str,
    revocation_version: int | None = None,
    pair_id: str | None = None,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair_id or pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": (
            revocation_version
            if revocation_version is not None
            else pair["revocation_version"]
        ),
        "request_nonce": request_nonce,
    }
    payload = entitlement_status_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _revoke(pair: dict) -> dict:
    return DualMachineAdminService(
        pair["settings"],
    ).revoke_entitlement(
        pair["entitlement_id"],
        reason="security incident",
    )


def _assert_no_billing_and_no_session(pair: dict) -> None:
    connection = connect_database(pair["settings"])
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


def test_status_nonce_replay_is_rejected_without_billing(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    command = _signed_status(
        activated_pair,
        request_nonce="9a" * 16,
    )
    first = service.entitlement_status(
        command,
        now_epoch=1_700_000_050,
    )

    assert first["ok"] is True
    assert first["status"] == "active"
    with pytest.raises(
        DualMachineServiceError,
        match="usage_request_replayed",
    ):
        service.entitlement_status(
            command,
            now_epoch=1_700_000_051,
        )
    _assert_no_billing_and_no_session(activated_pair)


def test_revoked_entitlement_with_stale_rv_returns_revoked_and_current_rv(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    before = service.entitlement_status(
        _signed_status(activated_pair, request_nonce="a" * 32),
        now_epoch=1_700_000_050,
    )
    assert before["status"] == "active"
    assert before["revocation_version"] == 1

    revoked = _revoke(activated_pair)
    assert revoked["revocation_version"] == 2

    # 已绑定客户端仍持有吊销前的 rv=1：必须获知 revoked 与最新 rv。
    stale = service.entitlement_status(
        _signed_status(activated_pair, request_nonce="b" * 32),
        now_epoch=1_700_000_060,
    )
    assert stale["ok"] is True
    assert stale["status"] == "revoked"
    assert stale["revocation_version"] == 2
    assert stale["entitlement_id"] == activated_pair["entitlement_id"]
    assert stale["pair_id"] == activated_pair["pair_id"]
    assert stale["remaining_seconds"] == 86_400
    assert stale["usage_session_status"] == ""

    # 客户端升级到最新 rv 后，精确匹配路径仍然可用。
    current = service.entitlement_status(
        _signed_status(
            activated_pair,
            request_nonce="c" * 32,
            revocation_version=2,
        ),
        now_epoch=1_700_000_061,
    )
    assert current["status"] == "revoked"
    assert current["revocation_version"] == 2

    _assert_no_billing_and_no_session(activated_pair)


def test_revoked_status_with_tampered_signature_rejects_without_billing(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    _revoke(activated_pair)
    command = _signed_status(activated_pair, request_nonce="d" * 32)
    other_private, _ = _identity()
    command["android_signature_b64"] = _sign(
        other_private,
        entitlement_status_payload(command),
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.entitlement_status(command, now_epoch=1_700_000_060)
    _assert_no_billing_and_no_session(activated_pair)


def test_revoked_status_with_wrong_pair_rejects_without_billing(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    _revoke(activated_pair)
    command = _signed_status(
        activated_pair,
        request_nonce="e" * 32,
        pair_id="9" * 32,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_invalid",
    ):
        service.entitlement_status(command, now_epoch=1_700_000_060)
    _assert_no_billing_and_no_session(activated_pair)


def test_status_with_future_rv_rejects_without_billing(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    # active 状态下 rv 不一致（未来 rv）必须拒绝。
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_invalid",
    ):
        service.entitlement_status(
            _signed_status(
                activated_pair,
                request_nonce="f" * 32,
                revocation_version=2,
            ),
            now_epoch=1_700_000_060,
        )
    # revoked 后未来 rv 仍然拒绝。
    _revoke(activated_pair)
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_invalid",
    ):
        service.entitlement_status(
            _signed_status(
                activated_pair,
                request_nonce="1a" * 16,
                revocation_version=3,
            ),
            now_epoch=1_700_000_061,
        )
    _assert_no_billing_and_no_session(activated_pair)


def test_exhausted_status_with_stale_rv_rejects_without_billing(
    activated_pair: dict,
) -> None:
    connection = connect_database(activated_pair["settings"])
    try:
        connection.execute(
            "UPDATE dm_entitlements SET status = 'exhausted', "
            "revocation_version = 2, remaining_seconds = 0, "
            "total_consumed_seconds = 86400",
        )
        connection.commit()
    finally:
        connection.close()

    service = UsageService(activated_pair["settings"])
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_invalid",
    ):
        service.entitlement_status(
            _signed_status(activated_pair, request_nonce="2a" * 16),
            now_epoch=1_700_000_060,
        )
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
    finally:
        connection.close()
