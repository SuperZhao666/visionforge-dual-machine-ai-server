from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dual_machine_service.admin_service import DualMachineAdminService
from dual_machine_service.card_service import (
    CardActivationService,
    CardIssuanceService,
)
from dual_machine_service.database import (
    connect_database,
    initialize_database,
)
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.identity import canonical_base64
from dual_machine_service.pair_security_bootstrap import (
    PairSecurityBootstrapError,
)
from dual_machine_service.settings import DualMachineSettings


@pytest.fixture()
def dual_settings(tmp_path: Path) -> DualMachineSettings:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    private_path = tmp_path / "dual-ticket-private.pem"
    public_path = tmp_path / "dual-ticket-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
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
    return settings


def _identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, canonical_base64(public_der)


def _activation_command(
    code: str,
    *,
    request_id: str,
    pair_id: str,
    host_public_key: str,
    android_public_key: str,
) -> dict:
    return {
        "request_id": request_id,
        "pair_id": pair_id,
        "protocol_version": 2,
        "card_code": code,
        "host": {
            "device_code": "HOST-DEVICE-1",
            "client_version": "17.8.81",
            "identity_public_key_b64": host_public_key,
        },
        "android": {
            "device_code": "ANDROID-DEVICE-1",
            "client_version": "1.0.0",
            "identity_public_key_b64": android_public_key,
        },
    }


def _confirm_command(
    challenge: dict,
    host_private_key: ec.EllipticCurvePrivateKey,
    android_private_key: ec.EllipticCurvePrivateKey,
) -> dict:
    payload = base64.b64decode(
        challenge["proof_payload_b64"],
        validate=True,
    )
    return {
        "challenge_id": challenge["challenge_id"],
        "challenge_token": challenge["challenge_token"],
        "host_signature_b64": base64.b64encode(
            host_private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256()),
            )
        ).decode("ascii"),
        "android_signature_b64": base64.b64encode(
            android_private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256()),
            )
        ).decode("ascii"),
    }


def _sidecar_text_cells(
    settings: DualMachineSettings,
) -> list[tuple[str, str, str]]:
    connection = connect_database(settings)
    try:
        tables = [
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name LIKE 'dm_%' "
                "ORDER BY name",
            ).fetchall()
        ]
        cells: list[tuple[str, str, str]] = []
        for table in tables:
            columns = connection.execute(
                f'PRAGMA table_info("{table}")',
            ).fetchall()
            text_columns = [
                row["name"]
                for row in columns
                if "TEXT" in str(row["type"]).upper()
            ]
            if not text_columns:
                continue
            selected = ", ".join(
                f'"{column}"' for column in text_columns
            )
            for data_row in connection.execute(
                f'SELECT {selected} FROM "{table}"',
            ).fetchall():
                for column in text_columns:
                    value = data_row[column]
                    if value is not None:
                        cells.append((table, column, str(value)))
        return cells
    finally:
        connection.close()


def test_activation_credits_balance_without_starting_billing(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=1,
        channel="manual",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation_service = CardActivationService(dual_settings)
    challenge = activation_service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="2" * 32,
            pair_id="3" * 32,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    confirmation = _confirm_command(
        challenge,
        host_private,
        android_private,
    )
    activated = activation_service.confirm_activation(
        confirmation,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_011,
    )
    repeated = activation_service.confirm_activation(
        confirmation,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_012,
    )

    assert activated == repeated
    assert activated["remaining_seconds"] == 86_400
    assert activated["total_consumed_seconds"] == 0
    assert activated["billing_started"] is False
    assert activated["binding_revision"] == 1
    assert activated["pair_assurance_state"] == "active"
    assert len(activated["binding_id"]) == 32

    connection = connect_database(dual_settings)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
        stored = connection.execute(
            "SELECT code_digest, code_suffix, status "
            "FROM dm_license_codes",
        ).fetchone()
        assert stored["status"] == "activated"
        assert issuance.codes[0] not in str(tuple(stored))
        assert str(stored["code_digest"]).startswith("hmac-sha256:v1:")
        pair_state = connection.execute(
            "SELECT entitlement_id, binding_id, binding_revision, "
            "revocation_version, assurance_state, generation_high_water "
            "FROM dm_pair_security_state",
        ).fetchone()
        assert tuple(pair_state) == (
            activated["entitlement_id"],
            activated["binding_id"],
            1,
            activated["revocation_version"],
            "active",
            0,
        )
    finally:
        connection.close()


def test_card_code_plaintext_is_never_persisted_to_database_or_audit(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="e1" * 16,
        product_key="day",
        quantity=2,
        channel="security-test",
        note="plaintext scan",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation_service = CardActivationService(dual_settings)
    challenge = activation_service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="e2" * 16,
            pair_id="e3" * 16,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_001,
    )
    activation_service.confirm_activation(
        _confirm_command(challenge, host_private, android_private),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )

    forbidden_values = (*issuance.codes, challenge["challenge_token"])
    leaked_cells = [
        (table, column, value)
        for table, column, value in _sidecar_text_cells(dual_settings)
        if any(secret_value in value for secret_value in forbidden_values)
    ]

    assert leaked_cells == []


def test_invalid_device_proof_never_consumes_card(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="4" * 32,
        product_key="day",
        quantity=1,
        channel="manual",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    other_private, _ = _identity()
    service = CardActivationService(dual_settings)
    challenge = service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="5" * 32,
            pair_id="6" * 32,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    confirmation = _confirm_command(
        challenge,
        host_private,
        other_private,
    )

    with pytest.raises(
        DualMachineServiceError,
        match="activation_device_proof_invalid",
    ):
        service.confirm_activation(
            confirmation,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )

    connection = connect_database(dual_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_license_codes",
        ).fetchone()["status"] == "issued"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_entitlements",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_pair_security_state",
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_pair_security_bootstrap_failure_rolls_back_activation_transaction(
    dual_settings: DualMachineSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="d" * 32,
        product_key="day",
        quantity=1,
        channel="manual",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    service = CardActivationService(dual_settings)
    challenge = service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="e" * 32,
            pair_id="f" * 32,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )

    def fail_bootstrap(*_args, **_kwargs):
        raise PairSecurityBootstrapError("synthetic_pair_bootstrap_failure")

    monkeypatch.setattr(
        "dual_machine_service.pair_security_bootstrap."
        "_PairSecurityBootstrapService.commit_verified_binding",
        fail_bootstrap,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="synthetic_pair_bootstrap_failure",
    ):
        service.confirm_activation(
            _confirm_command(challenge, host_private, android_private),
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )

    connection = connect_database(dual_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_license_codes",
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT status FROM dm_activation_challenges",
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_entitlements",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_pair_security_state",
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_second_card_cannot_top_up_existing_entitlement(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="7" * 32,
        product_key="day",
        quantity=2,
        channel="manual",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    service = CardActivationService(dual_settings)
    first_challenge = service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="8" * 32,
            pair_id="a" * 32,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_008,
    )
    first = service.confirm_activation(
        _confirm_command(
            first_challenge,
            host_private,
            android_private,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_009,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="activation_entitlement_already_exists",
    ):
        service.create_challenge(
            _activation_command(
                issuance.codes[1],
                request_id="9" * 32,
                pair_id="a" * 32,
                host_public_key=host_public,
                android_public_key=android_public,
            ),
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )

    connection = connect_database(dual_settings)
    try:
        entitlements = connection.execute(
            "SELECT remaining_seconds, total_credited_seconds, "
            "total_consumed_seconds FROM dm_entitlements",
        ).fetchall()
        assert len(entitlements) == 1
        assert dict(entitlements[0]) == {
            "remaining_seconds": 86_400,
            "total_credited_seconds": 86_400,
            "total_consumed_seconds": 0,
        }
        assert first["entitlement_id"]
        assert connection.execute(
            "SELECT status FROM dm_license_codes ORDER BY id DESC LIMIT 1",
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_versioned_license_keyring_preserves_unactivated_cards(
    dual_settings: DualMachineSettings,
) -> None:
    original = CardIssuanceService(dual_settings).issue_batch(
        request_id="b1" * 16,
        product_key="day",
        quantity=1,
        channel="rotation-test",
        now_epoch=1_700_000_000,
    )
    rotated = DualMachineSettings(
        database_path=dual_settings.database_path,
        license_code_secret=(
            b"rotated-dual-machine-license-secret-32-bytes-min"
        ),
        token_secret=dual_settings.token_secret,
        minimum_host_client_version=(
            dual_settings.minimum_host_client_version
        ),
        minimum_android_client_version=(
            dual_settings.minimum_android_client_version
        ),
        license_code_key_version=2,
        license_code_previous_keys=(
            (1, dual_settings.license_code_secret),
        ),
        ticket_private_key_path=dual_settings.ticket_private_key_path,
        ticket_public_key_path=dual_settings.ticket_public_key_path,
    )
    replayed = CardIssuanceService(rotated).issue_batch(
        request_id="b1" * 16,
        product_key="day",
        quantity=1,
        channel="rotation-test",
        now_epoch=1_700_000_001,
    )
    assert replayed.codes == original.codes

    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation_service = CardActivationService(rotated)
    challenge = activation_service.create_challenge(
        _activation_command(
            original.codes[0],
            request_id="b2" * 16,
            pair_id="b3" * 16,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )
    activated = activation_service.confirm_activation(
        _confirm_command(challenge, host_private, android_private),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_003,
    )
    assert activated["remaining_seconds"] == 86_400

    newly_issued = CardIssuanceService(rotated).issue_batch(
        request_id="b4" * 16,
        product_key="day",
        quantity=1,
        channel="rotation-test",
        now_epoch=1_700_000_004,
    )
    assert newly_issued.codes != original.codes

    connection = connect_database(rotated)
    try:
        versions = connection.execute(
            "SELECT key_version FROM dm_license_codes ORDER BY id",
        ).fetchall()
        assert [row[0] for row in versions] == [1, 2]
    finally:
        connection.close()


def test_batch_revocation_requires_explicit_activated_cascade(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="c1" * 16,
        product_key="day",
        quantity=2,
        channel="revocation-test",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation_service = CardActivationService(dual_settings)
    challenge = activation_service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="c2" * 16,
            pair_id="c3" * 16,
            host_public_key=host_public,
            android_public_key=android_public,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_001,
    )
    activated = activation_service.confirm_activation(
        _confirm_command(challenge, host_private, android_private),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )

    admin = DualMachineAdminService(dual_settings)
    unactivated_only = admin.revoke_batch(
        issuance.batch_id,
        reason="batch investigation",
    )
    assert unactivated_only["revoked_issued_codes"] == 1
    assert unactivated_only["revoked_activated_entitlements"] == 0
    assert admin.entitlement_summary(
        activated["entitlement_id"],
    )["status"] == "active"

    cascaded = admin.revoke_batch(
        issuance.batch_id,
        reason="confirmed batch leak",
        revoke_activated_entitlements=True,
    )
    assert cascaded["revoked_activated_entitlements"] == 1
    assert admin.entitlement_summary(
        activated["entitlement_id"],
    )["status"] == "revoked"


def test_admin_lists_batches_and_codes_without_plaintext_or_digest(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="e1" * 16,
        product_key="day",
        quantity=2,
        channel="support",
        now_epoch=1_700_000_000,
    )

    admin = DualMachineAdminService(dual_settings)
    batches = admin.list_batches(limit=10)
    assert batches["ok"] is True
    assert batches["total"] == 1
    assert batches["batches"][0]["id"] == issuance.batch_id
    assert batches["batches"][0]["issued_count"] == 2

    codes = admin.list_codes(batch_id=issuance.batch_id, limit=10)
    assert codes["ok"] is True
    assert codes["total"] == 2
    assert [item["status"] for item in codes["codes"]] == [
        "issued",
        "issued",
    ]
    for item, plaintext in zip(codes["codes"], issuance.codes, strict=True):
        assert item["code_suffix"] == plaintext[-4:]
        assert plaintext not in str(item)
        assert "code_digest" not in item
        assert "derivation_ref" not in item


def test_outdated_client_is_rejected_before_card_consumption(
    dual_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(dual_settings).issue_batch(
        request_id="d1" * 16,
        product_key="day",
        quantity=1,
        channel="version-test",
        now_epoch=1_700_000_000,
    )
    _, host_public = _identity()
    _, android_public = _identity()
    command = _activation_command(
        issuance.codes[0],
        request_id="d2" * 16,
        pair_id="d3" * 16,
        host_public_key=host_public,
        android_public_key=android_public,
    )
    command["host"]["client_version"] = "17.8.80"

    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_client_update_required",
    ):
        CardActivationService(dual_settings).create_challenge(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_001,
        )

    connection = connect_database(dual_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_license_codes",
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_activation_challenges",
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_single_machine_database_has_no_dual_machine_tables(
    tmp_path: Path,
) -> None:
    single_database = tmp_path / "single.db"
    connection = sqlite3.connect(single_database)
    try:
        connection.execute(
            "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT)",
        )
        dual_tables = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name LIKE 'dm_%'",
        ).fetchall()
        assert dual_tables == []
    finally:
        connection.close()
