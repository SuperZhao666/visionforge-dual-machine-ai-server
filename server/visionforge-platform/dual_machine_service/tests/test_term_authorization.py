from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from dual_machine_service.admin_service import DualMachineAdminService
from dual_machine_service.card_service import (
    CardActivationService,
    CardIssuanceService,
)
from dual_machine_service.contracts import (
    usage_heartbeat_payload,
    usage_start_challenge_payload,
    usage_start_payload,
)
from dual_machine_service.database import connect_database, initialize_database
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.identity import canonical_base64
from dual_machine_service.pair_security_repository import PairSecurityRepository
from dual_machine_service.settings import DualMachineSettings
from dual_machine_service.usage_service import UsageService

CHANNEL_BINDING_SHA256 = "f" * 64


@pytest.fixture()
def term_settings(tmp_path: Path) -> DualMachineSettings:
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
        license_code_secret=b"term-license-code-secret-at-least-32-bytes",
        token_secret=b"term-token-secret-at-least-32-bytes-long",
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


def _sign(private_key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    return base64.b64encode(
        private_key.sign(payload, ec.ECDSA(hashes.SHA256())),
    ).decode("ascii")


def _activate(
    settings: DualMachineSettings,
    code: str,
    *,
    request_seed: str,
    pair_id: str,
    host: tuple[ec.EllipticCurvePrivateKey, str] | None = None,
    android: tuple[ec.EllipticCurvePrivateKey, str] | None = None,
    profile: dict | None = None,
    now_epoch: int = 1_700_000_000,
) -> tuple[dict, tuple, tuple, dict]:
    host_identity = host or _identity()
    android_identity = android or _identity()
    command = {
        "request_id": request_seed * 32,
        "pair_id": pair_id,
        "protocol_version": 2,
        "card_code": code,
        "host": {
            "device_code": "HOST-1",
            "client_version": "17.8.81",
            "identity_public_key_b64": host_identity[1],
        },
        "android": {
            "device_code": "ANDROID-1",
            "client_version": "1.0.0",
            "identity_public_key_b64": android_identity[1],
        },
    }
    if profile is not None:
        command["android_device_profile"] = profile
    service = CardActivationService(settings)
    challenge = service.create_challenge(
        command,
        client_ip="127.0.0.1",
        now_epoch=now_epoch,
    )
    proof = base64.b64decode(challenge["proof_payload_b64"], validate=True)
    response = service.confirm_activation(
        {
            "challenge_id": challenge["challenge_id"],
            "challenge_token": challenge["challenge_token"],
            "host_signature_b64": _sign(host_identity[0], proof),
            "android_signature_b64": _sign(android_identity[0], proof),
        },
        client_ip="127.0.0.1",
        now_epoch=now_epoch + 1,
    )
    return response, host_identity, android_identity, challenge


def _create_pending_rebind(
    settings: DualMachineSettings,
    code: str,
    *,
    request_id: str,
    pair_id: str,
    now_epoch: int,
    host: tuple[ec.EllipticCurvePrivateKey, str] | None = None,
    android: tuple[ec.EllipticCurvePrivateKey, str] | None = None,
) -> tuple[CardActivationService, dict, dict]:
    host = host or _identity()
    android = android or _identity()
    service = CardActivationService(settings)
    challenge = service.create_challenge(
        {
            "request_id": request_id,
            "pair_id": pair_id,
            "protocol_version": 2,
            "card_code": code,
            "host": {
                "device_code": "HOST-REBOUND",
                "client_version": "17.8.81",
                "identity_public_key_b64": host[1],
            },
            "android": {
                "device_code": "ANDROID-REBOUND",
                "client_version": "1.0.0",
                "identity_public_key_b64": android[1],
            },
        },
        client_ip="127.0.0.1",
        now_epoch=now_epoch,
    )
    proof = base64.b64decode(challenge["proof_payload_b64"], validate=True)
    confirmation = {
        "challenge_id": challenge["challenge_id"],
        "challenge_token": challenge["challenge_token"],
        "host_signature_b64": _sign(host[0], proof),
        "android_signature_b64": _sign(android[0], proof),
    }
    return service, challenge, confirmation


def _hex_id(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]


def _start_formal_usage(
    settings: DualMachineSettings,
    activated: dict,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
    *,
    label: str,
    now_epoch: int,
) -> tuple[UsageService, dict]:
    service = UsageService(settings)
    challenge_command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": _hex_id(label + ":challenge"),
        "request_nonce": _hex_id(label + ":challenge-nonce"),
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
    }
    challenge_payload = usage_start_challenge_payload(challenge_command)
    challenge = service.create_start_challenge(
        {
            **challenge_command,
            "host_signature_b64": _sign(host_private, challenge_payload),
            "android_signature_b64": _sign(
                android_private,
                challenge_payload,
            ),
        },
        client_ip="127.0.0.1",
        now_epoch=now_epoch,
    )
    start_command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": _hex_id(label + ":start"),
        "request_nonce": _hex_id(label + ":start-nonce"),
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "host_frames_total": 0,
        "android_frames_total": 0,
        "start_challenge_id": challenge["challenge_id"],
        "start_challenge_token": challenge["challenge_token"],
    }
    start_payload = usage_start_payload(start_command)
    started = service.start_usage(
        {
            **start_command,
            "host_signature_b64": _sign(host_private, start_payload),
            "android_signature_b64": _sign(android_private, start_payload),
        },
        now_epoch=now_epoch + 1,
    )
    return service, started


@pytest.mark.parametrize(
    ("product_key", "expected_seconds"),
    (("day", 86_400), ("week", 604_800), ("month", 2_592_000)),
)
def test_finite_term_cards_credit_only_their_formal_usage_allowance(
    term_settings: DualMachineSettings,
    product_key: str,
    expected_seconds: int,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=hashlib.sha256(
            f"issue:{product_key}".encode(),
        ).hexdigest()[:32],
        product_key=product_key,
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    activated, _, _, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="a",
        pair_id=hashlib.sha256(product_key.encode()).hexdigest()[:32],
    )

    assert issued.authorization_kind == product_key
    assert issued.duration_seconds == expected_seconds
    assert activated["authorization_kind"] == product_key
    assert activated["credited_seconds"] == expected_seconds
    assert activated["remaining_seconds"] == expected_seconds
    assert activated["is_permanent"] is False


def test_second_card_cannot_top_up_an_existing_entitlement(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=2,
        channel="test",
        now_epoch=1_700_000_000,
    )
    host = _identity()
    android = _identity()
    first, _, _, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="2",
        pair_id="3" * 32,
        host=host,
        android=android,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="activation_entitlement_already_exists",
    ):
        CardActivationService(term_settings).create_challenge(
            {
                "request_id": "4" * 32,
                "pair_id": "3" * 32,
                "protocol_version": 2,
                "card_code": issued.codes[1],
                "host": {
                    "device_code": "HOST-1",
                    "client_version": "17.8.81",
                    "identity_public_key_b64": host[1],
                },
                "android": {
                    "device_code": "ANDROID-1",
                    "client_version": "1.0.0",
                    "identity_public_key_b64": android[1],
                },
            },
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )

    connection = connect_database(term_settings)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_entitlements",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_400
        assert connection.execute(
            "SELECT status FROM dm_license_codes ORDER BY ordinal",
        ).fetchall()[1][0] == "issued"
        assert first["total_credited_seconds"] == 86_400
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("replacement_product", "expected_remaining"),
    (("week", 604_800), ("permanent", 0)),
)
def test_new_card_reactivates_only_an_exhausted_entitlement(
    term_settings: DualMachineSettings,
    replacement_product: str,
    expected_remaining: int,
) -> None:
    first_card = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate:first:" + replacement_product),
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    replacement_card = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate:replacement:" + replacement_product),
        product_key=replacement_product,
        quantity=1,
        channel="test",
        now_epoch=1_700_000_001,
    )
    pair_id = _hex_id("reactivate:pair:" + replacement_product)
    host = _identity()
    android = _identity()
    first, _, _, _ = _activate(
        term_settings,
        first_card.codes[0],
        request_seed="a",
        pair_id=pair_id,
        host=host,
        android=android,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        binding = connection.execute(
            "SELECT host_key_sha256, android_key_sha256 "
            "FROM dm_entitlement_device_bindings WHERE is_current = 1",
        ).fetchone()
    finally:
        connection.close()
    pair_repository = PairSecurityRepository(term_settings)
    generation_challenge_id = _hex_id(
        "reactivate:generation-challenge:" + replacement_product,
    )
    generation_payload_sha256 = _hex_id(
        "reactivate:generation-payload:" + replacement_product,
    ) * 2
    generation_common = {
        "pair_id": pair_id,
        "binding_id": first["binding_id"],
        "binding_revision": first["binding_revision"],
        "revocation_version": first["revocation_version"],
        "host_key_sha256": str(binding["host_key_sha256"]),
        "android_key_sha256": str(binding["android_key_sha256"]),
    }
    pair_repository.issue_generation_challenge(
        **generation_common,
        challenge_id=generation_challenge_id,
        request_id=_hex_id(
            "reactivate:generation-request:" + replacement_product,
        ),
        request_payload_sha256=generation_payload_sha256,
        server_nonce_sha256=(
            _hex_id("reactivate:generation-nonce:" + replacement_product)
            * 2
        ),
        expires_at_epoch=1_700_000_019,
        now_epoch=1_700_000_015,
    )
    pair_repository.allocate_generation(
        **generation_common,
        allocation_request_id=_hex_id(
            "reactivate:allocation:" + replacement_product,
        ),
        request_payload_sha256=generation_payload_sha256,
        challenge_id=generation_challenge_id,
        connection_id=5_000,
        transcript_proposal_sha256=(
            _hex_id("reactivate:transcript:" + replacement_product) * 2
        ),
        now_epoch=1_700_000_016,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 0, "
            "total_consumed_seconds = total_credited_seconds, "
            "status = 'exhausted' WHERE entitlement_id = ?",
            (first["entitlement_id"],),
        )
    finally:
        connection.close()

    replacement, _, _, challenge = _activate(
        term_settings,
        replacement_card.codes[0],
        request_seed="b",
        pair_id=pair_id,
        host=host,
        android=android,
        now_epoch=1_700_000_020,
    )

    assert challenge["activation_mode"] == "reactivate"
    assert challenge["target_entitlement_id"] == first["entitlement_id"]
    assert replacement["entitlement_id"] == first["entitlement_id"]
    assert replacement["activation_mode"] == "reactivate"
    assert replacement["revocation_version"] == (
        first["revocation_version"] + 1
    )
    assert replacement["authorization_kind"] == replacement_product
    assert replacement["is_permanent"] is (
        replacement_product == "permanent"
    )
    assert replacement["remaining_seconds"] == expected_remaining
    assert replacement["billing_started"] is False
    assert replacement["binding_id"] == first["binding_id"]
    assert replacement["binding_revision"] == first["binding_revision"]
    assert replacement["pair_assurance_state"] == "active"

    connection = connect_database(term_settings)
    try:
        entitlement = connection.execute(
            "SELECT status, remaining_seconds, total_credited_seconds, "
            "total_consumed_seconds, authorization_kind "
            "FROM dm_entitlements",
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_entitlements",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_license_activations",
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert dict(entitlement) == {
            "status": "active",
            "remaining_seconds": expected_remaining,
            "total_credited_seconds": expected_remaining,
            "total_consumed_seconds": 0,
            "authorization_kind": replacement_product,
        }
        pair_state = connection.execute(
            "SELECT assurance_state, binding_revision, revocation_version, "
            "generation_high_water FROM dm_pair_security_state",
        ).fetchone()
        assert tuple(pair_state) == (
            "active",
            first["binding_revision"],
            replacement["revocation_version"],
            1,
        )
    finally:
        connection.close()


def test_historical_batch_revocation_preserves_reactivated_entitlement(
    term_settings: DualMachineSettings,
) -> None:
    historical_batch = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-batch-owner:historical"),
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    current_batch = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-batch-owner:current"),
        product_key="week",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_001,
    )
    pair_id = _hex_id("reactivate-batch-owner:pair")
    host = _identity()
    android = _identity()
    original, _, _, _ = _activate(
        term_settings,
        historical_batch.codes[0],
        request_seed="a",
        pair_id=pair_id,
        host=host,
        android=android,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 0, "
            "total_consumed_seconds = total_credited_seconds, "
            "status = 'exhausted' WHERE entitlement_id = ?",
            (original["entitlement_id"],),
        )
    finally:
        connection.close()

    current, _, _, _ = _activate(
        term_settings,
        current_batch.codes[0],
        request_seed="b",
        pair_id=pair_id,
        host=host,
        android=android,
        now_epoch=1_700_000_020,
    )
    binding_service, pending_binding, confirmation = _create_pending_rebind(
        term_settings,
        current_batch.codes[0],
        request_id=_hex_id("reactivate-batch-owner:binding"),
        pair_id=_hex_id("reactivate-batch-owner:rebound-pair"),
        now_epoch=1_700_000_030,
        host=host,
        android=android,
    )
    assert pending_binding["activation_mode"] == "bind_device"

    admin = DualMachineAdminService(term_settings)
    historical_revocation = admin.revoke_batch(
        historical_batch.batch_id,
        reason="historical batch incident",
        revoke_activated_entitlements=True,
    )
    assert historical_revocation["revoked_activated_entitlements"] == 0
    assert historical_revocation["expired_binding_challenges"] == 0
    preserved = admin.entitlement_summary(current["entitlement_id"])
    assert preserved["status"] == "active"
    assert preserved["remaining_seconds"] == 604_800

    rebound = binding_service.confirm_activation(
        confirmation,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_031,
    )
    assert rebound["binding_updated"] is True
    assert rebound["status"] == "active"

    current_revocation = admin.revoke_batch(
        current_batch.batch_id,
        reason="current batch incident",
        revoke_activated_entitlements=True,
    )
    assert current_revocation["revoked_activated_entitlements"] == 1
    assert admin.entitlement_summary(current["entitlement_id"])[
        "status"
    ] == "revoked"


def test_batch_revocation_keeps_legacy_activation_source_fallback(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("legacy-batch-owner:issue"),
        product_key="day",
        quantity=1,
        channel="migration-test",
        now_epoch=1_700_000_000,
    )
    activated, _, _, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="a",
        pair_id=_hex_id("legacy-batch-owner:pair"),
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET source_license_code_id = NULL "
            "WHERE entitlement_id = ?",
            (activated["entitlement_id"],),
        )
    finally:
        connection.close()

    revoked = DualMachineAdminService(term_settings).revoke_batch(
        issued.batch_id,
        reason="legacy batch incident",
        revoke_activated_entitlements=True,
    )
    assert revoked["revoked_activated_entitlements"] == 1
    assert DualMachineAdminService(term_settings).entitlement_summary(
        activated["entitlement_id"],
    )["status"] == "revoked"


def test_reactivation_rejects_a_different_android_device_without_side_effect(
    term_settings: DualMachineSettings,
) -> None:
    first_card = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-device:first"),
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    replacement_card = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-device:replacement"),
        product_key="week",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_001,
    )
    pair_id = _hex_id("reactivate-device:pair")
    first, host, _, _ = _activate(
        term_settings,
        first_card.codes[0],
        request_seed="c",
        pair_id=pair_id,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 0, "
            "total_consumed_seconds = total_credited_seconds, "
            "status = 'exhausted' WHERE entitlement_id = ?",
            (first["entitlement_id"],),
        )
        before = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM dm_activation_challenges), "
            "(SELECT COUNT(*) FROM dm_license_activations), "
            "(SELECT COUNT(*) FROM dm_entitlement_device_bindings), "
            "(SELECT status FROM dm_license_codes WHERE ordinal = 1 "
            "ORDER BY id DESC LIMIT 1)",
        ).fetchone())
    finally:
        connection.close()

    with pytest.raises(DualMachineServiceError) as rejected:
        _create_pending_rebind(
            term_settings,
            replacement_card.codes[0],
            request_id=_hex_id("reactivate-device:attempt"),
            pair_id=pair_id,
            now_epoch=1_700_000_020,
            host=host,
            android=_identity(),
        )

    assert rejected.value.code == "license_bound_to_another_device"
    connection = connect_database(term_settings)
    try:
        after = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM dm_activation_challenges), "
            "(SELECT COUNT(*) FROM dm_license_activations), "
            "(SELECT COUNT(*) FROM dm_entitlement_device_bindings), "
            "(SELECT status FROM dm_license_codes WHERE ordinal = 1 "
            "ORDER BY id DESC LIMIT 1)",
        ).fetchone())
    finally:
        connection.close()
    assert after == before


def test_reactivation_confirmation_rechecks_current_android_binding(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-race:cards"),
        product_key="day",
        quantity=2,
        channel="test",
        now_epoch=1_700_000_000,
    )
    pair_id = _hex_id("reactivate-race:pair")
    first, host, android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="d",
        pair_id=pair_id,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 0, "
            "total_consumed_seconds = total_credited_seconds, "
            "status = 'exhausted' WHERE entitlement_id = ?",
            (first["entitlement_id"],),
        )
    finally:
        connection.close()

    service, challenge, confirmation = _create_pending_rebind(
        term_settings,
        issued.codes[1],
        request_id=_hex_id("reactivate-race:challenge"),
        pair_id=pair_id,
        now_epoch=1_700_000_020,
        host=host,
        android=android,
    )
    assert challenge["activation_mode"] == "reactivate"

    _, replacement_android_public = _identity()
    replacement_android_key = hashlib.sha256(base64.b64decode(
        replacement_android_public,
        validate=True,
    )).hexdigest()
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlement_device_bindings SET "
            "android_identity_public_key_b64 = ?, android_key_sha256 = ? "
            "WHERE entitlement_id = ? AND is_current = 1",
            (
                replacement_android_public,
                replacement_android_key,
                first["entitlement_id"],
            ),
        )
    finally:
        connection.close()

    with pytest.raises(DualMachineServiceError) as rejected:
        service.confirm_activation(
            confirmation,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_021,
        )
    assert rejected.value.code == "license_bound_to_another_device"

    connection = connect_database(term_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_activation_challenges "
            "WHERE challenge_id = ?",
            (challenge["challenge_id"],),
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT status FROM dm_license_codes WHERE id = ("
            "SELECT license_code_id FROM dm_activation_challenges "
            "WHERE challenge_id = ?)",
            (challenge["challenge_id"],),
        ).fetchone()[0] == "issued"
        assert connection.execute(
            "SELECT status FROM dm_entitlements WHERE entitlement_id = ?",
            (first["entitlement_id"],),
        ).fetchone()[0] == "exhausted"
    finally:
        connection.close()


def test_reactivation_rejects_inconsistent_exhaustion_counters(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate-inconsistent:cards"),
        product_key="day",
        quantity=2,
        channel="test",
        now_epoch=1_700_000_000,
    )
    pair_id = _hex_id("reactivate-inconsistent:pair")
    first, host, android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="e",
        pair_id=pair_id,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        # Simulate a pre-hardening/corrupted database row. The service layer
        # must still fail closed even when the current schema CHECK was not
        # present at the time the row was written.
        connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            connection.execute(
                "UPDATE dm_entitlements SET remaining_seconds = 0, "
                "status = 'exhausted' WHERE entitlement_id = ?",
                (first["entitlement_id"],),
            )
        finally:
            connection.execute("PRAGMA ignore_check_constraints=OFF")
    finally:
        connection.close()

    with pytest.raises(DualMachineServiceError) as rejected:
        _create_pending_rebind(
            term_settings,
            issued.codes[1],
            request_id=_hex_id("reactivate-inconsistent:attempt"),
            pair_id=pair_id,
            now_epoch=1_700_000_020,
            host=host,
            android=android,
        )
    assert rejected.value.code == "activation_entitlement_already_exists"

    connection = connect_database(term_settings)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_activation_challenges",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT status FROM dm_license_codes WHERE id = ("
            "SELECT MAX(id) FROM dm_license_codes)",
        ).fetchone()[0] == "issued"
    finally:
        connection.close()


@pytest.mark.parametrize("product_key", ("day", "week", "month"))
def test_finite_term_card_exhausts_and_immediately_blocks_new_usage(
    term_settings: DualMachineSettings,
    product_key: str,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("exhaust-issue:" + product_key),
        product_key=product_key,
        quantity=1,
        channel="test",
    )
    activated, host, android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="a",
        pair_id=_hex_id("exhaust-pair:" + product_key),
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 1, "
            "total_credited_seconds = 1, total_consumed_seconds = 0 "
            "WHERE entitlement_id = ?",
            (activated["entitlement_id"],),
        )
    finally:
        connection.close()
    service, started = _start_formal_usage(
        term_settings,
        activated,
        host[0],
        android[0],
        label="exhaust:" + product_key,
        now_epoch=1_700_000_100,
    )
    assert started["charged_seconds"] == 1
    assert started["remaining_seconds"] == 0
    assert started["usage_lease_expires_at_epoch"] == 1_700_000_102
    connection = connect_database(term_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_entitlements",
        ).fetchone()[0] == "exhausted"
    finally:
        connection.close()

    command = {
        "entitlement_id": activated["entitlement_id"],
        "pair_id": activated["pair_id"],
        "protocol_version": 2,
        "revocation_version": activated["revocation_version"],
        "request_id": _hex_id("blocked:" + product_key),
        "request_nonce": _hex_id("blocked-nonce:" + product_key),
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
    }
    payload = usage_start_challenge_payload(command)
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_inactive",
    ):
        service.create_start_challenge(
            {
                **command,
                "host_signature_b64": _sign(host[0], payload),
                "android_signature_b64": _sign(android[0], payload),
            },
            client_ip="127.0.0.1",
            now_epoch=1_700_000_103,
        )


def test_exhausted_entitlement_waits_for_active_session_to_end_before_reactivation(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id("reactivate:active-session:issue"),
        product_key="day",
        quantity=2,
        channel="test",
        now_epoch=1_700_000_000,
    )
    pair_id = _hex_id("reactivate:active-session:pair")
    first, host, android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="c",
        pair_id=pair_id,
        now_epoch=1_700_000_010,
    )
    connection = connect_database(term_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 1, "
            "total_credited_seconds = 1, total_consumed_seconds = 0 "
            "WHERE entitlement_id = ?",
            (first["entitlement_id"],),
        )
    finally:
        connection.close()
    _start_formal_usage(
        term_settings,
        first,
        host[0],
        android[0],
        label="reactivate:active-session",
        now_epoch=1_700_000_100,
    )
    service, challenge, confirmation = _create_pending_rebind(
        term_settings,
        issued.codes[1],
        request_id=_hex_id("reactivate:active-session:replacement"),
        pair_id=pair_id,
        now_epoch=1_700_000_103,
        host=host,
        android=android,
    )

    assert challenge["activation_mode"] == "reactivate"
    assert challenge["target_entitlement_id"] == first["entitlement_id"]
    with pytest.raises(
        DualMachineServiceError,
        match="activation_entitlement_already_exists",
    ):
        service.confirm_activation(
            confirmation,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_104,
        )

    connection = connect_database(term_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_entitlements",
        ).fetchone()[0] == "exhausted"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions "
            "WHERE status = 'active'",
        ).fetchone()[0] == 1
        assert [row[0] for row in connection.execute(
            "SELECT status FROM dm_license_codes ORDER BY ordinal",
        ).fetchall()] == ["activated", "issued"]
    finally:
        connection.close()


def test_activated_card_is_device_locked_until_admin_unbind(
    term_settings: DualMachineSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id="5" * 32,
        product_key="week",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    first_profile = {
        "manufacturer": "Google",
        "model": "Pixel 9",
        "sdk_int": 36,
        "supported_abis": ["arm64-v8a"],
        "device_fingerprint": "a" * 64,
    }
    first, first_host, first_android, first_challenge = _activate(
        term_settings,
        issued.codes[0],
        request_seed="6",
        pair_id="7" * 32,
        profile=first_profile,
    )
    expected_hash = hashlib.sha256(json.dumps(
        first_profile,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    assert first_challenge["activation_mode"] == "activate"
    assert first_challenge["target_entitlement_id"] == ""
    assert first_challenge["android_device_profile_sha256"] == expected_hash
    first_usage, first_started = _start_formal_usage(
        term_settings,
        first,
        first_host[0],
        first_android[0],
        label="first-device",
        now_epoch=1_700_000_050,
    )
    pending_command = {
        "entitlement_id": first["entitlement_id"],
        "pair_id": first["pair_id"],
        "protocol_version": 2,
        "revocation_version": first["revocation_version"],
        "request_id": _hex_id("pending-before-rebind"),
        "request_nonce": _hex_id("pending-before-rebind-nonce"),
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
    }
    pending_payload = usage_start_challenge_payload(pending_command)
    pending = first_usage.create_start_challenge(
        {
            **pending_command,
            "host_signature_b64": _sign(first_host[0], pending_payload),
            "android_signature_b64": _sign(
                first_android[0],
                pending_payload,
            ),
        },
        client_ip="127.0.0.1",
        now_epoch=1_700_000_052,
    )

    with pytest.raises(
        DualMachineServiceError,
        match="license_bound_to_another_device",
    ):
        _activate(
            term_settings,
            issued.codes[0],
            request_seed="8",
            pair_id="9" * 32,
            profile={
                "brand": "Samsung",
                # A shared card stays rejected even when another client can
                # copy arbitrary profile metadata.
                "device_fingerprint": "a" * 64,
            },
            now_epoch=1_700_000_053,
        )

    monkeypatch.setattr(
        "dual_machine_service.admin_service.time.time",
        lambda: 1_700_000_054,
    )
    before_unbind = DualMachineAdminService(
        term_settings,
    ).entitlement_summary(first["entitlement_id"])
    assert len(before_unbind["device_bindings"]) == 1
    assert before_unbind["device_bindings"][0]["is_current"] is True
    DualMachineAdminService(term_settings).unbind_entitlement_device(
        first["entitlement_id"],
        before_unbind["device_bindings"][0]["binding_id"],
        reason="customer approved device replacement",
    )

    rebound, rebound_host, rebound_android, rebound_challenge = _activate(
        term_settings,
        issued.codes[0],
        request_seed="8",
        pair_id="9" * 32,
        profile={"brand": "Samsung", "device_fingerprint": "b" * 64},
        now_epoch=1_700_000_055,
    )
    assert rebound_challenge["activation_mode"] == "bind_device"
    assert rebound_challenge["target_entitlement_id"] == first["entitlement_id"]
    assert set(rebound) == set(first)
    assert rebound["activation_id"] == first["activation_id"]
    assert rebound["entitlement_id"] == first["entitlement_id"]
    assert rebound["revocation_version"] == first["revocation_version"] + 2
    assert rebound["activation_mode"] == "bind_device"
    assert rebound["binding_updated"] is True
    assert rebound["credited_seconds"] == 0
    assert rebound["remaining_seconds"] == first_started["remaining_seconds"]
    assert rebound["binding_id"] != first["binding_id"]
    assert rebound["binding_revision"] == first["binding_revision"] + 1
    assert rebound["pair_assurance_state"] == "active"

    connection = connect_database(term_settings)
    try:
        ended_session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchone()
        assert tuple(ended_session) == ("ended", "admin_device_unbound")
        assert connection.execute(
            "SELECT status FROM dm_usage_start_challenges "
            "WHERE challenge_id = ?",
            (pending["challenge_id"],),
        ).fetchone()[0] == "expired"
        pair_states = connection.execute(
            "SELECT pair_id, binding_revision, assurance_state, "
            "predecessor_pair_id FROM dm_pair_security_state "
            "ORDER BY binding_revision",
        ).fetchall()
        assert [tuple(row) for row in pair_states] == [
            (first["pair_id"], first["binding_revision"], "rotated", None),
            (
                rebound["pair_id"],
                rebound["binding_revision"],
                "active",
                first["pair_id"],
            ),
        ]
    finally:
        connection.close()

    summary = DualMachineAdminService(term_settings).entitlement_summary(
        first["entitlement_id"],
    )
    assert len(summary["device_bindings"]) == 2
    assert summary["device_bindings"][0]["is_current"] is True
    assert summary["device_bindings"][0]["android_device_profile"]["brand"] == "Samsung"
    assert summary["device_bindings"][1]["android_device_profile"]["model"] == "Pixel 9"
    assert all(
        "identity_public_key_b64" not in binding
        for binding in summary["device_bindings"]
    )
    usage, started = _start_formal_usage(
        term_settings,
        rebound,
        rebound_host[0],
        rebound_android[0],
        label="rebound-device",
        now_epoch=1_700_000_200,
    )


    claims = usage.token_codec.verify_usage_lease(
        started["usage_lease"],
        now_epoch=1_700_000_201,
    )
    current_binding = summary["device_bindings"][0]
    assert claims["hkh"] == current_binding["host_key_sha256"]
    assert claims["akh"] == current_binding["android_key_sha256"]
    admin = DualMachineAdminService(term_settings)
    code = admin.list_codes(batch_id=issued.batch_id)["codes"][0]
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_batch_has_activated_codes",
    ):
        admin.update_batch(
            issued.batch_id,
            note="must not mutate sold cards",
            expires_at_epoch=None,
            reason="invalid sold-card edit",
        )
    archived_code = admin.delete_code(
        code["id"],
        reason="archive used sale history",
    )
    assert archived_code["activated_history_preserved"] is True
    archived_batch = admin.delete_batch(
        issued.batch_id,
        reason="archive completed batch",
    )
    assert archived_batch["activated_history_preserved"] == 1
    assert admin.entitlement_summary(first["entitlement_id"])["status"] == "active"


@pytest.mark.parametrize("revocation_scope", ("entitlement", "batch"))
def test_revoke_restore_cannot_confirm_pre_revocation_rebind_challenge(
    term_settings: DualMachineSettings,
    revocation_scope: str,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id=_hex_id(f"stale-rebind:{revocation_scope}:batch"),
        product_key="week",
        quantity=1,
        channel="security-regression",
        now_epoch=1_700_001_000,
    )
    activated, activated_host, activated_android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="a",
        pair_id=_hex_id(f"stale-rebind:{revocation_scope}:initial"),
        now_epoch=1_700_001_001,
    )
    service, pending, confirmation = _create_pending_rebind(
        term_settings,
        issued.codes[0],
        request_id=_hex_id(f"stale-rebind:{revocation_scope}:pending"),
        pair_id=_hex_id(f"stale-rebind:{revocation_scope}:replacement"),
        now_epoch=1_700_001_010,
        host=activated_host,
        android=activated_android,
    )
    assert pending["activation_mode"] == "bind_device"
    assert pending["target_entitlement_id"] == activated["entitlement_id"]

    admin = DualMachineAdminService(term_settings)
    if revocation_scope == "batch":
        revoked = admin.revoke_batch(
            issued.batch_id,
            reason="security incident",
            revoke_activated_entitlements=True,
        )
        assert revoked["revoked_activated_entitlements"] == 1
        admin.restore_batch(issued.batch_id, reason="incident resolved")
        expected_revoke_reason = "license_batch_revoked"
    else:
        revoked = admin.revoke_entitlement(
            activated["entitlement_id"],
            reason="security incident",
        )
        expected_revoke_reason = "entitlement_revoked"
    assert revoked["expired_binding_challenges"] == 1
    restored = admin.restore_entitlement(
        activated["entitlement_id"],
        reason="incident resolved",
    )
    assert restored["requires_card_rebind"] is True

    connection = connect_database(term_settings)
    try:
        stored_challenge = connection.execute(
            "SELECT status, revoke_reason FROM dm_activation_challenges "
            "WHERE challenge_id = ?",
            (pending["challenge_id"],),
        ).fetchone()
        assert str(stored_challenge["status"]) == "expired"
        assert str(stored_challenge["revoke_reason"]) == expected_revoke_reason
    finally:
        connection.close()

    with pytest.raises(
        DualMachineServiceError,
        match="activation_challenge_invalid",
    ):
        service.confirm_activation(
            confirmation,
            client_ip="127.0.0.1",
            now_epoch=1_700_001_011,
        )


def test_android_profile_rejects_raw_identifiers(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id="a" * 32,
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    host = _identity()
    android = _identity()
    with pytest.raises(
        DualMachineServiceError,
        match="android_device_profile_invalid",
    ):
        CardActivationService(term_settings).create_challenge(
            {
                "request_id": "b" * 32,
                "pair_id": "c" * 32,
                "protocol_version": 2,
                "card_code": issued.codes[0],
                "host": {
                    "device_code": "HOST-1",
                    "client_version": "17.8.81",
                    "identity_public_key_b64": host[1],
                },
                "android": {
                    "device_code": "ANDROID-1",
                    "client_version": "1.0.0",
                    "identity_public_key_b64": android[1],
                },
                "android_device_profile": {"imei": "forbidden"},
            },
            client_ip="127.0.0.1",
        )


def test_permanent_usage_has_zero_balance_and_never_debits(
    term_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(term_settings).issue_batch(
        request_id="d" * 32,
        product_key="permanent",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    activated, host, android, _ = _activate(
        term_settings,
        issued.codes[0],
        request_seed="e",
        pair_id="f" * 32,
    )
    pair = {
        **activated,
        "host_private": host[0],
        "android_private": android[0],
    }
    service = UsageService(term_settings)
    challenge_command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": "1" * 32,
        "request_nonce": "2" * 32,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
    }
    challenge_payload = usage_start_challenge_payload(challenge_command)
    challenge = service.create_start_challenge(
        {
            **challenge_command,
            "host_signature_b64": _sign(host[0], challenge_payload),
            "android_signature_b64": _sign(android[0], challenge_payload),
        },
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    start_command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": "3" * 32,
        "request_nonce": "4" * 32,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "host_frames_total": 0,
        "android_frames_total": 0,
        "start_challenge_id": challenge["challenge_id"],
        "start_challenge_token": challenge["challenge_token"],
    }
    start_payload = usage_start_payload(start_command)
    started = service.start_usage(
        {
            **start_command,
            "host_signature_b64": _sign(host[0], start_payload),
            "android_signature_b64": _sign(android[0], start_payload),
        },
        now_epoch=1_700_000_011,
    )
    heartbeat_command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "session_id": started["session_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": "5" * 32,
        "request_nonce": "6" * 32,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "sequence": 1,
        "host_frames_total": 1,
        "android_frames_total": 1,
        "previous_lease": started["usage_lease"],
    }
    heartbeat_payload = usage_heartbeat_payload(heartbeat_command)
    renewed = service.heartbeat_usage(
        {
            **heartbeat_command,
            "host_signature_b64": _sign(host[0], heartbeat_payload),
            "android_signature_b64": _sign(android[0], heartbeat_payload),
        },
        now_epoch=1_700_000_014,
    )

    assert issued.duration_seconds == 0
    assert activated["credited_seconds"] == 0
    assert activated["remaining_seconds"] == 0
    assert started["authorization_kind"] == "permanent"
    assert started["is_permanent"] is True
    assert started["charged_seconds"] == 0
    assert started["billing_started"] is True
    assert renewed["charged_seconds"] == 0
    assert renewed["remaining_seconds"] == 0
    connection = connect_database(term_settings)
    try:
        entitlement = connection.execute(
            "SELECT remaining_seconds, total_credited_seconds, "
            "total_consumed_seconds FROM dm_entitlements",
        ).fetchone()
        assert tuple(entitlement) == (0, 0, 0)
        assert connection.execute(
            "SELECT credited_seconds FROM dm_license_activations",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
    finally:
        connection.close()
