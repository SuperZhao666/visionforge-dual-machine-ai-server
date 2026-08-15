from __future__ import annotations

import base64
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dual_machine_service.admin_service import DualMachineAdminService
from dual_machine_service import usage_service as usage_service_module
from dual_machine_service.card_service import (
    CardActivationService,
    CardIssuanceService,
)
from dual_machine_service.contracts import (
    entitlement_status_payload,
    usage_heartbeat_payload,
    usage_start_cancel_payload,
    usage_start_challenge_payload,
    usage_start_payload,
    usage_stop_payload,
)
from dual_machine_service.database import (
    connect_database,
    initialize_database,
)
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.identity import canonical_base64, parse_p256_identity
from dual_machine_service.settings import DualMachineSettings
from dual_machine_service.usage_service import UsageService


CHANNEL_BINDING_SHA256 = "f" * 64


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
        "card_code": issued.codes[0],
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


def _signed_start(
    pair: dict,
    challenge: dict,
    *,
    request_id: str,
    request_nonce: str,
    host_frames_total: int = 10,
    android_frames_total: int = 9,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "host_frames_total": host_frames_total,
        "android_frames_total": android_frames_total,
        "start_challenge_id": challenge["challenge_id"],
        "start_challenge_token": challenge["challenge_token"],
    }
    payload = usage_start_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _signed_heartbeat(
    pair: dict,
    started: dict,
    *,
    request_id: str,
    request_nonce: str,
    sequence: int,
    host_frames_total: int,
    android_frames_total: int,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "session_id": started["session_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "sequence": sequence,
        "host_frames_total": host_frames_total,
        "android_frames_total": android_frames_total,
        "previous_lease": started["usage_lease"],
    }
    payload = usage_heartbeat_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _signed_start_challenge(
    pair: dict,
    *,
    request_id: str,
    request_nonce: str,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
    }
    payload = usage_start_challenge_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _signed_start_cancel(
    pair: dict,
    *,
    start_request_id: str,
    request_id: str,
    request_nonce: str,
    channel_binding_sha256: str = CHANNEL_BINDING_SHA256,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "start_request_id": start_request_id,
        "channel_binding_sha256": channel_binding_sha256,
    }
    payload = usage_start_cancel_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _start_challenge(
    service: UsageService,
    pair: dict,
    *,
    request_id: str,
    request_nonce: str,
    now_epoch: int,
) -> dict:
    return service.create_start_challenge(
        _signed_start_challenge(
            pair,
            request_id=request_id,
            request_nonce=request_nonce,
        ),
        client_ip="127.0.0.1",
        now_epoch=now_epoch,
    )


def _rebind_pair(
    pair: dict,
    *,
    challenge_request_id: str,
    replacement_pair_id: str,
    now_epoch: int,
    reason: str,
) -> dict:
    admin = DualMachineAdminService(pair["settings"])
    connection = connect_database(pair["settings"])
    try:
        current_binding = connection.execute(
            "SELECT binding_id FROM dm_entitlement_device_bindings "
            "WHERE entitlement_id = ? AND is_current = 1",
            (pair["entitlement_id"],),
        ).fetchone()
        assert current_binding is not None
        binding_id = str(current_binding["binding_id"])
    finally:
        connection.close()
    admin.unbind_entitlement_device(
        pair["entitlement_id"],
        binding_id,
        reason=reason,
    )

    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation = CardActivationService(pair["settings"])
    suffix = replacement_pair_id[:8].upper()
    challenge = activation.create_challenge(
        {
            "request_id": challenge_request_id,
            "pair_id": replacement_pair_id,
            "protocol_version": 2,
            "card_code": pair["card_code"],
            "host": {
                "device_code": f"HOST-{suffix}",
                "client_version": "17.8.81",
                "identity_public_key_b64": host_public,
            },
            "android": {
                "device_code": f"ANDROID-{suffix}",
                "client_version": "1.0.0",
                "identity_public_key_b64": android_public,
            },
        },
        client_ip="127.0.0.1",
        now_epoch=now_epoch,
    )
    proof = base64.b64decode(
        challenge["proof_payload_b64"],
        validate=True,
    )
    rebound = activation.confirm_activation(
        {
            "challenge_id": challenge["challenge_id"],
            "challenge_token": challenge["challenge_token"],
            "host_signature_b64": _sign(host_private, proof),
            "android_signature_b64": _sign(android_private, proof),
        },
        client_ip="127.0.0.1",
        now_epoch=now_epoch + 1,
    )
    assert rebound["binding_updated"] is True
    return {
        **pair,
        "host_private": host_private,
        "android_private": android_private,
        "pair_id": rebound["pair_id"],
        "revocation_version": rebound["revocation_version"],
    }


def _migrate_v5_start_cancellation(
    pair: dict,
    command: dict,
    *,
    created_at_epoch: int,
) -> None:
    request_hash = hashlib.sha256(
        usage_start_cancel_payload(command),
    ).hexdigest()
    connection = connect_database(pair["settings"])
    try:
        connection.execute("DROP TABLE dm_usage_start_cancellations")
        connection.execute(
            "CREATE TABLE dm_usage_start_cancellations ("
            "entitlement_id TEXT NOT NULL REFERENCES "
            "dm_entitlements(entitlement_id), "
            "start_request_id TEXT NOT NULL, "
            "cancel_request_id TEXT NOT NULL, "
            "cancel_request_hash TEXT NOT NULL, "
            "channel_binding_sha256 TEXT NOT NULL, "
            "created_at_epoch INTEGER NOT NULL, "
            "PRIMARY KEY(entitlement_id, start_request_id), "
            "UNIQUE(entitlement_id, cancel_request_id))",
        )
        connection.execute(
            "INSERT INTO dm_usage_start_cancellations "
            "(entitlement_id, start_request_id, cancel_request_id, "
            "cancel_request_hash, channel_binding_sha256, "
            "created_at_epoch) VALUES (?, ?, ?, ?, ?, ?)",
            (
                command["entitlement_id"],
                command["start_request_id"],
                command["request_id"],
                request_hash,
                command["channel_binding_sha256"],
                int(created_at_epoch),
            ),
        )
    finally:
        connection.close()
    initialize_database(pair["settings"])


def _signed_stop(
    pair: dict,
    session: dict,
    *,
    request_id: str,
    request_nonce: str,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "session_id": session["session_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
        "request_id": request_id,
        "request_nonce": request_nonce,
        "channel_binding_sha256": CHANNEL_BINDING_SHA256,
        "previous_lease": session["usage_lease"],
    }
    payload = usage_stop_payload(command)
    return {
        **command,
        "host_signature_b64": _sign(pair["host_private"], payload),
        "android_signature_b64": _sign(
            pair["android_private"],
            payload,
        ),
    }


def _signed_status(
    pair: dict,
    *,
    request_nonce: str,
) -> dict:
    command = {
        "entitlement_id": pair["entitlement_id"],
        "pair_id": pair["pair_id"],
        "protocol_version": 2,
        "revocation_version": pair["revocation_version"],
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


def test_formal_start_and_renewal_charge_once_with_contiguous_leases(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="4" * 32,
        request_nonce="5" * 32,
        now_epoch=1_700_000_099,
    )
    start_command = _signed_start(
        activated_pair,
        challenge,
        request_id="6" * 32,
        request_nonce="7" * 32,
        # Pre-use baselines may be zero: the paid active lease must exist
        # before either data plane is allowed to move a frame.
        host_frames_total=0,
        android_frames_total=0,
    )
    started = service.start_usage(
        start_command,
        now_epoch=1_700_000_100,
    )
    repeated_start = service.start_usage(
        start_command,
        now_epoch=1_700_000_101,
    )
    assert repeated_start == started
    assert started["charged_seconds"] == 5
    assert started["remaining_seconds"] == 86_395
    assert started["sequence"] == 0
    assert started["billing_started"] is True
    assert started["usage_lease_not_before_epoch"] == 1_700_000_100
    assert started["usage_lease_expires_at_epoch"] == 1_700_000_105

    heartbeat_command = _signed_heartbeat(
        activated_pair,
        started,
        request_id="8" * 32,
        request_nonce="9" * 32,
        sequence=1,
        host_frames_total=20,
        android_frames_total=19,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_heartbeat_too_early",
    ):
        service.heartbeat_usage(
            heartbeat_command,
            now_epoch=1_700_000_102,
        )
    heartbeat = service.heartbeat_usage(
        heartbeat_command,
        now_epoch=1_700_000_103,
    )
    repeated = service.heartbeat_usage(
        heartbeat_command,
        now_epoch=1_700_000_104,
    )
    assert heartbeat == repeated
    assert heartbeat["charged_seconds"] == 5
    assert heartbeat["remaining_seconds"] == 86_390
    assert heartbeat["sequence"] == 1
    assert heartbeat["usage_lease_not_before_epoch"] == 1_700_000_105
    assert heartbeat["usage_lease_expires_at_epoch"] == 1_700_000_110

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        entitlement = connection.execute(
            "SELECT remaining_seconds, total_consumed_seconds "
            "FROM dm_entitlements",
        ).fetchone()
        assert dict(entitlement) == {
            "remaining_seconds": 86_390,
            "total_consumed_seconds": 10,
        }
        intervals = connection.execute(
            "SELECT sequence, interval_started_at_epoch, "
            "interval_ended_at_epoch, charged_seconds "
            "FROM dm_usage_ledger ORDER BY sequence",
        ).fetchall()
        assert [tuple(row) for row in intervals] == [
            (0, 1_700_000_100, 1_700_000_105, 5),
            (1, 1_700_000_105, 1_700_000_110, 5),
        ]
    finally:
        connection.close()


def test_start_challenge_is_zero_cost_and_idempotent(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    command = _signed_start_challenge(
        activated_pair,
        request_id="a" * 32,
        request_nonce="b" * 32,
    )
    challenge = service.create_start_challenge(
        command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_099,
    )
    repeated = service.create_start_challenge(
        command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_100,
    )
    assert repeated == challenge
    assert challenge["billing_started"] is False

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_400
    finally:
        connection.close()


def test_entitlement_status_expires_stale_session_without_extra_charge(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="8a" * 16,
        request_nonce="8b" * 16,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id="8c" * 16,
            request_nonce="8d" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    assert started["charged_seconds"] == 5

    status = service.entitlement_status(
        _signed_status(activated_pair, request_nonce="8e" * 16),
        now_epoch=1_700_000_106,
    )

    assert status["usage_session_status"] == ""
    assert status["remaining_seconds"] == 86_395
    connection = connect_database(activated_pair["settings"])
    try:
        session = connection.execute(
            "SELECT status, ended_reason, seconds_consumed "
            "FROM dm_usage_sessions WHERE session_id = ?",
            (started["session_id"],),
        ).fetchone()
        assert dict(session) == {
            "status": "ended",
            "ended_reason": "usage_lease_expired",
            "seconds_consumed": 5,
        }
        ledger = connection.execute(
            "SELECT COUNT(*) AS rows, SUM(charged_seconds) AS charged "
            "FROM dm_usage_ledger WHERE session_id = ?",
            (started["session_id"],),
        ).fetchone()
        assert tuple(ledger) == (1, 5)
    finally:
        connection.close()


def test_expired_session_cannot_be_restarted_for_free(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    first_challenge = _start_challenge(
        service,
        activated_pair,
        request_id="c" * 32,
        request_nonce="d" * 32,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            first_challenge,
            request_id="e" * 32,
            request_nonce="f" * 32,
        ),
        now_epoch=1_700_000_100,
    )
    second_challenge = _start_challenge(
        service,
        activated_pair,
        request_id="1a" * 16,
        request_nonce="1b" * 16,
        now_epoch=1_700_000_106,
    )
    replacement = service.start_usage(
        _signed_start(
            activated_pair,
            second_challenge,
            request_id="1c" * 16,
            request_nonce="1d" * 16,
        ),
        now_epoch=1_700_000_107,
    )
    assert replacement["session_id"] != started["session_id"]
    assert replacement["remaining_seconds"] == 86_390

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_390
        stale = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions "
            "WHERE session_id = ?",
            (started["session_id"],),
        ).fetchone()
        assert dict(stale) == {
            "status": "ended",
            "ended_reason": "usage_lease_expired",
        }
    finally:
        connection.close()


def test_missing_frame_progress_ends_session_without_extra_charge(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="2a" * 16,
        request_nonce="2b" * 16,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id="2c" * 16,
            request_nonce="2d" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    heartbeat = _signed_heartbeat(
        activated_pair,
        started,
        request_id="2e" * 16,
        request_nonce="2f" * 16,
        sequence=1,
        host_frames_total=10,
        android_frames_total=9,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_progress_not_confirmed",
    ):
        service.heartbeat_usage(
            heartbeat,
            now_epoch=1_700_000_103,
        )

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_395
        session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchone()
        assert dict(session) == {
            "status": "ended",
            "ended_reason": "usage_progress_not_confirmed",
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_invalid_device_signature_never_starts_or_charges(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="3a" * 16,
        request_nonce="3b" * 16,
        now_epoch=1_700_000_099,
    )
    command = _signed_start(
        activated_pair,
        challenge,
        request_id="3c" * 16,
        request_nonce="3d" * 16,
    )
    other_private, _ = _identity()
    command["android_signature_b64"] = _sign(
        other_private,
        usage_start_payload(command),
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.start_usage(command, now_epoch=1_700_000_100)

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_400
    finally:
        connection.close()


def test_start_rechecks_device_signatures_after_acquiring_write_lock(
    activated_pair: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="3e" * 16,
        request_nonce="3f" * 16,
        now_epoch=1_700_000_099,
    )
    command = _signed_start(
        activated_pair,
        challenge,
        request_id="4e" * 16,
        request_nonce="4f" * 16,
    )
    first_verification_finished = threading.Event()
    identity_keys_changed = threading.Event()
    verification_calls = {"count": 0}
    verification_calls_lock = threading.Lock()
    original_verify = usage_service_module._verify_entitlement_command

    def gated_verify(
        entitlement: dict | None,
        normalized: dict,
        signed_payload: bytes,
    ) -> None:
        with verification_calls_lock:
            verification_calls["count"] += 1
            call_number = verification_calls["count"]
        original_verify(entitlement, normalized, signed_payload)
        if call_number == 1:
            first_verification_finished.set()
            if not identity_keys_changed.wait(timeout=10):
                raise AssertionError("identity key swap did not finish")

    monkeypatch.setattr(
        usage_service_module,
        "_verify_entitlement_command",
        gated_verify,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            service.start_usage,
            command,
            now_epoch=1_700_000_100,
        )
        try:
            assert first_verification_finished.wait(timeout=10)
            _, replacement_host_public = _identity()
            _, replacement_android_public = _identity()
            replacement_host = parse_p256_identity(
                replacement_host_public,
            )
            replacement_android = parse_p256_identity(
                replacement_android_public,
            )
            connection = connect_database(activated_pair["settings"])
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE dm_entitlements SET "
                    "host_identity_public_key_b64 = ?, "
                    "android_identity_public_key_b64 = ? "
                    "WHERE entitlement_id = ?",
                    (
                        replacement_host.public_key_b64,
                        replacement_android.public_key_b64,
                        activated_pair["entitlement_id"],
                    ),
                )
                updated = connection.execute(
                    "UPDATE dm_entitlement_device_bindings SET "
                    "host_identity_public_key_b64 = ?, host_key_sha256 = ?, "
                    "android_identity_public_key_b64 = ?, "
                    "android_key_sha256 = ? "
                    "WHERE entitlement_id = ? AND is_current = 1",
                    (
                        replacement_host.public_key_b64,
                        replacement_host.fingerprint_sha256,
                        replacement_android.public_key_b64,
                        replacement_android.fingerprint_sha256,
                        activated_pair["entitlement_id"],
                    ),
                )
                assert int(updated.rowcount or 0) == 1
                connection.commit()
            finally:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
        finally:
            identity_keys_changed.set()

        with pytest.raises(
            DualMachineServiceError,
            match="usage_device_proof_invalid",
        ):
            future.result(timeout=15)

    assert verification_calls["count"] == 2
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
        assert tuple(connection.execute(
            "SELECT remaining_seconds, total_consumed_seconds, "
            "pair_id, revocation_version FROM dm_entitlements",
        ).fetchone()) == (
            86_400,
            0,
            activated_pair["pair_id"],
            activated_pair["revocation_version"],
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start'",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT status FROM dm_usage_start_challenges "
            "WHERE challenge_id = ?",
            (challenge["challenge_id"],),
        ).fetchone()[0] == "issued"
    finally:
        connection.close()


def test_entitlement_revocation_stops_active_usage_without_extra_charge(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="4a" * 16,
        request_nonce="4b" * 16,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id="4c" * 16,
            request_nonce="4d" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    revoked = DualMachineAdminService(
        activated_pair["settings"],
    ).revoke_entitlement(
        activated_pair["entitlement_id"],
        reason="security incident",
    )
    assert revoked["status"] == "revoked"
    assert revoked["revocation_version"] == 2

    heartbeat = _signed_heartbeat(
        activated_pair,
        started,
        request_id="2c" * 16,
        request_nonce="2d" * 16,
        sequence=1,
        host_frames_total=20,
        android_frames_total=19,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_entitlement_invalid",
    ):
        service.heartbeat_usage(
            heartbeat,
            now_epoch=1_700_000_105,
        )

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_395
        assert connection.execute(
            "SELECT status FROM dm_usage_sessions",
        ).fetchone()[0] == "revoked"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_final_partial_segment_is_paid_and_remains_valid(
    activated_pair: dict,
) -> None:
    connection = connect_database(activated_pair["settings"])
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 3, "
            "total_consumed_seconds = 86397",
        )
    finally:
        connection.close()

    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="5a" * 16,
        request_nonce="5b" * 16,
        now_epoch=1_700_000_099,
    )
    command = _signed_start(
        activated_pair,
        challenge,
        request_id="5c" * 16,
        request_nonce="5d" * 16,
    )
    started = service.start_usage(command, now_epoch=1_700_000_100)
    repeated = service.start_usage(command, now_epoch=1_700_000_101)
    claims = service.token_codec.verify_usage_lease(
        started["usage_lease"],
        now_epoch=1_700_000_101,
    )

    assert repeated == started
    assert started["charged_seconds"] == 3
    assert started["remaining_seconds"] == 0
    assert started["usage_lease_ttl_seconds"] == 3
    assert started["usage_lease_expires_at_epoch"] == 1_700_000_103
    assert claims["remaining"] == 0

    connection = connect_database(activated_pair["settings"])
    try:
        entitlement = connection.execute(
            "SELECT status, remaining_seconds, total_consumed_seconds "
            "FROM dm_entitlements",
        ).fetchone()
        assert tuple(entitlement) == ("exhausted", 0, 86_400)
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_concurrent_identical_renewal_is_charged_exactly_once(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="6a" * 16,
        request_nonce="6b" * 16,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id="6c" * 16,
            request_nonce="6d" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    command = _signed_heartbeat(
        activated_pair,
        started,
        request_id="6e" * 16,
        request_nonce="6f" * 16,
        sequence=1,
        host_frames_total=20,
        android_frames_total=19,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.heartbeat_usage,
                command,
                now_epoch=1_700_000_103,
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=15) for future in futures]

    assert results[0] == results[1]
    assert results[0]["charged_seconds"] == 5
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_390
    finally:
        connection.close()


def test_stop_adds_no_charge_and_does_not_refund_current_segment(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="7a" * 16,
        request_nonce="7b" * 16,
        now_epoch=1_700_000_099,
    )
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id="7c" * 16,
            request_nonce="7d" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    command = _signed_stop(
        activated_pair,
        started,
        request_id="7e" * 16,
        request_nonce="7f" * 16,
    )
    stopped = service.stop_usage(command, now_epoch=1_700_000_102)
    repeated = service.stop_usage(command, now_epoch=1_700_000_103)

    assert repeated == stopped
    assert stopped["charged_seconds"] == 0
    assert stopped["remaining_seconds"] == 86_395
    assert stopped["status"] == "ended"
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT ended_reason FROM dm_usage_sessions",
        ).fetchone()[0] == "user_stopped"
    finally:
        connection.close()


def test_cancel_before_start_is_idempotent_and_blocks_billing(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="81" * 16,
        request_nonce="82" * 16,
        now_epoch=1_700_000_099,
    )
    start_request_id = "83" * 16
    start_command = _signed_start(
        activated_pair,
        challenge,
        request_id=start_request_id,
        request_nonce="84" * 16,
    )
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="85" * 16,
        request_nonce="86" * 16,
    )

    cancelled = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_100,
    )
    repeated = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_101,
    )

    assert repeated == cancelled
    assert cancelled == {
        "ok": True,
        "start_request_id": start_request_id,
        "session_id": "",
        "session_status": "not_started",
        "remaining_seconds": 86_400,
        "charged_seconds": 0,
        "billing_started": False,
        "authorization_kind": "day",
        "is_permanent": False,
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancelled",
    ):
        service.start_usage(start_command, now_epoch=1_700_000_102)

    conflicting = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="87" * 16,
        request_nonce="88" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(conflicting, now_epoch=1_700_000_103)

    replayed_nonce = _signed_start_cancel(
        activated_pair,
        start_request_id="89" * 16,
        request_id="8a" * 16,
        request_nonce="86" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_request_replayed",
    ):
        service.cancel_start_usage(replayed_nonce, now_epoch=1_700_000_104)

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_400
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_cancel_after_start_ends_session_and_blocks_start_retry(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="91" * 16,
        request_nonce="92" * 16,
        now_epoch=1_700_000_099,
    )
    start_request_id = "93" * 16
    start_command = _signed_start(
        activated_pair,
        challenge,
        request_id=start_request_id,
        request_nonce="94" * 16,
    )
    started = service.start_usage(
        start_command,
        now_epoch=1_700_000_100,
    )
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="95" * 16,
        request_nonce="96" * 16,
    )

    cancelled = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_101,
    )
    repeated = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_102,
    )

    assert repeated == cancelled
    assert cancelled["session_id"] == started["session_id"]
    assert cancelled["session_status"] == "ended"
    assert cancelled["remaining_seconds"] == 86_395
    assert cancelled["charged_seconds"] == 0
    assert cancelled["billing_started"] is True
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancelled",
    ):
        service.start_usage(start_command, now_epoch=1_700_000_103)

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert tuple(connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchone()) == ("ended", "client_start_cancelled")
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_395
    finally:
        connection.close()


def test_start_cancel_requires_both_signatures_before_consuming_nonce(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    command = _signed_start_cancel(
        activated_pair,
        start_request_id="9a" * 16,
        request_id="9b" * 16,
        request_nonce="9c" * 16,
    )
    tampered = {
        **command,
        "android_signature_b64": command["host_signature_b64"],
    }

    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(tampered, now_epoch=1_700_000_100)

    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 0
    finally:
        connection.close()

    cancelled = service.cancel_start_usage(
        command,
        now_epoch=1_700_000_101,
    )
    assert cancelled["session_status"] == "not_started"


def test_exact_start_cancel_replays_snapshot_after_revocation(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="b1" * 16,
        request_nonce="b2" * 16,
        now_epoch=1_700_000_099,
    )
    start_request_id = "b3" * 16
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id=start_request_id,
            request_nonce="b4" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="b5" * 16,
        request_nonce="b6" * 16,
    )
    first_response = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_101,
    )

    revoked = DualMachineAdminService(
        activated_pair["settings"],
    ).revoke_entitlement(
        activated_pair["entitlement_id"],
        reason="response lost before client observed cancellation",
    )
    assert revoked["revocation_version"] == 2
    replayed = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_102,
    )

    assert replayed == first_response
    assert list(replayed) == list(first_response)
    assert replayed["session_id"] == started["session_id"]
    assert replayed["session_status"] == "ended"
    assert replayed["remaining_seconds"] == 86_395

    forged = {
        **cancel_command,
        "android_signature_b64": cancel_command["host_signature_b64"],
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(forged, now_epoch=1_700_000_103)

    connection = connect_database(activated_pair["settings"])
    try:
        cancellation = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert len(cancellation["authenticated_request_hash"]) == 64
        assert cancellation["response_json"]
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions "
            "WHERE status = 'active'",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_exact_start_cancel_replays_after_completed_device_rebind(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id="c1" * 16,
        request_id="c2" * 16,
        request_nonce="c3" * 16,
    )
    first_response = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_100,
    )
    replacement_pair = _rebind_pair(
        activated_pair,
        challenge_request_id="c4" * 16,
        replacement_pair_id="c5" * 16,
        now_epoch=1_700_000_101,
        reason="approved replacement after lost cancel response",
    )
    assert replacement_pair["pair_id"] == "c5" * 16

    replayed = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_103,
    )
    assert replayed == first_response
    assert replayed["session_status"] == "not_started"
    assert replayed["session_id"] == ""

    forged = {
        **cancel_command,
        "host_signature_b64": cancel_command["android_signature_b64"],
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(forged, now_epoch=1_700_000_104)


def test_migrated_v5_cancel_exact_retry_backfills_stable_replay(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    command = _signed_start_cancel(
        activated_pair,
        start_request_id="81" * 16,
        request_id="82" * 16,
        request_nonce="83" * 16,
    )
    _migrate_v5_start_cancellation(
        activated_pair,
        command,
        created_at_epoch=1_700_000_100,
    )

    forged = {
        **command,
        "android_signature_b64": command["host_signature_b64"],
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(forged, now_epoch=1_700_000_101)

    wrong_nonce = _signed_start_cancel(
        activated_pair,
        start_request_id=command["start_request_id"],
        request_id=command["request_id"],
        request_nonce="84" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_nonce,
            now_epoch=1_700_000_102,
        )

    wrong_channel = _signed_start_cancel(
        activated_pair,
        start_request_id=command["start_request_id"],
        request_id=command["request_id"],
        request_nonce=command["request_nonce"],
        channel_binding_sha256="e" * 64,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_channel,
            now_epoch=1_700_000_103,
        )

    wrong_start_id = _signed_start_cancel(
        activated_pair,
        start_request_id="85" * 16,
        request_id=command["request_id"],
        request_nonce=command["request_nonce"],
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_start_id,
            now_epoch=1_700_000_104,
        )

    connection = connect_database(activated_pair["settings"])
    try:
        legacy = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert tuple(legacy) == ("", "")
    finally:
        connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.cancel_start_usage,
                command,
                now_epoch=1_700_000_105,
            )
            for _ in range(2)
        ]
        first, repeated = [
            future.result(timeout=15)
            for future in futures
        ]
    assert repeated == first
    assert first["session_status"] == "not_started"
    assert first["session_id"] == ""
    assert first["remaining_seconds"] == 86_400

    resigned = _signed_start_cancel(
        activated_pair,
        start_request_id=command["start_request_id"],
        request_id=command["request_id"],
        request_nonce=command["request_nonce"],
    )
    assert (
        resigned["host_signature_b64"] != command["host_signature_b64"]
        or resigned["android_signature_b64"]
        != command["android_signature_b64"]
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(resigned, now_epoch=1_700_000_107)
    assert service.cancel_start_usage(
        command,
        now_epoch=1_700_000_108,
    ) == first

    connection = connect_database(activated_pair["settings"])
    try:
        upgraded = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert len(upgraded["authenticated_request_hash"]) == 64
        assert upgraded["response_json"]
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_audit_events "
            "WHERE event_type = "
            "'usage_start_cancellation_replay_upgraded'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_delayed_old_pair_cancel_without_session_uses_start_challenge(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    old_start_request_id = "41" * 16
    old_challenge = _start_challenge(
        service,
        activated_pair,
        request_id=old_start_request_id,
        request_nonce="42" * 16,
        now_epoch=1_700_000_099,
    )
    old_cancel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id="43" * 16,
        request_nonce="44" * 16,
    )

    replacement_pair = _rebind_pair(
        activated_pair,
        challenge_request_id="45" * 16,
        replacement_pair_id="46" * 16,
        now_epoch=1_700_000_101,
        reason="replace pair before old start or cancel arrived",
    )
    new_challenge_request_id = "47" * 16
    new_challenge = _start_challenge(
        service,
        replacement_pair,
        request_id=new_challenge_request_id,
        request_nonce="48" * 16,
        now_epoch=1_700_000_103,
    )
    new_started = service.start_usage(
        _signed_start(
            replacement_pair,
            new_challenge,
            request_id="49" * 16,
            request_nonce="4a" * 16,
        ),
        now_epoch=1_700_000_104,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.cancel_start_usage,
                old_cancel,
                now_epoch=1_700_000_105,
            )
            for _ in range(2)
        ]
        responses = [future.result(timeout=15) for future in futures]

    assert responses[0] == responses[1]
    assert responses[0]["session_id"] == ""
    assert responses[0]["session_status"] == "not_started"
    assert responses[0]["remaining_seconds"] == 86_395
    assert responses[0]["billing_started"] is False
    assert responses[0]["authorization_kind"] == "day"
    assert responses[0]["is_permanent"] is False

    forged = {
        **old_cancel,
        "android_signature_b64": old_cancel["host_signature_b64"],
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(forged, now_epoch=1_700_000_106)

    wrong_channel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id="4b" * 16,
        request_nonce="4c" * 16,
        channel_binding_sha256="e" * 64,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_channel,
            now_epoch=1_700_000_107,
        )

    wrong_start_id = _signed_start_cancel(
        activated_pair,
        start_request_id="4d" * 16,
        request_id="4e" * 16,
        request_nonce="4f" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_start_id,
            now_epoch=1_700_000_108,
        )

    wrong_pair_challenge = _signed_start_cancel(
        activated_pair,
        start_request_id=new_challenge_request_id,
        request_id="50" * 16,
        request_nonce="51" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_pair_challenge,
            now_epoch=1_700_000_109,
        )

    connection = connect_database(activated_pair["settings"])
    try:
        new_session = connection.execute(
            "SELECT status, ended_reason, last_heartbeat_sequence "
            "FROM dm_usage_sessions WHERE session_id = ?",
            (new_started["session_id"],),
        ).fetchone()
        assert tuple(new_session) == ("active", "", 0)
        assert connection.execute(
            "SELECT status FROM dm_usage_start_challenges "
            "WHERE challenge_id = ?",
            (old_challenge["challenge_id"],),
        ).fetchone()[0] == "expired"
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_395
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_delayed_old_pair_cancel_after_rebind_is_target_scoped(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    old_challenge = _start_challenge(
        service,
        activated_pair,
        request_id="61" * 16,
        request_nonce="62" * 16,
        now_epoch=1_700_000_099,
    )
    old_start_request_id = "63" * 16
    old_started = service.start_usage(
        _signed_start(
            activated_pair,
            old_challenge,
            request_id=old_start_request_id,
            request_nonce="64" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    old_cancel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id="65" * 16,
        request_nonce="66" * 16,
    )

    replacement_pair = _rebind_pair(
        activated_pair,
        challenge_request_id="67" * 16,
        replacement_pair_id="68" * 16,
        now_epoch=1_700_000_101,
        reason="replace pair before delayed old cancellation arrived",
    )
    new_challenge = _start_challenge(
        service,
        replacement_pair,
        request_id="69" * 16,
        request_nonce="6a" * 16,
        now_epoch=1_700_000_103,
    )
    new_start_request_id = "6b" * 16
    new_started = service.start_usage(
        _signed_start(
            replacement_pair,
            new_challenge,
            request_id=new_start_request_id,
            request_nonce="6c" * 16,
        ),
        now_epoch=1_700_000_104,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.cancel_start_usage,
                old_cancel,
                now_epoch=1_700_000_105,
            )
            for _ in range(2)
        ]
        responses = [future.result(timeout=15) for future in futures]

    assert responses[0] == responses[1]
    assert responses[0]["session_id"] == old_started["session_id"]
    assert responses[0]["session_status"] == "ended"
    assert responses[0]["remaining_seconds"] == 86_390
    assert responses[0]["billing_started"] is True

    forged = {
        **old_cancel,
        "android_signature_b64": old_cancel["host_signature_b64"],
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(forged, now_epoch=1_700_000_106)

    wrong_channel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id="6d" * 16,
        request_nonce="6e" * 16,
        channel_binding_sha256="e" * 64,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_channel,
            now_epoch=1_700_000_107,
        )

    wrong_target = _signed_start_cancel(
        activated_pair,
        start_request_id=new_start_request_id,
        request_id="6f" * 16,
        request_nonce="70" * 16,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_target,
            now_epoch=1_700_000_108,
        )

    connection = connect_database(activated_pair["settings"])
    try:
        old_session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions "
            "WHERE session_id = ?",
            (old_started["session_id"],),
        ).fetchone()
        new_session = connection.execute(
            "SELECT status, ended_reason, last_heartbeat_sequence "
            "FROM dm_usage_sessions WHERE session_id = ?",
            (new_started["session_id"],),
        ).fetchone()
        assert tuple(old_session) == (
            "ended",
            "admin_device_unbound",
        )
        assert tuple(new_session) == ("active", "", 0)
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_390
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_migrated_v5_cancel_replays_through_historical_pair(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    old_challenge = _start_challenge(
        service,
        activated_pair,
        request_id="91" * 16,
        request_nonce="92" * 16,
        now_epoch=1_700_000_099,
    )
    old_start_request_id = "93" * 16
    old_started = service.start_usage(
        _signed_start(
            activated_pair,
            old_challenge,
            request_id=old_start_request_id,
            request_nonce="94" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    old_cancel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id="95" * 16,
        request_nonce="96" * 16,
    )
    connection = connect_database(activated_pair["settings"])
    try:
        connection.execute(
            "UPDATE dm_usage_sessions SET status = 'ended', "
            "ended_at_epoch = ?, ended_reason = 'client_start_cancelled' "
            "WHERE session_id = ?",
            (1_700_000_101, old_started["session_id"]),
        )
    finally:
        connection.close()
    _migrate_v5_start_cancellation(
        activated_pair,
        old_cancel,
        created_at_epoch=1_700_000_101,
    )

    replacement_pair = _rebind_pair(
        activated_pair,
        challenge_request_id="97" * 16,
        replacement_pair_id="98" * 16,
        now_epoch=1_700_000_102,
        reason="replace pair before migrated cancel retry",
    )
    new_challenge = _start_challenge(
        service,
        replacement_pair,
        request_id="99" * 16,
        request_nonce="9a" * 16,
        now_epoch=1_700_000_104,
    )
    new_started = service.start_usage(
        _signed_start(
            replacement_pair,
            new_challenge,
            request_id="9b" * 16,
            request_nonce="9c" * 16,
        ),
        now_epoch=1_700_000_105,
    )

    signed_payload = usage_start_cancel_payload(old_cancel)
    new_pair_signatures = {
        **old_cancel,
        "host_signature_b64": _sign(
            replacement_pair["host_private"],
            signed_payload,
        ),
        "android_signature_b64": _sign(
            replacement_pair["android_private"],
            signed_payload,
        ),
    }
    with pytest.raises(
        DualMachineServiceError,
        match="usage_device_proof_invalid",
    ):
        service.cancel_start_usage(
            new_pair_signatures,
            now_epoch=1_700_000_106,
        )

    wrong_channel = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id=old_cancel["request_id"],
        request_nonce=old_cancel["request_nonce"],
        channel_binding_sha256="e" * 64,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(
            wrong_channel,
            now_epoch=1_700_000_107,
        )

    first = service.cancel_start_usage(
        old_cancel,
        now_epoch=1_700_000_108,
    )
    assert first["session_id"] == old_started["session_id"]
    assert first["session_status"] == "ended"
    assert first["remaining_seconds"] == 86_390

    resigned = _signed_start_cancel(
        activated_pair,
        start_request_id=old_start_request_id,
        request_id=old_cancel["request_id"],
        request_nonce=old_cancel["request_nonce"],
    )
    with pytest.raises(
        DualMachineServiceError,
        match="usage_start_cancel_request_conflict",
    ):
        service.cancel_start_usage(resigned, now_epoch=1_700_000_109)
    assert service.cancel_start_usage(
        old_cancel,
        now_epoch=1_700_000_110,
    ) == first

    connection = connect_database(activated_pair["settings"])
    try:
        old_session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions "
            "WHERE session_id = ?",
            (old_started["session_id"],),
        ).fetchone()
        new_session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions "
            "WHERE session_id = ?",
            (new_started["session_id"],),
        ).fetchone()
        replay = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert tuple(old_session) == (
            "ended",
            "client_start_cancelled",
        )
        assert tuple(new_session) == ("active", "")
        assert len(replay["authenticated_request_hash"]) == 64
        assert replay["response_json"]
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0] == 86_390
    finally:
        connection.close()


def test_migrated_v5_not_started_cancel_uses_historical_challenge(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    start_request_id = "a1" * 16
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id=start_request_id,
        request_nonce="a2" * 16,
        now_epoch=1_700_000_099,
    )
    old_cancel = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="a3" * 16,
        request_nonce="a4" * 16,
    )
    _migrate_v5_start_cancellation(
        activated_pair,
        old_cancel,
        created_at_epoch=1_700_000_100,
    )
    _rebind_pair(
        activated_pair,
        challenge_request_id="a5" * 16,
        replacement_pair_id="a6" * 16,
        now_epoch=1_700_000_101,
        reason="replace pair before migrated not-started retry",
    )

    response = service.cancel_start_usage(
        old_cancel,
        now_epoch=1_700_000_103,
    )
    assert response["session_status"] == "not_started"
    assert response["session_id"] == ""
    assert response["remaining_seconds"] == 86_400
    assert service.cancel_start_usage(
        old_cancel,
        now_epoch=1_700_000_104,
    ) == response

    connection = connect_database(activated_pair["settings"])
    try:
        stored_challenge = connection.execute(
            "SELECT status FROM dm_usage_start_challenges "
            "WHERE challenge_id = ?",
            (challenge["challenge_id"],),
        ).fetchone()
        replay = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert stored_challenge["status"] == "expired"
        assert len(replay["authenticated_request_hash"]) == 64
        assert replay["response_json"]
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions",
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_revocation_before_first_cancel_still_reaches_terminal_response(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="d1" * 16,
        request_nonce="d2" * 16,
        now_epoch=1_700_000_099,
    )
    start_request_id = "d3" * 16
    started = service.start_usage(
        _signed_start(
            activated_pair,
            challenge,
            request_id=start_request_id,
            request_nonce="d4" * 16,
        ),
        now_epoch=1_700_000_100,
    )
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="d5" * 16,
        request_nonce="d6" * 16,
    )
    DualMachineAdminService(
        activated_pair["settings"],
    ).revoke_entitlement(
        activated_pair["entitlement_id"],
        reason="revoked before delayed cancel arrived",
    )

    cancelled = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_101,
    )
    repeated = service.cancel_start_usage(
        cancel_command,
        now_epoch=1_700_000_102,
    )

    assert repeated == cancelled
    assert cancelled["session_id"] == started["session_id"]
    assert cancelled["session_status"] == "revoked"
    assert cancelled["billing_started"] is True
    assert cancelled["remaining_seconds"] == 86_395
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_sessions "
            "WHERE status = 'active'",
        ).fetchone()[0] == 0
        assert tuple(connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchone()) == ("revoked", "entitlement_revoked")
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_concurrent_exact_start_cancels_share_one_stable_tombstone(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id="e1" * 16,
        request_id="e2" * 16,
        request_nonce="e3" * 16,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.cancel_start_usage,
                cancel_command,
                now_epoch=1_700_000_100,
            )
            for _ in range(2)
        ]
        responses = [future.result(timeout=15) for future in futures]

    assert responses[0] == responses[1]
    assert responses[0]["session_status"] == "not_started"
    connection = connect_database(activated_pair["settings"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_auth_nonces "
            "WHERE scope = 'usage_start_cancel'",
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_concurrent_start_and_cancel_never_leave_an_active_session(
    activated_pair: dict,
) -> None:
    service = UsageService(activated_pair["settings"])
    challenge = _start_challenge(
        service,
        activated_pair,
        request_id="a1" * 16,
        request_nonce="a2" * 16,
        now_epoch=1_700_000_099,
    )
    start_request_id = "a3" * 16
    start_command = _signed_start(
        activated_pair,
        challenge,
        request_id=start_request_id,
        request_nonce="a4" * 16,
    )
    cancel_command = _signed_start_cancel(
        activated_pair,
        start_request_id=start_request_id,
        request_id="a5" * 16,
        request_nonce="a6" * 16,
    )

    def attempt_start() -> tuple[str, dict | str]:
        try:
            return (
                "started",
                service.start_usage(
                    start_command,
                    now_epoch=1_700_000_100,
                ),
            )
        except DualMachineServiceError as exc:
            return "rejected", exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        start_future = executor.submit(attempt_start)
        cancel_future = executor.submit(
            service.cancel_start_usage,
            cancel_command,
            now_epoch=1_700_000_100,
        )
        start_result = start_future.result(timeout=15)
        cancel_result = cancel_future.result(timeout=15)

    assert start_result[0] in {"started", "rejected"}
    if start_result[0] == "rejected":
        assert start_result[1] == "usage_start_cancelled"
    assert cancel_result["session_status"] in {"not_started", "ended"}

    connection = connect_database(activated_pair["settings"])
    try:
        cancellation_count = connection.execute(
            "SELECT COUNT(*) FROM dm_usage_start_cancellations",
        ).fetchone()[0]
        session_rows = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions",
        ).fetchall()
        ledger_count = connection.execute(
            "SELECT COUNT(*) FROM dm_usage_ledger",
        ).fetchone()[0]
        remaining_seconds = connection.execute(
            "SELECT remaining_seconds FROM dm_entitlements",
        ).fetchone()[0]
        assert cancellation_count == 1
        assert all(row["status"] != "active" for row in session_rows)
        if session_rows:
            assert [tuple(row) for row in session_rows] == [
                ("ended", "client_start_cancelled"),
            ]
            assert ledger_count == 1
            assert remaining_seconds == 86_395
        else:
            assert ledger_count == 0
            assert remaining_seconds == 86_400
    finally:
        connection.close()


def test_start_cancellation_schema_upgrade_uses_composite_target_key(
    activated_pair: dict,
) -> None:
    connection = connect_database(activated_pair["settings"])
    try:
        connection.execute("DROP TABLE dm_usage_start_cancellations")
        connection.execute(
            "CREATE TABLE dm_usage_start_cancellations ("
            "entitlement_id TEXT NOT NULL REFERENCES "
            "dm_entitlements(entitlement_id), "
            "start_request_id TEXT NOT NULL, "
            "cancel_request_id TEXT NOT NULL, "
            "cancel_request_hash TEXT NOT NULL, "
            "channel_binding_sha256 TEXT NOT NULL, "
            "created_at_epoch INTEGER NOT NULL, "
            "PRIMARY KEY(entitlement_id, start_request_id), "
            "UNIQUE(entitlement_id, cancel_request_id))",
        )
        connection.execute(
            "INSERT INTO dm_usage_start_cancellations "
            "(entitlement_id, start_request_id, cancel_request_id, "
            "cancel_request_hash, channel_binding_sha256, "
            "created_at_epoch) VALUES (?, ?, ?, ?, ?, ?)",
            (
                activated_pair["entitlement_id"],
                "71" * 16,
                "72" * 16,
                "a" * 64,
                CHANNEL_BINDING_SHA256,
                1_700_000_100,
            ),
        )
    finally:
        connection.close()

    initialize_database(activated_pair["settings"])
    connection = connect_database(activated_pair["settings"])
    try:
        columns = connection.execute(
            "PRAGMA table_info(dm_usage_start_cancellations)",
        ).fetchall()
        assert [
            row["name"]
            for row in sorted(columns, key=lambda row: int(row["pk"]))
            if int(row["pk"]) > 0
        ] == ["entitlement_id", "start_request_id"]
        assert {
            row["name"]
            for row in columns
        } >= {
            "cancel_request_id",
            "cancel_request_hash",
            "authenticated_request_hash",
            "response_json",
            "channel_binding_sha256",
            "created_at_epoch",
        }
        migrated = connection.execute(
            "SELECT authenticated_request_hash, response_json "
            "FROM dm_usage_start_cancellations",
        ).fetchone()
        assert tuple(migrated) == ("", "")
        assert connection.execute(
            "SELECT COUNT(*) FROM dm_entitlements",
        ).fetchone()[0] == 1
    finally:
        connection.close()
