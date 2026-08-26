"""One-card-one-device binding, replay, and concurrency contracts."""
from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier
from typing import Any

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
from dual_machine_service.settings import DualMachineSettings


INITIAL_FINGERPRINT = "a" * 64
SECOND_FINGERPRINT = "b" * 64
THIRD_FINGERPRINT = "c" * 64


@dataclass(frozen=True, slots=True)
class ActivatedCard:
    service: CardActivationService
    code: str
    entitlement_id: str
    host_private_key: ec.EllipticCurvePrivateKey
    host_public_key: str
    android_private_key: ec.EllipticCurvePrivateKey
    android_public_key: str


@pytest.fixture()
def device_lock_settings(tmp_path: Path) -> DualMachineSettings:
    ticket_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    private_path = tmp_path / "dual-ticket-private.pem"
    public_path = tmp_path / "dual-ticket-public.pem"
    private_path.write_bytes(ticket_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(ticket_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    settings = DualMachineSettings(
        database_path=tmp_path / "dual-device-lock.db",
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
    android_device_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    command: dict[str, Any] = {
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
    if android_device_profile is not None:
        command["android_device_profile"] = android_device_profile
    return command


def _confirm_command(
    challenge: dict[str, Any],
    host_private_key: ec.EllipticCurvePrivateKey,
    android_private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, str]:
    payload = base64.b64decode(
        challenge["proof_payload_b64"],
        validate=True,
    )
    return {
        "challenge_id": str(challenge["challenge_id"]),
        "challenge_token": str(challenge["challenge_token"]),
        "host_signature_b64": base64.b64encode(
            host_private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256()),
            ),
        ).decode("ascii"),
        "android_signature_b64": base64.b64encode(
            android_private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256()),
            ),
        ).decode("ascii"),
    }


def _issue_and_activate(
    settings: DualMachineSettings,
    *,
    android_device_profile: dict[str, Any] | None,
) -> ActivatedCard:
    issuance = CardIssuanceService(settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=1,
        channel="device-lock-test",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    service = CardActivationService(settings)
    challenge = service.create_challenge(
        _activation_command(
            issuance.codes[0],
            request_id="2" * 32,
            pair_id="3" * 32,
            host_public_key=host_public,
            android_public_key=android_public,
            android_device_profile=android_device_profile,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_001,
    )
    activated = service.confirm_activation(
        _confirm_command(challenge, host_private, android_private),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )
    return ActivatedCard(
        service=service,
        code=issuance.codes[0],
        entitlement_id=str(activated["entitlement_id"]),
        host_private_key=host_private,
        host_public_key=host_public,
        android_private_key=android_private,
        android_public_key=android_public,
    )


def _database_snapshot(
    settings: DualMachineSettings,
) -> tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...]:
    connection = connect_database(settings)
    try:
        table_names = [
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name LIKE 'dm_%' ORDER BY name",
            ).fetchall()
        ]
        return tuple(
            (
                table_name,
                tuple(
                    tuple(row)
                    for row in connection.execute(
                        f'SELECT * FROM "{table_name}" ORDER BY rowid',
                    ).fetchall()
                ),
            )
            for table_name in table_names
        )
    finally:
        connection.close()


def _current_binding(settings: DualMachineSettings) -> dict[str, Any] | None:
    connection = connect_database(settings)
    try:
        row = connection.execute(
            "SELECT * FROM dm_entitlement_device_bindings "
            "WHERE is_current = 1",
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        connection.close()


def _event_count(settings: DualMachineSettings, event_type: str) -> int:
    connection = connect_database(settings)
    try:
        return int(connection.execute(
            "SELECT COUNT(*) FROM dm_audit_events WHERE event_type = ?",
            (event_type,),
        ).fetchone()[0])
    finally:
        connection.close()


def test_same_device_reinstall_rotates_android_key_after_proof(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    other_android_private, other_android_public = _identity()
    command = _activation_command(
        activated.code,
        request_id="4" * 32,
        pair_id="5" * 32,
        host_public_key=activated.host_public_key,
        android_public_key=other_android_public,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    challenge = activated.service.create_challenge(
        command,
        client_ip="127.0.0.2",
        now_epoch=1_700_000_010,
    )
    rebound = activated.service.confirm_activation(
        _confirm_command(
            challenge,
            activated.host_private_key,
            other_android_private,
        ),
        client_ip="127.0.0.2",
        now_epoch=1_700_000_011,
    )

    current = _current_binding(device_lock_settings)
    assert challenge["activation_mode"] == "bind_device"
    assert rebound["entitlement_id"] == activated.entitlement_id
    assert rebound["binding_updated"] is True
    assert current is not None
    assert current["android_identity_public_key_b64"] == other_android_public
    assert json.loads(current["android_device_profile_json"])[
        "device_fingerprint"
    ] == INITIAL_FINGERPRINT


def test_same_device_fingerprint_cannot_rotate_key_from_another_host(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    _, other_host_public = _identity()
    _, other_android_public = _identity()
    before = _database_snapshot(device_lock_settings)

    with pytest.raises(DualMachineServiceError) as error:
        activated.service.create_challenge(
            _activation_command(
                activated.code,
                request_id="4" * 32,
                pair_id="5" * 32,
                host_public_key=other_host_public,
                android_public_key=other_android_public,
                android_device_profile={
                    "device_fingerprint": INITIAL_FINGERPRINT,
                },
            ),
            client_ip="127.0.0.2",
            now_epoch=1_700_000_010,
        )

    assert error.value.code == "license_bound_to_another_device"
    assert error.value.status_code == 409
    assert _database_snapshot(device_lock_settings) == before


@pytest.mark.parametrize(
    "replacement_profile",
    [{}, {"device_fingerprint": SECOND_FINGERPRINT}],
)
def test_android_key_rotation_requires_same_nonempty_device_fingerprint(
    device_lock_settings: DualMachineSettings,
    replacement_profile: dict[str, str],
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    _, other_android_public = _identity()
    before = _database_snapshot(device_lock_settings)

    with pytest.raises(DualMachineServiceError) as error:
        activated.service.create_challenge(
            _activation_command(
                activated.code,
                request_id="6" * 32,
                pair_id="7" * 32,
                host_public_key=activated.host_public_key,
                android_public_key=other_android_public,
                android_device_profile=replacement_profile,
            ),
            client_ip="127.0.0.2",
            now_epoch=1_700_000_010,
        )

    assert error.value.code == "license_bound_to_another_device"
    assert error.value.status_code == 409
    assert _database_snapshot(device_lock_settings) == before


def test_same_key_and_same_fingerprint_pass_and_replay_is_idempotent(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    command = _activation_command(
        activated.code,
        request_id="6" * 32,
        pair_id="7" * 32,
        host_public_key=activated.host_public_key,
        android_public_key=activated.android_public_key,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )

    challenge = activated.service.create_challenge(
        command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    after_challenge = _database_snapshot(device_lock_settings)
    replayed_challenge = activated.service.create_challenge(
        command,
        client_ip="127.0.0.9",
        now_epoch=1_700_000_011,
    )
    assert replayed_challenge == challenge
    assert _database_snapshot(device_lock_settings) == after_challenge

    confirmation = _confirm_command(
        challenge,
        activated.host_private_key,
        activated.android_private_key,
    )
    rebound = activated.service.confirm_activation(
        confirmation,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_012,
    )
    after_confirmation = _database_snapshot(device_lock_settings)
    replayed_confirmation = activated.service.confirm_activation(
        confirmation,
        client_ip="127.0.0.9",
        now_epoch=1_700_999_999,
    )

    assert challenge["activation_mode"] == "bind_device"
    assert rebound == replayed_confirmation
    assert rebound["entitlement_id"] == activated.entitlement_id
    assert rebound["binding_updated"] is True
    assert _database_snapshot(device_lock_settings) == after_confirmation
    assert _event_count(
        device_lock_settings,
        "entitlement_device_bound",
    ) == 1


def test_same_key_with_different_nonempty_fingerprint_is_rejected(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    command = _activation_command(
        activated.code,
        request_id="8" * 32,
        pair_id="9" * 32,
        host_public_key=activated.host_public_key,
        android_public_key=activated.android_public_key,
        android_device_profile={"device_fingerprint": SECOND_FINGERPRINT},
    )
    before = _database_snapshot(device_lock_settings)

    with pytest.raises(DualMachineServiceError) as error:
        activated.service.create_challenge(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )

    assert error.value.code == "license_bound_to_another_device"
    assert _database_snapshot(device_lock_settings) == before


def test_legacy_empty_profile_accepts_same_key_and_records_fingerprint(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile=None,
    )
    legacy_binding = _current_binding(device_lock_settings)
    assert legacy_binding is not None
    assert legacy_binding["android_device_profile_json"] == "{}"

    challenge = activated.service.create_challenge(
        _activation_command(
            activated.code,
            request_id="a" * 32,
            pair_id="b" * 32,
            host_public_key=activated.host_public_key,
            android_public_key=activated.android_public_key,
            android_device_profile={
                "device_fingerprint": INITIAL_FINGERPRINT,
            },
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    response = activated.service.confirm_activation(
        _confirm_command(
            challenge,
            activated.host_private_key,
            activated.android_private_key,
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_011,
    )

    current = _current_binding(device_lock_settings)
    assert response["entitlement_id"] == activated.entitlement_id
    assert current is not None
    assert json.loads(current["android_device_profile_json"])[
        "device_fingerprint"
    ] == INITIAL_FINGERPRINT


def test_admin_unbind_opens_one_atomic_replacement_slot(
    device_lock_settings: DualMachineSettings,
) -> None:
    activated = _issue_and_activate(
        device_lock_settings,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    old_binding = _current_binding(device_lock_settings)
    assert old_binding is not None
    second_private, second_public = _identity()
    third_private, third_public = _identity()
    candidates = {
        "second": (
            second_private,
            second_public,
            SECOND_FINGERPRINT,
            "c" * 32,
            "d" * 32,
        ),
        "third": (
            third_private,
            third_public,
            THIRD_FINGERPRINT,
            "e" * 32,
            "f" * 32,
        ),
    }

    before_rejection = _database_snapshot(device_lock_settings)
    with pytest.raises(DualMachineServiceError) as error:
        activated.service.create_challenge(
            _activation_command(
                activated.code,
                request_id="a" * 32,
                pair_id="b" * 32,
                host_public_key=activated.host_public_key,
                android_public_key=second_public,
                android_device_profile={
                    "device_fingerprint": SECOND_FINGERPRINT,
                },
            ),
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )
    assert error.value.code == "license_bound_to_another_device"
    assert _database_snapshot(device_lock_settings) == before_rejection

    entitlement_before = DualMachineAdminService(
        device_lock_settings,
    ).entitlement_summary(activated.entitlement_id)
    unbound = DualMachineAdminService(
        device_lock_settings,
    ).unbind_entitlement_device(
        activated.entitlement_id,
        str(old_binding["binding_id"]),
        reason="verified replacement",
        trace_id="device-lock-unbind",
    )
    assert unbound["current_device_bound"] is False
    assert unbound["pair_assurance_state"] == "recovery_pending"

    barrier = Barrier(len(candidates))

    def create_candidate(label: str) -> tuple[str, dict[str, Any] | None, str]:
        candidate = candidates[label]
        barrier.wait()
        try:
            challenge = activated.service.create_challenge(
                _activation_command(
                    activated.code,
                    request_id=candidate[3],
                    pair_id=candidate[4],
                    host_public_key=activated.host_public_key,
                    android_public_key=candidate[1],
                    android_device_profile={
                        "device_fingerprint": candidate[2],
                    },
                ),
                client_ip="127.0.0.1",
                now_epoch=1_700_000_020,
            )
            return label, challenge, ""
        except DualMachineServiceError as exc:
            return label, None, exc.code

    with ThreadPoolExecutor(max_workers=len(candidates)) as executor:
        results = list(executor.map(create_candidate, candidates))
    winners = [item for item in results if item[1] is not None]
    losers = [item for item in results if item[1] is None]
    assert len(winners) == 1
    assert len(losers) == 1
    assert losers[0][2] == "activation_already_in_progress"

    winner_label, winner_challenge, _ = winners[0]
    assert winner_challenge is not None
    winner = candidates[winner_label]
    rebound = activated.service.confirm_activation(
        _confirm_command(
            winner_challenge,
            activated.host_private_key,
            winner[0],
        ),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_021,
    )
    assert rebound["entitlement_id"] == activated.entitlement_id

    loser_label = losers[0][0]
    loser = candidates[loser_label]
    after_rebind = _database_snapshot(device_lock_settings)
    with pytest.raises(DualMachineServiceError) as retry_error:
        activated.service.create_challenge(
                _activation_command(
                    activated.code,
                    request_id="8" * 32,
                    pair_id="9" * 32,
                host_public_key=activated.host_public_key,
                android_public_key=loser[1],
                android_device_profile={"device_fingerprint": loser[2]},
            ),
            client_ip="127.0.0.1",
            now_epoch=1_700_000_022,
        )
    assert retry_error.value.code == "license_bound_to_another_device"
    assert _database_snapshot(device_lock_settings) == after_rebind

    current = _current_binding(device_lock_settings)
    entitlement_after = DualMachineAdminService(
        device_lock_settings,
    ).entitlement_summary(activated.entitlement_id)
    assert current is not None
    assert current["android_identity_public_key_b64"] == winner[1]
    assert json.loads(current["android_device_profile_json"])[
        "device_fingerprint"
    ] == winner[2]
    for field_name in (
        "remaining_seconds",
        "total_credited_seconds",
        "total_consumed_seconds",
    ):
        assert entitlement_after[field_name] == entitlement_before[field_name]
    assert _event_count(
        device_lock_settings,
        "entitlement_device_unbound",
    ) == 1
    assert _event_count(
        device_lock_settings,
        "entitlement_device_bound",
    ) == 1


def test_concurrent_activation_and_confirmation_replays_commit_once(
    device_lock_settings: DualMachineSettings,
) -> None:
    issuance = CardIssuanceService(device_lock_settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=1,
        channel="concurrency-test",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    service = CardActivationService(device_lock_settings)
    command = _activation_command(
        issuance.codes[0],
        request_id="2" * 32,
        pair_id="3" * 32,
        host_public_key=host_public,
        android_public_key=android_public,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    concurrency = 6
    challenge_barrier = Barrier(concurrency)

    def create_replay(_: int) -> dict[str, Any]:
        challenge_barrier.wait()
        return service.create_challenge(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_001,
        )

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        challenges = list(executor.map(create_replay, range(concurrency)))
    assert all(challenge == challenges[0] for challenge in challenges)
    assert _event_count(
        device_lock_settings,
        "license_activation_challenge_issued",
    ) == 1

    conflicting_replay = _activation_command(
        issuance.codes[0],
        request_id="2" * 32,
        pair_id="4" * 32,
        host_public_key=host_public,
        android_public_key=android_public,
        android_device_profile={"device_fingerprint": INITIAL_FINGERPRINT},
    )
    before_conflict = _database_snapshot(device_lock_settings)
    with pytest.raises(DualMachineServiceError) as conflict:
        service.create_challenge(
            conflicting_replay,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_002,
        )
    assert conflict.value.code == "activation_request_conflict"
    assert _database_snapshot(device_lock_settings) == before_conflict

    confirmation = _confirm_command(
        challenges[0],
        host_private,
        android_private,
    )
    confirmation_barrier = Barrier(concurrency)

    def confirm_replay(_: int) -> dict[str, Any]:
        confirmation_barrier.wait()
        return service.confirm_activation(
            confirmation,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_003,
        )

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        activations = list(executor.map(confirm_replay, range(concurrency)))
    assert all(activation == activations[0] for activation in activations)
    assert service.confirm_activation(
        confirmation,
        client_ip="127.0.0.9",
        now_epoch=1_700_999_999,
    ) == activations[0]

    connection = connect_database(device_lock_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_license_codes",
        ).fetchone()[0] == "activated"
        for table_name in (
            "dm_activation_challenges",
            "dm_entitlements",
            "dm_entitlement_device_bindings",
            "dm_license_activations",
        ):
            assert connection.execute(
                f'SELECT COUNT(*) FROM "{table_name}"',
            ).fetchone()[0] == 1
    finally:
        connection.close()
    assert _event_count(device_lock_settings, "license_activated") == 1
