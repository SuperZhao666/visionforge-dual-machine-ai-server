from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from dual_machine_service import database as database_module
from dual_machine_service.database import connect_database, initialize_database
from dual_machine_service.pair_security_repository import (
    SIGNED_64_MAX,
    PairGenerationAllocation,
    PairSecurityRepository,
    PairSecurityRepositoryError,
)
from dual_machine_service.settings import DualMachineSettings


HOST_HASH = "1" * 64
ANDROID_HASH = "2" * 64
PAIR_ID = "3" * 32
ENTITLEMENT_ID = "4" * 32
BINDING_ID = "5" * 32


@dataclass(frozen=True, slots=True)
class PairFixture:
    settings: DualMachineSettings
    repository: PairSecurityRepository
    binding_revision: int = 1

    def expected(self) -> dict[str, object]:
        return {
            "pair_id": PAIR_ID,
            "binding_id": BINDING_ID,
            "binding_revision": self.binding_revision,
            "revocation_version": 1,
            "host_key_sha256": HOST_HASH,
            "android_key_sha256": ANDROID_HASH,
        }


@pytest.fixture()
def active_pair(tmp_path: Path) -> PairFixture:
    fixture = _create_pair_fixture(tmp_path)
    repository = fixture.repository
    state = repository.register_pending_pair(
        pair_id=PAIR_ID,
        entitlement_id=ENTITLEMENT_ID,
        binding_id=BINDING_ID,
        revocation_version=1,
        host_key_sha256=HOST_HASH,
        android_key_sha256=ANDROID_HASH,
        predecessor_pair_id=None,
        now_epoch=100,
    )
    _activate_test_fixture(fixture, state.binding_revision, now_epoch=101)
    return PairFixture(fixture.settings, repository, state.binding_revision)


def test_pending_revision_is_server_allocated_and_retry_revalidates_binding(
    tmp_path: Path,
) -> None:
    fixture = _create_pair_fixture(tmp_path)

    def register(_: int) -> int:
        return _register_pending(fixture).binding_revision

    with ThreadPoolExecutor(max_workers=6) as executor:
        revisions = list(executor.map(register, range(6)))
    assert revisions == [1] * 6
    with pytest.raises(TypeError, match="binding_revision"):
        fixture.repository.register_pending_pair(
            pair_id=PAIR_ID,
            entitlement_id=ENTITLEMENT_ID,
            binding_id=BINDING_ID,
            binding_revision=99,  # type: ignore[call-arg]
            revocation_version=1,
            host_key_sha256=HOST_HASH,
            android_key_sha256=ANDROID_HASH,
            predecessor_pair_id=None,
            now_epoch=102,
        )

    connection = connect_database(fixture.settings)
    try:
        connection.execute(
            "UPDATE dm_entitlement_device_bindings SET host_key_sha256 = ? "
            "WHERE binding_id = ?",
            ("6" * 64, BINDING_ID),
        )
    finally:
        connection.close()
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_security_identity_mismatch",
    ):
        _register_pending(fixture)


def test_legacy_revision_is_history_and_next_pending_receives_revision_two(
    tmp_path: Path,
) -> None:
    fixture = _create_pair_fixture(tmp_path)
    initialize_database(fixture.settings)
    legacy = fixture.repository.pair_state(PAIR_ID)
    assert legacy is not None
    assert legacy.binding_revision == 1

    second_pair_id = "7" * 32
    second_binding_id = "8" * 32
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE dm_entitlement_device_bindings SET is_current = 0 "
            "WHERE binding_id = ?",
            (BINDING_ID,),
        )
        connection.execute(
            "INSERT INTO dm_entitlement_device_bindings "
            "(binding_id, entitlement_id, pair_id, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, is_current) "
            "VALUES (?, ?, ?, 'HOST-2', '17.8.47', 'host-public-2', ?, "
            "'ANDROID-2', '1.0.0', 'android-public-2', ?, 1)",
            (
                second_binding_id,
                ENTITLEMENT_ID,
                second_pair_id,
                HOST_HASH,
                ANDROID_HASH,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    pending = fixture.repository.register_pending_pair(
        pair_id=second_pair_id,
        entitlement_id=ENTITLEMENT_ID,
        binding_id=second_binding_id,
        revocation_version=1,
        host_key_sha256=HOST_HASH,
        android_key_sha256=ANDROID_HASH,
        predecessor_pair_id=PAIR_ID,
        now_epoch=103,
    )
    assert pending.binding_revision == 2
    assert pending.assurance_state == "pending"


def test_binding_revision_signed_64_exhaustion_fails_closed(
    tmp_path: Path,
) -> None:
    fixture = _create_pair_fixture(tmp_path)
    next_pair_id = "a" * 32
    next_binding_id = "b" * 32
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO dm_pair_security_state "
            "(pair_id, entitlement_id, binding_id, binding_revision, "
            "revocation_version, host_key_sha256, android_key_sha256, "
            "assurance_state, generation_high_water, predecessor_pair_id, "
            "created_at_epoch, updated_at_epoch) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, 'rotated', 0, NULL, 1, 1)",
            (
                PAIR_ID,
                ENTITLEMENT_ID,
                BINDING_ID,
                SIGNED_64_MAX,
                HOST_HASH,
                ANDROID_HASH,
            ),
        )
        connection.execute(
            "UPDATE dm_entitlement_device_bindings SET is_current = 0 "
            "WHERE binding_id = ?",
            (BINDING_ID,),
        )
        connection.execute(
            "INSERT INTO dm_entitlement_device_bindings "
            "(binding_id, entitlement_id, pair_id, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, is_current) "
            "VALUES (?, ?, ?, 'HOST-2', '17.8.47', 'host-public-2', ?, "
            "'ANDROID-2', '1.0.0', 'android-public-2', ?, 1)",
            (
                next_binding_id,
                ENTITLEMENT_ID,
                next_pair_id,
                HOST_HASH,
                ANDROID_HASH,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_binding_revision_exhausted",
    ):
        fixture.repository.register_pending_pair(
            pair_id=next_pair_id,
            entitlement_id=ENTITLEMENT_ID,
            binding_id=next_binding_id,
            revocation_version=1,
            host_key_sha256=HOST_HASH,
            android_key_sha256=ANDROID_HASH,
            predecessor_pair_id=PAIR_ID,
            now_epoch=2,
        )
    assert fixture.repository.pair_state(next_pair_id) is None


def test_allocation_exact_retry_persists_response_and_restart_high_water(
    active_pair: PairFixture,
) -> None:
    first = _issue_and_allocate(active_pair, ordinal=1)
    retry = active_pair.repository.allocate_generation(
        **active_pair.expected(),
        **_allocation_values(ordinal=1, now_epoch=999),
    )

    assert retry == first
    assert retry.generation == 1
    restarted = PairSecurityRepository(active_pair.settings)
    assert restarted.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]

    _issue(active_pair, ordinal=2)
    second = restarted.allocate_generation(
        **active_pair.expected(),
        **_allocation_values(ordinal=2),
    )
    assert second.generation == 2
    assert restarted.pair_state(PAIR_ID).generation_high_water == 2  # type: ignore[union-attr]

    connection = connect_database(active_pair.settings)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE dm_pair_generation_allocations SET generation = 7 "
                "WHERE allocation_request_id = ?",
                (_identifier("allocation", 1),),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM dm_pair_generation_allocations "
                "WHERE allocation_request_id = ?",
                (_identifier("allocation", 1),),
            )
    finally:
        connection.close()


def test_exact_retry_rejects_payload_or_tuple_mutation(
    active_pair: PairFixture,
) -> None:
    original = _issue_and_allocate(active_pair, ordinal=3)
    altered_payload = _allocation_values(ordinal=3)
    altered_payload["request_payload_sha256"] = _sha("different-payload")
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_request_payload_mismatch",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **altered_payload,
        )

    altered_tuple = _allocation_values(ordinal=3)
    altered_tuple["connection_id"] = 91_003
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_request_payload_mismatch",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **altered_tuple,
        )

    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]
    assert original.transcript_proposal_sha256 == _sha("transcript-3")


def test_challenge_is_one_time_and_expiry_and_status_fail_closed(
    active_pair: PairFixture,
) -> None:
    _issue_and_allocate(active_pair, ordinal=4)
    replay = _allocation_values(ordinal=4)
    replay["allocation_request_id"] = _identifier("replay", 4)
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_challenge_not_issued",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **replay,
        )

    _issue(active_pair, ordinal=5, expires_at_epoch=210)
    expired = _allocation_values(ordinal=5, now_epoch=210)
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_challenge_expired",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **expired,
        )

    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE dm_pair_generation_challenges SET status = 'revoked' "
            "WHERE challenge_id = ?",
            (_identifier("challenge", 5),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_challenge_not_issued",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(ordinal=5),
        )


@pytest.mark.parametrize(
    ("column", "replacement", "expected_error"),
    [
        ("assurance_state", "recovery_pending", "state_not_active"),
        ("revocation_version", 2, "revocation_mismatch"),
        ("host_key_sha256", "6" * 64, "identity_mismatch"),
    ],
)
def test_exact_retry_rereads_live_security_context(
    active_pair: PairFixture,
    column: str,
    replacement: object,
    expected_error: str,
) -> None:
    original = _issue_and_allocate(active_pair, ordinal=6)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        target_table = (
            "dm_pair_security_state"
            if column == "assurance_state"
            else "dm_entitlements"
            if column == "revocation_version"
            else "dm_entitlement_device_bindings"
        )
        key_column = (
            "pair_id"
            if target_table == "dm_pair_security_state"
            else "entitlement_id"
            if target_table == "dm_entitlements"
            else "binding_id"
        )
        key_value = (
            PAIR_ID
            if key_column == "pair_id"
            else ENTITLEMENT_ID
            if key_column == "entitlement_id"
            else BINDING_ID
        )
        connection.execute(
            f'UPDATE "{target_table}" SET "{column}" = ? '
            f'WHERE "{key_column}" = ?',
            (replacement, key_value),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(PairSecurityRepositoryError, match=expected_error):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(ordinal=6),
        )
    assert original.generation == 1
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]


def test_failed_journal_insert_rolls_back_counter_and_challenge(
    active_pair: PairFixture,
) -> None:
    first = _issue_and_allocate(active_pair, ordinal=7, connection_id=77)
    assert first.generation == 1
    _issue(active_pair, ordinal=8)

    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_allocation_conflict",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(ordinal=8, connection_id=77),
        )

    connection = connect_database(active_pair.settings)
    try:
        state = connection.execute(
            "SELECT generation_high_water FROM dm_pair_security_state "
            "WHERE pair_id = ?",
            (PAIR_ID,),
        ).fetchone()
        challenge = connection.execute(
            "SELECT status, consumed_at_epoch "
            "FROM dm_pair_generation_challenges WHERE challenge_id = ?",
            (_identifier("challenge", 8),),
        ).fetchone()
        count = connection.execute(
            "SELECT COUNT(*) FROM dm_pair_generation_allocations",
        ).fetchone()
    finally:
        connection.close()
    assert int(state[0]) == 1
    assert tuple(challenge) == ("issued", None)
    assert int(count[0]) == 1


def test_database_guards_state_and_challenge_anti_rollback(
    active_pair: PairFixture,
) -> None:
    consumed = _issue_and_allocate(active_pair, ordinal=40)
    connection = connect_database(active_pair.settings)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="state_rollback"):
            connection.execute(
                "UPDATE dm_pair_security_state SET generation_high_water = 0 "
                "WHERE pair_id = ?",
                (PAIR_ID,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="identity_immutable"):
            connection.execute(
                "UPDATE dm_pair_security_state SET binding_revision = 2 "
                "WHERE pair_id = ?",
                (PAIR_ID,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="state_immutable"):
            connection.execute(
                "DELETE FROM dm_pair_security_state WHERE pair_id = ?",
                (PAIR_ID,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="terminal"):
            connection.execute(
                "UPDATE dm_pair_generation_challenges SET status = 'issued', "
                "consumed_at_epoch = NULL WHERE challenge_id = ?",
                (consumed.challenge_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM dm_pair_generation_challenges "
                "WHERE challenge_id = ?",
                (consumed.challenge_id,),
            )
    finally:
        connection.close()

    _issue(active_pair, ordinal=41)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute(
            "UPDATE dm_pair_generation_challenges SET status = 'expired' "
            "WHERE challenge_id = ?",
            (_identifier("challenge", 41),),
        )
        with pytest.raises(sqlite3.IntegrityError, match="terminal"):
            connection.execute(
                "UPDATE dm_pair_generation_challenges SET status = 'revoked' "
                "WHERE challenge_id = ?",
                (_identifier("challenge", 41),),
            )
        status = connection.execute(
            "SELECT status FROM dm_pair_generation_challenges "
            "WHERE challenge_id = ?",
            (_identifier("challenge", 41),),
        ).fetchone()
    finally:
        connection.close()
    assert str(status[0]) == "expired"
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]


def test_database_rejects_allocation_that_does_not_match_consumed_challenge(
    active_pair: PairFixture,
) -> None:
    _issue(active_pair, ordinal=42)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE dm_pair_security_state SET generation_high_water = 1, "
            "updated_at_epoch = 201 WHERE pair_id = ?",
            (PAIR_ID,),
        )
        connection.execute(
            "UPDATE dm_pair_generation_challenges SET status = 'consumed', "
            "consumed_at_epoch = 201 WHERE challenge_id = ?",
            (_identifier("challenge", 42),),
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="allocation_authority_invalid",
        ):
            connection.execute(
                "INSERT INTO dm_pair_generation_allocations "
                "(allocation_request_id, request_payload_sha256, challenge_id, "
                "pair_id, binding_revision, generation, connection_id, "
                "transcript_proposal_sha256, allocated_at_epoch) "
                "VALUES (?, ?, ?, ?, 1, 1, 42001, ?, 201)",
                (
                    _identifier("allocation", 42),
                    _sha("different-payload"),
                    _identifier("challenge", 42),
                    PAIR_ID,
                    _sha("proposal-42"),
                ),
            )
        connection.rollback()
    finally:
        connection.close()


def test_generation_exhaustion_and_signed_64_inputs_fail_closed(
    active_pair: PairFixture,
) -> None:
    _issue(active_pair, ordinal=9)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE dm_pair_security_state SET generation_high_water = ? "
            "WHERE pair_id = ?",
            (SIGNED_64_MAX, PAIR_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_generation_exhausted",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(ordinal=9),
        )
    invalid = _allocation_values(ordinal=9)
    invalid["connection_id"] = SIGNED_64_MAX + 1
    with pytest.raises(
        PairSecurityRepositoryError,
        match="connection_id_invalid",
    ):
        active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **invalid,
        )

    connection = connect_database(active_pair.settings)
    try:
        challenge = connection.execute(
            "SELECT status FROM dm_pair_generation_challenges "
            "WHERE challenge_id = ?",
            (_identifier("challenge", 9),),
        ).fetchone()
        count = connection.execute(
            "SELECT COUNT(*) FROM dm_pair_generation_allocations",
        ).fetchone()
    finally:
        connection.close()
    assert str(challenge[0]) == "issued"
    assert int(count[0]) == 0


def test_concurrent_requests_receive_unique_monotonic_generations(
    active_pair: PairFixture,
) -> None:
    def allocate(ordinal: int) -> PairGenerationAllocation:
        while True:
            try:
                _issue(active_pair, ordinal=ordinal, now_epoch=300)
                break
            except PairSecurityRepositoryError as exc:
                if exc.code != "pair_generation_challenge_conflict":
                    raise
                time.sleep(0.002)
        return active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(
                ordinal=ordinal,
                connection_id=10_000 + ordinal,
                now_epoch=301,
            ),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        allocations = list(executor.map(allocate, range(20, 28)))

    generations = sorted(item.generation for item in allocations)
    assert generations == list(range(1, 9))
    assert len({item.connection_id for item in allocations}) == 8
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 8  # type: ignore[union-attr]


def test_concurrent_exact_allocation_retry_returns_one_stored_tuple(
    active_pair: PairFixture,
) -> None:
    _issue(active_pair, ordinal=50)
    barrier = threading.Barrier(8)

    def allocate(_: int) -> PairGenerationAllocation:
        barrier.wait()
        return active_pair.repository.allocate_generation(
            **active_pair.expected(),
            **_allocation_values(ordinal=50),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        allocations = list(executor.map(allocate, range(8)))
    assert allocations == [allocations[0]] * 8
    assert allocations[0].generation == 1
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]


def test_same_challenge_different_allocation_requests_have_one_winner(
    active_pair: PairFixture,
) -> None:
    _issue(active_pair, ordinal=51)
    barrier = threading.Barrier(2)

    def allocate(variant: int) -> PairGenerationAllocation | str:
        values = _allocation_values(
            ordinal=51,
            connection_id=20_000 + variant,
        )
        values["allocation_request_id"] = _identifier(
            "challenge-race",
            variant,
        )
        barrier.wait()
        try:
            return active_pair.repository.allocate_generation(
                **active_pair.expected(),
                **values,
            )
        except PairSecurityRepositoryError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(allocate, range(2)))
    allocations = [
        outcome
        for outcome in outcomes
        if isinstance(outcome, PairGenerationAllocation)
    ]
    errors = [outcome for outcome in outcomes if isinstance(outcome, str)]
    assert len(allocations) == 1
    assert errors == ["pair_generation_challenge_not_issued"]
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]


def test_same_allocation_request_different_payload_has_one_exact_winner(
    active_pair: PairFixture,
) -> None:
    _issue(active_pair, ordinal=52)
    barrier = threading.Barrier(2)

    def allocate(use_valid_payload: bool) -> PairGenerationAllocation | str:
        values = _allocation_values(ordinal=52)
        if not use_valid_payload:
            values["request_payload_sha256"] = _sha("payload-52-mismatch")
        barrier.wait()
        try:
            return active_pair.repository.allocate_generation(
                **active_pair.expected(),
                **values,
            )
        except PairSecurityRepositoryError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(allocate, (False, True)))
    allocations = [
        outcome
        for outcome in outcomes
        if isinstance(outcome, PairGenerationAllocation)
    ]
    errors = [outcome for outcome in outcomes if isinstance(outcome, str)]
    assert len(allocations) == 1
    assert errors == ["pair_generation_request_payload_mismatch"]
    assert active_pair.repository.pair_state(PAIR_ID).generation_high_water == 1  # type: ignore[union-attr]


def test_legacy_binding_migration_is_blocked_not_activated(
    tmp_path: Path,
) -> None:
    fixture = _create_pair_fixture(tmp_path)
    initialize_database(fixture.settings)
    state = fixture.repository.pair_state(PAIR_ID)

    assert state is not None
    assert state.assurance_state == "legacy_blocked"
    assert state.generation_high_water == 0
    with pytest.raises(
        PairSecurityRepositoryError,
        match="pair_security_state_not_active",
    ):
        _issue(fixture, ordinal=30)
    assert not hasattr(fixture.repository, "activate_pair")


def test_initialization_replaces_a_weak_known_security_trigger(
    active_pair: PairFixture,
) -> None:
    allocation = _issue_and_allocate(active_pair, ordinal=60)
    assert allocation.generation == 1
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("DROP TRIGGER dm_pair_state_reject_rollback")
        connection.execute(
            "CREATE TRIGGER dm_pair_state_reject_rollback "
            "BEFORE UPDATE ON dm_pair_security_state WHEN 0 BEGIN "
            "SELECT RAISE(ABORT, 'weak-trigger'); END",
        )
    finally:
        connection.close()

    initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'dm_pair_state_reject_rollback'",
        ).fetchone()
        assert "NEW.generation_high_water < OLD.generation_high_water" in str(
            trigger_sql[0],
        )
        with pytest.raises(sqlite3.IntegrityError, match="state_rollback"):
            connection.execute(
                "UPDATE dm_pair_security_state SET generation_high_water = 0 "
                "WHERE pair_id = ?",
                (PAIR_ID,),
            )
    finally:
        connection.close()


def test_initialization_replaces_weak_allocation_authority_trigger(
    active_pair: PairFixture,
) -> None:
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("DROP TRIGGER dm_pair_allocations_validate_insert")
        connection.execute(
            "CREATE TRIGGER dm_pair_allocations_validate_insert "
            "BEFORE INSERT ON dm_pair_generation_allocations WHEN 0 BEGIN "
            "SELECT RAISE(ABORT, 'weak-trigger'); END",
        )
    finally:
        connection.close()

    initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'dm_pair_allocations_validate_insert'",
        ).fetchone()
    finally:
        connection.close()
    normalized = " ".join(str(trigger_sql[0]).split())
    assert "challenge.request_payload_sha256 = NEW.request_payload_sha256" in normalized
    assert "state.generation_high_water = NEW.generation" in normalized


def test_initialization_replaces_wrong_one_issued_challenge_index(
    active_pair: PairFixture,
) -> None:
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("DROP INDEX idx_dm_pair_one_issued_challenge")
        connection.execute(
            "CREATE INDEX idx_dm_pair_one_issued_challenge "
            "ON dm_pair_generation_challenges(pair_id) "
            "WHERE status = 'consumed'",
        )
    finally:
        connection.close()

    initialize_database(active_pair.settings)
    _issue(active_pair, ordinal=62)
    connection = connect_database(active_pair.settings)
    try:
        index_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_dm_pair_one_issued_challenge'",
        ).fetchone()
        normalized = " ".join(str(index_sql[0]).split()).lower()
        assert normalized.startswith("create unique index")
        assert "where status = 'issued'" in normalized
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint"):
            connection.execute(
                "INSERT INTO dm_pair_generation_challenges "
                "(challenge_id, request_id, request_payload_sha256, "
                "pair_id, binding_revision, server_nonce_sha256, status, "
                "expires_at_epoch, consumed_at_epoch, created_at_epoch) "
                "VALUES (?, ?, ?, ?, 1, ?, 'issued', 1000, NULL, 200)",
                (
                    _identifier("challenge-duplicate", 62),
                    _identifier("challenge-request-duplicate", 62),
                    _sha("payload-duplicate-62"),
                    PAIR_ID,
                    _sha("nonce-duplicate-62"),
                ),
            )
    finally:
        connection.close()


def test_initialization_rejects_preexisting_duplicate_issued_challenges(
    active_pair: PairFixture,
) -> None:
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("DROP INDEX idx_dm_pair_one_issued_challenge")
        connection.execute(
            "CREATE INDEX idx_dm_pair_one_issued_challenge "
            "ON dm_pair_generation_challenges(pair_id) "
            "WHERE status = 'consumed'",
        )
        for ordinal in (63, 64):
            connection.execute(
                "INSERT INTO dm_pair_generation_challenges "
                "(challenge_id, request_id, request_payload_sha256, "
                "pair_id, binding_revision, server_nonce_sha256, status, "
                "expires_at_epoch, consumed_at_epoch, created_at_epoch) "
                "VALUES (?, ?, ?, ?, 1, ?, 'issued', 1000, NULL, 200)",
                (
                    _identifier("challenge-duplicate", ordinal),
                    _identifier("challenge-request-duplicate", ordinal),
                    _sha(f"payload-duplicate-{ordinal}"),
                    PAIR_ID,
                    _sha(f"nonce-duplicate-{ordinal}"),
                ),
            )
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint"):
        initialize_database(active_pair.settings)

    connection = connect_database(active_pair.settings)
    try:
        issued_count = connection.execute(
            "SELECT COUNT(*) FROM dm_pair_generation_challenges "
            "WHERE pair_id = ? AND status = 'issued'",
            (PAIR_ID,),
        ).fetchone()
        assert int(issued_count[0]) == 2
        index_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_dm_pair_one_issued_challenge'",
        ).fetchone()
        normalized = " ".join(str(index_sql[0]).split()).lower()
        assert not normalized.startswith("create unique index")
        assert "where status = 'consumed'" in normalized
    finally:
        connection.close()


def test_true_legacy_schema_without_pair_tables_upgrades_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = _create_pair_fixture(tmp_path)
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _drop_pair_security_objects(connection)
        connection.commit()
    finally:
        connection.close()

    initialize_database(fixture.settings)
    connection = connect_database(fixture.settings)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name LIKE 'dm_pair_%'",
            ).fetchall()
        }
        columns = {
            str(row["name"])
            for row in connection.execute(
                'PRAGMA table_info("dm_pair_generation_allocations")',
            ).fetchall()
        }
        state = connection.execute(
            "SELECT assurance_state, binding_revision "
            "FROM dm_pair_security_state WHERE pair_id = ?",
            (PAIR_ID,),
        ).fetchone()
    finally:
        connection.close()
    assert tables == {
        "dm_pair_security_state",
        "dm_pair_generation_challenges",
        "dm_pair_generation_allocations",
        "dm_pair_generation_credentials",
    }
    assert "credential_token" not in columns
    assert "credential_sha256" not in columns
    assert tuple(state) == ("legacy_blocked", 1)


@pytest.mark.parametrize("current_nonempty", [False, True])
def test_orphaned_allocation_migration_table_requires_operator_recovery(
    active_pair: PairFixture,
    current_nonempty: bool,
) -> None:
    original = _issue_and_allocate(active_pair, ordinal=63)
    _install_interim_credential_allocation_schema(active_pair)
    _interrupt_allocation_schema_migration(
        active_pair,
        keep_current_row=current_nonempty,
    )

    for _ in range(2):
        with pytest.raises(
            RuntimeError,
            match="migration requires operator recovery",
        ):
            initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        legacy_count = connection.execute(
            "SELECT COUNT(*) FROM "
            "dm_pair_generation_allocations_with_credential_v7",
        ).fetchone()
        current_count = connection.execute(
            "SELECT COUNT(*) FROM dm_pair_generation_allocations",
        ).fetchone()
        legacy_row = connection.execute(
            "SELECT generation, connection_id FROM "
            "dm_pair_generation_allocations_with_credential_v7 "
            "WHERE allocation_request_id = ?",
            (original.allocation_request_id,),
        ).fetchone()
    finally:
        connection.close()
    assert int(legacy_count[0]) == 1
    assert int(current_count[0]) == int(current_nonempty)
    assert tuple(legacy_row) == (original.generation, original.connection_id)


def test_half_upgraded_credential_schema_is_removed_and_reentry_is_exact(
    active_pair: PairFixture,
) -> None:
    original = _issue_and_allocate(active_pair, ordinal=61)
    _install_interim_credential_allocation_schema(active_pair)

    initialize_database(active_pair.settings)
    initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        columns = {
            str(row["name"])
            for row in connection.execute(
                'PRAGMA table_info("dm_pair_generation_allocations")',
            ).fetchall()
        }
        row = connection.execute(
            "SELECT * FROM dm_pair_generation_allocations "
            "WHERE allocation_request_id = ?",
            (original.allocation_request_id,),
        ).fetchone()
        credential_count = connection.execute(
            "SELECT COUNT(*) FROM dm_pair_generation_credentials",
        ).fetchone()
    finally:
        connection.close()
    assert "credential_token" not in columns
    assert "credential_sha256" not in columns
    assert int(row["generation"]) == original.generation
    assert int(row["connection_id"]) == original.connection_id
    assert int(credential_count[0]) == 0
    retry = active_pair.repository.allocate_generation(
        **active_pair.expected(),
        **_allocation_values(ordinal=61, now_epoch=999),
    )
    assert retry == original


def test_allocation_downgrade_after_v10_requires_operator_recovery(
    active_pair: PairFixture,
) -> None:
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "ALTER TABLE dm_pair_generation_allocations "
            "ADD COLUMN credential_token BLOB",
        )
        connection.execute(
            "ALTER TABLE dm_pair_generation_allocations "
            "ADD COLUMN credential_sha256 TEXT",
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(
        RuntimeError,
        match="allocation downgrade requires operator recovery",
    ):
        initialize_database(active_pair.settings)


def _create_pair_fixture(tmp_path: Path) -> PairFixture:
    settings = DualMachineSettings(
        database_path=tmp_path / "pair-generation.db",
        license_code_secret=b"pair-generation-license-secret-32-bytes-min",
        token_secret=b"pair-generation-token-secret-32-bytes-minimum",
        minimum_host_client_version="17.8.47",
        minimum_android_client_version="1.0.0",
    )
    initialize_database(settings)
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _insert_entitlement_and_binding(connection)
        connection.commit()
    finally:
        connection.close()
    return PairFixture(settings, PairSecurityRepository(settings))


def _activate_test_fixture(
    fixture: PairFixture,
    binding_revision: int,
    *,
    now_epoch: int,
) -> None:
    """Test-only stand-in until a proof-verifying bootstrap service exists."""
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE dm_pair_security_state SET assurance_state = 'active', "
            "updated_at_epoch = ? WHERE pair_id = ? "
            "AND binding_revision = ? AND assurance_state = 'pending'",
            (now_epoch, PAIR_ID, binding_revision),
        )
        assert int(cursor.rowcount or 0) == 1
        connection.commit()
    finally:
        connection.close()


def _register_pending(fixture: PairFixture):
    return fixture.repository.register_pending_pair(
        pair_id=PAIR_ID,
        entitlement_id=ENTITLEMENT_ID,
        binding_id=BINDING_ID,
        revocation_version=1,
        host_key_sha256=HOST_HASH,
        android_key_sha256=ANDROID_HASH,
        predecessor_pair_id=None,
        now_epoch=100,
    )


def _drop_pair_security_objects(connection: sqlite3.Connection) -> None:
    trigger_names = [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' "
            "AND name LIKE 'dm_pair_%'",
        ).fetchall()
    ]
    for trigger_name in trigger_names:
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
    connection.execute("DROP TABLE dm_pair_generation_credentials")
    connection.execute("DROP TABLE dm_pair_generation_allocations")
    connection.execute("DROP TABLE dm_pair_generation_challenges")
    connection.execute("DROP TABLE dm_pair_security_state")


def _install_interim_credential_allocation_schema(
    fixture: PairFixture,
) -> None:
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER dm_pair_allocations_validate_insert",
        )
        connection.execute(
            "DROP TRIGGER dm_pair_allocations_reject_update",
        )
        connection.execute(
            "DROP TRIGGER dm_pair_allocations_reject_delete",
        )
        connection.execute(
            "DROP TRIGGER dm_pair_credentials_validate_insert",
        )
        connection.execute(
            "DROP TRIGGER dm_pair_credentials_reject_update",
        )
        connection.execute(
            "DROP TRIGGER dm_pair_credentials_reject_delete",
        )
        connection.execute("DROP TABLE dm_pair_generation_credentials")
        connection.execute(
            "DROP INDEX idx_dm_pair_allocation_created",
        )
        connection.execute(
            "ALTER TABLE dm_pair_generation_allocations "
            "RENAME TO dm_pair_generation_allocations_current_v8",
        )
        connection.execute(
            "CREATE TABLE dm_pair_generation_allocations ("
            "allocation_request_id TEXT PRIMARY KEY, "
            "request_payload_sha256 TEXT NOT NULL, "
            "challenge_id TEXT UNIQUE NOT NULL REFERENCES "
            "dm_pair_generation_challenges(challenge_id), "
            "pair_id TEXT NOT NULL REFERENCES dm_pair_security_state(pair_id), "
            "binding_revision INTEGER NOT NULL, generation INTEGER NOT NULL, "
            "connection_id INTEGER NOT NULL, "
            "transcript_proposal_sha256 TEXT NOT NULL, "
            "credential_token BLOB NOT NULL, credential_sha256 TEXT NOT NULL, "
            "allocated_at_epoch INTEGER NOT NULL, "
            "UNIQUE(pair_id, generation), UNIQUE(pair_id, connection_id))",
        )
        connection.execute(
            "INSERT INTO dm_pair_generation_allocations "
            "(allocation_request_id, request_payload_sha256, challenge_id, "
            "pair_id, binding_revision, generation, connection_id, "
            "transcript_proposal_sha256, credential_token, "
            "credential_sha256, allocated_at_epoch) "
            "SELECT allocation_request_id, request_payload_sha256, "
            "challenge_id, pair_id, binding_revision, generation, "
            "connection_id, transcript_proposal_sha256, ?, ?, "
            "allocated_at_epoch FROM "
            "dm_pair_generation_allocations_current_v8",
            (b"obsolete-v7-token", "9" * 64),
        )
        connection.execute(
            "DROP TABLE dm_pair_generation_allocations_current_v8",
        )
        connection.execute(
            "CREATE INDEX idx_dm_pair_allocation_created ON "
            "dm_pair_generation_allocations(pair_id, allocated_at_epoch)",
        )
        connection.execute(
            "CREATE TRIGGER dm_pair_allocations_reject_update "
            "BEFORE UPDATE ON dm_pair_generation_allocations WHEN 0 BEGIN "
            "SELECT RAISE(ABORT, 'weak-interim-trigger'); END",
        )
        connection.commit()
    finally:
        connection.close()


def _interrupt_allocation_schema_migration(
    fixture: PairFixture,
    *,
    keep_current_row: bool,
) -> None:
    connection = connect_database(fixture.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER dm_pair_allocations_reject_update",
        )
        connection.execute(
            "DROP INDEX idx_dm_pair_allocation_created",
        )
        connection.execute(
            "ALTER TABLE dm_pair_generation_allocations RENAME TO "
            "dm_pair_generation_allocations_with_credential_v7",
        )
        if keep_current_row:
            database_module._create_pair_generation_allocations_table(
                connection,
            )
            connection.execute(
                "INSERT INTO dm_pair_generation_allocations "
                "(allocation_request_id, request_payload_sha256, "
                "challenge_id, pair_id, binding_revision, generation, "
                "connection_id, transcript_proposal_sha256, "
                "allocated_at_epoch) SELECT allocation_request_id, "
                "request_payload_sha256, challenge_id, pair_id, "
                "binding_revision, generation, connection_id, "
                "transcript_proposal_sha256, allocated_at_epoch FROM "
                "dm_pair_generation_allocations_with_credential_v7",
            )
        connection.commit()
    finally:
        connection.close()


def _insert_entitlement_and_binding(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO dm_entitlements "
        "(entitlement_id, pair_id, protocol_version, host_device_code, "
        "host_client_version, host_identity_public_key_b64, host_key_sha256, "
        "android_device_code, android_client_version, "
        "android_identity_public_key_b64, android_key_sha256, "
        "remaining_seconds, total_credited_seconds, total_consumed_seconds, "
        "status, revocation_version) "
        "VALUES (?, ?, 2, 'HOST-1', '17.8.47', 'host-public', ?, "
        "'ANDROID-1', '1.0.0', 'android-public', ?, 3600, 3600, 0, "
        "'active', 1)",
        (ENTITLEMENT_ID, PAIR_ID, HOST_HASH, ANDROID_HASH),
    )
    connection.execute(
        "INSERT INTO dm_entitlement_device_bindings "
        "(binding_id, entitlement_id, pair_id, host_device_code, "
        "host_client_version, host_identity_public_key_b64, host_key_sha256, "
        "android_device_code, android_client_version, "
        "android_identity_public_key_b64, android_key_sha256, is_current) "
        "VALUES (?, ?, ?, 'HOST-1', '17.8.47', 'host-public', ?, "
        "'ANDROID-1', '1.0.0', 'android-public', ?, 1)",
        (BINDING_ID, ENTITLEMENT_ID, PAIR_ID, HOST_HASH, ANDROID_HASH),
    )


def _issue(
    fixture: PairFixture,
    *,
    ordinal: int,
    expires_at_epoch: int = 1_000,
    now_epoch: int = 200,
) -> None:
    fixture.repository.issue_generation_challenge(
        **fixture.expected(),
        challenge_id=_identifier("challenge", ordinal),
        request_id=_identifier("challenge-request", ordinal),
        request_payload_sha256=_sha(f"payload-{ordinal}"),
        server_nonce_sha256=_sha(f"nonce-{ordinal}"),
        expires_at_epoch=expires_at_epoch,
        now_epoch=now_epoch,
    )


def _issue_and_allocate(
    fixture: PairFixture,
    *,
    ordinal: int,
    connection_id: int | None = None,
) -> PairGenerationAllocation:
    _issue(fixture, ordinal=ordinal)
    return fixture.repository.allocate_generation(
        **fixture.expected(),
        **_allocation_values(
            ordinal=ordinal,
            connection_id=connection_id,
        ),
    )


def _allocation_values(
    *,
    ordinal: int,
    connection_id: int | None = None,
    now_epoch: int = 201,
) -> dict[str, object]:
    return {
        "allocation_request_id": _identifier("allocation", ordinal),
        "request_payload_sha256": _sha(f"payload-{ordinal}"),
        "challenge_id": _identifier("challenge", ordinal),
        "connection_id": connection_id or 1_000 + ordinal,
        "transcript_proposal_sha256": _sha(f"transcript-{ordinal}"),
        "now_epoch": now_epoch,
    }


def _identifier(prefix: str, ordinal: int) -> str:
    return f"{prefix}-{ordinal:04d}"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()
