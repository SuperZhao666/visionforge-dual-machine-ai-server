from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dual_machine_service import pair_generation_credential_v1 as credential_module
from dual_machine_service import pair_security_repository as repository_module
from dual_machine_service.database import (
    PAIR_GENERATION_FOUNDATION_SCHEMA_VERSION,
    PAIR_GENERATION_CREDENTIAL_JOURNAL_SCHEMA_VERSION,
    REACTIVATION_SCHEMA_VERSION,
    SCHEMA_VERSION,
    connect_database,
    initialize_database,
)
from dual_machine_service.pair_generation_credential_service import (
    PairGenerationCredentialIssueRequestV1,
    PairGenerationCredentialService,
    PairGenerationCredentialServiceError,
    PairGenerationCredentialServiceErrorCode,
)
from dual_machine_service.pair_generation_credential_v1 import (
    PairGenerationCredentialError,
    PairGenerationCredentialErrorCode,
    PairGenerationCredentialExpectedV1,
    PairGenerationCredentialV1Verifier,
)
from dual_machine_service.pair_generation_proposal_v1 import (
    PairGenerationProposalFields,
    ProposalTransportKind,
    VerifiedPairGenerationProposalV1,
    build_pair_generation_proposal_v1,
)
from dual_machine_service.pair_security_repository import (
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
class CredentialServiceFixture:
    settings: DualMachineSettings
    repository: PairSecurityRepository
    binding_revision: int

    def issue_challenge(self, ordinal: int, *, now_epoch: int = 200) -> None:
        self.repository.issue_generation_challenge(
            challenge_id=_identifier("challenge", ordinal),
            request_id=_identifier("challenge-request", ordinal),
            request_payload_sha256=_sha(f"payload-{ordinal}"),
            pair_id=PAIR_ID,
            binding_id=BINDING_ID,
            binding_revision=self.binding_revision,
            revocation_version=1,
            host_key_sha256=HOST_HASH,
            android_key_sha256=ANDROID_HASH,
            server_nonce_sha256=_sha(f"nonce-{ordinal}"),
            expires_at_epoch=1_000,
            now_epoch=now_epoch,
        )

    def request(self, ordinal: int) -> PairGenerationCredentialIssueRequestV1:
        return PairGenerationCredentialIssueRequestV1(
            allocation_request_id=_identifier("allocation", ordinal),
            request_payload_sha256=_sha(f"payload-{ordinal}"),
            challenge_id=_identifier("challenge", ordinal),
            binding_id=BINDING_ID,
            binding_revision=self.binding_revision,
            revocation_version=1,
            proposal=_proposal(ordinal),
        )


@pytest.fixture(scope="module")
def current_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def next_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def third_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def fourth_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture()
def active_pair(tmp_path: Path) -> CredentialServiceFixture:
    settings = DualMachineSettings(
        database_path=tmp_path / "pair-generation-credential.db",
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
    repository = PairSecurityRepository(settings)
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
    _activate_test_fixture(
        settings,
        binding_revision=state.binding_revision,
        now_epoch=101,
    )
    return CredentialServiceFixture(
        settings=settings,
        repository=repository,
        binding_revision=state.binding_revision,
    )


def test_issue_persists_and_restart_returns_exact_token_even_after_expiry(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(1)
    request = active_pair.request(1)
    service = _service(active_pair, current_private_key)

    first = service.issue(request, now_epoch=201)
    restarted = _service(active_pair, current_private_key)
    replay = restarted.issue(request, now_epoch=500)

    assert replay == first
    assert replay.credential_token == first.credential_token
    assert replay.allocation.generation == 1
    assert replay.issued_at_epoch == 201
    assert replay.not_before_epoch == 201
    assert replay.expires_at_epoch == 216
    expected = _expected(first)
    verified = PairGenerationCredentialV1Verifier(
        public_keys=(current_private_key.public_key(),),
    ).verify(first.credential_token, expected=expected, now_epoch=201)
    assert verified.generation == 1

    connection = connect_database(active_pair.settings)
    try:
        row = connection.execute(
            "SELECT typeof(credential_token) AS token_type, * "
            "FROM dm_pair_generation_credentials",
        ).fetchone()
        assert row is not None
        assert row["token_type"] == "blob"
        assert bytes(row["credential_token"]).decode("ascii") == first.credential_token
        assert int(
            connection.execute(
                "SELECT generation_high_water FROM dm_pair_security_state "
                "WHERE pair_id = ?",
                (PAIR_ID,),
            ).fetchone()[0],
        ) == 1
    finally:
        connection.close()


def test_concurrent_exact_issue_mints_one_token(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(2)
    request = active_pair.request(2)
    service = _service(active_pair, current_private_key)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _ordinal: service.issue(request, now_epoch=201),
                range(8),
            ),
        )

    assert len({result.credential_token for result in results}) == 1
    assert len({result.credential_nonce_sha256 for result in results}) == 1
    assert {result.allocation.generation for result in results} == {1}
    assert _table_count(active_pair, "dm_pair_generation_allocations") == 1
    assert _table_count(active_pair, "dm_pair_generation_credentials") == 1


def test_same_challenge_different_allocation_requests_has_one_winner(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(3)
    original = active_pair.request(3)
    competing = replace(
        original,
        allocation_request_id=_identifier("allocation-competitor", 3),
        proposal=_proposal(3, connection_id=9_003, variant=1),
    )
    service = _service(active_pair, current_private_key)

    def issue(request: PairGenerationCredentialIssueRequestV1):
        try:
            return service.issue(request, now_epoch=201)
        except PairSecurityRepositoryError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(issue, (original, competing)))

    successes = [result for result in results if not isinstance(result, str)]
    failures = [result for result in results if isinstance(result, str)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0] in {
        "pair_generation_challenge_not_issued",
        "pair_generation_challenge_cas_failed",
    }
    assert _table_count(active_pair, "dm_pair_generation_allocations") == 1
    assert _table_count(active_pair, "dm_pair_generation_credentials") == 1


def test_exact_retry_rejects_payload_and_tuple_mutation_without_resigning(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(12)
    request = active_pair.request(12)
    service = _service(active_pair, current_private_key)
    original = service.issue(request, now_epoch=201)

    for mutation in (
        replace(request, request_payload_sha256=_sha("mutated-payload")),
        replace(
            request,
            proposal=_proposal(12, connection_id=9_012),
        ),
        replace(
            request,
            proposal=_proposal(12, variant=1),
        ),
    ):
        with pytest.raises(PairSecurityRepositoryError) as exc_info:
            service.issue(mutation, now_epoch=202)
        assert exc_info.value.code == "pair_generation_request_payload_mismatch"
    replay = service.issue(request, now_epoch=202)
    assert replay == original
    assert _table_count(active_pair, "dm_pair_generation_credentials") == 1


def test_authoritative_service_revalidates_committed_allocation(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(14)
    request = active_pair.request(14)
    result = _service(active_pair, current_private_key).issue(
        request,
        now_epoch=201,
    )

    assert result.allocation.pair_id == request.proposal.fields.pair_id
    assert result.allocation.connection_id == request.proposal.fields.connection_id
    assert (
        result.allocation.transcript_proposal_sha256
        == request.proposal.proposal_sha256.hex()
    )
    assert not hasattr(request, "transcript_proposal_sha256")


@pytest.mark.parametrize("failure_point", ["sign", "_post_verify"])
def test_signing_or_post_verify_failure_rolls_back_every_state_change(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    active_pair.issue_challenge(4)
    service = _service(active_pair, current_private_key)

    def fail(*_args, **_kwargs):
        raise PairGenerationCredentialError(
            PairGenerationCredentialErrorCode.SIGNING_FAILED,
        )

    monkeypatch.setattr(
        credential_module._PairGenerationCredentialV1Signer,
        failure_point,
        fail,
    )
    with pytest.raises(PairGenerationCredentialError) as exc_info:
        service.issue(active_pair.request(4), now_epoch=201)
    assert exc_info.value.code is PairGenerationCredentialErrorCode.SIGNING_FAILED
    _assert_unconsumed(active_pair, challenge_ordinal=4)


def test_journal_insert_failure_rolls_back_allocation_and_challenge(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_pair.issue_challenge(5)
    service = _service(active_pair, current_private_key)

    def fail_insert(*_args, **_kwargs) -> None:
        raise sqlite3.OperationalError("synthetic journal insert failure")

    monkeypatch.setattr(
        repository_module.PairGenerationCredentialUnitOfWork,
        "persist_generation_credential_issuance",
        fail_insert,
    )
    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        service.issue(active_pair.request(5), now_epoch=201)
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.PERSISTENCE_FAILED
    )
    _assert_unconsumed(active_pair, challenge_ordinal=5)


def test_preexisting_allocation_without_journal_is_never_adopted(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(6)
    request = active_pair.request(6)
    active_pair.repository.allocate_generation(
        allocation_request_id=request.allocation_request_id,
        request_payload_sha256=request.request_payload_sha256,
        challenge_id=request.challenge_id,
        pair_id=request.proposal.fields.pair_id,
        binding_id=request.binding_id,
        binding_revision=request.binding_revision,
        revocation_version=request.revocation_version,
        host_key_sha256=(
            request.proposal.fields.host_identity_spki_sha256.hex()
        ),
        android_key_sha256=(
            request.proposal.fields.android_identity_spki_sha256.hex()
        ),
        connection_id=request.proposal.fields.connection_id,
        transcript_proposal_sha256=request.proposal.proposal_sha256.hex(),
        now_epoch=201,
    )

    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        _service(active_pair, current_private_key).issue(
            request,
            now_epoch=202,
        )
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.JOURNAL_MISSING
    )
    assert _table_count(active_pair, "dm_pair_generation_allocations") == 1
    assert _table_count(active_pair, "dm_pair_generation_credentials") == 0


def test_rotation_replays_previous_key_but_missing_previous_key_fails_closed(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    next_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(7)
    request = active_pair.request(7)
    original = _service(active_pair, current_private_key).issue(
        request,
        now_epoch=201,
    )
    rotated = _service(
        active_pair,
        next_private_key,
        previous_public_keys=(current_private_key.public_key(),),
    ).issue(request, now_epoch=500)
    assert rotated == original

    without_previous = _service(active_pair, next_private_key)
    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        without_previous.issue(request, now_epoch=500)
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID
    )


def test_four_generation_rotation_replays_from_trusted_archival_key(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    next_private_key: rsa.RSAPrivateKey,
    third_private_key: rsa.RSAPrivateKey,
    fourth_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(16)
    request = active_pair.request(16)
    original = _service(active_pair, current_private_key).issue(
        request,
        now_epoch=201,
    )
    fourth_generation = _service(
        active_pair,
        fourth_private_key,
        previous_public_keys=(
            third_private_key.public_key(),
            next_private_key.public_key(),
        ),
        archived_public_keys=(current_private_key.public_key(),),
    )
    assert fourth_generation.issue(request, now_epoch=500) == original

    without_archive = _service(
        active_pair,
        fourth_private_key,
        previous_public_keys=(
            third_private_key.public_key(),
            next_private_key.public_key(),
        ),
    )
    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        without_archive.issue(request, now_epoch=500)
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID
    )


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("credential_sha256", "f" * 64),
        ("key_id", "f" * 16),
        ("credential_nonce_sha256", "e" * 64),
        ("credential_token", b"invalid.persisted.token"),
    ],
)
def test_persisted_hash_claim_key_or_token_drift_fails_closed(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    column: str,
    replacement: object,
) -> None:
    active_pair.issue_challenge(8)
    request = active_pair.request(8)
    _service(active_pair, current_private_key).issue(request, now_epoch=201)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TRIGGER dm_pair_credentials_reject_update")
        connection.execute(
            f"UPDATE dm_pair_generation_credentials SET {column} = ? "
            "WHERE allocation_request_id = ?",
            (replacement, request.allocation_request_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        _service(active_pair, current_private_key).issue(
            request,
            now_epoch=202,
        )
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID
    )


def test_credential_journal_is_append_only_and_schema_history_is_preserved(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(9)
    request = active_pair.request(9)
    _service(active_pair, current_private_key).issue(request, now_epoch=201)
    connection = connect_database(active_pair.settings)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE dm_pair_generation_credentials SET key_id = ? "
                "WHERE allocation_request_id = ?",
                ("f" * 16, request.allocation_request_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM dm_pair_generation_credentials "
                "WHERE allocation_request_id = ?",
                (request.allocation_request_id,),
            )
        migrations = {
            str(row[0])
            for row in connection.execute(
                "SELECT migration_key FROM dm_schema_migrations",
            ).fetchall()
        }
    finally:
        connection.close()
    assert {
        PAIR_GENERATION_FOUNDATION_SCHEMA_VERSION,
        REACTIVATION_SCHEMA_VERSION,
        PAIR_GENERATION_CREDENTIAL_JOURNAL_SCHEMA_VERSION,
        SCHEMA_VERSION,
    }.issubset(migrations)


def test_initialization_replaces_weak_credential_immutability_trigger(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    active_pair.issue_challenge(13)
    request = active_pair.request(13)
    _service(active_pair, current_private_key).issue(request, now_epoch=201)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TRIGGER dm_pair_credentials_reject_update")
        connection.execute(
            "CREATE TRIGGER dm_pair_credentials_reject_update "
            "BEFORE UPDATE ON dm_pair_generation_credentials WHEN 0 BEGIN "
            "SELECT RAISE(ABORT, 'weak-trigger'); END",
        )
        connection.commit()
    finally:
        connection.close()

    initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE dm_pair_generation_credentials SET key_id = ? "
                "WHERE allocation_request_id = ?",
                ("f" * 16, request.allocation_request_id),
            )
    finally:
        connection.close()


def test_initialization_rebuilds_empty_weak_credential_journal_schema(
    active_pair: CredentialServiceFixture,
) -> None:
    _install_weak_credential_journal(active_pair.settings, include_row=False)

    initialize_database(active_pair.settings)
    connection = connect_database(active_pair.settings)
    try:
        columns = {
            str(row["name"]): (int(row["notnull"]), int(row["pk"]))
            for row in connection.execute(
                'PRAGMA table_info("dm_pair_generation_credentials")',
            ).fetchall()
        }
        foreign_keys = connection.execute(
            'PRAGMA foreign_key_list("dm_pair_generation_credentials")',
        ).fetchall()
        unique_columns = _single_column_unique_indexes(
            connection,
            "dm_pair_generation_credentials",
        )
    finally:
        connection.close()
    assert columns["allocation_request_id"][1] == 1
    assert columns["credential_token"][0] == 1
    assert {
        "credential_token",
        "credential_sha256",
        "credential_nonce_sha256",
    }.issubset(unique_columns)
    assert len(foreign_keys) == 1
    assert str(foreign_keys[0]["table"]) == "dm_pair_generation_allocations"
    assert str(foreign_keys[0]["from"]) == "allocation_request_id"
    assert str(foreign_keys[0]["to"]) == "allocation_request_id"


def test_initialization_rejects_nonempty_weak_credential_journal_schema(
    active_pair: CredentialServiceFixture,
) -> None:
    _install_weak_credential_journal(active_pair.settings, include_row=True)

    with pytest.raises(
        RuntimeError,
        match="credential journal requires operator recovery",
    ):
        initialize_database(active_pair.settings)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("assurance", "pair_security_state_not_active"),
        ("revocation", "pair_security_revocation_mismatch"),
        ("binding", "pair_security_binding_not_current"),
    ],
)
def test_live_assurance_revocation_or_binding_drift_blocks_replay(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
    mutation: str,
    expected_code: str,
) -> None:
    active_pair.issue_challenge(10)
    request = active_pair.request(10)
    service = _service(active_pair, current_private_key)
    service.issue(request, now_epoch=201)
    connection = connect_database(active_pair.settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if mutation == "assurance":
            connection.execute(
                "UPDATE dm_pair_security_state SET "
                "assurance_state = 'recovery_pending', updated_at_epoch = 202 "
                "WHERE pair_id = ?",
                (PAIR_ID,),
            )
        elif mutation == "revocation":
            connection.execute(
                "UPDATE dm_entitlements SET revocation_version = 2 "
                "WHERE entitlement_id = ?",
                (ENTITLEMENT_ID,),
            )
        else:
            connection.execute(
                "UPDATE dm_entitlement_device_bindings SET is_current = 0 "
                "WHERE binding_id = ?",
                (BINDING_ID,),
            )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(PairSecurityRepositoryError) as exc_info:
        service.issue(request, now_epoch=202)
    assert exc_info.value.code == expected_code


def test_request_requires_exact_dto_and_integer_types(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    service = _service(active_pair, current_private_key)
    request = active_pair.request(11)
    for invalid in (
        replace(request, binding_revision=True),
        replace(request, revocation_version=1.0),
        replace(request, proposal=True),
    ):
        with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
            service.issue(invalid, now_epoch=201)
        assert (
            exc_info.value.code
            is PairGenerationCredentialServiceErrorCode.REQUEST_INVALID
        )
    with pytest.raises(PairGenerationCredentialServiceError):
        service.issue(request, now_epoch=True)


def test_request_rejects_proposal_subclass_without_accessing_overrides(
    active_pair: CredentialServiceFixture,
    current_private_key: rsa.RSAPrivateKey,
) -> None:
    accessed = False

    class MaliciousProposal(VerifiedPairGenerationProposalV1):
        @property
        def fields(self):
            nonlocal accessed
            accessed = True
            raise AssertionError("malicious override reached")

    malicious = object.__new__(MaliciousProposal)
    request = replace(active_pair.request(15), proposal=malicious)
    with pytest.raises(PairGenerationCredentialServiceError) as exc_info:
        _service(active_pair, current_private_key).issue(request, now_epoch=201)
    assert (
        exc_info.value.code
        is PairGenerationCredentialServiceErrorCode.REQUEST_INVALID
    )
    assert accessed is False


def _service(
    fixture: CredentialServiceFixture,
    private_key: rsa.RSAPrivateKey,
    *,
    previous_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
    archived_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
) -> PairGenerationCredentialService:
    return PairGenerationCredentialService(
        settings=fixture.settings,
        private_key=private_key,
        current_public_key=private_key.public_key(),
        previous_public_keys=previous_public_keys,
        archived_public_keys=archived_public_keys,
    )


def _expected(result) -> PairGenerationCredentialExpectedV1:
    allocation = result.allocation
    return PairGenerationCredentialExpectedV1(
        allocation_request_id=allocation.allocation_request_id,
        pair_id=PAIR_ID,
        entitlement_id=ENTITLEMENT_ID,
        binding_id=BINDING_ID,
        binding_revision=1,
        revocation_version=1,
        generation=allocation.generation,
        connection_id=allocation.connection_id,
        host_identity_spki_sha256=HOST_HASH,
        android_identity_spki_sha256=ANDROID_HASH,
        transcript_proposal_sha256=allocation.transcript_proposal_sha256,
    )


def _assert_unconsumed(
    fixture: CredentialServiceFixture,
    *,
    challenge_ordinal: int,
) -> None:
    connection = connect_database(fixture.settings)
    try:
        state = connection.execute(
            "SELECT generation_high_water FROM dm_pair_security_state "
            "WHERE pair_id = ?",
            (PAIR_ID,),
        ).fetchone()
        challenge = connection.execute(
            "SELECT status, consumed_at_epoch "
            "FROM dm_pair_generation_challenges WHERE challenge_id = ?",
            (_identifier("challenge", challenge_ordinal),),
        ).fetchone()
        assert state is not None and int(state[0]) == 0
        assert challenge is not None and challenge["status"] == "issued"
        assert challenge["consumed_at_epoch"] is None
        assert _table_count(fixture, "dm_pair_generation_allocations") == 0
        assert _table_count(fixture, "dm_pair_generation_credentials") == 0
    finally:
        connection.close()


def _table_count(fixture: CredentialServiceFixture, table_name: str) -> int:
    assert table_name in {
        "dm_pair_generation_allocations",
        "dm_pair_generation_credentials",
    }
    connection = connect_database(fixture.settings)
    try:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])
    finally:
        connection.close()


def _install_weak_credential_journal(
    settings: DualMachineSettings,
    *,
    include_row: bool,
) -> None:
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TABLE dm_pair_generation_credentials")
        connection.execute(
            "CREATE TABLE dm_pair_generation_credentials ("
            "allocation_request_id TEXT, credential_token BLOB, "
            "credential_sha256 TEXT, key_id TEXT, "
            "credential_nonce_sha256 TEXT, issued_at_epoch INTEGER, "
            "not_before_epoch INTEGER, expires_at_epoch INTEGER)",
        )
        if include_row:
            connection.execute(
                "INSERT INTO dm_pair_generation_credentials VALUES "
                "('legacy-allocation', X'41', ?, ?, ?, 1, 1, 2)",
                ("1" * 64, "2" * 16, "3" * 64),
            )
        connection.commit()
    finally:
        connection.close()


def _single_column_unique_indexes(
    connection: sqlite3.Connection,
    table_name: str,
) -> set[str]:
    unique_columns: set[str] = set()
    for index in connection.execute(
        f'PRAGMA index_list("{table_name}")',
    ).fetchall():
        if int(index["unique"]) != 1:
            continue
        columns = connection.execute(
            f'PRAGMA index_info("{index["name"]}")',
        ).fetchall()
        if len(columns) == 1:
            unique_columns.add(str(columns[0]["name"]))
    return unique_columns


def _activate_test_fixture(
    settings: DualMachineSettings,
    *,
    binding_revision: int,
    now_epoch: int,
) -> None:
    """Test-only proof stand-in; production still has no activation shortcut."""
    connection = connect_database(settings)
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


def _identifier(prefix: str, ordinal: int) -> str:
    return f"{prefix}-{ordinal:04d}"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _proposal(
    ordinal: int,
    *,
    connection_id: int | None = None,
    variant: int = 0,
):
    return build_pair_generation_proposal_v1(
        PairGenerationProposalFields(
            host_identity_spki_sha256=bytes.fromhex(HOST_HASH),
            android_identity_spki_sha256=bytes.fromhex(ANDROID_HASH),
            host_ephemeral_public_key=_p256_public_point(1),
            android_ephemeral_public_key=_p256_public_point(2),
            host_nonce=hashlib.sha256(
                f"host-nonce-{ordinal}-{variant}".encode("ascii"),
            ).digest(),
            android_nonce=hashlib.sha256(
                f"android-nonce-{ordinal}-{variant}".encode("ascii"),
            ).digest(),
            connection_id=connection_id or 1_000 + ordinal,
            transport_kind=ProposalTransportKind.CAT6,
            host_ipv4=bytes((192, 168, 1, 18)),
            android_ipv4=bytes((192, 168, 1, 42)),
            video_port=50_000,
            control_port=50_001,
            pair_id=PAIR_ID,
            host_runtime_version="1.0.8",
            android_runtime_version="1.0.8",
        ),
    )


def _p256_public_point(private_scalar: int) -> bytes:
    return ec.derive_private_key(
        private_scalar,
        ec.SECP256R1(),
    ).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
