"""Transactional pair-generation security state for the sidecar database.

This module deliberately owns persistence only. It does not expose HTTP
routes, produce credentials, or provide a proof-free transition to ``active``.
A future trusted bootstrap service must own that transition and its evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from .audit import write_audit_event
from .database import connect_database
from .settings import DualMachineSettings
from .validation import is_nonzero_lower_hex


SIGNED_64_MAX = (1 << 63) - 1
MAX_GENERATION_CHALLENGE_TTL_SECONDS = 120
ASSURANCE_STATES = frozenset({
    "legacy_blocked",
    "pending",
    "active",
    "rotated",
    "revoked",
    "recovery_pending",
})


class PairSecurityRepositoryError(RuntimeError):
    """Stable, non-sensitive failure raised by the persistence boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = str(code)


@dataclass(frozen=True, slots=True)
class PairSecurityState:
    pair_id: str
    entitlement_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    host_key_sha256: str
    android_key_sha256: str
    assurance_state: str
    generation_high_water: int
    predecessor_pair_id: str | None
    created_at_epoch: int
    updated_at_epoch: int


@dataclass(frozen=True, slots=True)
class PairGenerationChallenge:
    challenge_id: str
    request_id: str
    request_payload_sha256: str
    pair_id: str
    binding_revision: int
    server_nonce_sha256: str
    status: str
    expires_at_epoch: int
    consumed_at_epoch: int | None
    created_at_epoch: int


@dataclass(frozen=True, slots=True)
class PairGenerationAllocation:
    allocation_request_id: str
    request_payload_sha256: str
    challenge_id: str
    pair_id: str
    binding_revision: int
    generation: int
    connection_id: int
    transcript_proposal_sha256: str
    allocated_at_epoch: int


@dataclass(frozen=True, slots=True)
class PairGenerationCredentialJournalRecord:
    """Append-only credential bytes owned by the persistence boundary."""

    allocation_request_id: str
    credential_token: bytes
    credential_sha256: str
    key_id: str
    credential_nonce_sha256: str
    issued_at_epoch: int
    not_before_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True, slots=True)
class PairGenerationCredentialAuthority:
    """Committed authority loaded inside the credential issuance UoW."""

    allocation: PairGenerationAllocation
    pair_state: PairSecurityState
    allocation_existed: bool
    existing_journal: PairGenerationCredentialJournalRecord | None


@dataclass(frozen=True, slots=True)
class PairGenerationPeerAuthority:
    """Current active pair plus its registered canonical identity keys."""

    pair_state: PairSecurityState
    host_identity_public_key_b64: str
    android_identity_public_key_b64: str


@dataclass(frozen=True, slots=True)
class PairSecurityRepository:
    """Own atomic security-state and generation-allocation persistence."""

    settings: DualMachineSettings

    def pair_state(self, pair_id: str) -> PairSecurityState | None:
        normalized_pair_id = _identifier(pair_id, "pair_id")
        connection = connect_database(self.settings)
        try:
            row = connection.execute(
                "SELECT * FROM dm_pair_security_state WHERE pair_id = ?",
                (normalized_pair_id,),
            ).fetchone()
            return _state_from_row(row) if row is not None else None
        finally:
            connection.close()

    def register_pending_pair(
        self,
        *,
        pair_id: str,
        entitlement_id: str,
        binding_id: str,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        predecessor_pair_id: str | None,
        now_epoch: int,
    ) -> PairSecurityState:
        identity = _PairIdentity.normalize(
            pair_id=pair_id,
            entitlement_id=entitlement_id,
            binding_id=binding_id,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        predecessor = _optional_identifier(
            predecessor_pair_id,
            "predecessor_pair_id",
        )
        timestamp = _signed_64(now_epoch, "now_epoch", allow_zero=True)
        if predecessor == identity.pair_id:
            raise PairSecurityRepositoryError("pair_predecessor_self_reference")
        with _immediate_transaction(self.settings) as connection:
            return self._register_pending(
                connection,
                identity=identity,
                predecessor_pair_id=predecessor,
                now_epoch=timestamp,
            )

    def issue_generation_challenge(
        self,
        *,
        challenge_id: str,
        request_id: str,
        request_payload_sha256: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        server_nonce_sha256: str,
        expires_at_epoch: int,
        now_epoch: int,
    ) -> PairGenerationChallenge:
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        challenge = _ChallengeProposal.normalize(
            challenge_id=challenge_id,
            request_id=request_id,
            request_payload_sha256=request_payload_sha256,
            server_nonce_sha256=server_nonce_sha256,
            expires_at_epoch=expires_at_epoch,
            now_epoch=now_epoch,
        )
        with self.pair_generation_challenge_unit_of_work() as unit:
            unit.load_peer_authority(
                pair_id=expected.pair_id,
                binding_id=expected.binding_id,
                binding_revision=expected.binding_revision,
                revocation_version=expected.revocation_version,
                host_key_sha256=expected.host_key_sha256,
                android_key_sha256=expected.android_key_sha256,
            )
            return unit.issue_generation_challenge(
                challenge_id=challenge.challenge_id,
                request_id=challenge.request_id,
                request_payload_sha256=challenge.request_payload_sha256,
                pair_id=expected.pair_id,
                binding_id=expected.binding_id,
                binding_revision=expected.binding_revision,
                revocation_version=expected.revocation_version,
                host_key_sha256=expected.host_key_sha256,
                android_key_sha256=expected.android_key_sha256,
                server_nonce_sha256=challenge.server_nonce_sha256,
                expires_at_epoch=challenge.expires_at_epoch,
                now_epoch=challenge.now_epoch,
            )

    def issue_or_replay_generation_challenge(
        self,
        *,
        challenge_id: str,
        request_id: str,
        request_payload_sha256: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        server_nonce_sha256: str,
        challenge_ttl_seconds: int,
        now_epoch: int,
    ) -> PairGenerationChallenge:
        """Issue once while exact retries retain the original expiry."""
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        now = _signed_64(now_epoch, "now_epoch")
        if (
            type(challenge_ttl_seconds) is not int
            or not (
                1
                <= challenge_ttl_seconds
                <= MAX_GENERATION_CHALLENGE_TTL_SECONDS
            )
            or now > SIGNED_64_MAX - challenge_ttl_seconds
        ):
            raise PairSecurityRepositoryError(
                "pair_generation_challenge_ttl_invalid",
            )
        proposal = _ChallengeProposal.normalize(
            challenge_id=challenge_id,
            request_id=request_id,
            request_payload_sha256=request_payload_sha256,
            server_nonce_sha256=server_nonce_sha256,
            expires_at_epoch=now + challenge_ttl_seconds,
            now_epoch=now,
        )
        with _immediate_transaction(self.settings) as connection:
            _require_active_pair_context(connection, expected)
            existing = connection.execute(
                "SELECT * FROM dm_pair_generation_challenges "
                "WHERE request_id = ?",
                (proposal.request_id,),
            ).fetchone()
            if existing is not None:
                return _stable_challenge_retry(
                    existing,
                    expected,
                    proposal,
                )
            return self._issue_challenge(
                connection,
                expected=expected,
                proposal=proposal,
            )

    def allocate_generation(
        self,
        *,
        allocation_request_id: str,
        request_payload_sha256: str,
        challenge_id: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        connection_id: int,
        transcript_proposal_sha256: str,
        now_epoch: int,
    ) -> PairGenerationAllocation:
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        proposal = _AllocationProposal.normalize(
            allocation_request_id=allocation_request_id,
            request_payload_sha256=request_payload_sha256,
            challenge_id=challenge_id,
            connection_id=connection_id,
            transcript_proposal_sha256=transcript_proposal_sha256,
            now_epoch=now_epoch,
        )
        with _immediate_transaction(self.settings) as connection:
            return self._allocate_generation(
                connection,
                expected=expected,
                proposal=proposal,
            )

    @contextmanager
    def pair_generation_credential_unit_of_work(
        self,
    ) -> Iterator[PairGenerationCredentialUnitOfWork]:
        """Open the single transaction used by authoritative issuance.

        The returned object exposes only pair-generation allocation, live
        authority, and credential-journal operations.  It never exposes the
        underlying SQLite connection and never receives a signer or key.
        """
        with _immediate_transaction(self.settings) as connection:
            unit_of_work = PairGenerationCredentialUnitOfWork(
                repository=self,
                connection=connection,
            )
            try:
                yield unit_of_work
            finally:
                unit_of_work._close()

    def pair_generation_peer_authority(
        self,
        *,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
    ) -> PairGenerationPeerAuthority:
        """Read the current peer-key authority for an early PoP check."""
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        connection = connect_database(self.settings)
        try:
            return _require_peer_authority(connection, expected)
        finally:
            connection.close()

    def pair_generation_peer_authority_for_context(
        self,
        *,
        entitlement_id: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
    ) -> PairGenerationPeerAuthority:
        """Load server-owned identity hashes and keys for dual-PoP."""
        expected = _ExpectedPeerContext.normalize(
            entitlement_id=entitlement_id,
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
        )
        connection = connect_database(self.settings)
        try:
            return _require_peer_authority_for_context(connection, expected)
        finally:
            connection.close()

    @contextmanager
    def pair_generation_challenge_unit_of_work(
        self,
    ) -> Iterator[PairGenerationChallengeUnitOfWork]:
        """Open the narrow transaction used to authenticate a challenge."""
        with _immediate_transaction(self.settings) as connection:
            unit_of_work = PairGenerationChallengeUnitOfWork(
                repository=self,
                connection=connection,
            )
            try:
                yield unit_of_work
            finally:
                unit_of_work._close()

    @staticmethod
    def _register_pending(
        connection: sqlite3.Connection,
        *,
        identity: _PairIdentity,
        predecessor_pair_id: str | None,
        now_epoch: int,
    ) -> PairSecurityState:
        existing = _state_row(connection, identity.pair_id)
        if existing is not None:
            _require_exact_pending_retry(
                existing,
                identity=identity,
                predecessor_pair_id=predecessor_pair_id,
            )
            _require_live_binding(connection, identity)
            return _state_from_row(existing)
        _require_live_binding(connection, identity)
        binding_revision = _next_binding_revision(
            connection,
            identity.entitlement_id,
        )
        try:
            connection.execute(
                "INSERT INTO dm_pair_security_state "
                "(pair_id, entitlement_id, binding_id, binding_revision, "
                "revocation_version, host_key_sha256, android_key_sha256, "
                "assurance_state, generation_high_water, "
                "predecessor_pair_id, created_at_epoch, updated_at_epoch) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
                (
                    identity.pair_id,
                    identity.entitlement_id,
                    identity.binding_id,
                    binding_revision,
                    identity.revocation_version,
                    identity.host_key_sha256,
                    identity.android_key_sha256,
                    predecessor_pair_id,
                    now_epoch,
                    now_epoch,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise PairSecurityRepositoryError(
                "pair_security_state_conflict",
            ) from exc
        return _required_state(connection, identity.pair_id)

    def _issue_challenge(
        self,
        connection: sqlite3.Connection,
        *,
        expected: _ExpectedPair,
        proposal: _ChallengeProposal,
    ) -> PairGenerationChallenge:
        existing = connection.execute(
            "SELECT * FROM dm_pair_generation_challenges "
            "WHERE request_id = ?",
            (proposal.request_id,),
        ).fetchone()
        if existing is not None:
            return _challenge_retry(existing, expected, proposal)
        connection.execute(
            "UPDATE dm_pair_generation_challenges SET status = 'expired' "
            "WHERE pair_id = ? AND status = 'issued' "
            "AND expires_at_epoch <= ?",
            (expected.pair_id, proposal.now_epoch),
        )
        try:
            connection.execute(
                "INSERT INTO dm_pair_generation_challenges "
                "(challenge_id, request_id, request_payload_sha256, "
                "pair_id, binding_revision, server_nonce_sha256, status, "
                "expires_at_epoch, consumed_at_epoch, created_at_epoch) "
                "VALUES (?, ?, ?, ?, ?, ?, 'issued', ?, NULL, ?)",
                (
                    proposal.challenge_id,
                    proposal.request_id,
                    proposal.request_payload_sha256,
                    expected.pair_id,
                    expected.binding_revision,
                    proposal.server_nonce_sha256,
                    proposal.expires_at_epoch,
                    proposal.now_epoch,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise PairSecurityRepositoryError(
                "pair_generation_challenge_conflict",
            ) from exc
        return _required_challenge(connection, proposal.challenge_id)

    def _allocate_generation(
        self,
        connection: sqlite3.Connection,
        *,
        expected: _ExpectedPair,
        proposal: _AllocationProposal,
    ) -> PairGenerationAllocation:
        existing = _allocation_row(
            connection,
            proposal.allocation_request_id,
        )
        context = _require_active_pair_context(connection, expected)
        if existing is not None:
            _require_exact_allocation_retry(existing, expected, proposal)
            return _allocation_from_row(existing)
        challenge = _require_issued_challenge(
            connection,
            expected=expected,
            proposal=proposal,
        )
        generation = _advance_generation_high_water(
            connection,
            context=context,
            now_epoch=proposal.now_epoch,
        )
        _consume_challenge(
            connection,
            challenge=challenge,
            proposal=proposal,
        )
        _insert_allocation(
            connection,
            expected=expected,
            proposal=proposal,
            generation=generation,
        )
        return _required_allocation(
            connection,
            proposal.allocation_request_id,
        )


class PairGenerationCredentialUnitOfWork:
    """Narrow transaction interface for the authoritative signing service."""

    __slots__ = ("_connection", "_is_open", "_repository")

    def __init__(
        self,
        *,
        repository: PairSecurityRepository,
        connection: sqlite3.Connection,
    ) -> None:
        self._repository = repository
        self._connection = connection
        self._is_open = True

    def allocate_generation(
        self,
        *,
        allocation_request_id: str,
        request_payload_sha256: str,
        challenge_id: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        connection_id: int,
        transcript_proposal_sha256: str,
        now_epoch: int,
    ) -> PairGenerationCredentialAuthority:
        """Allocate once and return the live committed signing authority."""
        self._require_open()
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        proposal = _AllocationProposal.normalize(
            allocation_request_id=allocation_request_id,
            request_payload_sha256=request_payload_sha256,
            challenge_id=challenge_id,
            connection_id=connection_id,
            transcript_proposal_sha256=transcript_proposal_sha256,
            now_epoch=now_epoch,
        )
        allocation_existed = (
            _allocation_row(self._connection, proposal.allocation_request_id)
            is not None
        )
        existing_journal = self.load_generation_credential_issuance(
            proposal.allocation_request_id,
        )
        allocation = self._repository._allocate_generation(
            self._connection,
            expected=expected,
            proposal=proposal,
        )
        pair_state = _require_active_pair_context(self._connection, expected)
        return PairGenerationCredentialAuthority(
            allocation=allocation,
            pair_state=pair_state,
            allocation_existed=allocation_existed,
            existing_journal=existing_journal,
        )

    def load_peer_authority(
        self,
        *,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
    ) -> PairGenerationPeerAuthority:
        """Reload current registered peer keys while holding the write lock."""
        self._require_open()
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        return _require_peer_authority(self._connection, expected)

    def load_peer_authority_for_context(
        self,
        *,
        entitlement_id: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
    ) -> PairGenerationPeerAuthority:
        self._require_open()
        expected = _ExpectedPeerContext.normalize(
            entitlement_id=entitlement_id,
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
        )
        return _require_peer_authority_for_context(self._connection, expected)

    def load_generation_challenge(
        self,
        challenge_id: str,
    ) -> PairGenerationChallenge | None:
        """Load the immutable challenge used by the final dual-PoP proof."""
        self._require_open()
        normalized_id = _identifier(challenge_id, "challenge_id")
        row = _challenge_row(self._connection, normalized_id)
        return _challenge_from_row(row) if row is not None else None

    def load_generation_credential_issuance(
        self,
        allocation_request_id: str,
    ) -> PairGenerationCredentialJournalRecord | None:
        """Load immutable bytes without parsing or re-encoding the token."""
        self._require_open()
        normalized_id = _identifier(
            allocation_request_id,
            "allocation_request_id",
        )
        row = self._connection.execute(
            "SELECT * FROM dm_pair_generation_credentials "
            "WHERE allocation_request_id = ?",
            (normalized_id,),
        ).fetchone()
        return _credential_journal_from_row(row) if row is not None else None

    def persist_generation_credential_issuance(
        self,
        record: PairGenerationCredentialJournalRecord,
    ) -> PairGenerationCredentialJournalRecord:
        """Insert the sole terminal credential result for an allocation."""
        self._require_open()
        normalized = _normalize_credential_journal_record(record)
        try:
            self._connection.execute(
                "INSERT INTO dm_pair_generation_credentials "
                "(allocation_request_id, credential_token, credential_sha256, "
                "key_id, credential_nonce_sha256, issued_at_epoch, "
                "not_before_epoch, expires_at_epoch) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    normalized.allocation_request_id,
                    normalized.credential_token,
                    normalized.credential_sha256,
                    normalized.key_id,
                    normalized.credential_nonce_sha256,
                    normalized.issued_at_epoch,
                    normalized.not_before_epoch,
                    normalized.expires_at_epoch,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise PairSecurityRepositoryError(
                "pair_generation_credential_journal_conflict",
            ) from exc
        persisted = self.load_generation_credential_issuance(
            normalized.allocation_request_id,
        )
        if persisted is None:
            raise PairSecurityRepositoryError(
                "pair_generation_credential_journal_missing_after_write",
            )
        return persisted

    def record_security_audit(
        self,
        *,
        event_type: str,
        subject_id: str,
        trace_id: str,
        ip_address: str,
        detail: dict[str, object],
    ) -> None:
        self._require_open()
        _record_pair_generation_audit(
            self._connection,
            event_type=event_type,
            subject_id=subject_id,
            trace_id=trace_id,
            ip_address=ip_address,
            detail=detail,
        )

    def _require_open(self) -> None:
        if not self._is_open:
            raise PairSecurityRepositoryError(
                "pair_generation_credential_unit_of_work_closed",
            )

    def _close(self) -> None:
        self._is_open = False


class PairGenerationChallengeUnitOfWork:
    """Narrow transaction interface for double-verified challenge issuance."""

    __slots__ = ("_connection", "_is_open", "_repository")

    def __init__(
        self,
        *,
        repository: PairSecurityRepository,
        connection: sqlite3.Connection,
    ) -> None:
        self._repository = repository
        self._connection = connection
        self._is_open = True

    def load_peer_authority(
        self,
        *,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
    ) -> PairGenerationPeerAuthority:
        self._require_open()
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        return _require_peer_authority(self._connection, expected)

    def load_peer_authority_for_context(
        self,
        *,
        entitlement_id: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
    ) -> PairGenerationPeerAuthority:
        self._require_open()
        expected = _ExpectedPeerContext.normalize(
            entitlement_id=entitlement_id,
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
        )
        return _require_peer_authority_for_context(self._connection, expected)

    def load_generation_challenge_by_request_id(
        self,
        request_id: str,
    ) -> PairGenerationChallenge | None:
        self._require_open()
        normalized_id = _identifier(request_id, "request_id")
        row = self._connection.execute(
            "SELECT * FROM dm_pair_generation_challenges WHERE request_id = ?",
            (normalized_id,),
        ).fetchone()
        return _challenge_from_row(row) if row is not None else None

    def issue_generation_challenge(
        self,
        *,
        challenge_id: str,
        request_id: str,
        request_payload_sha256: str,
        pair_id: str,
        binding_id: str,
        binding_revision: int,
        revocation_version: int,
        host_key_sha256: str,
        android_key_sha256: str,
        server_nonce_sha256: str,
        expires_at_epoch: int,
        now_epoch: int,
    ) -> PairGenerationChallenge:
        self._require_open()
        expected = _ExpectedPair.normalize(
            pair_id=pair_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            revocation_version=revocation_version,
            host_key_sha256=host_key_sha256,
            android_key_sha256=android_key_sha256,
        )
        proposal = _ChallengeProposal.normalize(
            challenge_id=challenge_id,
            request_id=request_id,
            request_payload_sha256=request_payload_sha256,
            server_nonce_sha256=server_nonce_sha256,
            expires_at_epoch=expires_at_epoch,
            now_epoch=now_epoch,
        )
        _require_active_pair_context(self._connection, expected)
        return self._repository._issue_challenge(
            self._connection,
            expected=expected,
            proposal=proposal,
        )

    def record_security_audit(
        self,
        *,
        event_type: str,
        subject_id: str,
        trace_id: str,
        ip_address: str,
        detail: dict[str, object],
    ) -> None:
        self._require_open()
        _record_pair_generation_audit(
            self._connection,
            event_type=event_type,
            subject_id=subject_id,
            trace_id=trace_id,
            ip_address=ip_address,
            detail=detail,
        )

    def _require_open(self) -> None:
        if not self._is_open:
            raise PairSecurityRepositoryError(
                "pair_generation_challenge_unit_of_work_closed",
            )

    def _close(self) -> None:
        self._is_open = False


@dataclass(frozen=True, slots=True)
class _PairIdentity:
    pair_id: str
    entitlement_id: str
    binding_id: str
    revocation_version: int
    host_key_sha256: str
    android_key_sha256: str

    @classmethod
    def normalize(cls, **values: object) -> _PairIdentity:
        host_hash = _sha256(values["host_key_sha256"], "host_key_sha256")
        android_hash = _sha256(
            values["android_key_sha256"],
            "android_key_sha256",
        )
        if host_hash == android_hash:
            raise PairSecurityRepositoryError("pair_identity_hashes_equal")
        return cls(
            pair_id=_identifier(values["pair_id"], "pair_id"),
            entitlement_id=_identifier(
                values["entitlement_id"],
                "entitlement_id",
            ),
            binding_id=_identifier(values["binding_id"], "binding_id"),
            revocation_version=_signed_64(
                values["revocation_version"],
                "revocation_version",
            ),
            host_key_sha256=host_hash,
            android_key_sha256=android_hash,
        )


@dataclass(frozen=True, slots=True)
class _ExpectedPeerContext:
    entitlement_id: str
    pair_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int

    @classmethod
    def normalize(cls, **values: object) -> _ExpectedPeerContext:
        return cls(
            entitlement_id=_identifier(
                values["entitlement_id"],
                "entitlement_id",
            ),
            pair_id=_identifier(values["pair_id"], "pair_id"),
            binding_id=_identifier(values["binding_id"], "binding_id"),
            binding_revision=_signed_64(
                values["binding_revision"],
                "binding_revision",
            ),
            revocation_version=_signed_64(
                values["revocation_version"],
                "revocation_version",
            ),
        )


@dataclass(frozen=True, slots=True)
class _ExpectedPair:
    pair_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    host_key_sha256: str
    android_key_sha256: str

    @classmethod
    def normalize(cls, **values: object) -> _ExpectedPair:
        host_hash = _sha256(values["host_key_sha256"], "host_key_sha256")
        android_hash = _sha256(
            values["android_key_sha256"],
            "android_key_sha256",
        )
        if host_hash == android_hash:
            raise PairSecurityRepositoryError("pair_identity_hashes_equal")
        return cls(
            pair_id=_identifier(values["pair_id"], "pair_id"),
            binding_id=_identifier(values["binding_id"], "binding_id"),
            binding_revision=_signed_64(
                values["binding_revision"],
                "binding_revision",
            ),
            revocation_version=_signed_64(
                values["revocation_version"],
                "revocation_version",
            ),
            host_key_sha256=host_hash,
            android_key_sha256=android_hash,
        )


@dataclass(frozen=True, slots=True)
class _ChallengeProposal:
    challenge_id: str
    request_id: str
    request_payload_sha256: str
    server_nonce_sha256: str
    expires_at_epoch: int
    now_epoch: int

    @classmethod
    def normalize(cls, **values: object) -> _ChallengeProposal:
        now_epoch = _signed_64(values["now_epoch"], "now_epoch", allow_zero=True)
        expires = _signed_64(
            values["expires_at_epoch"],
            "expires_at_epoch",
            allow_zero=True,
        )
        if expires <= now_epoch:
            raise PairSecurityRepositoryError(
                "pair_generation_challenge_expiry_invalid",
            )
        return cls(
            challenge_id=_identifier(values["challenge_id"], "challenge_id"),
            request_id=_identifier(values["request_id"], "request_id"),
            request_payload_sha256=_sha256(
                values["request_payload_sha256"],
                "request_payload_sha256",
            ),
            server_nonce_sha256=_sha256(
                values["server_nonce_sha256"],
                "server_nonce_sha256",
            ),
            expires_at_epoch=expires,
            now_epoch=now_epoch,
        )


@dataclass(frozen=True, slots=True)
class _AllocationProposal:
    allocation_request_id: str
    request_payload_sha256: str
    challenge_id: str
    connection_id: int
    transcript_proposal_sha256: str
    now_epoch: int

    @classmethod
    def normalize(cls, **values: object) -> _AllocationProposal:
        return cls(
            allocation_request_id=_identifier(
                values["allocation_request_id"],
                "allocation_request_id",
            ),
            request_payload_sha256=_sha256(
                values["request_payload_sha256"],
                "request_payload_sha256",
            ),
            challenge_id=_identifier(values["challenge_id"], "challenge_id"),
            connection_id=_signed_64(values["connection_id"], "connection_id"),
            transcript_proposal_sha256=_sha256(
                values["transcript_proposal_sha256"],
                "transcript_proposal_sha256",
            ),
            now_epoch=_signed_64(
                values["now_epoch"],
                "now_epoch",
                allow_zero=True,
            ),
        )


def _require_live_binding(
    connection: sqlite3.Connection,
    expected: _PairIdentity,
) -> None:
    row = connection.execute(
        "SELECT e.status AS entitlement_status, "
        "e.revocation_version AS live_revocation_version, "
        "b.pair_id AS binding_pair_id, b.host_key_sha256, "
        "b.android_key_sha256, b.is_current "
        "FROM dm_entitlements e JOIN dm_entitlement_device_bindings b "
        "ON b.entitlement_id = e.entitlement_id "
        "WHERE e.entitlement_id = ? AND b.binding_id = ?",
        (expected.entitlement_id, expected.binding_id),
    ).fetchone()
    if row is None:
        raise PairSecurityRepositoryError("pair_security_binding_not_found")
    _check_live_binding_row(row, expected)


def _next_binding_revision(
    connection: sqlite3.Connection,
    entitlement_id: str,
) -> int:
    row = connection.execute(
        "SELECT COALESCE(MAX(binding_revision), 0) AS high_water "
        "FROM dm_pair_security_state WHERE entitlement_id = ?",
        (entitlement_id,),
    ).fetchone()
    high_water = int(row["high_water"])
    if high_water >= SIGNED_64_MAX:
        raise PairSecurityRepositoryError("pair_binding_revision_exhausted")
    return high_water + 1


def _require_pair_context(
    connection: sqlite3.Connection,
    expected: _ExpectedPair,
) -> PairSecurityState:
    row = connection.execute(
        "SELECT s.*, e.status AS entitlement_status, "
        "e.revocation_version AS live_revocation_version, "
        "b.pair_id AS binding_pair_id, "
        "b.host_key_sha256 AS binding_host_key_sha256, "
        "b.android_key_sha256 AS binding_android_key_sha256, "
        "b.is_current AS binding_is_current "
        "FROM dm_pair_security_state s "
        "JOIN dm_entitlements e ON e.entitlement_id = s.entitlement_id "
        "JOIN dm_entitlement_device_bindings b ON b.binding_id = s.binding_id "
        "AND b.entitlement_id = s.entitlement_id WHERE s.pair_id = ?",
        (expected.pair_id,),
    ).fetchone()
    if row is None:
        raise PairSecurityRepositoryError("pair_security_state_not_found")
    _check_state_row(row, expected)
    return _state_from_row(row)


def _require_active_pair_context(
    connection: sqlite3.Connection,
    expected: _ExpectedPair,
) -> PairSecurityState:
    context = _require_pair_context(connection, expected)
    if context.assurance_state != "active":
        raise PairSecurityRepositoryError("pair_security_state_not_active")
    return context


def _require_peer_authority(
    connection: sqlite3.Connection,
    expected: _ExpectedPair,
) -> PairGenerationPeerAuthority:
    authority = _require_peer_authority_for_context(
        connection,
        _ExpectedPeerContext(
            entitlement_id=_require_active_pair_context(
                connection,
                expected,
            ).entitlement_id,
            pair_id=expected.pair_id,
            binding_id=expected.binding_id,
            binding_revision=expected.binding_revision,
            revocation_version=expected.revocation_version,
        ),
    )
    pair_state = authority.pair_state
    if (
        pair_state.host_key_sha256 != expected.host_key_sha256
        or pair_state.android_key_sha256 != expected.android_key_sha256
    ):
        raise PairSecurityRepositoryError("pair_security_identity_mismatch")
    return authority


def _require_peer_authority_for_context(
    connection: sqlite3.Connection,
    expected: _ExpectedPeerContext,
) -> PairGenerationPeerAuthority:
    row = connection.execute(
        "SELECT s.*, e.status AS entitlement_status, "
        "e.revocation_version AS live_revocation_version, "
        "b.pair_id AS binding_pair_id, b.is_current AS binding_is_current, "
        "b.host_key_sha256 AS binding_host_key_sha256, "
        "b.android_key_sha256 AS binding_android_key_sha256, "
        "b.host_identity_public_key_b64, b.android_identity_public_key_b64 "
        "FROM dm_pair_security_state s "
        "JOIN dm_entitlements e ON e.entitlement_id = s.entitlement_id "
        "JOIN dm_entitlement_device_bindings b ON b.binding_id = s.binding_id "
        "AND b.entitlement_id = s.entitlement_id "
        "WHERE s.entitlement_id = ? AND s.pair_id = ? AND s.binding_id = ? "
        "AND s.binding_revision = ? AND s.revocation_version = ?",
        (
            expected.entitlement_id,
            expected.pair_id,
            expected.binding_id,
            expected.binding_revision,
            expected.revocation_version,
        ),
    ).fetchone()
    if row is None:
        raise PairSecurityRepositoryError("pair_generation_peer_authority_missing")
    if (
        str(row["assurance_state"]) != "active"
        or str(row["entitlement_status"]) != "active"
        or int(row["live_revocation_version"]) != expected.revocation_version
        or int(row["binding_is_current"]) != 1
        or str(row["binding_pair_id"]) != expected.pair_id
    ):
        raise PairSecurityRepositoryError("pair_generation_peer_authority_invalid")
    host_hash = _sha256(row["host_key_sha256"], "host_key_sha256")
    android_hash = _sha256(row["android_key_sha256"], "android_key_sha256")
    if (
        host_hash == android_hash
        or host_hash != row["binding_host_key_sha256"]
        or android_hash != row["binding_android_key_sha256"]
    ):
        raise PairSecurityRepositoryError("pair_generation_peer_authority_invalid")
    host_public_key = row["host_identity_public_key_b64"]
    android_public_key = row["android_identity_public_key_b64"]
    if (
        type(host_public_key) is not str
        or type(android_public_key) is not str
        or not host_public_key
        or not android_public_key
    ):
        raise PairSecurityRepositoryError("pair_generation_peer_authority_invalid")
    return PairGenerationPeerAuthority(
        pair_state=_state_from_row(row),
        host_identity_public_key_b64=host_public_key,
        android_identity_public_key_b64=android_public_key,
    )


def _check_live_binding_row(
    row: sqlite3.Row,
    expected: _PairIdentity,
) -> None:
    if str(row["entitlement_status"]) != "active":
        raise PairSecurityRepositoryError("pair_entitlement_not_active")
    if int(row["is_current"]) != 1:
        raise PairSecurityRepositoryError("pair_security_binding_not_current")
    if str(row["binding_pair_id"]) != expected.pair_id:
        raise PairSecurityRepositoryError("pair_security_binding_mismatch")
    if int(row["live_revocation_version"]) != expected.revocation_version:
        raise PairSecurityRepositoryError("pair_security_revocation_mismatch")
    if (
        str(row["host_key_sha256"]) != expected.host_key_sha256
        or str(row["android_key_sha256"]) != expected.android_key_sha256
    ):
        raise PairSecurityRepositoryError("pair_security_identity_mismatch")


def _check_state_row(row: sqlite3.Row, expected: _ExpectedPair) -> None:
    if str(row["binding_id"]) != expected.binding_id:
        raise PairSecurityRepositoryError("pair_security_binding_mismatch")
    if int(row["binding_revision"]) != expected.binding_revision:
        raise PairSecurityRepositoryError("pair_security_binding_mismatch")
    if (
        int(row["revocation_version"]) != expected.revocation_version
        or int(row["live_revocation_version"]) != expected.revocation_version
    ):
        raise PairSecurityRepositoryError("pair_security_revocation_mismatch")
    if str(row["entitlement_status"]) != "active":
        raise PairSecurityRepositoryError("pair_entitlement_not_active")
    if int(row["binding_is_current"]) != 1:
        raise PairSecurityRepositoryError("pair_security_binding_not_current")
    if str(row["binding_pair_id"]) != expected.pair_id:
        raise PairSecurityRepositoryError("pair_security_binding_mismatch")
    state_hashes = (str(row["host_key_sha256"]), str(row["android_key_sha256"]))
    binding_hashes = (
        str(row["binding_host_key_sha256"]),
        str(row["binding_android_key_sha256"]),
    )
    if state_hashes != binding_hashes or state_hashes != (
        expected.host_key_sha256,
        expected.android_key_sha256,
    ):
        raise PairSecurityRepositoryError("pair_security_identity_mismatch")


def _require_issued_challenge(
    connection: sqlite3.Connection,
    *,
    expected: _ExpectedPair,
    proposal: _AllocationProposal,
) -> PairGenerationChallenge:
    row = connection.execute(
        "SELECT * FROM dm_pair_generation_challenges WHERE challenge_id = ?",
        (proposal.challenge_id,),
    ).fetchone()
    if row is None:
        raise PairSecurityRepositoryError("pair_generation_challenge_not_found")
    if str(row["status"]) != "issued":
        raise PairSecurityRepositoryError("pair_generation_challenge_not_issued")
    if int(row["expires_at_epoch"]) <= proposal.now_epoch:
        raise PairSecurityRepositoryError("pair_generation_challenge_expired")
    if (
        str(row["pair_id"]) != expected.pair_id
        or int(row["binding_revision"]) != expected.binding_revision
    ):
        raise PairSecurityRepositoryError("pair_generation_challenge_mismatch")
    if str(row["request_payload_sha256"]) != proposal.request_payload_sha256:
        raise PairSecurityRepositoryError(
            "pair_generation_request_payload_mismatch",
        )
    return _challenge_from_row(row)


def _advance_generation_high_water(
    connection: sqlite3.Connection,
    *,
    context: PairSecurityState,
    now_epoch: int,
) -> int:
    current = context.generation_high_water
    if current >= SIGNED_64_MAX:
        raise PairSecurityRepositoryError("pair_generation_exhausted")
    cursor = connection.execute(
        "UPDATE dm_pair_security_state SET generation_high_water = "
        "generation_high_water + 1, updated_at_epoch = ? "
        "WHERE pair_id = ? AND assurance_state = 'active' "
        "AND generation_high_water = ? AND binding_id = ? "
        "AND binding_revision = ? AND revocation_version = ? "
        "AND host_key_sha256 = ? AND android_key_sha256 = ?",
        (
            now_epoch,
            context.pair_id,
            current,
            context.binding_id,
            context.binding_revision,
            context.revocation_version,
            context.host_key_sha256,
            context.android_key_sha256,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise PairSecurityRepositoryError("pair_generation_high_water_conflict")
    return current + 1


def _consume_challenge(
    connection: sqlite3.Connection,
    *,
    challenge: PairGenerationChallenge,
    proposal: _AllocationProposal,
) -> None:
    cursor = connection.execute(
        "UPDATE dm_pair_generation_challenges "
        "SET status = 'consumed', consumed_at_epoch = ? "
        "WHERE challenge_id = ? AND status = 'issued' "
        "AND expires_at_epoch > ? AND pair_id = ? "
        "AND binding_revision = ? AND request_payload_sha256 = ?",
        (
            proposal.now_epoch,
            challenge.challenge_id,
            proposal.now_epoch,
            challenge.pair_id,
            challenge.binding_revision,
            challenge.request_payload_sha256,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise PairSecurityRepositoryError("pair_generation_challenge_cas_failed")


def _insert_allocation(
    connection: sqlite3.Connection,
    *,
    expected: _ExpectedPair,
    proposal: _AllocationProposal,
    generation: int,
) -> None:
    try:
        connection.execute(
            "INSERT INTO dm_pair_generation_allocations "
            "(allocation_request_id, request_payload_sha256, challenge_id, "
            "pair_id, binding_revision, generation, connection_id, "
            "transcript_proposal_sha256, allocated_at_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                proposal.allocation_request_id,
                proposal.request_payload_sha256,
                proposal.challenge_id,
                expected.pair_id,
                expected.binding_revision,
                generation,
                proposal.connection_id,
                proposal.transcript_proposal_sha256,
                proposal.now_epoch,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise PairSecurityRepositoryError(
            "pair_generation_allocation_conflict",
        ) from exc


def _require_exact_pending_retry(
    row: sqlite3.Row,
    *,
    identity: _PairIdentity,
    predecessor_pair_id: str | None,
) -> None:
    actual = (
        str(row["entitlement_id"]),
        str(row["binding_id"]),
        int(row["revocation_version"]),
        str(row["host_key_sha256"]),
        str(row["android_key_sha256"]),
        str(row["assurance_state"]),
        row["predecessor_pair_id"],
    )
    expected = (
        identity.entitlement_id,
        identity.binding_id,
        identity.revocation_version,
        identity.host_key_sha256,
        identity.android_key_sha256,
        "pending",
        predecessor_pair_id,
    )
    if actual != expected:
        raise PairSecurityRepositoryError("pair_security_state_conflict")


def _challenge_retry(
    row: sqlite3.Row,
    expected: _ExpectedPair,
    proposal: _ChallengeProposal,
) -> PairGenerationChallenge:
    actual = (
        str(row["challenge_id"]),
        str(row["request_payload_sha256"]),
        str(row["pair_id"]),
        int(row["binding_revision"]),
        str(row["server_nonce_sha256"]),
        int(row["expires_at_epoch"]),
    )
    exact = (
        proposal.challenge_id,
        proposal.request_payload_sha256,
        expected.pair_id,
        expected.binding_revision,
        proposal.server_nonce_sha256,
        proposal.expires_at_epoch,
    )
    if actual != exact:
        raise PairSecurityRepositoryError(
            "pair_generation_request_payload_mismatch",
        )
    if str(row["status"]) != "issued":
        raise PairSecurityRepositoryError("pair_generation_challenge_not_issued")
    if int(row["expires_at_epoch"]) <= proposal.now_epoch:
        raise PairSecurityRepositoryError("pair_generation_challenge_expired")
    return _challenge_from_row(row)


def _stable_challenge_retry(
    row: sqlite3.Row,
    expected: _ExpectedPair,
    proposal: _ChallengeProposal,
) -> PairGenerationChallenge:
    actual = (
        str(row["challenge_id"]),
        str(row["request_payload_sha256"]),
        str(row["pair_id"]),
        int(row["binding_revision"]),
        str(row["server_nonce_sha256"]),
    )
    exact = (
        proposal.challenge_id,
        proposal.request_payload_sha256,
        expected.pair_id,
        expected.binding_revision,
        proposal.server_nonce_sha256,
    )
    if actual != exact:
        raise PairSecurityRepositoryError(
            "pair_generation_request_payload_mismatch",
        )
    if str(row["status"]) != "issued":
        raise PairSecurityRepositoryError(
            "pair_generation_challenge_not_issued",
        )
    if int(row["expires_at_epoch"]) <= proposal.now_epoch:
        raise PairSecurityRepositoryError(
            "pair_generation_challenge_expired",
        )
    return _challenge_from_row(row)


def _require_exact_allocation_retry(
    row: sqlite3.Row,
    expected: _ExpectedPair,
    proposal: _AllocationProposal,
) -> None:
    actual = (
        str(row["request_payload_sha256"]),
        str(row["challenge_id"]),
        str(row["pair_id"]),
        int(row["binding_revision"]),
        int(row["connection_id"]),
        str(row["transcript_proposal_sha256"]),
    )
    exact = (
        proposal.request_payload_sha256,
        proposal.challenge_id,
        expected.pair_id,
        expected.binding_revision,
        proposal.connection_id,
        proposal.transcript_proposal_sha256,
    )
    if actual != exact:
        raise PairSecurityRepositoryError(
            "pair_generation_request_payload_mismatch",
        )


@contextmanager
def _immediate_transaction(
    settings: DualMachineSettings,
) -> Iterator[sqlite3.Connection]:
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def _record_pair_generation_audit(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    subject_id: str,
    trace_id: str,
    ip_address: str,
    detail: dict[str, object],
) -> None:
    if (
        any(
            type(value) is not str
            for value in (event_type, subject_id, trace_id, ip_address)
        )
        or type(detail) is not dict
    ):
        raise PairSecurityRepositoryError(
            "pair_generation_audit_input_invalid",
        )
    write_audit_event(
        connection,
        event_type=event_type,
        subject_type="pair_generation",
        subject_id=subject_id,
        trace_id=trace_id,
        ip_address=ip_address,
        detail=detail,
    )


def _state_row(
    connection: sqlite3.Connection,
    pair_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM dm_pair_security_state WHERE pair_id = ?",
        (pair_id,),
    ).fetchone()


def _required_state(
    connection: sqlite3.Connection,
    pair_id: str,
) -> PairSecurityState:
    row = _state_row(connection, pair_id)
    if row is None:
        raise PairSecurityRepositoryError("pair_security_state_missing_after_write")
    return _state_from_row(row)


def _required_challenge(
    connection: sqlite3.Connection,
    challenge_id: str,
) -> PairGenerationChallenge:
    row = connection.execute(
        "SELECT * FROM dm_pair_generation_challenges WHERE challenge_id = ?",
        (challenge_id,),
    ).fetchone()
    if row is None:
        raise PairSecurityRepositoryError("pair_challenge_missing_after_write")
    return _challenge_from_row(row)


def _challenge_row(
    connection: sqlite3.Connection,
    challenge_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM dm_pair_generation_challenges WHERE challenge_id = ?",
        (challenge_id,),
    ).fetchone()


def _allocation_row(
    connection: sqlite3.Connection,
    request_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM dm_pair_generation_allocations "
        "WHERE allocation_request_id = ?",
        (request_id,),
    ).fetchone()


def _required_allocation(
    connection: sqlite3.Connection,
    request_id: str,
) -> PairGenerationAllocation:
    row = _allocation_row(connection, request_id)
    if row is None:
        raise PairSecurityRepositoryError("pair_allocation_missing_after_write")
    return _allocation_from_row(row)


def _state_from_row(row: sqlite3.Row) -> PairSecurityState:
    return PairSecurityState(
        pair_id=str(row["pair_id"]),
        entitlement_id=str(row["entitlement_id"]),
        binding_id=str(row["binding_id"]),
        binding_revision=int(row["binding_revision"]),
        revocation_version=int(row["revocation_version"]),
        host_key_sha256=str(row["host_key_sha256"]),
        android_key_sha256=str(row["android_key_sha256"]),
        assurance_state=str(row["assurance_state"]),
        generation_high_water=int(row["generation_high_water"]),
        predecessor_pair_id=(
            str(row["predecessor_pair_id"])
            if row["predecessor_pair_id"] is not None
            else None
        ),
        created_at_epoch=int(row["created_at_epoch"]),
        updated_at_epoch=int(row["updated_at_epoch"]),
    )


def _challenge_from_row(row: sqlite3.Row) -> PairGenerationChallenge:
    return PairGenerationChallenge(
        challenge_id=str(row["challenge_id"]),
        request_id=str(row["request_id"]),
        request_payload_sha256=str(row["request_payload_sha256"]),
        pair_id=str(row["pair_id"]),
        binding_revision=int(row["binding_revision"]),
        server_nonce_sha256=str(row["server_nonce_sha256"]),
        status=str(row["status"]),
        expires_at_epoch=int(row["expires_at_epoch"]),
        consumed_at_epoch=(
            int(row["consumed_at_epoch"])
            if row["consumed_at_epoch"] is not None
            else None
        ),
        created_at_epoch=int(row["created_at_epoch"]),
    )


def _allocation_from_row(row: sqlite3.Row) -> PairGenerationAllocation:
    return PairGenerationAllocation(
        allocation_request_id=str(row["allocation_request_id"]),
        request_payload_sha256=str(row["request_payload_sha256"]),
        challenge_id=str(row["challenge_id"]),
        pair_id=str(row["pair_id"]),
        binding_revision=int(row["binding_revision"]),
        generation=int(row["generation"]),
        connection_id=int(row["connection_id"]),
        transcript_proposal_sha256=str(row["transcript_proposal_sha256"]),
        allocated_at_epoch=int(row["allocated_at_epoch"]),
    )


def _credential_journal_from_row(
    row: sqlite3.Row,
) -> PairGenerationCredentialJournalRecord:
    try:
        record = PairGenerationCredentialJournalRecord(
            allocation_request_id=row["allocation_request_id"],
            credential_token=row["credential_token"],
            credential_sha256=row["credential_sha256"],
            key_id=row["key_id"],
            credential_nonce_sha256=row["credential_nonce_sha256"],
            issued_at_epoch=row["issued_at_epoch"],
            not_before_epoch=row["not_before_epoch"],
            expires_at_epoch=row["expires_at_epoch"],
        )
        return _normalize_credential_journal_record(record)
    except PairSecurityRepositoryError:
        raise
    except Exception as exc:
        raise PairSecurityRepositoryError(
            "pair_generation_credential_journal_invalid",
        ) from exc


def _normalize_credential_journal_record(
    record: object,
) -> PairGenerationCredentialJournalRecord:
    if type(record) is not PairGenerationCredentialJournalRecord:
        raise PairSecurityRepositoryError(
            "pair_generation_credential_journal_invalid",
        )
    token = record.credential_token
    if type(token) is not bytes or not 1 <= len(token) <= 8192:
        raise PairSecurityRepositoryError(
            "pair_generation_credential_journal_invalid",
        )
    try:
        token.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PairSecurityRepositoryError(
            "pair_generation_credential_journal_invalid",
        ) from exc
    allocation_request_id = _identifier(
        record.allocation_request_id,
        "allocation_request_id",
    )
    credential_sha256 = _sha256(
        record.credential_sha256,
        "credential_sha256",
    )
    calculated_sha256 = hashlib.sha256(token).hexdigest()
    if not hmac.compare_digest(credential_sha256, calculated_sha256):
        raise PairSecurityRepositoryError(
            "pair_generation_credential_journal_invalid",
        )
    if not is_nonzero_lower_hex(record.key_id, 16):
        raise PairSecurityRepositoryError(
            "pair_generation_credential_key_id_invalid",
        )
    nonce_commitment = _sha256(
        record.credential_nonce_sha256,
        "credential_nonce_sha256",
    )
    issued_at_epoch = _signed_64(
        record.issued_at_epoch,
        "issued_at_epoch",
    )
    not_before_epoch = _signed_64(
        record.not_before_epoch,
        "not_before_epoch",
    )
    expires_at_epoch = _signed_64(
        record.expires_at_epoch,
        "expires_at_epoch",
    )
    if not_before_epoch != issued_at_epoch or expires_at_epoch <= issued_at_epoch:
        raise PairSecurityRepositoryError(
            "pair_generation_credential_time_invalid",
        )
    return PairGenerationCredentialJournalRecord(
        allocation_request_id=allocation_request_id,
        credential_token=bytes(token),
        credential_sha256=credential_sha256,
        key_id=record.key_id,
        credential_nonce_sha256=nonce_commitment,
        issued_at_epoch=issued_at_epoch,
        not_before_epoch=not_before_epoch,
        expires_at_epoch=expires_at_epoch,
    )


def _identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise PairSecurityRepositoryError(f"{field_name}_invalid")
    normalized = value.strip()
    if not normalized or len(normalized) > 128 or normalized != value:
        raise PairSecurityRepositoryError(f"{field_name}_invalid")
    return normalized


def _optional_identifier(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, field_name)


def _sha256(value: object, field_name: str) -> str:
    if not is_nonzero_lower_hex(value, 64):
        raise PairSecurityRepositoryError(f"{field_name}_invalid")
    return value


def _signed_64(
    value: object,
    field_name: str,
    *,
    allow_zero: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PairSecurityRepositoryError(f"{field_name}_invalid")
    minimum = 0 if allow_zero else 1
    if not minimum <= value <= SIGNED_64_MAX:
        raise PairSecurityRepositoryError(f"{field_name}_invalid")
    return value
