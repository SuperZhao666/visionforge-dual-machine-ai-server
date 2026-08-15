"""Atomic issuance service for pair-generation credential v1.

This module is the only trusted orchestration boundary allowed to construct
the credential module's private authoritative source.  It keeps generation
allocation, challenge consumption, signing, immediate verification, and the
append-only credential journal in one SQLite ``BEGIN IMMEDIATE`` transaction.

It deliberately registers no route and performs no proof-free pair activation.
Host and Android consumers must still verify the compact credential at their
operation boundary before any formal data-plane capability can be enabled.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric import rsa

from .pair_generation_credential_v1 import (
    DEFAULT_CREDENTIAL_TTL_SECONDS,
    MAX_ALLOCATION_TO_ISSUE_SECONDS,
    PairGenerationCredentialError,
    PairGenerationCredentialErrorCode,
    PairGenerationCredentialExpectedV1,
    PairGenerationCredentialV1Verifier,
    _AuthoritativePairGenerationCredentialSourceV1,
    _PairGenerationCredentialV1Signer,
    _SignedPairGenerationCredentialV1,
    _validated_public_key,
)
from .pair_generation_proposal_v1 import (
    PairGenerationProposalError,
    PairGenerationProposalFields,
    VerifiedPairGenerationProposalV1,
    parse_pair_generation_proposal_v1,
)
from .pair_security_repository import (
    SIGNED_64_MAX,
    PairGenerationAllocation,
    PairGenerationCredentialAuthority,
    PairGenerationCredentialJournalRecord,
    PairGenerationCredentialUnitOfWork,
    PairSecurityRepository,
    PairSecurityRepositoryError,
)
from .settings import DualMachineSettings


@dataclass(frozen=True, slots=True)
class PairGenerationCredentialIssueRequestV1:
    """Untrusted request tuple that is revalidated against live state."""

    allocation_request_id: str
    request_payload_sha256: str
    challenge_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    proposal: VerifiedPairGenerationProposalV1


@dataclass(frozen=True, slots=True)
class PairGenerationCredentialIssuanceV1:
    """Exact persisted response returned for both first issue and retries."""

    allocation: PairGenerationAllocation
    credential_token: str
    credential_sha256: str
    key_id: str
    credential_nonce_sha256: str
    issued_at_epoch: int
    not_before_epoch: int
    expires_at_epoch: int


class PairGenerationCredentialServiceErrorCode(StrEnum):
    REQUEST_INVALID = "pair_generation_credential_request_invalid"
    JOURNAL_MISSING = "pair_generation_credential_journal_missing"
    JOURNAL_INVALID = "pair_generation_credential_journal_invalid"
    PERSISTENCE_FAILED = "pair_generation_credential_persistence_failed"


class PairGenerationCredentialServiceError(RuntimeError):
    """Stable service failure without credential or identity material."""

    def __init__(
        self,
        code: PairGenerationCredentialServiceErrorCode,
    ) -> None:
        self.code = code
        super().__init__(code.value)


_JOURNAL_CORRUPTION_REPOSITORY_CODES = frozenset({
    "pair_generation_credential_journal_invalid",
    "pair_generation_credential_key_id_invalid",
    "pair_generation_credential_time_invalid",
})
_JOURNAL_PERSISTENCE_REPOSITORY_CODES = frozenset({
    "pair_generation_credential_journal_conflict",
    "pair_generation_credential_journal_missing_after_write",
})
MAX_JOURNAL_CREDENTIAL_PUBLIC_KEYS = 16


class _JournalCredentialVerifierArchive:
    """Startup-loaded trusted public keys used only for exact journal replay."""

    __slots__ = ("_verifiers",)

    def __init__(
        self,
        *,
        public_keys: tuple[rsa.RSAPublicKey, ...],
        other_purpose_public_keys: tuple[rsa.RSAPublicKey, ...],
    ) -> None:
        if (
            type(public_keys) is not tuple
            or not 1 <= len(public_keys) <= MAX_JOURNAL_CREDENTIAL_PUBLIC_KEYS
        ):
            raise PairGenerationCredentialError(
                PairGenerationCredentialErrorCode.KEY_INVALID,
            )
        entries: list[tuple[str, PairGenerationCredentialV1Verifier]] = []
        seen_key_ids: set[str] = set()
        for public_key in public_keys:
            normalized = _validated_public_key(public_key)
            if normalized.key_id in seen_key_ids:
                raise PairGenerationCredentialError(
                    PairGenerationCredentialErrorCode.KEY_INVALID,
                )
            seen_key_ids.add(normalized.key_id)
            entries.append((
                normalized.key_id,
                PairGenerationCredentialV1Verifier(
                    public_keys=(normalized.public_key,),
                    other_purpose_public_keys=other_purpose_public_keys,
                ),
            ))
        self._verifiers = tuple(entries)

    def verifier_for_key_id(
        self,
        key_id: str,
    ) -> PairGenerationCredentialV1Verifier:
        if type(key_id) is not str:
            _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
        selected: PairGenerationCredentialV1Verifier | None = None
        for candidate_key_id, verifier in self._verifiers:
            if hmac.compare_digest(candidate_key_id, key_id):
                selected = verifier
        if selected is None:
            _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
        return selected


class PairGenerationCredentialService:
    """Allocate, mint, journal, and exactly replay one credential."""

    __slots__ = ("_journal_archive", "_repository", "_signer")

    def __init__(
        self,
        *,
        settings: DualMachineSettings,
        private_key: rsa.RSAPrivateKey,
        current_public_key: rsa.RSAPublicKey,
        previous_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
        archived_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
        other_purpose_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
        ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    ) -> None:
        if type(archived_public_keys) is not tuple:
            raise PairGenerationCredentialError(
                PairGenerationCredentialErrorCode.KEY_INVALID,
            )
        verification_ring = (current_public_key, *previous_public_keys)
        self._repository = PairSecurityRepository(settings)
        self._signer = _PairGenerationCredentialV1Signer(
            private_key=private_key,
            current_public_key=current_public_key,
            previous_public_keys=previous_public_keys,
            other_purpose_public_keys=other_purpose_public_keys,
            ttl_seconds=ttl_seconds,
        )
        self._journal_archive = _JournalCredentialVerifierArchive(
            public_keys=(*verification_ring, *archived_public_keys),
            other_purpose_public_keys=other_purpose_public_keys,
        )

    def issue_pair_generation_credential(
        self,
        request: PairGenerationCredentialIssueRequestV1,
        *,
        now_epoch: int,
    ) -> PairGenerationCredentialIssuanceV1:
        """Issue once or return the exact immutable credential bytes.

        A pre-existing allocation without a credential journal row is an
        unrecoverable half-state.  It is never adopted or signed after the
        original transaction because doing so would defeat atomic issuance.
        """
        _require_exact_request_types(request, now_epoch=now_epoch)
        proposal_fields, proposal_sha256 = _verified_proposal_authority(
            request.proposal,
        )
        try:
            with (
                self._repository.pair_generation_credential_unit_of_work()
            ) as unit:
                return self._issue_with_unit_of_work(
                    unit=unit,
                    request=request,
                    proposal_fields=proposal_fields,
                    proposal_sha256=proposal_sha256,
                    now_epoch=now_epoch,
                )
        except (
            PairGenerationCredentialError,
            PairGenerationCredentialServiceError,
        ):
            raise
        except PairSecurityRepositoryError as exc:
            _translate_repository_error(exc)
        except sqlite3.Error as exc:
            raise PairGenerationCredentialServiceError(
                PairGenerationCredentialServiceErrorCode.PERSISTENCE_FAILED,
            ) from exc

    def issue_pair_generation_credential_in_unit_of_work(
        self,
        unit: PairGenerationCredentialUnitOfWork,
        request: PairGenerationCredentialIssueRequestV1,
        *,
        now_epoch: int,
    ) -> PairGenerationCredentialIssuanceV1:
        """Issue after dual-PoP was verified in this exact open transaction.

        The authorization orchestrator owns signature verification.  This
        method owns only allocation, signing, and journal persistence and must
        be called before that orchestrator exits the supplied unit of work.
        """
        if type(unit) is not PairGenerationCredentialUnitOfWork:
            _fail(PairGenerationCredentialServiceErrorCode.REQUEST_INVALID)
        _require_exact_request_types(request, now_epoch=now_epoch)
        proposal_fields, proposal_sha256 = _verified_proposal_authority(
            request.proposal,
        )
        try:
            return self._issue_with_unit_of_work(
                unit=unit,
                request=request,
                proposal_fields=proposal_fields,
                proposal_sha256=proposal_sha256,
                now_epoch=now_epoch,
            )
        except (
            PairGenerationCredentialError,
            PairGenerationCredentialServiceError,
        ):
            raise
        except PairSecurityRepositoryError as exc:
            _translate_repository_error(exc)
        except sqlite3.Error as exc:
            raise PairGenerationCredentialServiceError(
                PairGenerationCredentialServiceErrorCode.PERSISTENCE_FAILED,
            ) from exc

    def issue(
        self,
        request: PairGenerationCredentialIssueRequestV1,
        *,
        now_epoch: int,
    ) -> PairGenerationCredentialIssuanceV1:
        """Backward-compatible alias for the explicit side-effecting method."""
        return self.issue_pair_generation_credential(
            request,
            now_epoch=now_epoch,
        )

    def _issue_with_unit_of_work(
        self,
        *,
        unit: PairGenerationCredentialUnitOfWork,
        request: PairGenerationCredentialIssueRequestV1,
        proposal_fields: PairGenerationProposalFields,
        proposal_sha256: str,
        now_epoch: int,
    ) -> PairGenerationCredentialIssuanceV1:
        authority = unit.allocate_generation(
            allocation_request_id=request.allocation_request_id,
            request_payload_sha256=request.request_payload_sha256,
            challenge_id=request.challenge_id,
            pair_id=proposal_fields.pair_id,
            binding_id=request.binding_id,
            binding_revision=request.binding_revision,
            revocation_version=request.revocation_version,
            host_key_sha256=proposal_fields.host_identity_spki_sha256.hex(),
            android_key_sha256=(
                proposal_fields.android_identity_spki_sha256.hex()
            ),
            connection_id=proposal_fields.connection_id,
            transcript_proposal_sha256=proposal_sha256,
            now_epoch=now_epoch,
        )
        expected = _expected_from_authority(authority)
        if authority.allocation_existed:
            return _replay_existing_credential(
                authority=authority,
                expected=expected,
                verifier_archive=self._journal_archive,
            )
        if authority.existing_journal is not None:
            _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
        record = _sign_credential_record(
            allocation=authority.allocation,
            expected=expected,
            signer=self._signer,
            now_epoch=now_epoch,
        )
        persisted = unit.persist_generation_credential_issuance(record)
        return _verified_journal_result(
            record=persisted,
            allocation=authority.allocation,
            expected=expected,
            verifier_archive=self._journal_archive,
        )


def _require_exact_request_types(
    request: object,
    *,
    now_epoch: object,
) -> None:
    if type(request) is not PairGenerationCredentialIssueRequestV1:
        _fail(PairGenerationCredentialServiceErrorCode.REQUEST_INVALID)
    string_fields = (
        "allocation_request_id",
        "request_payload_sha256",
        "challenge_id",
        "binding_id",
    )
    integer_fields = (
        "binding_revision",
        "revocation_version",
    )
    if (
        any(type(getattr(request, name)) is not str for name in string_fields)
        or any(type(getattr(request, name)) is not int for name in integer_fields)
        or type(request.proposal) is not VerifiedPairGenerationProposalV1
        or type(now_epoch) is not int
        or not 1 <= now_epoch <= SIGNED_64_MAX
    ):
        _fail(PairGenerationCredentialServiceErrorCode.REQUEST_INVALID)


def _verified_proposal_authority(
    proposal: VerifiedPairGenerationProposalV1,
) -> tuple[PairGenerationProposalFields, str]:
    """Reparse registered canonical bytes and derive the server-owned hash."""
    try:
        canonical = proposal.canonical_bytes
        registered_sha256 = proposal.proposal_sha256
        reparsed = parse_pair_generation_proposal_v1(canonical)
        calculated_sha256 = hashlib.sha256(canonical).digest()
        if (
            type(canonical) is not bytes
            or type(registered_sha256) is not bytes
            or len(registered_sha256) != hashlib.sha256().digest_size
            or not hmac.compare_digest(registered_sha256, calculated_sha256)
            or not hmac.compare_digest(reparsed.canonical_bytes, canonical)
            or not hmac.compare_digest(
                reparsed.proposal_sha256,
                registered_sha256,
            )
        ):
            _fail(PairGenerationCredentialServiceErrorCode.REQUEST_INVALID)
        return reparsed.fields, registered_sha256.hex()
    except PairGenerationCredentialServiceError:
        raise
    except PairGenerationProposalError as exc:
        raise PairGenerationCredentialServiceError(
            PairGenerationCredentialServiceErrorCode.REQUEST_INVALID,
        ) from exc


def _expected_from_authority(
    authority: PairGenerationCredentialAuthority,
) -> PairGenerationCredentialExpectedV1:
    allocation = authority.allocation
    context = authority.pair_state
    if (
        allocation.pair_id != context.pair_id
        or allocation.binding_revision != context.binding_revision
        or allocation.generation > context.generation_high_water
    ):
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    return PairGenerationCredentialExpectedV1(
        allocation_request_id=allocation.allocation_request_id,
        pair_id=context.pair_id,
        entitlement_id=context.entitlement_id,
        binding_id=context.binding_id,
        binding_revision=context.binding_revision,
        revocation_version=context.revocation_version,
        generation=allocation.generation,
        connection_id=allocation.connection_id,
        host_identity_spki_sha256=context.host_key_sha256,
        android_identity_spki_sha256=context.android_key_sha256,
        transcript_proposal_sha256=(
            allocation.transcript_proposal_sha256
        ),
    )


def _replay_existing_credential(
    *,
    authority: PairGenerationCredentialAuthority,
    expected: PairGenerationCredentialExpectedV1,
    verifier_archive: _JournalCredentialVerifierArchive,
) -> PairGenerationCredentialIssuanceV1:
    if authority.existing_journal is None:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_MISSING)
    return _verified_journal_result(
        record=authority.existing_journal,
        allocation=authority.allocation,
        expected=expected,
        verifier_archive=verifier_archive,
    )


def _sign_credential_record(
    *,
    allocation: PairGenerationAllocation,
    expected: PairGenerationCredentialExpectedV1,
    signer: _PairGenerationCredentialV1Signer,
    now_epoch: int,
) -> PairGenerationCredentialJournalRecord:
    source = _AuthoritativePairGenerationCredentialSourceV1(
        expected=expected,
        allocated_at_epoch=allocation.allocated_at_epoch,
    )
    signed = signer.sign(source, now_epoch=now_epoch)
    return _credential_record_from_signed(allocation=allocation, signed=signed)


def _credential_record_from_signed(
    *,
    allocation: PairGenerationAllocation,
    signed: _SignedPairGenerationCredentialV1,
) -> PairGenerationCredentialJournalRecord:
    if type(signed) is not _SignedPairGenerationCredentialV1:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    token_ascii = _token_ascii(signed.token)
    calculated_sha256 = hashlib.sha256(token_ascii).hexdigest()
    verified = signed.verified_claims
    nonce_commitment = _nonce_commitment(verified.credential_nonce)
    if (
        not hmac.compare_digest(calculated_sha256, signed.token_sha256)
        or not hmac.compare_digest(verified.key_id, signed.key_id)
        or verified.allocation_request_id != allocation.allocation_request_id
        or verified.generation != allocation.generation
        or verified.connection_id != allocation.connection_id
        or verified.issued_at_epoch < allocation.allocated_at_epoch
        or (
            verified.issued_at_epoch - allocation.allocated_at_epoch
            > MAX_ALLOCATION_TO_ISSUE_SECONDS
        )
    ):
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    return PairGenerationCredentialJournalRecord(
        allocation_request_id=allocation.allocation_request_id,
        credential_token=token_ascii,
        credential_sha256=calculated_sha256,
        key_id=signed.key_id,
        credential_nonce_sha256=nonce_commitment,
        issued_at_epoch=verified.issued_at_epoch,
        not_before_epoch=verified.not_before_epoch,
        expires_at_epoch=verified.expires_at_epoch,
    )


def _verified_journal_result(
    *,
    record: PairGenerationCredentialJournalRecord,
    allocation: PairGenerationAllocation,
    expected: PairGenerationCredentialExpectedV1,
    verifier_archive: _JournalCredentialVerifierArchive,
) -> PairGenerationCredentialIssuanceV1:
    try:
        if type(record) is not PairGenerationCredentialJournalRecord:
            raise ValueError("credential journal owner invalid")
        raw_token = record.credential_token
        if type(raw_token) is not bytes:
            raise ValueError("credential token storage type invalid")
        token = raw_token.decode("ascii")
        token_ascii = _token_ascii(token)
        credential_sha256 = record.credential_sha256
        key_id = record.key_id
        nonce_commitment = record.credential_nonce_sha256
        if any(
            type(value) is not str
            for value in (credential_sha256, key_id, nonce_commitment)
        ):
            raise ValueError("credential journal text type invalid")
        issued_at_epoch = _strict_journal_epoch(record.issued_at_epoch)
        not_before_epoch = _strict_journal_epoch(record.not_before_epoch)
        expires_at_epoch = _strict_journal_epoch(record.expires_at_epoch)
        verifier = verifier_archive.verifier_for_key_id(key_id)
        verified = verifier.verify(
            token,
            expected=expected,
            now_epoch=issued_at_epoch,
        )
        calculated_sha256 = hashlib.sha256(token_ascii).hexdigest()
        calculated_nonce_commitment = _nonce_commitment(
            verified.credential_nonce,
        )
        if (
            type(record.allocation_request_id) is not str
            or record.allocation_request_id != allocation.allocation_request_id
            or not hmac.compare_digest(
                credential_sha256,
                calculated_sha256,
            )
            or not hmac.compare_digest(key_id, verified.key_id)
            or not hmac.compare_digest(
                nonce_commitment,
                calculated_nonce_commitment,
            )
            or verified.issued_at_epoch != issued_at_epoch
            or verified.not_before_epoch != not_before_epoch
            or verified.expires_at_epoch != expires_at_epoch
            or issued_at_epoch < allocation.allocated_at_epoch
            or (
                issued_at_epoch - allocation.allocated_at_epoch
                > MAX_ALLOCATION_TO_ISSUE_SECONDS
            )
        ):
            raise ValueError("credential journal metadata mismatch")
    except Exception as exc:
        raise PairGenerationCredentialServiceError(
            PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID,
        ) from exc
    return PairGenerationCredentialIssuanceV1(
        allocation=allocation,
        credential_token=token,
        credential_sha256=credential_sha256,
        key_id=key_id,
        credential_nonce_sha256=nonce_commitment,
        issued_at_epoch=issued_at_epoch,
        not_before_epoch=not_before_epoch,
        expires_at_epoch=expires_at_epoch,
    )


def _token_ascii(token: object) -> bytes:
    if type(token) is not str:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    if not 1 <= len(encoded) <= 8192:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    return encoded


def _nonce_commitment(nonce: object) -> str:
    if type(nonce) is not str or len(nonce) != 64:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    try:
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    if len(nonce_bytes) != 32 or nonce != nonce_bytes.hex():
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    return hashlib.sha256(nonce_bytes).hexdigest()


def _strict_journal_epoch(value: object) -> int:
    if type(value) is not int or not 1 <= value <= SIGNED_64_MAX:
        _fail(PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID)
    return value


def _translate_repository_error(error: PairSecurityRepositoryError) -> None:
    if error.code in _JOURNAL_CORRUPTION_REPOSITORY_CODES:
        raise PairGenerationCredentialServiceError(
            PairGenerationCredentialServiceErrorCode.JOURNAL_INVALID,
        ) from error
    if error.code in _JOURNAL_PERSISTENCE_REPOSITORY_CODES:
        raise PairGenerationCredentialServiceError(
            PairGenerationCredentialServiceErrorCode.PERSISTENCE_FAILED,
        ) from error
    raise error


def _fail(code: PairGenerationCredentialServiceErrorCode) -> None:
    raise PairGenerationCredentialServiceError(code) from None


__all__ = (
    "MAX_JOURNAL_CREDENTIAL_PUBLIC_KEYS",
    "PairGenerationCredentialIssueRequestV1",
    "PairGenerationCredentialIssuanceV1",
    "PairGenerationCredentialService",
    "PairGenerationCredentialServiceError",
    "PairGenerationCredentialServiceErrorCode",
)
