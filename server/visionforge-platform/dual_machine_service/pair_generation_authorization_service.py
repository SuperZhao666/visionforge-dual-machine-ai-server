"""Transactional dual-peer authorization for pair-generation issuance.

The public routes enter only through this service.  Both registered P-256
identities sign a pre-proposal challenge request and then a distinct final
credential proof.  The final signatures are revalidated while the same
``BEGIN IMMEDIATE`` transaction owns challenge consumption, generation
allocation, RS256 signing, journal persistence, and the success audit.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import time
from typing import Any

from .errors import DualMachineServiceError
from .identity import (
    MAX_ECDSA_SIGNATURE_B64_CHARS,
    decode_canonical_base64,
    parse_p256_identity,
    verify_p256_signature,
)
from .pair_generation_credential_service import (
    PairGenerationCredentialIssueRequestV1,
    PairGenerationCredentialService,
    PairGenerationCredentialServiceError,
)
from .pair_generation_credential_v1 import PairGenerationCredentialError
from .pair_generation_pop_v1 import (
    MAXIMUM_CANONICAL_PROPOSAL_BYTES,
    PROTOCOL_VERSION,
    PairGenerationChallengeRequestFieldsV1,
    PairGenerationChallengeRequestV1,
    PairGenerationPopError,
    build_pair_generation_challenge_request_v1,
    build_pair_generation_final_credential_proof_v1,
    derive_pair_generation_server_nonce_v1,
)
from .pair_generation_proposal_v1 import (
    PairGenerationProposalError,
    VerifiedPairGenerationProposalV1,
    parse_pair_generation_proposal_v1,
)
from .pair_security_repository import (
    SIGNED_64_MAX,
    PairGenerationChallenge,
    PairGenerationChallengeUnitOfWork,
    PairGenerationCredentialUnitOfWork,
    PairGenerationPeerAuthority,
    PairSecurityRepository,
    PairSecurityRepositoryError,
)
from .settings import DualMachineSettings
from .validation import is_nonzero_lower_hex


PAIR_GENERATION_CHALLENGE_TTL_SECONDS = 30
MAX_PROPOSAL_BASE64_CHARACTERS = (
    4 * ((MAXIMUM_CANONICAL_PROPOSAL_BYTES + 2) // 3)
)
_CHALLENGE_ID_DOMAIN = b"vf-pair-generation-challenge-id-v2\x00"
_SERVER_NONCE_KEY_DOMAIN = b"vf-pair-generation-server-nonce-key-v2\x00"
_COMMON_COMMAND_KEYS = frozenset({
    "android_signature_b64",
    "binding_id",
    "binding_revision",
    "entitlement_id",
    "host_signature_b64",
    "pair_id",
    "protocol_version",
    "revocation_version",
})
_CHALLENGE_COMMAND_KEYS = _COMMON_COMMAND_KEYS | {
    "allocation_request_id",
    "request_id",
}
_CREDENTIAL_COMMAND_KEYS = _COMMON_COMMAND_KEYS | {
    "allocation_request_id",
    "challenge_id",
    "proposal_b64",
    "server_nonce",
}


class PairGenerationAuthorizationService:
    """Authenticate both active peers before any generation side effect."""

    __slots__ = ("_credential_service", "_repository", "_settings")

    def __init__(
        self,
        settings: DualMachineSettings,
        *,
        credential_service: PairGenerationCredentialService,
    ) -> None:
        if type(settings) is not DualMachineSettings:
            _request_invalid()
        self._settings = settings
        self._repository = PairSecurityRepository(settings)
        self._credential_service = credential_service

    def create_generation_challenge(
        self,
        command: dict[str, Any],
        *,
        client_ip: str,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Double-check peer PoP and commit one retry-stable challenge."""
        now = _now(now_epoch)
        normalized = _normalize_challenge_command(command)
        early_authority = _load_early_authority(
            self._repository,
            normalized,
        )
        early_request = _build_challenge_request(
            normalized,
            early_authority,
        )
        _verify_dual_signatures(
            early_authority,
            normalized,
            early_request.canonical_bytes,
        )
        try:
            with self._repository.pair_generation_challenge_unit_of_work() as unit:
                challenge, server_nonce = self._commit_challenge(
                    unit=unit,
                    command=normalized,
                    now_epoch=now,
                    trace_id=_audit_text(trace_id),
                    client_ip=_audit_text(client_ip),
                )
        except PairSecurityRepositoryError as exc:
            raise DualMachineServiceError(exc.code, 409) from exc
        except sqlite3.Error as exc:
            raise DualMachineServiceError(
                "pair_generation_persistence_failed",
                503,
            ) from exc
        return _challenge_response(
            challenge,
            challenge_request=early_request,
            server_nonce=server_nonce,
        )

    def issue_generation_credential(
        self,
        command: dict[str, Any],
        *,
        client_ip: str,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Verify final PoP and atomically return persisted credential bytes."""
        now = _now(now_epoch)
        normalized = _normalize_credential_command(command)
        proposal = _parse_proposal(normalized["proposal_b64"])
        try:
            with self._repository.pair_generation_credential_unit_of_work() as unit:
                issuance = self._commit_credential(
                    unit=unit,
                    command=normalized,
                    proposal=proposal,
                    now_epoch=now,
                    trace_id=_audit_text(trace_id),
                    client_ip=_audit_text(client_ip),
                )
        except PairSecurityRepositoryError as exc:
            raise DualMachineServiceError(exc.code, 409) from exc
        except PairGenerationCredentialError as exc:
            raise DualMachineServiceError(exc.code.value, 409) from exc
        except PairGenerationCredentialServiceError as exc:
            raise DualMachineServiceError(exc.code.value, 409) from exc
        except sqlite3.Error as exc:
            raise DualMachineServiceError(
                "pair_generation_persistence_failed",
                503,
            ) from exc
        return _credential_response(issuance)

    def _commit_challenge(
        self,
        *,
        unit: PairGenerationChallengeUnitOfWork,
        command: dict[str, Any],
        now_epoch: int,
        trace_id: str,
        client_ip: str,
    ) -> tuple[PairGenerationChallenge, bytes]:
        authority = _load_locked_authority(unit, command)
        request = _build_challenge_request(command, authority)
        _verify_dual_signatures(
            authority,
            command,
            request.canonical_bytes,
        )
        expected_challenge_id = _derive_challenge_id(
            self._settings.token_secret,
            request,
        )
        existing = unit.load_generation_challenge_by_request_id(
            request.fields.request_id,
        )
        if existing is not None:
            challenge = _require_exact_challenge_replay(
                existing,
                request=request,
                expected_challenge_id=expected_challenge_id,
                now_epoch=now_epoch,
            )
        else:
            challenge = _issue_new_challenge(
                unit,
                authority=authority,
                request=request,
                challenge_id=expected_challenge_id,
                server_nonce_key=_server_nonce_key(
                    self._settings.token_secret,
                ),
                now_epoch=now_epoch,
            )
        server_nonce = _derive_and_check_server_nonce(
            self._settings.token_secret,
            request=request,
            challenge=challenge,
        )
        unit.record_security_audit(
            event_type="pair_generation_challenge_issued",
            subject_id=challenge.challenge_id,
            trace_id=trace_id,
            ip_address=client_ip,
            detail={
                "pair_id": challenge.pair_id,
                "binding_revision": challenge.binding_revision,
                "expires_at_epoch": challenge.expires_at_epoch,
                "request_payload_sha256": challenge.request_payload_sha256,
            },
        )
        return challenge, server_nonce

    def _commit_credential(
        self,
        *,
        unit: PairGenerationCredentialUnitOfWork,
        command: dict[str, Any],
        proposal: VerifiedPairGenerationProposalV1,
        now_epoch: int,
        trace_id: str,
        client_ip: str,
    ):
        authority = _load_locked_authority(unit, command)
        challenge = unit.load_generation_challenge(command["challenge_id"])
        if challenge is None:
            raise DualMachineServiceError(
                "pair_generation_challenge_invalid",
                409,
            )
        request = _build_challenge_request(
            {**command, "request_id": challenge.request_id},
            authority,
        )
        _require_challenge_for_credential(
            challenge,
            request=request,
            command=command,
            now_epoch=now_epoch,
            expected_challenge_id=_derive_challenge_id(
                self._settings.token_secret,
                request,
            ),
        )
        server_nonce = _derive_and_check_server_nonce(
            self._settings.token_secret,
            request=request,
            challenge=challenge,
        )
        if not hmac.compare_digest(
            server_nonce,
            bytes.fromhex(command["server_nonce"]),
        ):
            raise DualMachineServiceError(
                "pair_generation_server_nonce_invalid",
                403,
            )
        try:
            proof = build_pair_generation_final_credential_proof_v1(
                request,
                challenge_id=challenge.challenge_id,
                challenge_expires_at_epoch=challenge.expires_at_epoch,
                server_nonce=server_nonce,
                canonical_proposal_bytes=proposal.canonical_bytes,
            )
        except PairGenerationPopError as exc:
            raise DualMachineServiceError(exc.code.value, 403) from exc
        _verify_dual_signatures(
            authority,
            command,
            proof.canonical_bytes,
        )
        issuance = (
            self._credential_service
            .issue_pair_generation_credential_in_unit_of_work(
                unit,
                PairGenerationCredentialIssueRequestV1(
                    allocation_request_id=request.fields.allocation_request_id,
                    request_payload_sha256=request.payload_sha256.hex(),
                    challenge_id=challenge.challenge_id,
                    binding_id=request.fields.binding_id,
                    binding_revision=request.fields.binding_revision,
                    revocation_version=request.fields.revocation_version,
                    proposal=proposal,
                ),
                now_epoch=now_epoch,
            )
        )
        unit.record_security_audit(
            event_type="pair_generation_credential_issued",
            subject_id=issuance.allocation.allocation_request_id,
            trace_id=trace_id,
            ip_address=client_ip,
            detail={
                "pair_id": issuance.allocation.pair_id,
                "generation": issuance.allocation.generation,
                "connection_id": issuance.allocation.connection_id,
                "credential_sha256": issuance.credential_sha256,
                "key_id": issuance.key_id,
            },
        )
        return issuance


def _normalize_challenge_command(command: object) -> dict[str, Any]:
    if type(command) is not dict or frozenset(command) != _CHALLENGE_COMMAND_KEYS:
        _request_invalid()
    normalized = _normalize_common(command)
    _require_hex(normalized.get("request_id"), 32)
    _require_hex(normalized.get("allocation_request_id"), 32)
    return normalized


def _normalize_credential_command(command: object) -> dict[str, Any]:
    if type(command) is not dict or frozenset(command) != _CREDENTIAL_COMMAND_KEYS:
        _request_invalid()
    normalized = _normalize_common(command)
    _require_hex(normalized.get("allocation_request_id"), 32)
    _require_hex(normalized.get("challenge_id"), 32)
    _require_hex(normalized.get("server_nonce"), 64)
    proposal_b64 = normalized.get("proposal_b64")
    if type(proposal_b64) is not str:
        _request_invalid()
    return normalized


def _normalize_common(command: object) -> dict[str, Any]:
    if type(command) is not dict:
        _request_invalid()
    string_fields = (
        "entitlement_id",
        "pair_id",
        "binding_id",
        "host_signature_b64",
        "android_signature_b64",
    )
    integer_fields = (
        "protocol_version",
        "binding_revision",
        "revocation_version",
    )
    if (
        any(type(command.get(name)) is not str for name in string_fields)
        or any(type(command.get(name)) is not int for name in integer_fields)
        or command.get("protocol_version") != PROTOCOL_VERSION
        or not 1 <= command.get("binding_revision", 0) <= SIGNED_64_MAX
        or not 1 <= command.get("revocation_version", 0) <= SIGNED_64_MAX
    ):
        _request_invalid()
    for name in ("entitlement_id", "pair_id", "binding_id"):
        _require_hex(command[name], 32)
    for name in ("host_signature_b64", "android_signature_b64"):
        if not 8 <= len(command[name]) <= MAX_ECDSA_SIGNATURE_B64_CHARS:
            _request_invalid()
    return dict(command)


def _load_early_authority(
    repository: PairSecurityRepository,
    command: dict[str, Any],
) -> PairGenerationPeerAuthority:
    try:
        return repository.pair_generation_peer_authority_for_context(
            entitlement_id=command["entitlement_id"],
            pair_id=command["pair_id"],
            binding_id=command["binding_id"],
            binding_revision=command["binding_revision"],
            revocation_version=command["revocation_version"],
        )
    except PairSecurityRepositoryError as exc:
        raise DualMachineServiceError(
            "pair_generation_authority_invalid",
            409,
        ) from exc


def _load_locked_authority(unit, command: dict[str, Any]):
    try:
        return unit.load_peer_authority_for_context(
            entitlement_id=command["entitlement_id"],
            pair_id=command["pair_id"],
            binding_id=command["binding_id"],
            binding_revision=command["binding_revision"],
            revocation_version=command["revocation_version"],
        )
    except PairSecurityRepositoryError as exc:
        raise DualMachineServiceError(
            "pair_generation_authority_invalid",
            409,
        ) from exc


def _build_challenge_request(
    command: dict[str, Any],
    authority: PairGenerationPeerAuthority,
) -> PairGenerationChallengeRequestV1:
    state = authority.pair_state
    try:
        return build_pair_generation_challenge_request_v1(
            PairGenerationChallengeRequestFieldsV1(
                request_id=command["request_id"],
                allocation_request_id=command["allocation_request_id"],
                entitlement_id=state.entitlement_id,
                pair_id=state.pair_id,
                binding_id=state.binding_id,
                binding_revision=state.binding_revision,
                revocation_version=state.revocation_version,
                host_identity_spki_sha256=state.host_key_sha256,
                android_identity_spki_sha256=state.android_key_sha256,
            ),
        )
    except PairGenerationPopError as exc:
        raise DualMachineServiceError(exc.code.value, 409) from exc


def _verify_dual_signatures(
    authority: PairGenerationPeerAuthority,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    try:
        host = parse_p256_identity(authority.host_identity_public_key_b64)
        android = parse_p256_identity(authority.android_identity_public_key_b64)
        state = authority.pair_state
        if (
            not hmac.compare_digest(
                host.fingerprint_sha256,
                state.host_key_sha256,
            )
            or not hmac.compare_digest(
                android.fingerprint_sha256,
                state.android_key_sha256,
            )
        ):
            raise ValueError("pair identity fingerprint mismatch")
        verify_p256_signature(
            host,
            command["host_signature_b64"],
            signed_payload,
        )
        verify_p256_signature(
            android,
            command["android_signature_b64"],
            signed_payload,
        )
    except ValueError as exc:
        raise DualMachineServiceError(
            "pair_generation_device_proof_invalid",
            403,
        ) from exc


def _derive_challenge_id(
    secret: bytes,
    request: PairGenerationChallengeRequestV1,
) -> str:
    try:
        digest = hmac.new(
            _domain_key(secret, _CHALLENGE_ID_DOMAIN),
            request.payload_sha256,
            hashlib.sha256,
        ).hexdigest()[:32]
    except Exception as exc:
        raise DualMachineServiceError(
            "pair_generation_challenge_material_invalid",
            503,
        ) from exc
    if not is_nonzero_lower_hex(digest, 32):
        raise DualMachineServiceError(
            "pair_generation_challenge_material_invalid",
            503,
        )
    return digest


def _issue_new_challenge(
    unit: PairGenerationChallengeUnitOfWork,
    *,
    authority: PairGenerationPeerAuthority,
    request: PairGenerationChallengeRequestV1,
    challenge_id: str,
    server_nonce_key: bytes,
    now_epoch: int,
) -> PairGenerationChallenge:
    if now_epoch > SIGNED_64_MAX - PAIR_GENERATION_CHALLENGE_TTL_SECONDS:
        _request_invalid()
    expires_at = now_epoch + PAIR_GENERATION_CHALLENGE_TTL_SECONDS
    try:
        server_nonce = derive_pair_generation_server_nonce_v1(
            server_nonce_key,
            request,
            challenge_id=challenge_id,
            challenge_expires_at_epoch=expires_at,
        )
    except PairGenerationPopError as exc:
        raise DualMachineServiceError(exc.code.value, 503) from exc
    state = authority.pair_state
    return unit.issue_generation_challenge(
        challenge_id=challenge_id,
        request_id=request.fields.request_id,
        request_payload_sha256=request.payload_sha256.hex(),
        pair_id=state.pair_id,
        binding_id=state.binding_id,
        binding_revision=state.binding_revision,
        revocation_version=state.revocation_version,
        host_key_sha256=state.host_key_sha256,
        android_key_sha256=state.android_key_sha256,
        server_nonce_sha256=hashlib.sha256(server_nonce).hexdigest(),
        expires_at_epoch=expires_at,
        now_epoch=now_epoch,
    )


def _require_exact_challenge_replay(
    challenge: PairGenerationChallenge,
    *,
    request: PairGenerationChallengeRequestV1,
    expected_challenge_id: str,
    now_epoch: int,
) -> PairGenerationChallenge:
    if (
        challenge.challenge_id != expected_challenge_id
        or challenge.request_payload_sha256 != request.payload_sha256.hex()
        or challenge.pair_id != request.fields.pair_id
        or challenge.binding_revision != request.fields.binding_revision
        or challenge.status != "issued"
        or challenge.expires_at_epoch <= now_epoch
    ):
        raise PairSecurityRepositoryError(
            "pair_generation_challenge_replay_invalid",
        )
    return challenge


def _derive_and_check_server_nonce(
    secret: bytes,
    *,
    request: PairGenerationChallengeRequestV1,
    challenge: PairGenerationChallenge,
) -> bytes:
    try:
        server_nonce = derive_pair_generation_server_nonce_v1(
            _server_nonce_key(secret),
            request,
            challenge_id=challenge.challenge_id,
            challenge_expires_at_epoch=challenge.expires_at_epoch,
        )
    except PairGenerationPopError as exc:
        raise DualMachineServiceError(exc.code.value, 409) from exc
    if not hmac.compare_digest(
        hashlib.sha256(server_nonce).hexdigest(),
        challenge.server_nonce_sha256,
    ):
        raise DualMachineServiceError(
            "pair_generation_challenge_invalid",
            409,
        )
    return server_nonce


def _require_challenge_for_credential(
    challenge: PairGenerationChallenge,
    *,
    request: PairGenerationChallengeRequestV1,
    command: dict[str, Any],
    now_epoch: int,
    expected_challenge_id: str,
) -> None:
    status_is_usable = challenge.status == "issued" and (
        challenge.expires_at_epoch > now_epoch
    )
    status_is_exact_replay = challenge.status == "consumed"
    if (
        challenge.challenge_id != expected_challenge_id
        or challenge.challenge_id != command["challenge_id"]
        or challenge.request_payload_sha256 != request.payload_sha256.hex()
        or challenge.pair_id != request.fields.pair_id
        or challenge.binding_revision != request.fields.binding_revision
        or not (status_is_usable or status_is_exact_replay)
    ):
        raise DualMachineServiceError(
            "pair_generation_challenge_mismatch",
            409,
        )


def _parse_proposal(proposal_b64: str) -> VerifiedPairGenerationProposalV1:
    try:
        encoded = decode_canonical_base64(
            proposal_b64,
            maximum_characters=MAX_PROPOSAL_BASE64_CHARACTERS,
            error_code="pair_generation_proposal_invalid",
        )
        return parse_pair_generation_proposal_v1(encoded)
    except (ValueError, PairGenerationProposalError) as exc:
        raise DualMachineServiceError(
            "pair_generation_proposal_invalid",
            422,
        ) from exc


def _challenge_response(
    challenge: PairGenerationChallenge,
    *,
    challenge_request: PairGenerationChallengeRequestV1,
    server_nonce: bytes,
) -> dict[str, Any]:
    return {
        "ok": True,
        "request_id": challenge.request_id,
        "allocation_request_id": (
            challenge_request.fields.allocation_request_id
        ),
        "challenge_id": challenge.challenge_id,
        "pair_id": challenge.pair_id,
        "binding_revision": challenge.binding_revision,
        "server_nonce": server_nonce.hex(),
        "challenge_expires_at_epoch": challenge.expires_at_epoch,
    }


def _credential_response(issuance) -> dict[str, Any]:
    allocation = issuance.allocation
    return {
        "ok": True,
        "allocation_request_id": allocation.allocation_request_id,
        "pair_id": allocation.pair_id,
        "binding_revision": allocation.binding_revision,
        "generation": allocation.generation,
        "connection_id": allocation.connection_id,
        "transcript_proposal_sha256": (
            allocation.transcript_proposal_sha256
        ),
        "credential_token": issuance.credential_token,
        "credential_sha256": issuance.credential_sha256,
        "key_id": issuance.key_id,
        "credential_issued_at_epoch": issuance.issued_at_epoch,
        "credential_not_before_epoch": issuance.not_before_epoch,
        "credential_expires_at_epoch": issuance.expires_at_epoch,
    }


def _server_nonce_key(secret: bytes) -> bytes:
    return _domain_key(secret, _SERVER_NONCE_KEY_DOMAIN)


def _domain_key(secret: bytes, domain: bytes) -> bytes:
    if type(secret) is not bytes or len(secret) < 32 or not any(secret):
        raise DualMachineServiceError(
            "pair_generation_challenge_material_invalid",
            503,
        )
    return hmac.new(secret, domain, hashlib.sha256).digest()


def _now(value: int | None) -> int:
    now = int(time.time()) if value is None else value
    if type(now) is not int or not 1 <= now <= SIGNED_64_MAX:
        _request_invalid()
    return now


def _audit_text(value: object) -> str:
    if type(value) is not str:
        return ""
    return value


def _require_hex(value: object, length: int) -> None:
    if not is_nonzero_lower_hex(value, length):
        _request_invalid()


def _request_invalid() -> None:
    raise DualMachineServiceError(
        "pair_generation_request_invalid",
        422,
    ) from None


__all__ = ("PairGenerationAuthorizationService",)
