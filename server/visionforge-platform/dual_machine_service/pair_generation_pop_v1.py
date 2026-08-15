"""Pure canonical dual-PoP contracts for pair-generation credential v1.

The two payloads in this module are deliberately separate signature domains:

* the challenge request authorizes the server to create one fresh challenge
  before a peer proposal exists;
* the final credential proof binds both peer identities to that challenge and
  to the exact canonical proposal that will be allocated.

This module does not verify signatures, persist state, allocate a generation,
issue a credential, or register a route.  Callers must obtain all identifiers
and live binding values from their authoritative boundaries.  Hash fields in
the final payload are always derived here from canonical bytes or raw nonce
bytes; they are never accepted from a caller.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

from .identity import canonical_json
from .pair_generation_proposal_v1 import (
    MAX_CANONICAL_BYTES as MAXIMUM_CANONICAL_PROPOSAL_BYTES,
)
from .pair_generation_proposal_v1 import (
    PairGenerationProposalError,
    VerifiedPairGenerationProposalV1,
    parse_pair_generation_proposal_v1,
)
from .validation import is_nonzero_lower_hex


PROTOCOL_VERSION = 2
PROPOSAL_VERSION = 1
SIGNED_64_MAX = (1 << 63) - 1

IDENTIFIER_HEX_CHARACTERS = 32
SHA256_HEX_CHARACTERS = 64
SHA256_BYTES = 32
PEER_NONCE_BYTES = 32
SERVER_NONCE_BYTES = 32
MINIMUM_SERVER_NONCE_KEY_BYTES = 32

CHALLENGE_REQUEST_DOMAIN = "visionforge-pair-generation-challenge-request-v1"
FINAL_CREDENTIAL_PROOF_DOMAIN = (
    "visionforge-pair-generation-final-credential-proof-v1"
)
SERVER_NONCE_DERIVATION_DOMAIN = (
    "visionforge-pair-generation-server-nonce-derivation-v1"
)
CONNECTION_ID_DERIVATION_DOMAIN = (
    "visionforge-pair-generation-connection-id-derivation-v1"
)


class PairGenerationPopErrorCode(StrEnum):
    """Stable, non-sensitive failures for the pure PoP boundary."""

    REQUEST_INVALID = "pair_generation_pop_request_invalid"
    IDENTIFIER_INVALID = "pair_generation_pop_identifier_invalid"
    IDENTITY_HASH_INVALID = "pair_generation_pop_identity_hash_invalid"
    IDENTITY_ROLES_INVALID = "pair_generation_pop_identity_roles_invalid"
    SIGNED_64_INVALID = "pair_generation_pop_signed_64_invalid"
    NONCE_INVALID = "pair_generation_pop_nonce_invalid"
    NONCE_ROLES_INVALID = "pair_generation_pop_nonce_roles_invalid"
    SERVER_NONCE_KEY_INVALID = "pair_generation_pop_server_nonce_key_invalid"
    PROPOSAL_INVALID = "pair_generation_pop_proposal_invalid"
    PROPOSAL_BINDING_INVALID = (
        "pair_generation_pop_proposal_binding_invalid"
    )
    REQUEST_INTEGRITY_INVALID = (
        "pair_generation_pop_request_integrity_invalid"
    )
    CONNECTION_ID_ZERO = "pair_generation_pop_connection_id_zero"
    CONNECTION_ID_MISMATCH = "pair_generation_pop_connection_id_mismatch"
    CRYPTO_UNAVAILABLE = "pair_generation_pop_crypto_unavailable"


class PairGenerationPopError(ValueError):
    """Sanitized contract failure without raw identifiers or nonce material."""

    def __init__(self, code: PairGenerationPopErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class PairGenerationChallengeRequestFieldsV1:
    """Caller values covered by the pre-proposal dual signature."""

    request_id: str
    allocation_request_id: str
    entitlement_id: str
    pair_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    host_identity_spki_sha256: str
    android_identity_spki_sha256: str


@dataclass(frozen=True, slots=True)
class PairGenerationChallengeRequestV1:
    """Immutable canonical challenge request and its internally derived hash."""

    fields: PairGenerationChallengeRequestFieldsV1
    canonical_bytes: bytes
    payload_sha256: bytes


@dataclass(frozen=True, slots=True)
class PairGenerationFinalCredentialProofFieldsV1:
    """Exact values covered by both final peer signatures."""

    allocation_request_id: str
    challenge_id: str
    challenge_request_id: str
    challenge_request_payload_sha256: str
    challenge_expires_at_epoch: int
    server_nonce_sha256: str
    entitlement_id: str
    pair_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    host_identity_spki_sha256: str
    android_identity_spki_sha256: str
    connection_id: int
    transcript_proposal_sha256: str


@dataclass(frozen=True, slots=True)
class PairGenerationFinalCredentialProofV1:
    """Immutable canonical final proof and internally derived digests."""

    fields: PairGenerationFinalCredentialProofFieldsV1
    canonical_bytes: bytes
    payload_sha256: bytes


def build_pair_generation_challenge_request_v1(
    fields: PairGenerationChallengeRequestFieldsV1,
) -> PairGenerationChallengeRequestV1:
    """Build the exact canonical JSON signed by both peers before proposal."""

    normalized = _normalize_challenge_request_fields(fields)
    payload = {
        "allocation_request_id": normalized.allocation_request_id,
        "android_identity_spki_sha256": (
            normalized.android_identity_spki_sha256
        ),
        "binding_id": normalized.binding_id,
        "binding_revision": normalized.binding_revision,
        "domain": CHALLENGE_REQUEST_DOMAIN,
        "entitlement_id": normalized.entitlement_id,
        "host_identity_spki_sha256": normalized.host_identity_spki_sha256,
        "pair_id": normalized.pair_id,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": normalized.request_id,
        "revocation_version": normalized.revocation_version,
    }
    canonical = _canonical_json(payload)
    digest = _sha256(canonical)
    return PairGenerationChallengeRequestV1(
        fields=normalized,
        canonical_bytes=canonical,
        payload_sha256=digest,
    )


def derive_pair_generation_server_nonce_v1(
    server_nonce_key: bytes,
    challenge_request: PairGenerationChallengeRequestV1,
    *,
    challenge_id: str,
    challenge_expires_at_epoch: int,
) -> bytes:
    """Derive the retry-stable raw 32-byte server challenge nonce.

    The seed binds the challenge identity, the internally recomputed challenge
    request hash, the pair, binding revision, and immutable expiry.  A distinct
    HMAC domain prevents the same key/message tuple from being reused by the
    connection-ID derivation.
    """

    key = _server_nonce_key(server_nonce_key)
    request = _validated_challenge_request(challenge_request)
    checked_challenge_id = _identifier(challenge_id)
    expires = _positive_signed_64(challenge_expires_at_epoch)
    seed = _canonical_json({
        "binding_revision": request.fields.binding_revision,
        "challenge_expires_at_epoch": expires,
        "challenge_id": checked_challenge_id,
        "challenge_request_payload_sha256": request.payload_sha256.hex(),
        "domain": SERVER_NONCE_DERIVATION_DOMAIN,
        "pair_id": request.fields.pair_id,
        "protocol_version": PROTOCOL_VERSION,
    })
    derived = _hmac_sha256(key, seed)
    if len(derived) != SERVER_NONCE_BYTES or not any(derived):
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    return derived


def derive_pair_generation_connection_id_v1(
    server_nonce: bytes,
    *,
    challenge_id: str,
    host_nonce: bytes,
    android_nonce: bytes,
    pair_id: str,
    host_identity_spki_sha256: str,
    android_identity_spki_sha256: str,
) -> int:
    """Derive a non-zero signed-63 connection ID from both peer roles.

    The first eight digest bytes are interpreted in big-endian order and the
    sign bit is cleared.  A zero result is rejected instead of silently being
    remapped, keeping every implementation's derivation contract identical.
    """

    checked_server_nonce = _fixed_nonzero_bytes(
        server_nonce,
        SERVER_NONCE_BYTES,
    )
    checked_challenge_id = _identifier(challenge_id)
    checked_host_nonce = _fixed_nonzero_bytes(host_nonce, PEER_NONCE_BYTES)
    checked_android_nonce = _fixed_nonzero_bytes(
        android_nonce,
        PEER_NONCE_BYTES,
    )
    if hmac.compare_digest(checked_host_nonce, checked_android_nonce):
        _fail(PairGenerationPopErrorCode.NONCE_ROLES_INVALID)
    checked_pair_id = _identifier(pair_id)
    checked_host_identity, checked_android_identity = _identity_hashes(
        host_identity_spki_sha256,
        android_identity_spki_sha256,
    )
    seed = _canonical_json({
        "android_identity_spki_sha256": checked_android_identity,
        "android_nonce": checked_android_nonce.hex(),
        "challenge_id": checked_challenge_id,
        "domain": CONNECTION_ID_DERIVATION_DOMAIN,
        "host_identity_spki_sha256": checked_host_identity,
        "host_nonce": checked_host_nonce.hex(),
        "pair_id": checked_pair_id,
        "proposal_version": PROPOSAL_VERSION,
        "protocol_version": PROTOCOL_VERSION,
    })
    digest = _hmac_sha256(checked_server_nonce, seed)
    if len(digest) != SHA256_BYTES:
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    connection_id = int.from_bytes(digest[:8], "big") & SIGNED_64_MAX
    if connection_id == 0:
        _fail(PairGenerationPopErrorCode.CONNECTION_ID_ZERO)
    return connection_id


def build_pair_generation_final_credential_proof_v1(
    challenge_request: PairGenerationChallengeRequestV1,
    *,
    challenge_id: str,
    challenge_expires_at_epoch: int,
    server_nonce: bytes,
    canonical_proposal_bytes: bytes,
) -> PairGenerationFinalCredentialProofV1:
    """Build the exact final dual-signature proof for credential issuance.

    The challenge-request, server-nonce, and proposal hashes are recomputed
    here.  No public API parameter exists for any of those digest fields.
    """

    request = _validated_challenge_request(challenge_request)
    checked_challenge_id = _identifier(challenge_id)
    expires = _positive_signed_64(challenge_expires_at_epoch)
    checked_server_nonce = _fixed_nonzero_bytes(
        server_nonce,
        SERVER_NONCE_BYTES,
    )
    request_fields = request.fields
    proposal = _verified_canonical_proposal(canonical_proposal_bytes)
    proposal_fields = proposal.fields
    if (
        proposal_fields.pair_id != request_fields.pair_id
        or proposal_fields.host_identity_spki_sha256.hex()
        != request_fields.host_identity_spki_sha256
        or proposal_fields.android_identity_spki_sha256.hex()
        != request_fields.android_identity_spki_sha256
    ):
        _fail(PairGenerationPopErrorCode.PROPOSAL_BINDING_INVALID)
    checked_connection_id = derive_pair_generation_connection_id_v1(
        checked_server_nonce,
        challenge_id=checked_challenge_id,
        host_nonce=proposal_fields.host_nonce,
        android_nonce=proposal_fields.android_nonce,
        pair_id=request_fields.pair_id,
        host_identity_spki_sha256=request_fields.host_identity_spki_sha256,
        android_identity_spki_sha256=(
            request_fields.android_identity_spki_sha256
        ),
    )
    if proposal_fields.connection_id != checked_connection_id:
        _fail(PairGenerationPopErrorCode.CONNECTION_ID_MISMATCH)
    fields = PairGenerationFinalCredentialProofFieldsV1(
        allocation_request_id=request_fields.allocation_request_id,
        challenge_id=checked_challenge_id,
        challenge_request_id=request_fields.request_id,
        challenge_request_payload_sha256=request.payload_sha256.hex(),
        challenge_expires_at_epoch=expires,
        server_nonce_sha256=_sha256(checked_server_nonce).hex(),
        entitlement_id=request_fields.entitlement_id,
        pair_id=request_fields.pair_id,
        binding_id=request_fields.binding_id,
        binding_revision=request_fields.binding_revision,
        revocation_version=request_fields.revocation_version,
        host_identity_spki_sha256=request_fields.host_identity_spki_sha256,
        android_identity_spki_sha256=(
            request_fields.android_identity_spki_sha256
        ),
        connection_id=checked_connection_id,
        transcript_proposal_sha256=_sha256(proposal.canonical_bytes).hex(),
    )
    canonical = _canonical_json({
        "allocation_request_id": fields.allocation_request_id,
        "android_identity_spki_sha256": (
            fields.android_identity_spki_sha256
        ),
        "binding_id": fields.binding_id,
        "binding_revision": fields.binding_revision,
        "challenge_expires_at_epoch": fields.challenge_expires_at_epoch,
        "challenge_id": fields.challenge_id,
        "challenge_request_id": fields.challenge_request_id,
        "challenge_request_payload_sha256": (
            fields.challenge_request_payload_sha256
        ),
        "connection_id": fields.connection_id,
        "domain": FINAL_CREDENTIAL_PROOF_DOMAIN,
        "entitlement_id": fields.entitlement_id,
        "host_identity_spki_sha256": fields.host_identity_spki_sha256,
        "pair_id": fields.pair_id,
        "proposal_version": PROPOSAL_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "revocation_version": fields.revocation_version,
        "server_nonce_sha256": fields.server_nonce_sha256,
        "transcript_proposal_sha256": fields.transcript_proposal_sha256,
    })
    return PairGenerationFinalCredentialProofV1(
        fields=fields,
        canonical_bytes=canonical,
        payload_sha256=_sha256(canonical),
    )


def _normalize_challenge_request_fields(
    fields: object,
) -> PairGenerationChallengeRequestFieldsV1:
    if type(fields) is not PairGenerationChallengeRequestFieldsV1:
        _fail(PairGenerationPopErrorCode.REQUEST_INVALID)
    host_identity, android_identity = _identity_hashes(
        fields.host_identity_spki_sha256,
        fields.android_identity_spki_sha256,
    )
    return PairGenerationChallengeRequestFieldsV1(
        request_id=_identifier(fields.request_id),
        allocation_request_id=_identifier(fields.allocation_request_id),
        entitlement_id=_identifier(fields.entitlement_id),
        pair_id=_identifier(fields.pair_id),
        binding_id=_identifier(fields.binding_id),
        binding_revision=_positive_signed_64(fields.binding_revision),
        revocation_version=_positive_signed_64(fields.revocation_version),
        host_identity_spki_sha256=host_identity,
        android_identity_spki_sha256=android_identity,
    )


def _validated_challenge_request(
    request: object,
) -> PairGenerationChallengeRequestV1:
    if type(request) is not PairGenerationChallengeRequestV1:
        _fail(PairGenerationPopErrorCode.REQUEST_INVALID)
    rebuilt = build_pair_generation_challenge_request_v1(request.fields)
    if (
        type(request.canonical_bytes) is not bytes
        or type(request.payload_sha256) is not bytes
        or len(request.payload_sha256) != SHA256_BYTES
        or not hmac.compare_digest(
            request.canonical_bytes,
            rebuilt.canonical_bytes,
        )
        or not hmac.compare_digest(
            request.payload_sha256,
            rebuilt.payload_sha256,
        )
    ):
        _fail(PairGenerationPopErrorCode.REQUEST_INTEGRITY_INVALID)
    return rebuilt


def _identifier(value: object) -> str:
    if not is_nonzero_lower_hex(value, IDENTIFIER_HEX_CHARACTERS):
        _fail(PairGenerationPopErrorCode.IDENTIFIER_INVALID)
    return value


def _identity_hashes(host_value: object, android_value: object) -> tuple[str, str]:
    if (
        not is_nonzero_lower_hex(host_value, SHA256_HEX_CHARACTERS)
        or not is_nonzero_lower_hex(android_value, SHA256_HEX_CHARACTERS)
    ):
        _fail(PairGenerationPopErrorCode.IDENTITY_HASH_INVALID)
    if hmac.compare_digest(host_value, android_value):
        _fail(PairGenerationPopErrorCode.IDENTITY_ROLES_INVALID)
    return host_value, android_value


def _positive_signed_64(value: object) -> int:
    if type(value) is not int or not 1 <= value <= SIGNED_64_MAX:
        _fail(PairGenerationPopErrorCode.SIGNED_64_INVALID)
    return value


def _fixed_nonzero_bytes(value: object, expected_length: int) -> bytes:
    if (
        type(value) is not bytes
        or len(value) != expected_length
        or not any(value)
    ):
        _fail(PairGenerationPopErrorCode.NONCE_INVALID)
    return value


def _server_nonce_key(value: object) -> bytes:
    if (
        type(value) is not bytes
        or len(value) < MINIMUM_SERVER_NONCE_KEY_BYTES
        or not any(value)
    ):
        _fail(PairGenerationPopErrorCode.SERVER_NONCE_KEY_INVALID)
    return value


def _verified_canonical_proposal(
    value: object,
) -> VerifiedPairGenerationProposalV1:
    if (
        type(value) is not bytes
        or not value
        or len(value) > MAXIMUM_CANONICAL_PROPOSAL_BYTES
    ):
        _fail(PairGenerationPopErrorCode.PROPOSAL_INVALID)
    try:
        verified = parse_pair_generation_proposal_v1(value)
        canonical = verified.canonical_bytes
    except PairGenerationProposalError:
        _fail(PairGenerationPopErrorCode.PROPOSAL_INVALID)
    except Exception:
        _fail(PairGenerationPopErrorCode.PROPOSAL_INVALID)
    if type(canonical) is not bytes or not hmac.compare_digest(canonical, value):
        _fail(PairGenerationPopErrorCode.PROPOSAL_INVALID)
    return verified


def _canonical_json(value: dict[str, object]) -> bytes:
    try:
        canonical = canonical_json(value)
    except Exception:
        _fail(PairGenerationPopErrorCode.REQUEST_INVALID)
    if type(canonical) is not bytes or not canonical:
        _fail(PairGenerationPopErrorCode.REQUEST_INVALID)
    return canonical


def _sha256(value: bytes) -> bytes:
    try:
        digest = hashlib.sha256(value).digest()
    except Exception:
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    if (
        type(digest) is not bytes
        or len(digest) != SHA256_BYTES
        or not any(digest)
    ):
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    return digest


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    try:
        digest = hmac.new(key, message, hashlib.sha256).digest()
    except Exception:
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    if type(digest) is not bytes or len(digest) != SHA256_BYTES:
        _fail(PairGenerationPopErrorCode.CRYPTO_UNAVAILABLE)
    return digest


def _fail(code: PairGenerationPopErrorCode) -> None:
    raise PairGenerationPopError(code) from None
