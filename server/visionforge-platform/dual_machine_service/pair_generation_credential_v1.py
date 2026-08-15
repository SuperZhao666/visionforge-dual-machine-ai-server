"""Strict RS256 credentials for an authoritative peer-generation allocation.

This module is deliberately a pure cryptographic boundary.  It neither reads
settings nor mutates persistence, registers routes, bills usage, or issues
runtime leases.  A future orchestration service must obtain an authoritative
allocation, mint the module-private source capability, persist the first
signed result, and return those same token bytes for exact retries.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import weakref
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


CREDENTIAL_TYPE = "vf-dual-machine-pair-generation-credential-v1"
CREDENTIAL_ISSUER = "visionforge-dual-machine-service"
CREDENTIAL_AUDIENCE = "visionforge-dual-machine-peer-handshake-v1"
DEFAULT_CREDENTIAL_TTL_SECONDS = 15
MAX_CREDENTIAL_TTL_SECONDS = 30
MAX_ALLOCATION_TO_ISSUE_SECONDS = 5
MAX_ISSUED_AT_FUTURE_SECONDS = 2
MAX_TOKEN_ASCII_CHARACTERS = 8192
SIGNED_64_MAX = (1 << 63) - 1

_LOWER_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX_16 = re.compile(r"[0-9a-f]{16}\Z")
_ALLOCATION_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]+\Z")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
_PAYLOAD_KEYS = frozenset({
    "allocation_request_id",
    "android_identity_spki_sha256",
    "aud",
    "binding_id",
    "binding_revision",
    "connection_id",
    "credential_nonce",
    "entitlement_id",
    "exp",
    "generation",
    "host_identity_spki_sha256",
    "iat",
    "iss",
    "nbf",
    "pair_id",
    "revocation_version",
    "transcript_proposal_sha256",
    "typ",
})
_VERIFIED_STRING_FIELDS = (
    "key_id",
    "allocation_request_id",
    "pair_id",
    "entitlement_id",
    "binding_id",
    "host_identity_spki_sha256",
    "android_identity_spki_sha256",
    "transcript_proposal_sha256",
    "credential_nonce",
    "credential_type",
    "issuer",
    "audience",
)
_VERIFIED_INTEGER_FIELDS = (
    "binding_revision",
    "revocation_version",
    "generation",
    "connection_id",
    "issued_at_epoch",
    "not_before_epoch",
    "expires_at_epoch",
)
_VERIFIED_OWNER_TOKEN = object()


__all__ = (
    "CREDENTIAL_AUDIENCE",
    "CREDENTIAL_ISSUER",
    "CREDENTIAL_TYPE",
    "DEFAULT_CREDENTIAL_TTL_SECONDS",
    "MAX_CREDENTIAL_TTL_SECONDS",
    "PairGenerationCredentialError",
    "PairGenerationCredentialErrorCode",
    "PairGenerationCredentialExpectedV1",
    "PairGenerationCredentialV1Verifier",
    "VerifiedPairGenerationCredentialV1",
)


class PairGenerationCredentialErrorCode(StrEnum):
    """Stable failures that never contain keys, tokens, claims, or providers."""

    KEY_INVALID = "pair_generation_credential_key_invalid"
    SOURCE_INVALID = "pair_generation_credential_source_invalid"
    ALLOCATION_TIME_INVALID = (
        "pair_generation_credential_allocation_time_invalid"
    )
    TOKEN_INVALID = "pair_generation_credential_invalid"
    SIGNING_FAILED = "pair_generation_credential_signing_failed"
    OWNER_INVALID = "pair_generation_credential_owner_invalid"


class PairGenerationCredentialError(ValueError):
    """Sanitized credential-boundary failure."""

    def __init__(self, code: PairGenerationCredentialErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class PairGenerationCredentialExpectedV1:
    """Public verification context for one expected allocation credential."""

    allocation_request_id: str
    pair_id: str
    entitlement_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    generation: int
    connection_id: int
    host_identity_spki_sha256: str
    android_identity_spki_sha256: str
    transcript_proposal_sha256: str


@dataclass(frozen=True, slots=True)
class _AuthoritativePairGenerationCredentialSourceV1:
    """Private minting capability reserved for a future trusted service."""

    expected: PairGenerationCredentialExpectedV1
    allocated_at_epoch: int


@dataclass(frozen=True, slots=True)
class _VerifiedCredentialClaimsSnapshot:
    key_id: str
    allocation_request_id: str
    pair_id: str
    entitlement_id: str
    binding_id: str
    binding_revision: int
    revocation_version: int
    generation: int
    connection_id: int
    host_identity_spki_sha256: str
    android_identity_spki_sha256: str
    transcript_proposal_sha256: str
    credential_nonce: str
    credential_type: str
    issuer: str
    audience: str
    issued_at_epoch: int
    not_before_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True, slots=True)
class _RegisteredCredentialSnapshot:
    claims: _VerifiedCredentialClaimsSnapshot
    canonical_token_ascii: bytes
    token_sha256: bytes


@dataclass(frozen=True, slots=True)
class _CredentialVerificationAnchor:
    token_sha256: bytes
    public_key: rsa.RSAPublicKey
    expected: PairGenerationCredentialExpectedV1
    verification_epoch: int


class VerifiedPairGenerationCredentialV1:
    """Integrity-checked typed owner returned only by strict verification."""

    __slots__ = ("_canonical_token_ascii", "_token_sha256", "__weakref__")

    def __init__(
        self,
        owner_token: object,
        canonical_token_ascii: bytes,
        token_sha256: bytes,
    ) -> None:
        if owner_token is not _VERIFIED_OWNER_TOKEN:
            raise TypeError("verified credential construction is restricted")
        self._canonical_token_ascii = canonical_token_ascii
        self._token_sha256 = token_sha256

    @property
    def key_id(self) -> str:
        return _verified_credential_snapshot(self).claims.key_id

    @property
    def allocation_request_id(self) -> str:
        return _verified_credential_snapshot(self).claims.allocation_request_id

    @property
    def pair_id(self) -> str:
        return _verified_credential_snapshot(self).claims.pair_id

    @property
    def entitlement_id(self) -> str:
        return _verified_credential_snapshot(self).claims.entitlement_id

    @property
    def binding_id(self) -> str:
        return _verified_credential_snapshot(self).claims.binding_id

    @property
    def binding_revision(self) -> int:
        return _verified_credential_snapshot(self).claims.binding_revision

    @property
    def revocation_version(self) -> int:
        return _verified_credential_snapshot(self).claims.revocation_version

    @property
    def generation(self) -> int:
        return _verified_credential_snapshot(self).claims.generation

    @property
    def connection_id(self) -> int:
        return _verified_credential_snapshot(self).claims.connection_id

    @property
    def host_identity_spki_sha256(self) -> str:
        return _verified_credential_snapshot(
            self,
        ).claims.host_identity_spki_sha256

    @property
    def android_identity_spki_sha256(self) -> str:
        return _verified_credential_snapshot(
            self,
        ).claims.android_identity_spki_sha256

    @property
    def transcript_proposal_sha256(self) -> str:
        return _verified_credential_snapshot(
            self,
        ).claims.transcript_proposal_sha256

    @property
    def credential_nonce(self) -> str:
        return _verified_credential_snapshot(self).claims.credential_nonce

    @property
    def credential_type(self) -> str:
        return _verified_credential_snapshot(self).claims.credential_type

    @property
    def issuer(self) -> str:
        return _verified_credential_snapshot(self).claims.issuer

    @property
    def audience(self) -> str:
        return _verified_credential_snapshot(self).claims.audience

    @property
    def issued_at_epoch(self) -> int:
        return _verified_credential_snapshot(self).claims.issued_at_epoch

    @property
    def not_before_epoch(self) -> int:
        return _verified_credential_snapshot(self).claims.not_before_epoch

    @property
    def expires_at_epoch(self) -> int:
        return _verified_credential_snapshot(self).claims.expires_at_epoch


@dataclass(frozen=True, slots=True)
class _SignedPairGenerationCredentialV1:
    """Immutable non-secret issuance result for atomic service persistence."""

    token: str
    token_sha256: str
    key_id: str
    verified_claims: VerifiedPairGenerationCredentialV1


@dataclass(frozen=True, slots=True)
class _VerificationKey:
    key_id: str
    canonical_spki_der: bytes
    public_key: rsa.RSAPublicKey


class PairGenerationCredentialV1Verifier:
    """Verify a credential against a bounded RSA rotation keyring and source."""

    __slots__ = ("_verification_keys",)

    def __init__(
        self,
        *,
        public_keys: tuple[rsa.RSAPublicKey, ...],
        other_purpose_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
    ) -> None:
        self._verification_keys = _validated_public_keyring(public_keys)
        _require_disjoint_key_purposes(
            self._verification_keys,
            other_purpose_public_keys,
        )

    def _select_key(self, key_id: str) -> _VerificationKey:
        for key in self._verification_keys:
            if hmac.compare_digest(key.key_id, key_id):
                return key
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _build_verified_owner_boundary():
    registry: weakref.WeakKeyDictionary[
        VerifiedPairGenerationCredentialV1,
        _RegisteredCredentialSnapshot,
    ] = weakref.WeakKeyDictionary()
    anchors: weakref.WeakKeyDictionary[
        VerifiedPairGenerationCredentialV1,
        _CredentialVerificationAnchor,
    ] = weakref.WeakKeyDictionary()
    lock = threading.RLock()

    def create_owner(
        token: str,
        decoded: _DecodedToken,
        key: _VerificationKey,
        expected: PairGenerationCredentialExpectedV1,
        verification_epoch: int,
    ) -> VerifiedPairGenerationCredentialV1:
        canonical_token_ascii = token.encode("ascii")
        token_sha256 = hashlib.sha256(canonical_token_ascii).digest()
        snapshot = _RegisteredCredentialSnapshot(
            claims=_claims_snapshot(decoded),
            canonical_token_ascii=canonical_token_ascii,
            token_sha256=token_sha256,
        )
        anchor = _CredentialVerificationAnchor(
            token_sha256=token_sha256,
            public_key=key.public_key,
            expected=expected,
            verification_epoch=verification_epoch,
        )
        owner = VerifiedPairGenerationCredentialV1(
            _VERIFIED_OWNER_TOKEN,
            canonical_token_ascii,
            token_sha256,
        )
        with lock:
            registry[owner] = snapshot
            anchors[owner] = anchor
        return owner

    def verify(
        self: PairGenerationCredentialV1Verifier,
        token: str,
        *,
        expected: PairGenerationCredentialExpectedV1,
        now_epoch: int,
    ) -> VerifiedPairGenerationCredentialV1:
        expected_claims = _validated_expected(expected)
        now = _strict_epoch(
            now_epoch,
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
        )
        decoded = _decode_compact_token(token)
        key = self._select_key(decoded.header["kid"])
        _verify_signature(key.public_key, decoded)
        _validate_payload(decoded.payload, now_epoch=now)
        _require_expected_claims(decoded.payload, expected_claims)
        return create_owner(
            token,
            decoded,
            key,
            expected_claims,
            now,
        )

    def snapshot_for_owner(
        owner: VerifiedPairGenerationCredentialV1,
    ) -> _RegisteredCredentialSnapshot:
        with lock:
            snapshot = registry.get(owner)
            anchor = anchors.get(owner)
        if (
            type(snapshot) is not _RegisteredCredentialSnapshot
            or type(anchor) is not _CredentialVerificationAnchor
        ):
            _fail(PairGenerationCredentialErrorCode.OWNER_INVALID)
        registered_token: bytes | None = None
        registered_hash: bytes | None = None
        registered_claims: _VerifiedCredentialClaimsSnapshot | None = None
        try:
            registered_token = snapshot.canonical_token_ascii
            registered_hash = snapshot.token_sha256
            registered_claims = snapshot.claims
            slot_token_is_registered = (
                owner._canonical_token_ascii is registered_token
            )
            slot_hash_is_registered = owner._token_sha256 is registered_hash
        except AttributeError:
            slot_token_is_registered = False
            slot_hash_is_registered = False
        if (
            type(registered_token) is not bytes
            or type(registered_hash) is not bytes
            or len(registered_hash) != 32
            or type(registered_claims) is not _VerifiedCredentialClaimsSnapshot
            or type(anchor.token_sha256) is not bytes
            or len(anchor.token_sha256) != 32
            or type(anchor.expected) is not PairGenerationCredentialExpectedV1
            or not _is_strict_signed_64(anchor.verification_epoch)
        ):
            _fail(PairGenerationCredentialErrorCode.OWNER_INVALID)
        calculated_hash = _sha256_or_none(registered_token)
        reparsed: _DecodedToken | None = None
        if (
            type(calculated_hash) is bytes
            and hmac.compare_digest(calculated_hash, anchor.token_sha256)
        ):
            try:
                trusted_key = _validated_public_key(anchor.public_key)
                reparsed = _decode_compact_token(
                    registered_token.decode("ascii")
                )
                _verify_signature(trusted_key.public_key, reparsed)
                _validate_payload(
                    reparsed.payload,
                    now_epoch=anchor.verification_epoch,
                )
                _require_expected_claims(reparsed.payload, anchor.expected)
            except Exception:
                reparsed = None
        reparsed_claims = (
            _claims_snapshot(reparsed) if reparsed is not None else None
        )
        if (
            not slot_token_is_registered
            or not slot_hash_is_registered
            or calculated_hash is None
            or not hmac.compare_digest(calculated_hash, registered_hash)
            or not _claims_exactly_match(reparsed_claims, registered_claims)
        ):
            _fail(PairGenerationCredentialErrorCode.OWNER_INVALID)
        return _RegisteredCredentialSnapshot(
            claims=reparsed_claims,
            canonical_token_ascii=registered_token,
            token_sha256=registered_hash,
        )

    return verify, snapshot_for_owner


(
    _verifier_verify_method,
    _verified_credential_snapshot,
) = _build_verified_owner_boundary()
setattr(PairGenerationCredentialV1Verifier, "verify", _verifier_verify_method)
del _verifier_verify_method
del _build_verified_owner_boundary


class _PairGenerationCredentialV1Signer:
    """Issue only typed credentials with the dedicated current RSA key."""

    __slots__ = (
        "_current_key_id",
        "_private_key",
        "_post_verifier",
        "_ttl_seconds",
    )

    def __init__(
        self,
        *,
        private_key: rsa.RSAPrivateKey,
        current_public_key: rsa.RSAPublicKey,
        previous_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
        other_purpose_public_keys: tuple[rsa.RSAPublicKey, ...] = (),
        ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    ) -> None:
        if type(previous_public_keys) is not tuple:
            _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
        verification_keys = _validated_public_keyring(
            (current_public_key, *previous_public_keys),
        )
        validated_private_key = _validated_private_key(
            private_key,
            verification_keys[0],
        )
        _require_disjoint_key_purposes(
            verification_keys,
            other_purpose_public_keys,
        )
        if type(ttl_seconds) is not int or not (
            1 <= ttl_seconds <= MAX_CREDENTIAL_TTL_SECONDS
        ):
            _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
        self._private_key = validated_private_key
        self._current_key_id = verification_keys[0].key_id
        self._ttl_seconds = ttl_seconds
        self._post_verifier = PairGenerationCredentialV1Verifier(
            public_keys=tuple(key.public_key for key in verification_keys),
            other_purpose_public_keys=other_purpose_public_keys,
        )

    def sign(
        self,
        source: _AuthoritativePairGenerationCredentialSourceV1,
        *,
        now_epoch: int,
    ) -> _SignedPairGenerationCredentialV1:
        authoritative_source = _validated_authoritative_source(source)
        now = _strict_epoch(
            now_epoch,
            PairGenerationCredentialErrorCode.ALLOCATION_TIME_INVALID,
        )
        _require_fresh_allocation(
            authoritative_source,
            now_epoch=now,
            ttl_seconds=self._ttl_seconds,
        )
        nonce = _new_credential_nonce()
        payload = _payload_for_source(
            authoritative_source,
            nonce=nonce,
            now_epoch=now,
            ttl_seconds=self._ttl_seconds,
        )
        token = _sign_token(
            private_key=self._private_key,
            key_id=self._current_key_id,
            payload=payload,
        )
        verified = self._post_verify(token, authoritative_source, now)
        return _SignedPairGenerationCredentialV1(
            token=token,
            token_sha256=hashlib.sha256(token.encode("ascii")).hexdigest(),
            key_id=self._current_key_id,
            verified_claims=verified,
        )

    def _post_verify(
        self,
        token: str,
        source: _AuthoritativePairGenerationCredentialSourceV1,
        now_epoch: int,
    ) -> VerifiedPairGenerationCredentialV1:
        verified: VerifiedPairGenerationCredentialV1 | None = None
        post_verification_failed = False
        try:
            verified = self._post_verifier.verify(
                token,
                expected=source.expected,
                now_epoch=now_epoch,
            )
        except Exception:
            post_verification_failed = True
        if (
            post_verification_failed
            or type(verified) is not VerifiedPairGenerationCredentialV1
            or not hmac.compare_digest(verified.key_id, self._current_key_id)
        ):
            _fail(PairGenerationCredentialErrorCode.SIGNING_FAILED)
        return verified


@dataclass(frozen=True, slots=True)
class _DecodedToken:
    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes
    signature: bytes


def _claims_exactly_match(
    reparsed: _VerifiedCredentialClaimsSnapshot | None,
    registered: _VerifiedCredentialClaimsSnapshot,
) -> bool:
    if type(reparsed) is not _VerifiedCredentialClaimsSnapshot:
        return False
    try:
        for field_name in _VERIFIED_STRING_FIELDS:
            reparsed_value = getattr(reparsed, field_name)
            registered_value = getattr(registered, field_name)
            if (
                type(reparsed_value) is not str
                or type(registered_value) is not str
                or not hmac.compare_digest(reparsed_value, registered_value)
            ):
                return False
        for field_name in _VERIFIED_INTEGER_FIELDS:
            reparsed_value = getattr(reparsed, field_name)
            registered_value = getattr(registered, field_name)
            if (
                type(reparsed_value) is not int
                or type(registered_value) is not int
                or reparsed_value != registered_value
            ):
                return False
    except Exception:
        return False
    return True


def _sha256_or_none(value: bytes) -> bytes | None:
    digest: bytes | None = None
    try:
        digest = hashlib.sha256(value).digest()
    except Exception:
        digest = None
    return digest


def _claims_snapshot(
    decoded: _DecodedToken,
) -> _VerifiedCredentialClaimsSnapshot:
    payload = decoded.payload
    return _VerifiedCredentialClaimsSnapshot(
        key_id=decoded.header["kid"],
        allocation_request_id=payload["allocation_request_id"],
        pair_id=payload["pair_id"],
        entitlement_id=payload["entitlement_id"],
        binding_id=payload["binding_id"],
        binding_revision=payload["binding_revision"],
        revocation_version=payload["revocation_version"],
        generation=payload["generation"],
        connection_id=payload["connection_id"],
        host_identity_spki_sha256=payload["host_identity_spki_sha256"],
        android_identity_spki_sha256=(
            payload["android_identity_spki_sha256"]
        ),
        transcript_proposal_sha256=payload["transcript_proposal_sha256"],
        credential_nonce=payload["credential_nonce"],
        credential_type=payload["typ"],
        issuer=payload["iss"],
        audience=payload["aud"],
        issued_at_epoch=payload["iat"],
        not_before_epoch=payload["nbf"],
        expires_at_epoch=payload["exp"],
    )


def _validated_public_keyring(
    public_keys: tuple[rsa.RSAPublicKey, ...],
) -> tuple[_VerificationKey, ...]:
    if type(public_keys) is not tuple or not 1 <= len(public_keys) <= 3:
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    normalized = tuple(_validated_public_key(key) for key in public_keys)
    key_ids = tuple(key.key_id for key in normalized)
    spkis = tuple(key.canonical_spki_der for key in normalized)
    if len(set(key_ids)) != len(key_ids) or len(set(spkis)) != len(spkis):
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    return normalized


def _validated_public_key(public_key: object) -> _VerificationKey:
    rebuilt = _rebuild_public_key(public_key)
    if rebuilt is None:
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    provider_public_key, canonical_der = rebuilt
    numbers = provider_public_key.public_numbers()
    if provider_public_key.key_size < 3072 or numbers.e != 65537:
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    key_id = hashlib.sha256(canonical_der).hexdigest()[:16]
    return _VerificationKey(key_id, canonical_der, provider_public_key)


def _validated_private_key(
    private_key: object,
    current_public_key: _VerificationKey,
) -> rsa.RSAPrivateKey:
    rebuilt_private_key: rsa.RSAPrivateKey | None = None
    if isinstance(private_key, rsa.RSAPrivateKey):
        try:
            private_numbers = private_key.private_numbers()
            if type(private_numbers) is rsa.RSAPrivateNumbers:
                rebuilt_private_key = private_numbers.private_key()
        except Exception:
            rebuilt_private_key = None
    if rebuilt_private_key is None:
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    private_public_numbers = rebuilt_private_key.public_key().public_numbers()
    if (
        rebuilt_private_key.key_size < 3072
        or private_public_numbers.e != 65537
        or private_public_numbers
        != current_public_key.public_key.public_numbers()
    ):
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    return rebuilt_private_key


def _rebuild_public_key(
    public_key: object,
) -> tuple[rsa.RSAPublicKey, bytes] | None:
    rebuilt_public_key: rsa.RSAPublicKey | None = None
    canonical_der: bytes | None = None
    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_numbers = public_key.public_numbers()
            if type(public_numbers) is rsa.RSAPublicNumbers:
                rebuilt_public_key = rsa.RSAPublicNumbers(
                    public_numbers.e,
                    public_numbers.n,
                ).public_key()
                canonical_der = rebuilt_public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        except Exception:
            rebuilt_public_key = None
            canonical_der = None
    if rebuilt_public_key is None or canonical_der is None:
        return None
    return rebuilt_public_key, canonical_der


def _require_disjoint_key_purposes(
    pair_keys: tuple[_VerificationKey, ...],
    other_purpose_public_keys: tuple[rsa.RSAPublicKey, ...],
) -> None:
    if type(other_purpose_public_keys) is not tuple:
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
    other_spki_hashes: set[bytes] = set()
    for public_key in other_purpose_public_keys:
        rebuilt = _rebuild_public_key(public_key)
        if rebuilt is None:
            _fail(PairGenerationCredentialErrorCode.KEY_INVALID)
        _provider_public_key, canonical_der = rebuilt
        other_spki_hashes.add(hashlib.sha256(canonical_der).digest())
    pair_spki_hashes = {
        hashlib.sha256(key.canonical_spki_der).digest()
        for key in pair_keys
    }
    if not pair_spki_hashes.isdisjoint(other_spki_hashes):
        _fail(PairGenerationCredentialErrorCode.KEY_INVALID)


def _validated_expected(
    source: object,
) -> PairGenerationCredentialExpectedV1:
    if type(source) is not PairGenerationCredentialExpectedV1:
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    if not _is_allocation_request_id(source.allocation_request_id):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    if not all(
        _is_lower_hex(value, _LOWER_HEX_32)
        for value in (source.pair_id, source.entitlement_id, source.binding_id)
    ):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    if not all(
        _is_strict_signed_64(value)
        for value in (
            source.binding_revision,
            source.revocation_version,
            source.generation,
            source.connection_id,
        )
    ):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    hashes_to_validate = (
        source.host_identity_spki_sha256,
        source.android_identity_spki_sha256,
        source.transcript_proposal_sha256,
    )
    if not all(_is_lower_hex(value, _LOWER_HEX_64) for value in hashes_to_validate):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    if hmac.compare_digest(
        source.host_identity_spki_sha256,
        source.android_identity_spki_sha256,
    ):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    return source


def _validated_authoritative_source(
    source: object,
) -> _AuthoritativePairGenerationCredentialSourceV1:
    if type(source) is not _AuthoritativePairGenerationCredentialSourceV1:
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    _validated_expected(source.expected)
    if not _is_strict_signed_64(source.allocated_at_epoch):
        _fail(PairGenerationCredentialErrorCode.SOURCE_INVALID)
    return source


def _is_allocation_request_id(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 128:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return _ALLOCATION_REQUEST_ID.fullmatch(value) is not None


def _strict_epoch(
    value: object,
    error_code: PairGenerationCredentialErrorCode,
) -> int:
    if not _is_strict_signed_64(value):
        _fail(error_code)
    return value


def _is_strict_signed_64(value: object) -> bool:
    return type(value) is int and 1 <= value <= SIGNED_64_MAX


def _is_lower_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return (
        type(value) is str
        and pattern.fullmatch(value) is not None
        and any(character != "0" for character in value)
    )


def _require_fresh_allocation(
    source: _AuthoritativePairGenerationCredentialSourceV1,
    *,
    now_epoch: int,
    ttl_seconds: int,
) -> None:
    if (
        now_epoch < source.allocated_at_epoch
        or now_epoch - source.allocated_at_epoch
        > MAX_ALLOCATION_TO_ISSUE_SECONDS
        or now_epoch > SIGNED_64_MAX - ttl_seconds
    ):
        _fail(PairGenerationCredentialErrorCode.ALLOCATION_TIME_INVALID)


def _new_credential_nonce() -> str:
    nonce: bytes | None = None
    try:
        candidate = secrets.token_bytes(32)
        if type(candidate) is bytes and len(candidate) == 32:
            nonce = candidate
    except Exception:
        nonce = None
    if nonce is None:
        _fail(PairGenerationCredentialErrorCode.SIGNING_FAILED)
    return nonce.hex()


def _payload_for_source(
    source: _AuthoritativePairGenerationCredentialSourceV1,
    *,
    nonce: str,
    now_epoch: int,
    ttl_seconds: int,
) -> dict[str, Any]:
    expected = source.expected
    return {
        "allocation_request_id": expected.allocation_request_id,
        "android_identity_spki_sha256": (
            expected.android_identity_spki_sha256
        ),
        "aud": CREDENTIAL_AUDIENCE,
        "binding_id": expected.binding_id,
        "binding_revision": expected.binding_revision,
        "connection_id": expected.connection_id,
        "credential_nonce": nonce,
        "entitlement_id": expected.entitlement_id,
        "exp": now_epoch + ttl_seconds,
        "generation": expected.generation,
        "host_identity_spki_sha256": expected.host_identity_spki_sha256,
        "iat": now_epoch,
        "iss": CREDENTIAL_ISSUER,
        "nbf": now_epoch,
        "pair_id": expected.pair_id,
        "revocation_version": expected.revocation_version,
        "transcript_proposal_sha256": expected.transcript_proposal_sha256,
        "typ": CREDENTIAL_TYPE,
    }


def _sign_token(
    *,
    private_key: rsa.RSAPrivateKey,
    key_id: str,
    payload: dict[str, Any],
) -> str:
    header = {"alg": "RS256", "kid": key_id, "typ": "JWT"}
    signing_input = (
        _base64url_encode(_canonical_json(header))
        + "."
        + _base64url_encode(_canonical_json(payload))
    ).encode("ascii")
    signature: bytes | None = None
    try:
        candidate = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        if type(candidate) is bytes:
            signature = candidate
    except Exception:
        signature = None
    if signature is None:
        _fail(PairGenerationCredentialErrorCode.SIGNING_FAILED)
    token = signing_input.decode("ascii") + "." + _base64url_encode(signature)
    if len(token) > MAX_TOKEN_ASCII_CHARACTERS:
        _fail(PairGenerationCredentialErrorCode.SIGNING_FAILED)
    return token


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_compact_token(token: object) -> _DecodedToken:
    token_ascii: bytes | None = None
    if type(token) is str and 1 <= len(token) <= MAX_TOKEN_ASCII_CHARACTERS:
        try:
            token_ascii = token.encode("ascii")
        except UnicodeEncodeError:
            token_ascii = None
    if token_ascii is None:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    segments = token.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    header_raw = _base64url_decode(segments[0])
    payload_raw = _base64url_decode(segments[1])
    signature = _base64url_decode(segments[2])
    header = _decode_canonical_json_object(header_raw)
    payload = _decode_canonical_json_object(payload_raw)
    _validate_header(header)
    return _DecodedToken(
        header=header,
        payload=payload,
        signing_input=(segments[0] + "." + segments[1]).encode("ascii"),
        signature=signature,
    )


def _base64url_decode(value: str) -> bytes:
    decoded: bytes | None = None
    if _BASE64URL.fullmatch(value) is not None:
        try:
            candidate = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
            if _base64url_encode(candidate) == value:
                decoded = candidate
        except Exception:
            decoded = None
    if decoded is None:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    return decoded


class _DuplicateJsonKey(ValueError):
    pass


def _decode_canonical_json_object(raw: bytes) -> dict[str, Any]:
    value: object | None = None
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except Exception:
        value = None
    if type(value) is not dict:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    canonical: bytes | None = None
    try:
        canonical = _canonical_json(value)
    except Exception:
        canonical = None
    if canonical != raw:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _validate_header(header: dict[str, Any]) -> None:
    if (
        frozenset(header) != _HEADER_KEYS
        or header.get("alg") != "RS256"
        or header.get("typ") != "JWT"
        or not _is_lower_hex(header.get("kid"), _LOWER_HEX_16)
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _verify_signature(
    public_key: rsa.RSAPublicKey,
    decoded: _DecodedToken,
) -> None:
    verified = False
    try:
        public_key.verify(
            decoded.signature,
            decoded.signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        verified = True
    except Exception:
        verified = False
    if not verified:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _validate_payload(payload: dict[str, Any], *, now_epoch: int) -> None:
    if frozenset(payload) != _PAYLOAD_KEYS:
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    if (
        payload.get("typ") != CREDENTIAL_TYPE
        or payload.get("iss") != CREDENTIAL_ISSUER
        or payload.get("aud") != CREDENTIAL_AUDIENCE
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    _validate_payload_identifiers(payload)
    _validate_payload_numbers(payload)
    _validate_payload_times(payload, now_epoch=now_epoch)


def _validate_payload_identifiers(payload: dict[str, Any]) -> None:
    if (
        not _is_allocation_request_id(payload.get("allocation_request_id"))
        or not all(
            _is_lower_hex(payload.get(name), _LOWER_HEX_32)
            for name in ("pair_id", "entitlement_id", "binding_id")
        )
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    hash_names = (
        "host_identity_spki_sha256",
        "android_identity_spki_sha256",
        "transcript_proposal_sha256",
        "credential_nonce",
    )
    if not all(
        _is_lower_hex(payload.get(name), _LOWER_HEX_64)
        for name in hash_names
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)
    if hmac.compare_digest(
        payload["host_identity_spki_sha256"],
        payload["android_identity_spki_sha256"],
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _validate_payload_numbers(payload: dict[str, Any]) -> None:
    number_names = (
        "binding_revision",
        "revocation_version",
        "generation",
        "connection_id",
        "iat",
        "nbf",
        "exp",
    )
    if not all(_is_strict_signed_64(payload.get(name)) for name in number_names):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _validate_payload_times(
    payload: dict[str, Any],
    *,
    now_epoch: int,
) -> None:
    issued_at = payload["iat"]
    not_before = payload["nbf"]
    expires_at = payload["exp"]
    if (
        not_before != issued_at
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_CREDENTIAL_TTL_SECONDS
        or issued_at > now_epoch + MAX_ISSUED_AT_FUTURE_SECONDS
        or expires_at <= now_epoch
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _require_expected_claims(
    payload: dict[str, Any],
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    string_matches = (
        (payload["allocation_request_id"], expected.allocation_request_id),
        (payload["pair_id"], expected.pair_id),
        (payload["entitlement_id"], expected.entitlement_id),
        (payload["binding_id"], expected.binding_id),
        (
            payload["host_identity_spki_sha256"],
            expected.host_identity_spki_sha256,
        ),
        (
            payload["android_identity_spki_sha256"],
            expected.android_identity_spki_sha256,
        ),
        (
            payload["transcript_proposal_sha256"],
            expected.transcript_proposal_sha256,
        ),
    )
    number_matches = (
        (payload["binding_revision"], expected.binding_revision),
        (payload["revocation_version"], expected.revocation_version),
        (payload["generation"], expected.generation),
        (payload["connection_id"], expected.connection_id),
    )
    if (
        not all(
            hmac.compare_digest(actual, expected_value)
            for actual, expected_value in string_matches
        )
        or not all(
            actual == expected_value
            for actual, expected_value in number_matches
        )
    ):
        _fail(PairGenerationCredentialErrorCode.TOKEN_INVALID)


def _fail(code: PairGenerationCredentialErrorCode) -> None:
    raise PairGenerationCredentialError(code)
