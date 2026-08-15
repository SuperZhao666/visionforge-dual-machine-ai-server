"""Canonical proposal-v1 cryptographic foundation.

Production callers must source ``connection_id`` from a non-zero 63-bit CSPRNG
or a controlled derivation of both fresh nonces plus a server challenge. Network
fields must come from the live direct-link/socket context, and ``pair_id`` must
come from the verified active server binding. This module does not prove those
authorities, allocate/sign a generation, or register a route.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import threading
import weakref
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from cryptography.hazmat.primitives.asymmetric import ec


PROPOSAL_DOMAIN = b"visionforge-peer-generation-proposal-v1"
FINAL_HANDSHAKE_DOMAIN = b"visionforge-peer-handshake-v1"
PROTOCOL_VERSION = 1
FIELD_COUNT = 17
TLV_HEADER_BYTES = 5
SHA256_BYTES = 32
P256_SEC1_BYTES = 65
NONCE_BYTES = 32
PAIR_ID_BYTES = 32
MAX_RUNTIME_VERSION_BYTES = 32
SIGNED_64_MAX = (1 << 63) - 1
MAX_CANONICAL_BYTES = 503
NO_FIELD_TAG = 0xFF


class ProposalTransportKind(IntEnum):
    CAT6 = 1
    WLAN = 2


class PairGenerationProposalErrorCode(StrEnum):
    PROPOSAL_TOO_LARGE = "proposal_too_large"
    TRUNCATED_TLV = "truncated_tlv"
    UNKNOWN_TAG = "unknown_tag"
    DUPLICATE_TAG = "duplicate_tag"
    OUT_OF_ORDER_TAG = "out_of_order_tag"
    MISSING_FIELD = "missing_field"
    TRAILING_DATA = "trailing_data"
    NONCANONICAL_ENCODING = "noncanonical_encoding"
    INVALID_FIELD_LENGTH = "invalid_field_length"
    INVALID_DOMAIN = "invalid_domain"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_IDENTITY_BINDING = "invalid_identity_binding"
    INVALID_EPHEMERAL_PUBLIC_KEY = "invalid_ephemeral_public_key"
    INVALID_NONCE = "invalid_nonce"
    INVALID_CONNECTION_ID = "invalid_connection_id"
    INVALID_TRANSPORT_KIND = "invalid_transport_kind"
    INVALID_ENDPOINT = "invalid_endpoint"
    INVALID_PAIR_ID = "invalid_pair_id"
    INVALID_RUNTIME_VERSION = "invalid_runtime_version"
    INVALID_GENERATION = "invalid_generation"
    CRYPTO_UNAVAILABLE = "crypto_unavailable"
    OPERATION_FAILED = "operation_failed"


class PairGenerationProposalError(ValueError):
    """Sanitized proposal failure without raw fields or provider exceptions."""

    def __init__(
        self,
        code: PairGenerationProposalErrorCode,
        *,
        field_tag: int = NO_FIELD_TAG,
    ) -> None:
        self.code = code
        self.field_tag = field_tag
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class PairGenerationProposalFields:
    host_identity_spki_sha256: bytes
    android_identity_spki_sha256: bytes
    host_ephemeral_public_key: bytes
    android_ephemeral_public_key: bytes
    host_nonce: bytes
    android_nonce: bytes
    connection_id: int
    transport_kind: ProposalTransportKind
    host_ipv4: bytes
    android_ipv4: bytes
    video_port: int
    control_port: int
    pair_id: str
    host_runtime_version: str
    android_runtime_version: str


_OWNER_TOKEN = object()


@dataclass(frozen=True, slots=True)
class _RegisteredProposalSnapshot:
    fields: PairGenerationProposalFields
    canonical: bytes
    proposal_sha256: bytes


class VerifiedPairGenerationProposalV1:
    """Integrity-checked owner produced only by the strict builder or parser."""

    __slots__ = ("_canonical", "_sha256", "__weakref__")

    def __init__(
        self,
        token: object,
        fields: PairGenerationProposalFields,
        canonical: bytes,
        proposal_sha256: bytes,
    ) -> None:
        if token is not _OWNER_TOKEN:
            raise TypeError("verified proposal construction is restricted")
        self._canonical = canonical
        self._sha256 = proposal_sha256
        _register_verified_proposal(
            self,
            _RegisteredProposalSnapshot(fields, canonical, proposal_sha256),
        )

    @property
    def fields(self) -> PairGenerationProposalFields:
        return _copy_fields(_verified_snapshot(self).fields)

    @property
    def canonical_bytes(self) -> bytes:
        return bytes(_verified_snapshot(self).canonical)

    @property
    def proposal_sha256(self) -> bytes:
        return bytes(_verified_snapshot(self).proposal_sha256)


_VERIFIED_PROPOSAL_REGISTRY: weakref.WeakKeyDictionary[
    VerifiedPairGenerationProposalV1,
    _RegisteredProposalSnapshot,
] = weakref.WeakKeyDictionary()
_VERIFIED_PROPOSAL_REGISTRY_LOCK = threading.RLock()


def _register_verified_proposal(
    proposal: VerifiedPairGenerationProposalV1,
    snapshot: _RegisteredProposalSnapshot,
) -> None:
    with _VERIFIED_PROPOSAL_REGISTRY_LOCK:
        _VERIFIED_PROPOSAL_REGISTRY[proposal] = snapshot


def _verified_snapshot(
    proposal: VerifiedPairGenerationProposalV1,
) -> _RegisteredProposalSnapshot:
    with _VERIFIED_PROPOSAL_REGISTRY_LOCK:
        snapshot = _VERIFIED_PROPOSAL_REGISTRY.get(proposal)
    if snapshot is None:
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    try:
        canonical_is_registered = proposal._canonical is snapshot.canonical
        hash_is_registered = proposal._sha256 is snapshot.proposal_sha256
    except AttributeError:
        canonical_is_registered = False
        hash_is_registered = False
    digest_failed = False
    try:
        calculated_digest = hashlib.sha256(snapshot.canonical).digest()
    except Exception:
        digest_failed = True
        calculated_digest = b""
    if digest_failed:
        _fail(PairGenerationProposalErrorCode.CRYPTO_UNAVAILABLE)
    if (
        not canonical_is_registered
        or not hash_is_registered
        or not hmac.compare_digest(calculated_digest, snapshot.proposal_sha256)
    ):
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    return snapshot


def _copy_fields(
    fields: PairGenerationProposalFields,
) -> PairGenerationProposalFields:
    return PairGenerationProposalFields(
        host_identity_spki_sha256=bytes(fields.host_identity_spki_sha256),
        android_identity_spki_sha256=bytes(fields.android_identity_spki_sha256),
        host_ephemeral_public_key=bytes(fields.host_ephemeral_public_key),
        android_ephemeral_public_key=bytes(fields.android_ephemeral_public_key),
        host_nonce=bytes(fields.host_nonce),
        android_nonce=bytes(fields.android_nonce),
        connection_id=fields.connection_id,
        transport_kind=fields.transport_kind,
        host_ipv4=bytes(fields.host_ipv4),
        android_ipv4=bytes(fields.android_ipv4),
        video_port=fields.video_port,
        control_port=fields.control_port,
        pair_id=fields.pair_id,
        host_runtime_version=fields.host_runtime_version,
        android_runtime_version=fields.android_runtime_version,
    )


class FinalHandshakeTranscriptV1:
    """Restricted Python mirror of the existing C++/Java 18-field transcript."""

    __slots__ = ("_canonical", "_sha256")

    def __init__(self, token: object, canonical: bytes, transcript_sha256: bytes) -> None:
        if token is not _OWNER_TOKEN:
            raise TypeError("final transcript construction is restricted")
        self._canonical = canonical
        self._sha256 = transcript_sha256

    @property
    def canonical_bytes(self) -> bytes:
        return bytes(self._canonical)

    @property
    def transcript_sha256(self) -> bytes:
        return bytes(self._sha256)


def build_pair_generation_proposal_v1(
    fields: PairGenerationProposalFields,
) -> VerifiedPairGenerationProposalV1:
    failure_code: PairGenerationProposalErrorCode | None = None
    try:
        normalized = _normalize_fields(fields)
        canonical = _encode_proposal(normalized)
        if len(canonical) > MAX_CANONICAL_BYTES:
            _fail(PairGenerationProposalErrorCode.PROPOSAL_TOO_LARGE)
        digest = hashlib.sha256(canonical).digest()
        return VerifiedPairGenerationProposalV1(
            _OWNER_TOKEN,
            normalized,
            canonical,
            digest,
        )
    except PairGenerationProposalError:
        raise
    except MemoryError:
        failure_code = PairGenerationProposalErrorCode.OPERATION_FAILED
    except Exception:
        failure_code = PairGenerationProposalErrorCode.OPERATION_FAILED
    _fail(failure_code or PairGenerationProposalErrorCode.OPERATION_FAILED)


def parse_pair_generation_proposal_v1(
    encoded: bytes | bytearray | memoryview,
) -> VerifiedPairGenerationProposalV1:
    if not isinstance(encoded, (bytes, bytearray, memoryview)):
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    encoded_size = encoded.nbytes if isinstance(encoded, memoryview) else len(encoded)
    if encoded_size > MAX_CANONICAL_BYTES:
        _fail(PairGenerationProposalErrorCode.PROPOSAL_TOO_LARGE)
    copy_failed = False
    try:
        canonical = bytes(encoded)
    except MemoryError:
        copy_failed = True
    except Exception:
        copy_failed = True
    if copy_failed:
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    if len(canonical) > MAX_CANONICAL_BYTES:
        _fail(PairGenerationProposalErrorCode.PROPOSAL_TOO_LARGE)

    values: list[bytes] = []
    seen: set[int] = set()
    offset = 0
    for expected_tag in range(FIELD_COUNT):
        remaining = len(canonical) - offset
        if remaining == 0:
            _fail(
                PairGenerationProposalErrorCode.MISSING_FIELD,
                expected_tag,
            )
        if remaining < TLV_HEADER_BYTES:
            _fail(PairGenerationProposalErrorCode.TRUNCATED_TLV)
        actual_tag = canonical[offset]
        if actual_tag >= FIELD_COUNT:
            _fail(PairGenerationProposalErrorCode.UNKNOWN_TAG, actual_tag)
        if actual_tag in seen:
            _fail(PairGenerationProposalErrorCode.DUPLICATE_TAG, actual_tag)
        if actual_tag != expected_tag:
            _fail(PairGenerationProposalErrorCode.OUT_OF_ORDER_TAG, actual_tag)
        encoded_length = int.from_bytes(canonical[offset + 1 : offset + 5], "big")
        if encoded_length > _maximum_field_length(actual_tag):
            _fail(
                PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH,
                actual_tag,
            )
        value_offset = offset + TLV_HEADER_BYTES
        if encoded_length > len(canonical) - value_offset:
            _fail(PairGenerationProposalErrorCode.TRUNCATED_TLV, actual_tag)
        values.append(canonical[value_offset : value_offset + encoded_length])
        seen.add(actual_tag)
        offset = value_offset + encoded_length
    if offset != len(canonical):
        _fail(PairGenerationProposalErrorCode.TRAILING_DATA)

    _require_exact(values[0], PROPOSAL_DOMAIN, 0)
    _require_length(values[1], 4, 1)
    if int.from_bytes(values[1], "big") != PROTOCOL_VERSION:
        _fail(PairGenerationProposalErrorCode.UNSUPPORTED_VERSION, 1)
    fields = PairGenerationProposalFields(
        host_identity_spki_sha256=values[2],
        android_identity_spki_sha256=values[3],
        host_ephemeral_public_key=values[4],
        android_ephemeral_public_key=values[5],
        host_nonce=values[6],
        android_nonce=values[7],
        connection_id=int.from_bytes(values[8], "big"),
        transport_kind=_parse_transport(values[9]),
        host_ipv4=values[10],
        android_ipv4=values[11],
        video_port=int.from_bytes(values[12], "big"),
        control_port=int.from_bytes(values[13], "big"),
        pair_id=_decode_ascii(values[14], 14),
        host_runtime_version=_decode_ascii(values[15], 15),
        android_runtime_version=_decode_ascii(values[16], 16),
    )
    verified = build_pair_generation_proposal_v1(fields)
    if verified.canonical_bytes != canonical:
        _fail(PairGenerationProposalErrorCode.NONCANONICAL_ENCODING)
    return verified


def build_final_handshake_transcript_v1(
    proposal: VerifiedPairGenerationProposalV1,
    generation: int,
) -> FinalHandshakeTranscriptV1:
    if type(proposal) is not VerifiedPairGenerationProposalV1:
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    if (
        type(generation) is not int
        or generation < 1
        or generation > SIGNED_64_MAX
    ):
        _fail(PairGenerationProposalErrorCode.INVALID_GENERATION, 9)
    snapshot = _verified_snapshot(proposal)
    reparsed = parse_pair_generation_proposal_v1(snapshot.canonical)
    reparsed_snapshot = _verified_snapshot(reparsed)
    if (
        not hmac.compare_digest(
            reparsed_snapshot.canonical,
            snapshot.canonical,
        )
        or not hmac.compare_digest(
            reparsed_snapshot.proposal_sha256,
            snapshot.proposal_sha256,
        )
        or reparsed_snapshot.fields != snapshot.fields
    ):
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    fields = reparsed_snapshot.fields
    values = [
        FINAL_HANDSHAKE_DOMAIN,
        PROTOCOL_VERSION.to_bytes(4, "big"),
        fields.host_identity_spki_sha256,
        fields.android_identity_spki_sha256,
        fields.host_ephemeral_public_key,
        fields.android_ephemeral_public_key,
        fields.host_nonce,
        fields.android_nonce,
        fields.connection_id.to_bytes(8, "big"),
        generation.to_bytes(8, "big"),
        bytes((int(fields.transport_kind),)),
        fields.host_ipv4,
        fields.android_ipv4,
        fields.video_port.to_bytes(2, "big"),
        fields.control_port.to_bytes(2, "big"),
        fields.pair_id.encode("ascii"),
        fields.host_runtime_version.encode("ascii"),
        fields.android_runtime_version.encode("ascii"),
    ]
    canonical = _encode_tlvs(values)
    hash_failed = False
    try:
        digest = hashlib.sha256(canonical).digest()
    except Exception:
        hash_failed = True
        digest = b""
    if hash_failed:
        _fail(PairGenerationProposalErrorCode.CRYPTO_UNAVAILABLE)
    return FinalHandshakeTranscriptV1(
        _OWNER_TOKEN,
        canonical,
        digest,
    )


def _normalize_fields(
    fields: PairGenerationProposalFields,
) -> PairGenerationProposalFields:
    if type(fields) is not PairGenerationProposalFields:
        _fail(PairGenerationProposalErrorCode.OPERATION_FAILED)
    host_identity = _fixed_bytes(fields.host_identity_spki_sha256, 32, 2)
    android_identity = _fixed_bytes(fields.android_identity_spki_sha256, 32, 3)
    if not any(host_identity) or not any(android_identity):
        _fail(PairGenerationProposalErrorCode.INVALID_IDENTITY_BINDING, 2)
    if host_identity == android_identity:
        _fail(PairGenerationProposalErrorCode.INVALID_IDENTITY_BINDING, 3)

    host_public = _validate_point(fields.host_ephemeral_public_key, 4)
    android_public = _validate_point(fields.android_ephemeral_public_key, 5)
    if host_public == android_public:
        _fail(PairGenerationProposalErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY, 5)

    host_nonce = _fixed_bytes(fields.host_nonce, 32, 6)
    android_nonce = _fixed_bytes(fields.android_nonce, 32, 7)
    if not any(host_nonce) or not any(android_nonce):
        _fail(PairGenerationProposalErrorCode.INVALID_NONCE, 6)
    if host_nonce == android_nonce:
        _fail(PairGenerationProposalErrorCode.INVALID_NONCE, 7)

    connection_id = fields.connection_id
    if (
        type(connection_id) is not int
        or connection_id < 1
        or connection_id > SIGNED_64_MAX
    ):
        _fail(PairGenerationProposalErrorCode.INVALID_CONNECTION_ID, 8)
    if isinstance(fields.transport_kind, bool):
        transport_kind = None
    else:
        try:
            transport_kind = ProposalTransportKind(fields.transport_kind)
        except (TypeError, ValueError):
            transport_kind = None
    if transport_kind is None:
        _fail(PairGenerationProposalErrorCode.INVALID_TRANSPORT_KIND, 9)
    host_ipv4 = _fixed_bytes(fields.host_ipv4, 4, 10)
    android_ipv4 = _fixed_bytes(fields.android_ipv4, 4, 11)
    video_port = _validate_port(fields.video_port, 12)
    control_port = _validate_port(fields.control_port, 13)
    if video_port == control_port:
        _fail(PairGenerationProposalErrorCode.INVALID_ENDPOINT, 13)
    pair_id = _validate_pair_id(fields.pair_id)
    host_version = _validate_runtime_version(fields.host_runtime_version, 15)
    android_version = _validate_runtime_version(
        fields.android_runtime_version,
        16,
    )
    return PairGenerationProposalFields(
        host_identity_spki_sha256=host_identity,
        android_identity_spki_sha256=android_identity,
        host_ephemeral_public_key=host_public,
        android_ephemeral_public_key=android_public,
        host_nonce=host_nonce,
        android_nonce=android_nonce,
        connection_id=connection_id,
        transport_kind=transport_kind,
        host_ipv4=host_ipv4,
        android_ipv4=android_ipv4,
        video_port=video_port,
        control_port=control_port,
        pair_id=pair_id,
        host_runtime_version=host_version,
        android_runtime_version=android_version,
    )


def _validate_point(value: object, tag: int) -> bytes:
    encoded = _fixed_bytes(value, P256_SEC1_BYTES, tag)
    invalid = False
    unavailable = False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    except ValueError:
        invalid = True
    except Exception:
        unavailable = True
    if invalid:
        _fail(PairGenerationProposalErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY, tag)
    if unavailable:
        _fail(PairGenerationProposalErrorCode.CRYPTO_UNAVAILABLE, tag)
    return encoded


def _fixed_bytes(value: object, length: int, tag: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        _fail(PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH, tag)
    conversion_failed = False
    try:
        encoded = bytes(value)
    except Exception:
        conversion_failed = True
        encoded = b""
    if conversion_failed or len(encoded) != length:
        _fail(PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH, tag)
    return encoded


def _validate_port(value: object, tag: int) -> int:
    if (
        type(value) is not int
        or value < 1
        or value > 0xFFFF
    ):
        _fail(PairGenerationProposalErrorCode.INVALID_ENDPOINT, tag)
    return value


def _validate_pair_id(value: object) -> str:
    if type(value) is not str or len(value) != PAIR_ID_BYTES:
        _fail(PairGenerationProposalErrorCode.INVALID_PAIR_ID, 14)
    if any(character not in "0123456789abcdef" for character in value):
        _fail(PairGenerationProposalErrorCode.INVALID_PAIR_ID, 14)
    return value


def _validate_runtime_version(value: object, tag: int) -> str:
    if type(value) is not str:
        _fail(PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION, tag)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        encoded = b""
    if not encoded or len(encoded) > MAX_RUNTIME_VERSION_BYTES:
        _fail(PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION, tag)
    components = value.split(".")
    if len(components) != 3:
        _fail(PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION, tag)
    if any(
        not component.isascii()
        or not component.isdigit()
        or (len(component) > 1 and component[0] == "0")
        for component in components
    ):
        _fail(PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION, tag)
    return value


def _encode_proposal(fields: PairGenerationProposalFields) -> bytes:
    values = [
        PROPOSAL_DOMAIN,
        PROTOCOL_VERSION.to_bytes(4, "big"),
        fields.host_identity_spki_sha256,
        fields.android_identity_spki_sha256,
        fields.host_ephemeral_public_key,
        fields.android_ephemeral_public_key,
        fields.host_nonce,
        fields.android_nonce,
        fields.connection_id.to_bytes(8, "big"),
        bytes((int(fields.transport_kind),)),
        fields.host_ipv4,
        fields.android_ipv4,
        fields.video_port.to_bytes(2, "big"),
        fields.control_port.to_bytes(2, "big"),
        fields.pair_id.encode("ascii"),
        fields.host_runtime_version.encode("ascii"),
        fields.android_runtime_version.encode("ascii"),
    ]
    return _encode_tlvs(values)


def _encode_tlvs(values: list[bytes]) -> bytes:
    output = bytearray()
    for tag, value in enumerate(values):
        output.append(tag)
        output.extend(struct.pack(">I", len(value)))
        output.extend(value)
    return bytes(output)


def _maximum_field_length(tag: int) -> int:
    return (
        len(PROPOSAL_DOMAIN),
        4,
        32,
        32,
        65,
        65,
        32,
        32,
        8,
        1,
        4,
        4,
        2,
        2,
        32,
        32,
        32,
    )[tag]


def _parse_transport(value: bytes) -> ProposalTransportKind:
    _require_length(value, 1, 9)
    try:
        return ProposalTransportKind(value[0])
    except ValueError:
        _fail(PairGenerationProposalErrorCode.INVALID_TRANSPORT_KIND, 9)


def _decode_ascii(value: bytes, tag: int) -> str:
    invalid = False
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        invalid = True
        decoded = ""
    if invalid:
        _fail(PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH, tag)
    return decoded


def _require_exact(value: bytes, expected: bytes, tag: int) -> None:
    if value != expected:
        _fail(PairGenerationProposalErrorCode.INVALID_DOMAIN, tag)


def _require_length(value: bytes, expected: int, tag: int) -> None:
    if len(value) != expected:
        _fail(PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH, tag)


def _fail(
    code: PairGenerationProposalErrorCode,
    field_tag: int = NO_FIELD_TAG,
) -> None:
    raise PairGenerationProposalError(code, field_tag=field_tag) from None
