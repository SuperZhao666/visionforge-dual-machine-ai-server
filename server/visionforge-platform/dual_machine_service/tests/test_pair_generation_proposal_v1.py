from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from dual_machine_service import pair_generation_proposal_v1 as proposal_module
from dual_machine_service.pair_generation_proposal_v1 import (
    MAX_CANONICAL_BYTES,
    SIGNED_64_MAX,
    PairGenerationProposalError,
    PairGenerationProposalErrorCode,
    PairGenerationProposalFields,
    ProposalTransportKind,
    build_final_handshake_transcript_v1,
    build_pair_generation_proposal_v1,
    parse_pair_generation_proposal_v1,
)


HOST_PUBLIC_HEX = (
    "046b17d1f2e12c4247f8bce6e563a440"
    "f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
    "162bce33576b315ececbb6406837bf51f5"
)
ANDROID_PUBLIC_HEX = (
    "047cf27b188d034f7e8a52380304b51a"
    "c3c08969e277f21b35a60b48fc47669978"
    "07775510db8ed040293d9ac69f7430d"
    "bba7dade63ce982299e04b79d227873d1"
)
PROPOSAL_CANONICAL_HEX = (
    "0000000027766973696f6e666f7267652d706565722d67656e65726174696f6e2d"
    "70726f706f73616c2d763101000000040000000102000000200001020304050607"
    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f030000002020212223"
    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0400000041"
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f505"
    "00000041047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc"
    "4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227"
    "873d10600000020404142434445464748494a4b4c4d4e4f50515253545556575859"
    "5a5b5c5d5e5f0700000020606162636465666768696a6b6c6d6e6f707172737475"
    "767778797a7b7c7d7e7f080000000810203040506070800900000001010a000000"
    "04c0a837010b00000004c0a837020c00000002b26e0d00000002b26f0e00000020"
    "30313233343536373839616263646566303132333435363738396162636465660f00"
    "00000731372e382e3437100000000731372e382e3437"
)
PROPOSAL_SHA256_HEX = (
    "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d"
)
FINAL_TRANSCRIPT_SHA256_HEX = (
    "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098"
)
VECTOR_GENERATION = 0x0102_0304_0506_0708


class WeirdInt(int):
    def __lt__(self, other: object) -> bool:
        del other
        return False

    def __gt__(self, other: object) -> bool:
        del other
        return False

    def to_bytes(self, *args: object, **kwargs: object) -> bytes:
        del args, kwargs
        return b"attacker-controlled"


class WeirdStr(str):
    def encode(self, *args: object, **kwargs: object) -> bytes:
        del args, kwargs
        return b"attacker-controlled"


def vector_fields() -> PairGenerationProposalFields:
    return PairGenerationProposalFields(
        host_identity_spki_sha256=bytes(range(0x00, 0x20)),
        android_identity_spki_sha256=bytes(range(0x20, 0x40)),
        host_ephemeral_public_key=bytes.fromhex(HOST_PUBLIC_HEX),
        android_ephemeral_public_key=bytes.fromhex(ANDROID_PUBLIC_HEX),
        host_nonce=bytes(range(0x40, 0x60)),
        android_nonce=bytes(range(0x60, 0x80)),
        connection_id=0x1020_3040_5060_7080,
        transport_kind=ProposalTransportKind.CAT6,
        host_ipv4=bytes.fromhex("c0a83701"),
        android_ipv4=bytes.fromhex("c0a83702"),
        video_port=45678,
        control_port=45679,
        pair_id="0123456789abcdef0123456789abcdef",
        host_runtime_version="17.8.47",
        android_runtime_version="17.8.47",
    )


def test_frozen_cross_language_vector_and_final_transcript_mapping() -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    assert len(proposal.canonical_bytes) == 453
    assert proposal.canonical_bytes.hex() == PROPOSAL_CANONICAL_HEX
    assert proposal.proposal_sha256.hex() == PROPOSAL_SHA256_HEX

    final = build_final_handshake_transcript_v1(proposal, VECTOR_GENERATION)
    assert len(final.canonical_bytes) == 456
    assert final.transcript_sha256.hex() == FINAL_TRANSCRIPT_SHA256_HEX

    proposal_values = _tlv_values(proposal.canonical_bytes, 17)
    final_values = _tlv_values(final.canonical_bytes, 18)
    assert final_values[0] == b"visionforge-peer-handshake-v1"
    assert final_values[1:9] == proposal_values[1:9]
    assert final_values[9] == VECTOR_GENERATION.to_bytes(8, "big")
    assert final_values[10:] == proposal_values[9:]


def test_parse_round_trip_owns_defensive_copies() -> None:
    built = build_pair_generation_proposal_v1(vector_fields())
    mutable = bytearray(built.canonical_bytes)
    parsed = parse_pair_generation_proposal_v1(mutable)
    mutable[0] ^= 0xFF

    assert parsed.canonical_bytes == built.canonical_bytes
    assert parsed.proposal_sha256 == built.proposal_sha256
    returned = parsed.fields
    assert returned == vector_fields()
    assert returned.host_nonce is not vector_fields().host_nonce


def test_builder_validates_converted_memoryview_byte_length() -> None:
    deceptive = memoryview(bytearray(64)).cast("H")
    assert len(deceptive) == 32
    assert deceptive.nbytes == 64
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(vector_fields(), host_identity_spki_sha256=deceptive)
        )
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH


@pytest.mark.parametrize(
    "identity_view",
    [
        memoryview(bytearray(range(32))).cast("I"),
        memoryview(bytearray(range(32))).cast("B", shape=(4, 8)),
        memoryview(bytearray(range(64)))[::2],
    ],
    ids=["cast-format", "multidimensional", "non-contiguous"],
)
def test_memoryview_normalization_always_builds_parseable_proposal(
    identity_view: memoryview,
) -> None:
    assert identity_view.nbytes == 32
    proposal = build_pair_generation_proposal_v1(
        replace(vector_fields(), host_identity_spki_sha256=identity_view)
    )
    parsed = parse_pair_generation_proposal_v1(proposal.canonical_bytes)
    assert parsed.canonical_bytes == proposal.canonical_bytes
    assert len(parsed.fields.host_identity_spki_sha256) == 32


def test_verified_owner_has_no_replaceable_field_bag() -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    changed = replace(
        vector_fields(),
        pair_id="f" * 32,
    )
    with pytest.raises(AttributeError):
        object.__setattr__(proposal, "_fields", changed)
    assert (
        build_final_handshake_transcript_v1(proposal, VECTOR_GENERATION)
        .transcript_sha256.hex()
        == FINAL_TRANSCRIPT_SHA256_HEX
    )


@pytest.mark.parametrize("attribute", ["_canonical", "_sha256"])
def test_verified_owner_rejects_private_integrity_slot_tampering(
    attribute: str,
) -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    replacement = build_pair_generation_proposal_v1(
        replace(vector_fields(), pair_id="f" * 32)
    )
    replacement_value = (
        replacement.canonical_bytes
        if attribute == "_canonical"
        else replacement.proposal_sha256
    )
    object.__setattr__(proposal, attribute, replacement_value)
    with pytest.raises(PairGenerationProposalError) as caught:
        build_final_handshake_transcript_v1(proposal, VECTOR_GENERATION)
    assert caught.value.code is PairGenerationProposalErrorCode.OPERATION_FAILED


def test_verified_owner_rejects_coordinated_canonical_and_hash_replacement() -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    replacement = build_pair_generation_proposal_v1(
        replace(vector_fields(), pair_id="f" * 32)
    )
    object.__setattr__(proposal, "_canonical", replacement.canonical_bytes)
    object.__setattr__(proposal, "_sha256", replacement.proposal_sha256)
    with pytest.raises(PairGenerationProposalError) as caught:
        build_final_handshake_transcript_v1(proposal, VECTOR_GENERATION)
    assert caught.value.code is PairGenerationProposalErrorCode.OPERATION_FAILED


def test_connection_id_rejects_int_subclass_behavior_override() -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(vector_fields(), connection_id=WeirdInt(1))
        )
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_CONNECTION_ID


def test_port_rejects_int_subclass_behavior_override() -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(vector_fields(), video_port=WeirdInt(45678))
        )
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_ENDPOINT


def test_generation_rejects_int_subclass_behavior_override() -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    with pytest.raises(PairGenerationProposalError) as caught:
        build_final_handshake_transcript_v1(
            proposal,
            WeirdInt(VECTOR_GENERATION),
        )
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_GENERATION


def test_pair_id_rejects_str_subclass_behavior_override() -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(
                vector_fields(),
                pair_id=WeirdStr("0123456789abcdef0123456789abcdef"),
            )
        )
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_PAIR_ID


def test_host_runtime_version_rejects_str_subclass_behavior_override() -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(
                vector_fields(),
                host_runtime_version=WeirdStr("17.8.47"),
            )
        )
    assert (
        caught.value.code
        is PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION
    )


def test_android_runtime_version_rejects_str_subclass_behavior_override() -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(
            replace(
                vector_fields(),
                android_runtime_version=WeirdStr("17.8.47"),
            )
        )
    assert (
        caught.value.code
        is PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION
    )


@pytest.mark.parametrize(
    ("mutator", "expected"),
    [
        (
            lambda value: value[: _spans(value)[7][0]]
            + value[_spans(value)[7][1] :],
            PairGenerationProposalErrorCode.OUT_OF_ORDER_TAG,
        ),
        (
            lambda value: _replace_tag(value, 1, 0),
            PairGenerationProposalErrorCode.DUPLICATE_TAG,
        ),
        (
            lambda value: _replace_tag(value, 1, 2),
            PairGenerationProposalErrorCode.OUT_OF_ORDER_TAG,
        ),
        (
            lambda value: _replace_tag(value, 16, 17),
            PairGenerationProposalErrorCode.UNKNOWN_TAG,
        ),
        (
            lambda value: value + b"\x00",
            PairGenerationProposalErrorCode.TRAILING_DATA,
        ),
        (
            lambda value: value[:4],
            PairGenerationProposalErrorCode.TRUNCATED_TLV,
        ),
        (
            lambda value: _replace_length(value, 2, 0xFFFF_FFFF),
            PairGenerationProposalErrorCode.INVALID_FIELD_LENGTH,
        ),
        (
            lambda value: _replace_value_byte(value, 0, -1, ord("2")),
            PairGenerationProposalErrorCode.INVALID_DOMAIN,
        ),
        (
            lambda value: _replace_value_byte(value, 1, -1, 2),
            PairGenerationProposalErrorCode.UNSUPPORTED_VERSION,
        ),
    ],
)
def test_parser_rejects_noncanonical_structures(
    mutator: object,
    expected: PairGenerationProposalErrorCode,
) -> None:
    canonical = build_pair_generation_proposal_v1(vector_fields()).canonical_bytes
    malformed = mutator(canonical)  # type: ignore[operator]
    with pytest.raises(PairGenerationProposalError) as caught:
        parse_pair_generation_proposal_v1(malformed)
    assert caught.value.code is expected


def test_parser_rejects_missing_and_oversize_containers() -> None:
    with pytest.raises(PairGenerationProposalError) as missing:
        parse_pair_generation_proposal_v1(b"")
    assert missing.value.code is PairGenerationProposalErrorCode.MISSING_FIELD

    with pytest.raises(PairGenerationProposalError) as oversized:
        parse_pair_generation_proposal_v1(b"x" * (MAX_CANONICAL_BYTES + 1))
    assert oversized.value.code is PairGenerationProposalErrorCode.PROPOSAL_TOO_LARGE


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        (
            {"host_identity_spki_sha256": bytes(32)},
            PairGenerationProposalErrorCode.INVALID_IDENTITY_BINDING,
        ),
        (
            {"android_identity_spki_sha256": bytes(range(32))},
            PairGenerationProposalErrorCode.INVALID_IDENTITY_BINDING,
        ),
        (
            {"host_ephemeral_public_key": b"\x04" + bytes(64)},
            PairGenerationProposalErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY,
        ),
        (
            {"android_ephemeral_public_key": bytes.fromhex(HOST_PUBLIC_HEX)},
            PairGenerationProposalErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY,
        ),
        (
            {"host_nonce": bytes(32)},
            PairGenerationProposalErrorCode.INVALID_NONCE,
        ),
        (
            {"android_nonce": bytes(range(0x40, 0x60))},
            PairGenerationProposalErrorCode.INVALID_NONCE,
        ),
        (
            {"connection_id": 0},
            PairGenerationProposalErrorCode.INVALID_CONNECTION_ID,
        ),
        (
            {"connection_id": SIGNED_64_MAX + 1},
            PairGenerationProposalErrorCode.INVALID_CONNECTION_ID,
        ),
        (
            {"transport_kind": 3},
            PairGenerationProposalErrorCode.INVALID_TRANSPORT_KIND,
        ),
        (
            {"transport_kind": True},
            PairGenerationProposalErrorCode.INVALID_TRANSPORT_KIND,
        ),
        (
            {"video_port": 0},
            PairGenerationProposalErrorCode.INVALID_ENDPOINT,
        ),
        (
            {"control_port": 45678},
            PairGenerationProposalErrorCode.INVALID_ENDPOINT,
        ),
        (
            {"pair_id": "A" * 32},
            PairGenerationProposalErrorCode.INVALID_PAIR_ID,
        ),
        (
            {"pair_id": "a" * 31},
            PairGenerationProposalErrorCode.INVALID_PAIR_ID,
        ),
        (
            {"host_runtime_version": "01.2.3"},
            PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION,
        ),
        (
            {"android_runtime_version": "1.2.3+dev"},
            PairGenerationProposalErrorCode.INVALID_RUNTIME_VERSION,
        ),
    ],
)
def test_builder_rejects_contract_boundaries(
    changes: dict[str, object],
    expected: PairGenerationProposalErrorCode,
) -> None:
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(replace(vector_fields(), **changes))
    assert caught.value.code is expected
    assert caught.value.__cause__ is None
    assert str(caught.value) == expected.value


@pytest.mark.parametrize("generation", [0, -1, SIGNED_64_MAX + 1, True])
def test_final_helper_requires_positive_signed_64_generation(generation: int) -> None:
    proposal = build_pair_generation_proposal_v1(vector_fields())
    with pytest.raises(PairGenerationProposalError) as caught:
        build_final_handshake_transcript_v1(proposal, generation)
    assert caught.value.code is PairGenerationProposalErrorCode.INVALID_GENERATION


def test_provider_failure_is_sanitized_without_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPublicKey:
        @staticmethod
        def from_encoded_point(curve: object, encoded: bytes) -> None:
            del curve, encoded
            raise RuntimeError("provider-secret-detail")

    monkeypatch.setattr(
        proposal_module,
        "ec",
        SimpleNamespace(
            EllipticCurvePublicKey=FailingPublicKey,
            SECP256R1=lambda: object(),
        ),
    )
    with pytest.raises(PairGenerationProposalError) as caught:
        build_pair_generation_proposal_v1(vector_fields())
    assert caught.value.code is PairGenerationProposalErrorCode.CRYPTO_UNAVAILABLE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "provider-secret-detail" not in str(caught.value)


def _spans(value: bytes) -> list[tuple[int, int, int, int]]:
    result: list[tuple[int, int, int, int]] = []
    offset = 0
    while offset < len(value):
        length = int.from_bytes(value[offset + 1 : offset + 5], "big")
        value_offset = offset + 5
        result.append((offset, value_offset + length, value_offset, length))
        offset = value_offset + length
    return result


def _replace_tag(value: bytes, field_index: int, tag: int) -> bytes:
    mutable = bytearray(value)
    mutable[_spans(value)[field_index][0]] = tag
    return bytes(mutable)


def _replace_length(value: bytes, field_index: int, length: int) -> bytes:
    mutable = bytearray(value)
    tag_offset = _spans(value)[field_index][0]
    mutable[tag_offset + 1 : tag_offset + 5] = length.to_bytes(4, "big")
    return bytes(mutable)


def _replace_value_byte(
    value: bytes,
    field_index: int,
    relative_index: int,
    replacement: int,
) -> bytes:
    mutable = bytearray(value)
    _, _, value_offset, length = _spans(value)[field_index]
    checked_index = relative_index if relative_index >= 0 else length + relative_index
    mutable[value_offset + checked_index] = replacement
    return bytes(mutable)


def _tlv_values(value: bytes, expected_count: int) -> list[bytes]:
    spans = _spans(value)
    assert len(spans) == expected_count
    return [value[value_offset : value_offset + length] for _, _, value_offset, length in spans]
