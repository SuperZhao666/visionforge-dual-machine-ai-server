from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from dual_machine_service import pair_generation_pop_v1 as pop_module
from dual_machine_service.identity import canonical_json
from dual_machine_service.pair_generation_pop_v1 import (
    CHALLENGE_REQUEST_DOMAIN,
    FINAL_CREDENTIAL_PROOF_DOMAIN,
    MAXIMUM_CANONICAL_PROPOSAL_BYTES,
    PROPOSAL_VERSION,
    PROTOCOL_VERSION,
    SIGNED_64_MAX,
    PairGenerationChallengeRequestFieldsV1,
    PairGenerationPopError,
    PairGenerationPopErrorCode,
    build_pair_generation_challenge_request_v1,
    build_pair_generation_final_credential_proof_v1,
    derive_pair_generation_connection_id_v1,
    derive_pair_generation_server_nonce_v1,
)
from dual_machine_service.pair_generation_proposal_v1 import (
    PairGenerationProposalFields,
    ProposalTransportKind,
    build_pair_generation_proposal_v1,
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

VECTOR_CHALLENGE_ID = "06" * 16
VECTOR_EXPIRES_AT = 0x1234_5678
VECTOR_SERVER_NONCE_KEY = bytes(range(1, 33))
VECTOR_HOST_NONCE = bytes(range(0x40, 0x60))
VECTOR_ANDROID_NONCE = bytes(range(0x60, 0x80))
VECTOR_REQUEST_SHA256 = (
    "f5fe7552fdd4009c4fcf6bb795cc8fe49c8ced14f90e82fdef384029f171acea"
)
VECTOR_SERVER_NONCE_HEX = (
    "dc66120c8c1a81e879aac654e34421b55111d30c5e6836df235f18e90c0b0e69"
)
VECTOR_CONNECTION_ID = 63_191_577_505_803_677
VECTOR_PROPOSAL_SHA256 = (
    "f347088b897243eb8a2f1a69fb1e031cacd7f35cd2163efa9741dcf2964caf3f"
)
VECTOR_FINAL_SHA256 = (
    "2fe727665a08adf4893b869a8d5c9842064b53f8952a32693ca37fd2a83a72e1"
)
VECTOR_REQUEST_CANONICAL = (
    b'{"allocation_request_id":"02020202020202020202020202020202",'
    b'"android_identity_spki_sha256":"2020202020202020202020202020202020'
    b'202020202020202020202020202020","binding_id":"050505050505050505'
    b'05050505050505","binding_revision":72623859790382856,"domain":"vision'
    b'forge-pair-generation-challenge-request-v1","entitlement_id":"030303030'
    b'30303030303030303030303","host_identity_spki_sha256":"1010101010101010'
    b'101010101010101010101010101010101010101010101010","pair_id":"04040404'
    b'040404040404040404040404","protocol_version":2,"request_id":"0101010101'
    b'0101010101010101010101","revocation_version":9}'
)
VECTOR_FINAL_CANONICAL = (
    b'{"allocation_request_id":"02020202020202020202020202020202",'
    b'"android_identity_spki_sha256":"2020202020202020202020202020202020'
    b'202020202020202020202020202020","binding_id":"050505050505050505'
    b'05050505050505","binding_revision":72623859790382856,"challenge_expires'
    b'_at_epoch":305419896,"challenge_id":"06060606060606060606060606060606",'
    b'"challenge_request_id":"01010101010101010101010101010101","challenge_'
    b'request_payload_sha256":"f5fe7552fdd4009c4fcf6bb795cc8fe49c8ced14f90e'
    b'82fdef384029f171acea","connection_id":63191577505803677,"domain":"visio'
    b'nforge-pair-generation-final-credential-proof-v1","entitlement_id":"0303'
    b'0303030303030303030303030303","host_identity_spki_sha256":"101010101010'
    b'1010101010101010101010101010101010101010101010101010","pair_id":"0404'
    b'0404040404040404040404040404","proposal_version":1,"protocol_version":2,'
    b'"revocation_version":9,"server_nonce_sha256":"1300be0e8854f84e03a0191a'
    b'985679b9b9d35cdad9c9df7b7a51fded7fd33d61","transcript_proposal_sha256"'
    b':"f347088b897243eb8a2f1a69fb1e031cacd7f35cd2163efa9741dcf2964caf3f"}'
)


class WeirdStr(str):
    def encode(self, *args: object, **kwargs: object) -> bytes:
        del args, kwargs
        return b"attacker-controlled"


class WeirdInt(int):
    def __index__(self) -> int:
        return 1

    def __lt__(self, other: object) -> bool:
        del other
        return False


class WeirdBytes(bytes):
    def hex(self, *args: object, **kwargs: object) -> str:
        del args, kwargs
        return "attacker-controlled"


class ChallengeFieldsSubclass(PairGenerationChallengeRequestFieldsV1):
    pass


def vector_request_fields() -> PairGenerationChallengeRequestFieldsV1:
    return PairGenerationChallengeRequestFieldsV1(
        request_id="01" * 16,
        allocation_request_id="02" * 16,
        entitlement_id="03" * 16,
        pair_id="04" * 16,
        binding_id="05" * 16,
        binding_revision=0x0102_0304_0506_0708,
        revocation_version=9,
        host_identity_spki_sha256="10" * 32,
        android_identity_spki_sha256="20" * 32,
    )


def build_vector_request(
    fields: PairGenerationChallengeRequestFieldsV1 | None = None,
):
    return build_pair_generation_challenge_request_v1(
        fields or vector_request_fields(),
    )


def derive_vector_server_nonce(
    request=None,
    *,
    challenge_id: str = VECTOR_CHALLENGE_ID,
    expires_at: int = VECTOR_EXPIRES_AT,
) -> bytes:
    return derive_pair_generation_server_nonce_v1(
        VECTOR_SERVER_NONCE_KEY,
        request or build_vector_request(),
        challenge_id=challenge_id,
        challenge_expires_at_epoch=expires_at,
    )


def build_vector_proposal(
    *,
    request_fields: PairGenerationChallengeRequestFieldsV1 | None = None,
    challenge_id: str = VECTOR_CHALLENGE_ID,
    server_nonce: bytes | None = None,
    host_nonce: bytes = VECTOR_HOST_NONCE,
    android_nonce: bytes = VECTOR_ANDROID_NONCE,
    connection_id: int | None = None,
    host_runtime_version: str = "17.8.47",
):
    fields = request_fields or vector_request_fields()
    nonce = server_nonce or derive_vector_server_nonce(
        build_vector_request(fields),
        challenge_id=challenge_id,
    )
    derived_connection_id = derive_pair_generation_connection_id_v1(
        nonce,
        challenge_id=challenge_id,
        host_nonce=host_nonce,
        android_nonce=android_nonce,
        pair_id=fields.pair_id,
        host_identity_spki_sha256=fields.host_identity_spki_sha256,
        android_identity_spki_sha256=fields.android_identity_spki_sha256,
    )
    return build_pair_generation_proposal_v1(
        PairGenerationProposalFields(
            host_identity_spki_sha256=bytes.fromhex(
                fields.host_identity_spki_sha256,
            ),
            android_identity_spki_sha256=bytes.fromhex(
                fields.android_identity_spki_sha256,
            ),
            host_ephemeral_public_key=bytes.fromhex(HOST_PUBLIC_HEX),
            android_ephemeral_public_key=bytes.fromhex(ANDROID_PUBLIC_HEX),
            host_nonce=host_nonce,
            android_nonce=android_nonce,
            connection_id=(
                derived_connection_id
                if connection_id is None
                else connection_id
            ),
            transport_kind=ProposalTransportKind.CAT6,
            host_ipv4=bytes.fromhex("c0a83701"),
            android_ipv4=bytes.fromhex("c0a83702"),
            video_port=45678,
            control_port=45679,
            pair_id=fields.pair_id,
            host_runtime_version=host_runtime_version,
            android_runtime_version="17.8.47",
        )
    )


def build_vector_final(
    *,
    request=None,
    challenge_id: str = VECTOR_CHALLENGE_ID,
    expires_at: int = VECTOR_EXPIRES_AT,
    server_nonce: bytes | None = None,
    proposal=None,
):
    checked_request = request or build_vector_request()
    checked_server_nonce = server_nonce or derive_vector_server_nonce(
        checked_request,
        challenge_id=challenge_id,
        expires_at=expires_at,
    )
    checked_proposal = proposal or build_vector_proposal(
        request_fields=checked_request.fields,
        challenge_id=challenge_id,
        server_nonce=checked_server_nonce,
    )
    return build_pair_generation_final_credential_proof_v1(
        checked_request,
        challenge_id=challenge_id,
        challenge_expires_at_epoch=expires_at,
        server_nonce=checked_server_nonce,
        canonical_proposal_bytes=checked_proposal.canonical_bytes,
    )


def test_frozen_cross_language_vectors() -> None:
    request = build_vector_request()
    assert len(request.canonical_bytes) == 587
    assert request.canonical_bytes == VECTOR_REQUEST_CANONICAL
    assert request.payload_sha256.hex() == VECTOR_REQUEST_SHA256

    server_nonce = derive_vector_server_nonce(request)
    assert server_nonce.hex() == VECTOR_SERVER_NONCE_HEX
    proposal = build_vector_proposal(server_nonce=server_nonce)
    assert proposal.fields.connection_id == VECTOR_CONNECTION_ID
    assert proposal.proposal_sha256.hex() == VECTOR_PROPOSAL_SHA256

    final = build_vector_final(
        request=request,
        server_nonce=server_nonce,
        proposal=proposal,
    )
    assert len(final.canonical_bytes) == 1033
    assert final.canonical_bytes == VECTOR_FINAL_CANONICAL
    assert final.payload_sha256.hex() == VECTOR_FINAL_SHA256
    assert final.fields.connection_id == VECTOR_CONNECTION_ID
    assert final.fields.challenge_request_payload_sha256 == VECTOR_REQUEST_SHA256
    assert final.fields.transcript_proposal_sha256 == VECTOR_PROPOSAL_SHA256


def test_canonical_domains_and_versions_are_fixed_and_separate() -> None:
    request_payload = json.loads(build_vector_request().canonical_bytes)
    final_payload = json.loads(build_vector_final().canonical_bytes)

    assert request_payload["domain"] == CHALLENGE_REQUEST_DOMAIN
    assert request_payload["protocol_version"] == PROTOCOL_VERSION
    assert "proposal_version" not in request_payload
    assert final_payload["domain"] == FINAL_CREDENTIAL_PROOF_DOMAIN
    assert final_payload["protocol_version"] == PROTOCOL_VERSION
    assert final_payload["proposal_version"] == PROPOSAL_VERSION
    assert request_payload["domain"] != final_payload["domain"]
    assert set(request_payload) == {
        "allocation_request_id",
        "android_identity_spki_sha256",
        "binding_id",
        "binding_revision",
        "domain",
        "entitlement_id",
        "host_identity_spki_sha256",
        "pair_id",
        "protocol_version",
        "request_id",
        "revocation_version",
    }
    assert set(final_payload) == {
        "allocation_request_id",
        "android_identity_spki_sha256",
        "binding_id",
        "binding_revision",
        "challenge_expires_at_epoch",
        "challenge_id",
        "challenge_request_id",
        "challenge_request_payload_sha256",
        "connection_id",
        "domain",
        "entitlement_id",
        "host_identity_spki_sha256",
        "pair_id",
        "proposal_version",
        "protocol_version",
        "revocation_version",
        "server_nonce_sha256",
        "transcript_proposal_sha256",
    }


def test_hashes_and_connection_id_have_no_caller_input_parameter() -> None:
    parameters = inspect.signature(
        build_pair_generation_final_credential_proof_v1,
    ).parameters
    assert "challenge_request_payload_sha256" not in parameters
    assert "server_nonce_sha256" not in parameters
    assert "transcript_proposal_sha256" not in parameters
    assert "connection_id" not in parameters
    assert "domain" not in parameters
    assert "protocol_version" not in parameters
    assert "proposal_version" not in parameters


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("request_id", "11" * 16),
        ("allocation_request_id", "12" * 16),
        ("entitlement_id", "13" * 16),
        ("pair_id", "14" * 16),
        ("binding_id", "15" * 16),
        ("binding_revision", 10),
        ("revocation_version", 10),
        ("host_identity_spki_sha256", "30" * 32),
        ("android_identity_spki_sha256", "40" * 32),
    ],
)
def test_every_challenge_request_field_mutation_changes_canonical_payload(
    field_name: str,
    replacement: object,
) -> None:
    original = build_vector_request()
    changed = build_vector_request(
        replace(vector_request_fields(), **{field_name: replacement}),
    )
    assert changed.canonical_bytes != original.canonical_bytes
    assert changed.payload_sha256 != original.payload_sha256


@pytest.mark.parametrize(
    "field_name",
    [
        "allocation_request_id",
        "android_identity_spki_sha256",
        "binding_id",
        "binding_revision",
        "domain",
        "entitlement_id",
        "host_identity_spki_sha256",
        "pair_id",
        "protocol_version",
        "request_id",
        "revocation_version",
    ],
)
def test_every_serialized_challenge_field_is_covered_by_canonical_bytes(
    field_name: str,
) -> None:
    request = build_vector_request()
    payload = json.loads(request.canonical_bytes)
    payload[field_name] = _mutated_json_value(payload[field_name])
    mutated = canonical_json(payload)
    assert mutated != request.canonical_bytes
    assert hashlib.sha256(mutated).digest() != request.payload_sha256


@pytest.mark.parametrize(
    "field_name",
    [
        "allocation_request_id",
        "android_identity_spki_sha256",
        "binding_id",
        "binding_revision",
        "challenge_expires_at_epoch",
        "challenge_id",
        "challenge_request_id",
        "challenge_request_payload_sha256",
        "connection_id",
        "domain",
        "entitlement_id",
        "host_identity_spki_sha256",
        "pair_id",
        "proposal_version",
        "protocol_version",
        "revocation_version",
        "server_nonce_sha256",
        "transcript_proposal_sha256",
    ],
)
def test_every_serialized_final_field_is_covered_by_canonical_bytes(
    field_name: str,
) -> None:
    final = build_vector_final()
    payload = json.loads(final.canonical_bytes)
    payload[field_name] = _mutated_json_value(payload[field_name])
    mutated = canonical_json(payload)
    assert mutated != final.canonical_bytes
    assert hashlib.sha256(mutated).digest() != final.payload_sha256


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("request_id", "0" * 32),
        ("allocation_request_id", "A" * 32),
        ("entitlement_id", "a" * 31),
        ("pair_id", "g" * 32),
        ("binding_id", ""),
    ],
)
def test_every_identifier_enforces_lowercase_nonzero_hex(
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_request(
            replace(vector_request_fields(), **{field_name: value}),
        )
    assert caught.value.code is PairGenerationPopErrorCode.IDENTIFIER_INVALID


@pytest.mark.parametrize(
    "field_name",
    [
        "request_id",
        "allocation_request_id",
        "entitlement_id",
        "pair_id",
        "binding_id",
        "host_identity_spki_sha256",
        "android_identity_spki_sha256",
    ],
)
def test_every_string_field_rejects_str_subclasses(field_name: str) -> None:
    value = getattr(vector_request_fields(), field_name)
    with pytest.raises(PairGenerationPopError):
        build_vector_request(
            replace(
                vector_request_fields(),
                **{field_name: WeirdStr(value)},
            ),
        )


@pytest.mark.parametrize("field_name", ["binding_revision", "revocation_version"])
@pytest.mark.parametrize("value_factory", [WeirdInt, bool])
def test_every_integer_field_rejects_subclasses_and_bool(
    field_name: str,
    value_factory: object,
) -> None:
    value = value_factory(getattr(vector_request_fields(), field_name))
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_request(
            replace(vector_request_fields(), **{field_name: value}),
        )
    assert caught.value.code is PairGenerationPopErrorCode.SIGNED_64_INVALID


def test_challenge_fields_dataclass_subclass_is_rejected() -> None:
    values = vector_request_fields()
    subclass = ChallengeFieldsSubclass(
        request_id=values.request_id,
        allocation_request_id=values.allocation_request_id,
        entitlement_id=values.entitlement_id,
        pair_id=values.pair_id,
        binding_id=values.binding_id,
        binding_revision=values.binding_revision,
        revocation_version=values.revocation_version,
        host_identity_spki_sha256=values.host_identity_spki_sha256,
        android_identity_spki_sha256=values.android_identity_spki_sha256,
    )
    with pytest.raises(PairGenerationPopError) as caught:
        build_pair_generation_challenge_request_v1(subclass)
    assert caught.value.code is PairGenerationPopErrorCode.REQUEST_INVALID


@pytest.mark.parametrize("value", [0, -1, SIGNED_64_MAX + 1])
@pytest.mark.parametrize("field_name", ["binding_revision", "revocation_version"])
def test_positive_signed_64_boundaries(
    field_name: str,
    value: int,
) -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_request(
            replace(vector_request_fields(), **{field_name: value}),
        )
    assert caught.value.code is PairGenerationPopErrorCode.SIGNED_64_INVALID


@pytest.mark.parametrize(
    ("host_hash", "android_hash", "expected"),
    [
        ("0" * 64, "20" * 32, PairGenerationPopErrorCode.IDENTITY_HASH_INVALID),
        ("10" * 32, "F" * 64, PairGenerationPopErrorCode.IDENTITY_HASH_INVALID),
        ("10" * 32, "10" * 32, PairGenerationPopErrorCode.IDENTITY_ROLES_INVALID),
    ],
)
def test_identity_hash_contract_and_equal_role_rejection(
    host_hash: str,
    android_hash: str,
    expected: PairGenerationPopErrorCode,
) -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_request(
            replace(
                vector_request_fields(),
                host_identity_spki_sha256=host_hash,
                android_identity_spki_sha256=android_hash,
            ),
        )
    assert caught.value.code is expected


def test_host_android_identity_role_swap_changes_request_and_connection_id() -> None:
    fields = vector_request_fields()
    swapped = replace(
        fields,
        host_identity_spki_sha256=fields.android_identity_spki_sha256,
        android_identity_spki_sha256=fields.host_identity_spki_sha256,
    )
    assert (
        build_vector_request(swapped).canonical_bytes
        != build_vector_request(fields).canonical_bytes
    )
    original_id = _derive_vector_connection_id()
    swapped_id = _derive_vector_connection_id(
        host_identity=swapped.host_identity_spki_sha256,
        android_identity=swapped.android_identity_spki_sha256,
    )
    assert swapped_id != original_id


def test_host_android_nonce_role_swap_changes_connection_id() -> None:
    original = _derive_vector_connection_id()
    swapped = _derive_vector_connection_id(
        host_nonce=VECTOR_ANDROID_NONCE,
        android_nonce=VECTOR_HOST_NONCE,
    )
    assert swapped != original


@pytest.mark.parametrize(
    "change",
    [
        "challenge_id",
        "host_nonce",
        "android_nonce",
        "pair_id",
        "host_identity",
        "android_identity",
        "server_nonce",
    ],
)
def test_every_connection_id_seed_field_mutation_changes_result(
    change: str,
) -> None:
    kwargs: dict[str, object] = {}
    replacements = {
        "challenge_id": "16" * 16,
        "host_nonce": bytes(range(0x20, 0x40)),
        "android_nonce": bytes(range(0x80, 0xA0)),
        "pair_id": "17" * 16,
        "host_identity": "30" * 32,
        "android_identity": "40" * 32,
        "server_nonce": bytes.fromhex("50" * 32),
    }
    kwargs[change] = replacements[change]
    assert _derive_vector_connection_id(**kwargs) != _derive_vector_connection_id()


def test_connection_id_uses_big_endian_first_64_bits_and_signed63_mask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = bytes.fromhex("f123456789abcdef") + b"x" * 24
    monkeypatch.setattr(pop_module, "_hmac_sha256", lambda key, seed: digest)
    expected = int.from_bytes(digest[:8], "big") & SIGNED_64_MAX
    assert _derive_vector_connection_id() == expected


def test_zero_connection_id_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pop_module,
        "_hmac_sha256",
        lambda key, seed: bytes(32),
    )
    with pytest.raises(PairGenerationPopError) as caught:
        _derive_vector_connection_id(
            server_nonce=bytes.fromhex(VECTOR_SERVER_NONCE_HEX),
        )
    assert caught.value.code is PairGenerationPopErrorCode.CONNECTION_ID_ZERO


@pytest.mark.parametrize(
    "change",
    [
        "challenge_id",
        "request_payload",
        "pair_id",
        "binding_revision",
        "expires_at",
    ],
)
def test_every_server_nonce_seed_field_mutation_changes_result(change: str) -> None:
    fields = vector_request_fields()
    challenge_id = VECTOR_CHALLENGE_ID
    expires_at = VECTOR_EXPIRES_AT
    if change == "challenge_id":
        challenge_id = "16" * 16
    elif change == "request_payload":
        fields = replace(fields, allocation_request_id="12" * 16)
    elif change == "pair_id":
        fields = replace(fields, pair_id="14" * 16)
    elif change == "binding_revision":
        fields = replace(fields, binding_revision=10)
    elif change == "expires_at":
        expires_at += 1
    changed = derive_vector_server_nonce(
        build_vector_request(fields),
        challenge_id=challenge_id,
        expires_at=expires_at,
    )
    assert changed != derive_vector_server_nonce()


def test_server_nonce_derivation_is_deterministic_raw_32_bytes() -> None:
    first = derive_vector_server_nonce()
    second = derive_vector_server_nonce()
    different_key = derive_pair_generation_server_nonce_v1(
        b"different-server-nonce-key-material",
        build_vector_request(),
        challenge_id=VECTOR_CHALLENGE_ID,
        challenge_expires_at_epoch=VECTOR_EXPIRES_AT,
    )
    assert type(first) is bytes
    assert len(first) == 32
    assert first == second
    assert different_key != first


@pytest.mark.parametrize(
    "key",
    [b"x" * 31, bytes(32), WeirdBytes(b"x" * 32)],
)
def test_server_nonce_key_is_exact_builtin_nonzero_minimum_32_bytes(
    key: bytes,
) -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        derive_pair_generation_server_nonce_v1(
            key,
            build_vector_request(),
            challenge_id=VECTOR_CHALLENGE_ID,
            challenge_expires_at_epoch=VECTOR_EXPIRES_AT,
        )
    assert caught.value.code is PairGenerationPopErrorCode.SERVER_NONCE_KEY_INVALID


@pytest.mark.parametrize(
    ("argument", "value", "expected"),
    [
        (
            "challenge_id",
            WeirdStr(VECTOR_CHALLENGE_ID),
            PairGenerationPopErrorCode.IDENTIFIER_INVALID,
        ),
        (
            "challenge_expires_at_epoch",
            WeirdInt(VECTOR_EXPIRES_AT),
            PairGenerationPopErrorCode.SIGNED_64_INVALID,
        ),
        (
            "challenge_expires_at_epoch",
            True,
            PairGenerationPopErrorCode.SIGNED_64_INVALID,
        ),
        (
            "challenge_expires_at_epoch",
            0,
            PairGenerationPopErrorCode.SIGNED_64_INVALID,
        ),
        (
            "challenge_expires_at_epoch",
            SIGNED_64_MAX + 1,
            PairGenerationPopErrorCode.SIGNED_64_INVALID,
        ),
    ],
)
def test_server_nonce_derivation_rejects_nonexact_argument_types_and_ranges(
    argument: str,
    value: object,
    expected: PairGenerationPopErrorCode,
) -> None:
    kwargs = {
        "challenge_id": VECTOR_CHALLENGE_ID,
        "challenge_expires_at_epoch": VECTOR_EXPIRES_AT,
    }
    kwargs[argument] = value
    with pytest.raises(PairGenerationPopError) as caught:
        derive_pair_generation_server_nonce_v1(
            VECTOR_SERVER_NONCE_KEY,
            build_vector_request(),
            **kwargs,
        )
    assert caught.value.code is expected


@pytest.mark.parametrize(
    "nonce_name",
    ["server_nonce", "host_nonce", "android_nonce"],
)
def test_connection_derivation_rejects_bytes_subclasses(nonce_name: str) -> None:
    values = {
        "server_nonce": derive_vector_server_nonce(),
        "host_nonce": VECTOR_HOST_NONCE,
        "android_nonce": VECTOR_ANDROID_NONCE,
    }
    values[nonce_name] = WeirdBytes(values[nonce_name])
    with pytest.raises(PairGenerationPopError) as caught:
        derive_pair_generation_connection_id_v1(
            values["server_nonce"],
            challenge_id=VECTOR_CHALLENGE_ID,
            host_nonce=values["host_nonce"],
            android_nonce=values["android_nonce"],
            pair_id=vector_request_fields().pair_id,
            host_identity_spki_sha256=(
                vector_request_fields().host_identity_spki_sha256
            ),
            android_identity_spki_sha256=(
                vector_request_fields().android_identity_spki_sha256
            ),
        )
    assert caught.value.code is PairGenerationPopErrorCode.NONCE_INVALID


def test_equal_peer_nonces_fail_closed() -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        _derive_vector_connection_id(android_nonce=VECTOR_HOST_NONCE)
    assert caught.value.code is PairGenerationPopErrorCode.NONCE_ROLES_INVALID


@pytest.mark.parametrize(
    ("argument", "value"),
    [
        ("challenge_id", WeirdStr(VECTOR_CHALLENGE_ID)),
        ("pair_id", WeirdStr(vector_request_fields().pair_id)),
        (
            "host_identity_spki_sha256",
            WeirdStr(vector_request_fields().host_identity_spki_sha256),
        ),
        (
            "android_identity_spki_sha256",
            WeirdStr(vector_request_fields().android_identity_spki_sha256),
        ),
    ],
)
def test_connection_derivation_rejects_string_subclasses(
    argument: str,
    value: str,
) -> None:
    fields = vector_request_fields()
    kwargs = {
        "challenge_id": VECTOR_CHALLENGE_ID,
        "host_nonce": VECTOR_HOST_NONCE,
        "android_nonce": VECTOR_ANDROID_NONCE,
        "pair_id": fields.pair_id,
        "host_identity_spki_sha256": fields.host_identity_spki_sha256,
        "android_identity_spki_sha256": fields.android_identity_spki_sha256,
    }
    kwargs[argument] = value
    with pytest.raises(PairGenerationPopError):
        derive_pair_generation_connection_id_v1(
            derive_vector_server_nonce(),
            **kwargs,
        )


def test_final_builder_recomputes_all_hash_fields() -> None:
    request = build_vector_request()
    server_nonce = derive_vector_server_nonce(request)
    proposal = build_vector_proposal(server_nonce=server_nonce)
    final = build_vector_final(
        request=request,
        server_nonce=server_nonce,
        proposal=proposal,
    )
    assert final.fields.challenge_request_payload_sha256 == hashlib.sha256(
        request.canonical_bytes,
    ).hexdigest()
    assert final.fields.server_nonce_sha256 == hashlib.sha256(
        server_nonce,
    ).hexdigest()
    assert final.fields.transcript_proposal_sha256 == hashlib.sha256(
        proposal.canonical_bytes,
    ).hexdigest()


@pytest.mark.parametrize("attribute", ["canonical_bytes", "payload_sha256"])
def test_final_builder_rejects_tampered_challenge_request_owner(
    attribute: str,
) -> None:
    request = build_vector_request()
    object.__setattr__(request, attribute, b"x" * 32)
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_final(request=request)
    assert caught.value.code is PairGenerationPopErrorCode.REQUEST_INTEGRITY_INVALID


def test_final_builder_rejects_proposal_pair_binding_mismatch() -> None:
    request = build_vector_request()
    changed_fields = replace(request.fields, pair_id="14" * 16)
    changed_request = build_vector_request(changed_fields)
    server_nonce = derive_vector_server_nonce(changed_request)
    mismatched = build_vector_proposal(
        request_fields=changed_fields,
        server_nonce=server_nonce,
    )
    with pytest.raises(PairGenerationPopError) as caught:
        build_pair_generation_final_credential_proof_v1(
            request,
            challenge_id=VECTOR_CHALLENGE_ID,
            challenge_expires_at_epoch=VECTOR_EXPIRES_AT,
            server_nonce=server_nonce,
            canonical_proposal_bytes=mismatched.canonical_bytes,
        )
    assert caught.value.code is PairGenerationPopErrorCode.PROPOSAL_BINDING_INVALID


def test_final_builder_rejects_host_android_identity_role_swap() -> None:
    request = build_vector_request()
    fields = request.fields
    swapped = replace(
        fields,
        host_identity_spki_sha256=fields.android_identity_spki_sha256,
        android_identity_spki_sha256=fields.host_identity_spki_sha256,
    )
    swapped_request = build_vector_request(swapped)
    server_nonce = derive_vector_server_nonce(swapped_request)
    proposal = build_vector_proposal(
        request_fields=swapped,
        server_nonce=server_nonce,
    )
    with pytest.raises(PairGenerationPopError) as caught:
        build_pair_generation_final_credential_proof_v1(
            request,
            challenge_id=VECTOR_CHALLENGE_ID,
            challenge_expires_at_epoch=VECTOR_EXPIRES_AT,
            server_nonce=server_nonce,
            canonical_proposal_bytes=proposal.canonical_bytes,
        )
    assert caught.value.code is PairGenerationPopErrorCode.PROPOSAL_BINDING_INVALID


def test_final_builder_rejects_caller_selected_connection_id() -> None:
    proposal = build_vector_proposal(connection_id=VECTOR_CONNECTION_ID + 1)
    with pytest.raises(PairGenerationPopError) as caught:
        build_vector_final(proposal=proposal)
    assert caught.value.code is PairGenerationPopErrorCode.CONNECTION_ID_MISMATCH


@pytest.mark.parametrize(
    "proposal",
    [
        b"",
        b"not-a-canonical-proposal",
        b"x" * (MAXIMUM_CANONICAL_PROPOSAL_BYTES + 1),
        WeirdBytes(b"x"),
    ],
)
def test_final_builder_requires_exact_valid_canonical_proposal_bytes(
    proposal: bytes,
) -> None:
    with pytest.raises(PairGenerationPopError) as caught:
        build_pair_generation_final_credential_proof_v1(
            build_vector_request(),
            challenge_id=VECTOR_CHALLENGE_ID,
            challenge_expires_at_epoch=VECTOR_EXPIRES_AT,
            server_nonce=derive_vector_server_nonce(),
            canonical_proposal_bytes=proposal,
        )
    assert caught.value.code is PairGenerationPopErrorCode.PROPOSAL_INVALID


@pytest.mark.parametrize(
    ("argument", "value"),
    [
        ("challenge_id", WeirdStr(VECTOR_CHALLENGE_ID)),
        ("challenge_expires_at_epoch", WeirdInt(VECTOR_EXPIRES_AT)),
        ("challenge_expires_at_epoch", True),
        ("challenge_expires_at_epoch", 0),
        ("challenge_expires_at_epoch", SIGNED_64_MAX + 1),
        ("server_nonce", WeirdBytes(bytes.fromhex(VECTOR_SERVER_NONCE_HEX))),
    ],
)
def test_final_builder_rejects_type_subclasses_and_bool(
    argument: str,
    value: object,
) -> None:
    kwargs = {
        "challenge_id": VECTOR_CHALLENGE_ID,
        "challenge_expires_at_epoch": VECTOR_EXPIRES_AT,
        "server_nonce": derive_vector_server_nonce(),
        "canonical_proposal_bytes": build_vector_proposal().canonical_bytes,
    }
    kwargs[argument] = value
    with pytest.raises(PairGenerationPopError):
        build_pair_generation_final_credential_proof_v1(
            build_vector_request(),
            **kwargs,
        )


def test_outputs_are_frozen_dataclasses_with_builtin_bytes() -> None:
    request = build_vector_request()
    final = build_vector_final()
    assert type(request.canonical_bytes) is bytes
    assert type(request.payload_sha256) is bytes
    assert type(final.canonical_bytes) is bytes
    assert type(final.payload_sha256) is bytes
    with pytest.raises(FrozenInstanceError):
        request.canonical_bytes = b"changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        final.payload_sha256 = b"changed"  # type: ignore[misc]


def _derive_vector_connection_id(
    *,
    server_nonce: bytes | None = None,
    challenge_id: str = VECTOR_CHALLENGE_ID,
    host_nonce: bytes = VECTOR_HOST_NONCE,
    android_nonce: bytes = VECTOR_ANDROID_NONCE,
    pair_id: str | None = None,
    host_identity: str | None = None,
    android_identity: str | None = None,
) -> int:
    fields = vector_request_fields()
    return derive_pair_generation_connection_id_v1(
        server_nonce or derive_vector_server_nonce(),
        challenge_id=challenge_id,
        host_nonce=host_nonce,
        android_nonce=android_nonce,
        pair_id=pair_id or fields.pair_id,
        host_identity_spki_sha256=(
            host_identity or fields.host_identity_spki_sha256
        ),
        android_identity_spki_sha256=(
            android_identity or fields.android_identity_spki_sha256
        ),
    )


def _mutated_json_value(value: object) -> object:
    if type(value) is int:
        return value + 1
    assert type(value) is str
    return value + "x"
