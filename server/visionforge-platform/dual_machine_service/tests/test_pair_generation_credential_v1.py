from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dual_machine_service import pair_generation_credential_v1 as credential
from dual_machine_service.pair_generation_credential_v1 import (
    CREDENTIAL_AUDIENCE,
    CREDENTIAL_ISSUER,
    CREDENTIAL_TYPE,
    MAX_CREDENTIAL_TTL_SECONDS,
    PairGenerationCredentialError,
    PairGenerationCredentialErrorCode,
    PairGenerationCredentialExpectedV1,
    PairGenerationCredentialV1Verifier,
    VerifiedPairGenerationCredentialV1,
)


PrivateSigner = credential._PairGenerationCredentialV1Signer
PrivateSource = credential._AuthoritativePairGenerationCredentialSourceV1
NOW = 1_700_000_000
INT64_MAX = (1 << 63) - 1
FIXED_NONCE = bytes(range(32))


class _NoOpVerifyPublicKey(rsa.RSAPublicKey):
    def __init__(
        self,
        delegate: rsa.RSAPublicKey,
        *,
        reported_key_size: int | None = None,
    ) -> None:
        self.delegate = delegate
        self.reported_key_size = reported_key_size
        self.verify_calls = 0

    @property
    def key_size(self) -> int:
        return self.reported_key_size or self.delegate.key_size

    def public_numbers(self):
        return self.delegate.public_numbers()

    def public_bytes(self, encoding, format):
        return b"caller-controlled-noncanonical-spki"

    def verify(self, signature, data, padding, algorithm) -> None:
        self.verify_calls += 1

    def encrypt(self, plaintext, padding):
        return self.delegate.encrypt(plaintext, padding)

    def recover_data_from_signature(self, signature, padding, algorithm):
        return self.delegate.recover_data_from_signature(
            signature,
            padding,
            algorithm,
        )

    def __eq__(self, other: object) -> bool:
        return self is other

    # cryptography 46 made key objects explicitly copyable through an abstract
    # method.  This adversarial test double must remain instantiable without
    # changing the production verifier contract.
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


class _NoOpSignPrivateKey(rsa.RSAPrivateKey):
    def __init__(self, delegate: rsa.RSAPrivateKey) -> None:
        self.delegate = delegate
        self.sign_calls = 0

    @property
    def key_size(self) -> int:
        return self.delegate.key_size

    def private_numbers(self):
        return self.delegate.private_numbers()

    def private_bytes(self, encoding, format, encryption_algorithm):
        return self.delegate.private_bytes(
            encoding,
            format,
            encryption_algorithm,
        )

    def public_key(self):
        return self.delegate.public_key()

    def decrypt(self, ciphertext, padding):
        return self.delegate.decrypt(ciphertext, padding)

    def sign(self, data, padding, algorithm) -> bytes:
        self.sign_calls += 1
        return b"\x00"

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


@pytest.fixture(scope="module")
def current_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def previous_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def third_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture
def expected() -> PairGenerationCredentialExpectedV1:
    return PairGenerationCredentialExpectedV1(
        allocation_request_id="alloc:req.1_test-0",
        pair_id="1" * 32,
        entitlement_id="2" * 32,
        binding_id="3" * 32,
        binding_revision=4,
        revocation_version=5,
        generation=6,
        connection_id=7,
        host_identity_spki_sha256="8" * 64,
        android_identity_spki_sha256="9" * 64,
        transcript_proposal_sha256="a" * 64,
    )


@pytest.fixture
def signer(current_private_key: rsa.RSAPrivateKey):
    return PrivateSigner(
        private_key=current_private_key,
        current_public_key=current_private_key.public_key(),
    )


@pytest.fixture
def verifier(
    current_private_key: rsa.RSAPrivateKey,
) -> PairGenerationCredentialV1Verifier:
    return PairGenerationCredentialV1Verifier(
        public_keys=(current_private_key.public_key(),),
    )


def _source(
    expected: PairGenerationCredentialExpectedV1,
    allocated_at_epoch: object = NOW,
):
    return PrivateSource(
        expected=expected,
        allocated_at_epoch=allocated_at_epoch,
    )


def _issue(
    signer,
    expected: PairGenerationCredentialExpectedV1,
    *,
    now_epoch: object = NOW,
    allocated_at_epoch: object = NOW,
):
    return signer.sign(
        _source(expected, allocated_at_epoch),
        now_epoch=now_epoch,
    )


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key_id(private_key: rsa.RSAPrivateKey) -> str:
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()[:16]


def _decode_token(token: str) -> tuple[dict[str, object], dict[str, object]]:
    header_encoded, payload_encoded, _signature_encoded = token.split(".")
    header = json.loads(
        base64.urlsafe_b64decode(
            header_encoded + "=" * (-len(header_encoded) % 4),
        ),
    )
    payload = json.loads(
        base64.urlsafe_b64decode(
            payload_encoded + "=" * (-len(payload_encoded) % 4),
        ),
    )
    return header, payload


def _sign_raw(
    private_key: rsa.RSAPrivateKey,
    header_raw: bytes,
    payload_raw: bytes,
) -> str:
    signing_input = (
        _base64url(header_raw) + "." + _base64url(payload_raw)
    ).encode("ascii")
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signing_input.decode("ascii") + "." + _base64url(signature)


def _sign_objects(
    private_key: rsa.RSAPrivateKey,
    header: dict[str, object],
    payload: dict[str, object],
) -> str:
    return _sign_raw(
        private_key,
        _canonical_json(header),
        _canonical_json(payload),
    )


def _parts(
    signer,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, dict[str, object], dict[str, object]]:
    monkeypatch.setattr(
        credential.secrets,
        "token_bytes",
        lambda size: FIXED_NONCE,
    )
    result = _issue(signer, expected)
    header, payload = _decode_token(result.token)
    return result.token, header, payload


def _assert_error(
    code: PairGenerationCredentialErrorCode,
    operation,
) -> PairGenerationCredentialError:
    with pytest.raises(PairGenerationCredentialError) as caught:
        operation()
    assert caught.value.code is code
    assert str(caught.value) == code.value
    return caught.value


def test_exact_token_is_canonical_bound_and_immediately_verified(
    signer,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        credential.secrets,
        "token_bytes",
        lambda size: FIXED_NONCE,
    )
    result = _issue(signer, expected)
    header = {
        "alg": "RS256",
        "kid": _key_id(current_private_key),
        "typ": "JWT",
    }
    payload = {
        "allocation_request_id": expected.allocation_request_id,
        "android_identity_spki_sha256": (
            expected.android_identity_spki_sha256
        ),
        "aud": CREDENTIAL_AUDIENCE,
        "binding_id": expected.binding_id,
        "binding_revision": expected.binding_revision,
        "connection_id": expected.connection_id,
        "credential_nonce": FIXED_NONCE.hex(),
        "entitlement_id": expected.entitlement_id,
        "exp": NOW + 15,
        "generation": expected.generation,
        "host_identity_spki_sha256": expected.host_identity_spki_sha256,
        "iat": NOW,
        "iss": CREDENTIAL_ISSUER,
        "nbf": NOW,
        "pair_id": expected.pair_id,
        "revocation_version": expected.revocation_version,
        "transcript_proposal_sha256": expected.transcript_proposal_sha256,
        "typ": CREDENTIAL_TYPE,
    }
    exact_token = _sign_objects(current_private_key, header, payload)

    assert result.token == exact_token
    assert result.token_sha256 == hashlib.sha256(
        exact_token.encode("ascii"),
    ).hexdigest()
    assert result.key_id == header["kid"]
    assert result.verified_claims.allocation_request_id == (
        expected.allocation_request_id
    )
    assert result.verified_claims.credential_nonce == FIXED_NONCE.hex()
    assert result.verified_claims.credential_type == CREDENTIAL_TYPE
    assert result.verified_claims.issuer == CREDENTIAL_ISSUER
    assert result.verified_claims.audience == CREDENTIAL_AUDIENCE
    assert "allocated_at_epoch" not in payload
    with pytest.raises(FrozenInstanceError):
        result.token = "changed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.verified_claims.generation = 99  # type: ignore[misc]


def test_public_verifier_returns_restricted_immutable_typed_owner(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    result = _issue(signer, expected)
    verified = verifier.verify(
        result.token,
        expected=expected,
        now_epoch=NOW + 1,
    )

    assert type(verified) is VerifiedPairGenerationCredentialV1
    assert verified.pair_id == expected.pair_id
    assert verified.expires_at_epoch == NOW + 15
    with pytest.raises(TypeError, match="construction is restricted"):
        VerifiedPairGenerationCredentialV1(
            object(),
            b"x.y.z",
            b"0" * 32,
        )


def test_imported_sentinel_cannot_create_a_registered_verified_owner() -> None:
    forged = VerifiedPairGenerationCredentialV1(
        credential._VERIFIED_OWNER_TOKEN,
        b"e30.e30.AA",
        hashlib.sha256(b"e30.e30.AA").digest(),
    )

    _assert_error(
        PairGenerationCredentialErrorCode.OWNER_INVALID,
        lambda: forged.generation,
    )


def test_verified_owner_has_no_mutable_claim_slots(
    signer,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    verified = _issue(signer, expected).verified_claims

    with pytest.raises(AttributeError):
        object.__setattr__(verified, "generation", 99)
    assert verified.generation == expected.generation
    with pytest.raises(AttributeError):
        object.__setattr__(verified, "new_claim", "forged")


@pytest.mark.parametrize(
    ("slot_name", "replacement"),
    (
        ("_canonical_token_ascii", b"e30.e30.AA"),
        ("_token_sha256", b"0" * 32),
    ),
)
def test_verified_owner_slot_tampering_fails_closed(
    signer,
    expected: PairGenerationCredentialExpectedV1,
    slot_name: str,
    replacement: bytes,
) -> None:
    verified = _issue(signer, expected).verified_claims
    object.__setattr__(verified, slot_name, replacement)

    _assert_error(
        PairGenerationCredentialErrorCode.OWNER_INVALID,
        lambda: verified.generation,
    )


def test_verified_owner_write_side_state_is_not_module_visible(
    signer,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    verified = _issue(signer, expected).verified_claims
    assert verified.generation == expected.generation
    prohibited_write_side_names = {
        "_VERIFIED_CREDENTIAL_REGISTRY",
        "_VERIFIED_CREDENTIAL_REGISTRY_LOCK",
        "_register_verification_anchor",
        "_new_verified_credential",
        "_build_verified_owner_boundary",
    }
    assert prohibited_write_side_names.isdisjoint(vars(credential))


def test_public_api_contains_no_signer_source_or_raw_signing_oracle() -> None:
    exported = set(credential.__all__)
    assert "PairGenerationCredentialV1Signer" not in exported
    assert "PairGenerationCredentialSourceV1" not in exported
    assert "SignedPairGenerationCredentialV1" not in exported
    assert not any(name.startswith("sign") for name in exported)
    assert {
        name
        for name, member in vars(PairGenerationCredentialV1Verifier).items()
        if callable(member) and not name.startswith("_")
    } == {"verify"}


def test_private_signer_rejects_untyped_dict_and_bytes(
    signer,
) -> None:
    for untyped in ({"pair_id": "1" * 32}, b"arbitrary-digest"):
        _assert_error(
            PairGenerationCredentialErrorCode.SOURCE_INVALID,
            lambda untyped=untyped: signer.sign(
                untyped,
                now_epoch=NOW,
            ),
        )


def test_rotation_accepts_current_plus_two_previous_only(
    current_private_key: rsa.RSAPrivateKey,
    previous_private_key: rsa.RSAPrivateKey,
    third_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    previous_signer = PrivateSigner(
        private_key=previous_private_key,
        current_public_key=previous_private_key.public_key(),
    )
    old_token = _issue(previous_signer, expected).token
    rotated = PairGenerationCredentialV1Verifier(
        public_keys=(
            current_private_key.public_key(),
            previous_private_key.public_key(),
            third_private_key.public_key(),
        ),
    )
    assert rotated.verify(
        old_token,
        expected=expected,
        now_epoch=NOW + 1,
    ).key_id == _key_id(previous_private_key)

    fourth = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _assert_error(
        PairGenerationCredentialErrorCode.KEY_INVALID,
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(
                current_private_key.public_key(),
                previous_private_key.public_key(),
                third_private_key.public_key(),
                fourth.public_key(),
            ),
        ),
    )


def test_key_policy_rejects_weak_exponent_mismatch_and_duplicate(
    current_private_key: rsa.RSAPrivateKey,
    previous_private_key: rsa.RSAPrivateKey,
) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    lying_weak_public_key = _NoOpVerifyPublicKey(
        weak.public_key(),
        reported_key_size=4096,
    )
    wrong_exponent = rsa.generate_private_key(public_exponent=3, key_size=3072)
    invalid_builders = (
        lambda: PairGenerationCredentialV1Verifier(public_keys=()),
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(weak.public_key(),),
        ),
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(lying_weak_public_key,),
        ),
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(wrong_exponent.public_key(),),
        ),
        lambda: PrivateSigner(
            private_key=current_private_key,
            current_public_key=previous_private_key.public_key(),
        ),
        lambda: PrivateSigner(
            private_key=current_private_key,
            current_public_key=current_private_key.public_key(),
            previous_public_keys=(current_private_key.public_key(),),
        ),
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=[current_private_key.public_key()],  # type: ignore[arg-type]
        ),
    )
    for build in invalid_builders:
        _assert_error(PairGenerationCredentialErrorCode.KEY_INVALID, build)


def test_verifier_rebuilds_caller_public_key_before_signature_check(
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    malicious_public_key = _NoOpVerifyPublicKey(
        current_private_key.public_key(),
    )
    signer = PrivateSigner(
        private_key=current_private_key,
        current_public_key=malicious_public_key,
    )
    valid_token = _issue(signer, expected).token
    invalid_signature_token = valid_token.rsplit(".", 1)[0] + ".AA"
    verifier = PairGenerationCredentialV1Verifier(
        public_keys=(malicious_public_key,),
    )

    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(
            invalid_signature_token,
            expected=expected,
            now_epoch=NOW,
        ),
    )
    assert malicious_public_key.verify_calls == 0
    assert verifier.verify(
        valid_token,
        expected=expected,
        now_epoch=NOW,
    ).generation == expected.generation


def test_signer_rebuilds_caller_private_key_before_signing(
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    malicious_private_key = _NoOpSignPrivateKey(current_private_key)
    signer = PrivateSigner(
        private_key=malicious_private_key,
        current_public_key=current_private_key.public_key(),
    )

    result = _issue(signer, expected)

    assert result.verified_claims.generation == expected.generation
    assert malicious_private_key.sign_calls == 0


def test_pair_credential_keys_must_be_disjoint_from_other_purposes(
    current_private_key: rsa.RSAPrivateKey,
    previous_private_key: rsa.RSAPrivateKey,
) -> None:
    PairGenerationCredentialV1Verifier(
        public_keys=(current_private_key.public_key(),),
        other_purpose_public_keys=(previous_private_key.public_key(),),
    )
    _assert_error(
        PairGenerationCredentialErrorCode.KEY_INVALID,
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(current_private_key.public_key(),),
            other_purpose_public_keys=(current_private_key.public_key(),),
        ),
    )
    malicious_same_key = _NoOpVerifyPublicKey(
        current_private_key.public_key(),
    )
    _assert_error(
        PairGenerationCredentialErrorCode.KEY_INVALID,
        lambda: PairGenerationCredentialV1Verifier(
            public_keys=(current_private_key.public_key(),),
            other_purpose_public_keys=(malicious_same_key,),
        ),
    )
    _assert_error(
        PairGenerationCredentialErrorCode.KEY_INVALID,
        lambda: PrivateSigner(
            private_key=current_private_key,
            current_public_key=current_private_key.public_key(),
            other_purpose_public_keys=(current_private_key.public_key(),),
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (("alg", "HS256"), ("typ", "JOSE"), ("kid", "f" * 16)),
)
def test_wrong_header_alg_typ_and_kid_are_rejected(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    header[field] = value
    candidate = _sign_objects(current_private_key, header, payload)
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(candidate, expected=expected, now_epoch=NOW),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (("typ", "wrong"), ("iss", "wrong"), ("aud", "wrong")),
)
def test_wrong_payload_typ_issuer_and_audience_are_rejected(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    payload[field] = value
    candidate = _sign_objects(current_private_key, header, payload)
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(candidate, expected=expected, now_epoch=NOW),
    )


def test_wrong_signature_key_is_sanitized_without_provider_context(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    previous_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, header, payload = _parts(signer, expected, monkeypatch)
    candidate = _sign_objects(previous_private_key, header, payload)
    error = _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(candidate, expected=expected, now_epoch=NOW),
    )
    assert error.__cause__ is None
    assert error.__context__ is None
    assert token not in repr(error)
    assert expected.pair_id not in repr(error)


def test_header_and_payload_require_exact_key_sets(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    variants: list[tuple[dict[str, object], dict[str, object]]] = []
    extra_header = dict(header)
    extra_header["cty"] = "JWT"
    variants.append((extra_header, payload))
    missing_header = dict(header)
    missing_header.pop("typ")
    variants.append((missing_header, payload))
    extra_payload = dict(payload)
    extra_payload["allocated_at_epoch"] = NOW
    variants.append((header, extra_payload))
    missing_payload = dict(payload)
    missing_payload.pop("credential_nonce")
    variants.append((header, missing_payload))

    for candidate_header, candidate_payload in variants:
        candidate = _sign_objects(
            current_private_key,
            candidate_header,
            candidate_payload,
        )
        _assert_error(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
            lambda candidate=candidate: verifier.verify(
                candidate,
                expected=expected,
                now_epoch=NOW,
            ),
        )


def test_noncanonical_json_duplicate_keys_and_padding_are_rejected(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, header, payload = _parts(signer, expected, monkeypatch)
    canonical_header = _canonical_json(header)
    canonical_payload = _canonical_json(payload)
    duplicate_header = (
        '{"alg":"RS256","alg":"RS256","kid":"'
        + str(header["kid"])
        + '","typ":"JWT"}'
    ).encode("ascii")
    duplicate_payload = canonical_payload[:-1] + (
        ',"pair_id":"' + expected.pair_id + '"}'
    ).encode("ascii")
    candidates = (
        _sign_raw(
            current_private_key,
            json.dumps(header, sort_keys=True).encode("ascii"),
            canonical_payload,
        ),
        _sign_raw(
            current_private_key,
            canonical_header,
            json.dumps(payload, sort_keys=True).encode("ascii"),
        ),
        _sign_raw(current_private_key, duplicate_header, canonical_payload),
        _sign_raw(current_private_key, canonical_header, duplicate_payload),
        token.split(".", 1)[0] + "=." + token.split(".", 1)[1],
        token + "=",
    )
    for candidate in candidates:
        _assert_error(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
            lambda candidate=candidate: verifier.verify(
                candidate,
                expected=expected,
                now_epoch=NOW,
            ),
        )


@pytest.mark.parametrize(
    "candidate",
    ("", "one.two", "one.two.three.four", "..", "é.abc.def", 1, b"a.b.c"),
)
def test_compact_jwt_requires_exact_three_ascii_segments(
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
    candidate: object,
) -> None:
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(
            candidate,  # type: ignore[arg-type]
            expected=expected,
            now_epoch=NOW,
        ),
    )


def test_compact_jwt_rejects_more_than_8192_ascii_characters(
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify("a" * 8193, expected=expected, now_epoch=NOW),
    )


@pytest.mark.parametrize(
    "field",
    ("binding_revision", "revocation_version", "generation", "connection_id"),
)
@pytest.mark.parametrize("bad_value", (True, "1", 1.0, 0, -1, INT64_MAX + 1))
def test_expected_integer_types_and_signed64_bounds_are_strict(
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
    field: str,
    bad_value: object,
) -> None:
    invalid = replace(expected, **{field: bad_value})
    _assert_error(
        PairGenerationCredentialErrorCode.SOURCE_INVALID,
        lambda: verifier.verify("x.y.z", expected=invalid, now_epoch=NOW),
    )


@pytest.mark.parametrize(
    "field",
    (
        "binding_revision",
        "revocation_version",
        "generation",
        "connection_id",
        "iat",
        "nbf",
        "exp",
    ),
)
@pytest.mark.parametrize("bad_value", (True, "1", 1.0, 0, -1, INT64_MAX + 1))
def test_claim_integer_types_and_signed64_bounds_are_strict(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    bad_value: object,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    payload[field] = bad_value
    candidate = _sign_objects(current_private_key, header, payload)
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(candidate, expected=expected, now_epoch=NOW),
    )


def test_non_time_claims_accept_signed64_maximum(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    maximum_expected = replace(
        expected,
        binding_revision=INT64_MAX,
        revocation_version=INT64_MAX,
        generation=INT64_MAX,
        connection_id=INT64_MAX,
    )
    payload.update({
        "binding_revision": INT64_MAX,
        "revocation_version": INT64_MAX,
        "generation": INT64_MAX,
        "connection_id": INT64_MAX,
    })
    candidate = _sign_objects(current_private_key, header, payload)
    assert verifier.verify(
        candidate,
        expected=maximum_expected,
        now_epoch=NOW,
    ).generation == INT64_MAX


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("allocation_request_id", ""),
        ("allocation_request_id", "a" * 129),
        ("allocation_request_id", "bad/request"),
        ("allocation_request_id", "请求"),
        ("pair_id", "A" * 32),
        ("entitlement_id", "1" * 31),
        ("binding_id", "z" * 32),
        ("host_identity_spki_sha256", "A" * 64),
        ("android_identity_spki_sha256", "1" * 63),
        ("transcript_proposal_sha256", "z" * 64),
    ),
)
def test_expected_identifiers_are_strict(
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
    field: str,
    value: str,
) -> None:
    invalid = replace(expected, **{field: value})
    _assert_error(
        PairGenerationCredentialErrorCode.SOURCE_INVALID,
        lambda: verifier.verify("x.y.z", expected=invalid, now_epoch=NOW),
    )


def test_host_and_android_identity_hashes_must_differ(
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    invalid = replace(
        expected,
        android_identity_spki_sha256=expected.host_identity_spki_sha256,
    )
    _assert_error(
        PairGenerationCredentialErrorCode.SOURCE_INVALID,
        lambda: verifier.verify("x.y.z", expected=invalid, now_epoch=NOW),
    )


@pytest.mark.parametrize(
    "field",
    (
        "allocation_request_id",
        "pair_id",
        "entitlement_id",
        "binding_id",
        "binding_revision",
        "revocation_version",
        "generation",
        "connection_id",
        "host_identity_spki_sha256",
        "android_identity_spki_sha256",
        "transcript_proposal_sha256",
    ),
)
def test_every_expected_credential_field_must_match(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
    field: str,
) -> None:
    token = _issue(signer, expected).token
    current = getattr(expected, field)
    replacement = current + 1 if type(current) is int else (
        ("f" if current[0] != "f" else "e") + current[1:]
    )
    wrong = replace(expected, **{field: replacement})
    _assert_error(
        PairGenerationCredentialErrorCode.TOKEN_INVALID,
        lambda: verifier.verify(token, expected=wrong, now_epoch=NOW),
    )


def test_private_allocation_freshness_is_strict_and_inclusive(
    signer,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    assert _issue(
        signer,
        expected,
        allocated_at_epoch=NOW - 5,
    ).verified_claims.issued_at_epoch == NOW
    for invalid_time in (NOW + 1, NOW - 6):
        _assert_error(
            PairGenerationCredentialErrorCode.ALLOCATION_TIME_INVALID,
            lambda invalid_time=invalid_time: _issue(
                signer,
                expected,
                allocated_at_epoch=invalid_time,
            ),
        )
    for invalid_type in (True, "1", 1.0, 0, INT64_MAX + 1):
        _assert_error(
            PairGenerationCredentialErrorCode.SOURCE_INVALID,
            lambda invalid_type=invalid_type: _issue(
                signer,
                expected,
                allocated_at_epoch=invalid_type,
            ),
        )


def test_issuance_accepts_exact_signed64_expiry_boundary(
    signer,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    boundary_now = INT64_MAX - 15
    result = _issue(
        signer,
        expected,
        now_epoch=boundary_now,
        allocated_at_epoch=boundary_now,
    )
    assert result.verified_claims.expires_at_epoch == INT64_MAX
    _assert_error(
        PairGenerationCredentialErrorCode.ALLOCATION_TIME_INVALID,
        lambda: _issue(
            signer,
            expected,
            now_epoch=boundary_now + 1,
            allocated_at_epoch=boundary_now + 1,
        ),
    )


def test_ttl_future_skew_and_expiration_boundaries(
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    maximum_signer = PrivateSigner(
        private_key=current_private_key,
        current_public_key=current_private_key.public_key(),
        ttl_seconds=MAX_CREDENTIAL_TTL_SECONDS,
    )
    verifier = PairGenerationCredentialV1Verifier(
        public_keys=(current_private_key.public_key(),),
    )
    token = _issue(maximum_signer, expected).token
    assert verifier.verify(
        token,
        expected=expected,
        now_epoch=NOW - 2,
    ).issued_at_epoch == NOW
    assert verifier.verify(
        token,
        expected=expected,
        now_epoch=NOW + MAX_CREDENTIAL_TTL_SECONDS - 1,
    ).expires_at_epoch == NOW + MAX_CREDENTIAL_TTL_SECONDS
    for invalid_now in (NOW - 3, NOW + MAX_CREDENTIAL_TTL_SECONDS):
        _assert_error(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
            lambda invalid_now=invalid_now: verifier.verify(
                token,
                expected=expected,
                now_epoch=invalid_now,
            ),
        )
    for invalid_ttl in (0, MAX_CREDENTIAL_TTL_SECONDS + 1, True, 15.0):
        _assert_error(
            PairGenerationCredentialErrorCode.KEY_INVALID,
            lambda invalid_ttl=invalid_ttl: PrivateSigner(
                private_key=current_private_key,
                current_public_key=current_private_key.public_key(),
                ttl_seconds=invalid_ttl,
            ),
        )


def test_token_time_relationships_and_absolute_ttl_are_strict(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    current_private_key: rsa.RSAPrivateKey,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _token, header, payload = _parts(signer, expected, monkeypatch)
    variants = (
        ("nbf", NOW + 1),
        ("exp", NOW),
        ("exp", NOW - 1),
        ("exp", NOW + MAX_CREDENTIAL_TTL_SECONDS + 1),
    )
    for field, value in variants:
        modified = dict(payload)
        modified[field] = value
        candidate = _sign_objects(current_private_key, header, modified)
        _assert_error(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
            lambda candidate=candidate: verifier.verify(
                candidate,
                expected=expected,
                now_epoch=NOW,
            ),
        )


def test_now_epoch_is_a_strict_signed64_integer(
    signer,
    verifier: PairGenerationCredentialV1Verifier,
    expected: PairGenerationCredentialExpectedV1,
) -> None:
    token = _issue(signer, expected).token
    for invalid_now in (True, "1", 1.0, 0, -1, INT64_MAX + 1):
        _assert_error(
            PairGenerationCredentialErrorCode.ALLOCATION_TIME_INVALID,
            lambda invalid_now=invalid_now: _issue(
                signer,
                expected,
                now_epoch=invalid_now,
            ),
        )
        _assert_error(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
            lambda invalid_now=invalid_now: verifier.verify(
                token,
                expected=expected,
                now_epoch=invalid_now,
            ),
        )


def test_signing_fails_closed_when_immediate_post_verify_fails(
    signer,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(*_args, **_kwargs):
        raise PairGenerationCredentialError(
            PairGenerationCredentialErrorCode.TOKEN_INVALID,
        )

    monkeypatch.setattr(PairGenerationCredentialV1Verifier, "verify", reject)
    error = _assert_error(
        PairGenerationCredentialErrorCode.SIGNING_FAILED,
        lambda: _issue(signer, expected),
    )
    assert error.__cause__ is None
    assert error.__context__ is None


def test_nonce_provider_failure_is_sanitized_without_cause(
    signer,
    expected: PairGenerationCredentialExpectedV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_nonce(_size: int) -> bytes:
        raise RuntimeError("provider-secret-detail")

    monkeypatch.setattr(credential.secrets, "token_bytes", fail_nonce)
    error = _assert_error(
        PairGenerationCredentialErrorCode.SIGNING_FAILED,
        lambda: _issue(signer, expected),
    )
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "provider-secret-detail" not in repr(error)
