from __future__ import annotations

import base64
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from dual_machine_service import pair_security_repository as repository_module

from dual_machine_service.card_service import (
    CardActivationService,
    CardIssuanceService,
)
from dual_machine_service.database import connect_database, initialize_database
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.identity import (
    canonical_base64,
    parse_p256_identity,
)
from dual_machine_service.main import create_app
from dual_machine_service.pair_generation_authorization_service import (
    PairGenerationAuthorizationService,
)
from dual_machine_service.pair_generation_credential_service import (
    PairGenerationCredentialService,
)
from dual_machine_service.pair_generation_credential_v1 import (
    PairGenerationCredentialExpectedV1,
    PairGenerationCredentialV1Verifier,
)
from dual_machine_service.pair_generation_pop_v1 import (
    PairGenerationChallengeRequestFieldsV1,
    build_pair_generation_challenge_request_v1,
    build_pair_generation_final_credential_proof_v1,
    derive_pair_generation_connection_id_v1,
)
from dual_machine_service.pair_generation_proposal_v1 import (
    PairGenerationProposalFields,
    ProposalTransportKind,
    build_pair_generation_proposal_v1,
)
from dual_machine_service.settings import DualMachineSettings


@dataclass(frozen=True, slots=True)
class AuthorizedPairFixture:
    settings: DualMachineSettings
    service: PairGenerationAuthorizationService
    credential_private_key: rsa.RSAPrivateKey
    host_private_key: ec.EllipticCurvePrivateKey
    android_private_key: ec.EllipticCurvePrivateKey
    activation: dict
    host_key_sha256: str
    android_key_sha256: str

    def challenge_command(self, label: str) -> dict:
        unsigned = {
            "request_id": _hex_id(f"challenge:{label}"),
            "allocation_request_id": _hex_id(f"allocation:{label}"),
            "entitlement_id": self.activation["entitlement_id"],
            "pair_id": self.activation["pair_id"],
            "binding_id": self.activation["binding_id"],
            "binding_revision": self.activation["binding_revision"],
            "revocation_version": self.activation["revocation_version"],
            "protocol_version": 2,
        }
        return _signed_command(
            unsigned,
            _challenge_request(self, unsigned).canonical_bytes,
            self.host_private_key,
            self.android_private_key,
        )

    def credential_command(
        self,
        label: str,
        challenge: dict,
        *,
        proposal=None,
    ) -> tuple[dict, object]:
        proposal = proposal or _proposal(self, label, challenge)
        unsigned = {
            "allocation_request_id": challenge["allocation_request_id"],
            "challenge_id": challenge["challenge_id"],
            "server_nonce": challenge["server_nonce"],
            "proposal_b64": canonical_base64(proposal.canonical_bytes),
            "entitlement_id": self.activation["entitlement_id"],
            "pair_id": self.activation["pair_id"],
            "binding_id": self.activation["binding_id"],
            "binding_revision": self.activation["binding_revision"],
            "revocation_version": self.activation["revocation_version"],
            "protocol_version": 2,
        }
        proof = build_pair_generation_final_credential_proof_v1(
            _challenge_request_from_response(self, challenge),
            challenge_id=challenge["challenge_id"],
            challenge_expires_at_epoch=(
                challenge["challenge_expires_at_epoch"]
            ),
            server_nonce=bytes.fromhex(challenge["server_nonce"]),
            canonical_proposal_bytes=proposal.canonical_bytes,
        )
        return (
            _signed_command(
                unsigned,
                proof.canonical_bytes,
                self.host_private_key,
                self.android_private_key,
            ),
            proposal,
        )


@pytest.fixture()
def authorized_pair(tmp_path: Path) -> AuthorizedPairFixture:
    ticket_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ticket_private_path = tmp_path / "ticket-private.pem"
    ticket_public_path = tmp_path / "ticket-public.pem"
    ticket_private_path.write_bytes(ticket_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    ticket_public_path.write_bytes(ticket_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    credential_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    credential_private_path = tmp_path / "pair-credential-private.pem"
    credential_public_path = tmp_path / "pair-credential-public.pem"
    credential_private_path.write_bytes(credential_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    credential_public_path.write_bytes(
        credential_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    settings = DualMachineSettings(
        database_path=tmp_path / "pair-authorization.db",
        license_code_secret=b"pair-authorization-license-secret-32-bytes",
        token_secret=b"pair-authorization-token-secret-32-bytes-min",
        minimum_host_client_version="17.8.81",
        minimum_android_client_version="1.0.0",
        ticket_private_key_path=ticket_private_path,
        ticket_public_key_path=ticket_public_path,
        pair_credential_private_key_path=credential_private_path,
        pair_credential_public_key_path=credential_public_path,
    )
    initialize_database(settings)
    issued = CardIssuanceService(settings).issue_batch(
        request_id=_hex_id("card-batch"),
        product_key="day",
        quantity=1,
        channel="test",
        now_epoch=1_700_000_000,
    )
    host_private, host_public = _identity()
    android_private, android_public = _identity()
    activation_service = CardActivationService(settings)
    challenge = activation_service.create_challenge(
        {
            "request_id": _hex_id("card-activation"),
            "pair_id": _hex_id("pair"),
            "protocol_version": 2,
            "card_code": issued.codes[0],
            "host": {
                "device_code": "HOST-PAIR-AUTH",
                "client_version": "17.8.81",
                "identity_public_key_b64": host_public,
            },
            "android": {
                "device_code": "ANDROID-PAIR-AUTH",
                "client_version": "1.0.0",
                "identity_public_key_b64": android_public,
            },
        },
        client_ip="127.0.0.1",
        now_epoch=1_700_000_001,
    )
    proof = base64.b64decode(challenge["proof_payload_b64"], validate=True)
    activation = activation_service.confirm_activation(
        {
            "challenge_id": challenge["challenge_id"],
            "challenge_token": challenge["challenge_token"],
            "host_signature_b64": _sign(host_private, proof),
            "android_signature_b64": _sign(android_private, proof),
        },
        client_ip="127.0.0.1",
        now_epoch=1_700_000_002,
    )
    credential_service = PairGenerationCredentialService(
        settings=settings,
        private_key=credential_private_key,
        current_public_key=credential_private_key.public_key(),
        other_purpose_public_keys=(ticket_key.public_key(),),
    )
    return AuthorizedPairFixture(
        settings=settings,
        service=PairGenerationAuthorizationService(
            settings,
            credential_service=credential_service,
        ),
        credential_private_key=credential_private_key,
        host_private_key=host_private,
        android_private_key=android_private,
        activation=activation,
        host_key_sha256=parse_p256_identity(host_public).fingerprint_sha256,
        android_key_sha256=(
            parse_p256_identity(android_public).fingerprint_sha256
        ),
    )


def test_dual_signed_challenge_and_credential_issue_then_exactly_replay(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge_command = authorized_pair.challenge_command("happy")
    challenge = authorized_pair.service.create_generation_challenge(
        challenge_command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
        trace_id="pair-challenge-happy",
    )
    replayed_challenge = authorized_pair.service.create_generation_challenge(
        challenge_command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_020,
        trace_id="pair-challenge-replay",
    )
    assert replayed_challenge == challenge
    assert challenge["challenge_expires_at_epoch"] == 1_700_000_040

    credential_command, proposal = authorized_pair.credential_command(
        "happy",
        challenge,
    )
    issued = authorized_pair.service.issue_generation_credential(
        credential_command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_021,
        trace_id="pair-credential-happy",
    )
    replayed = authorized_pair.service.issue_generation_credential(
        credential_command,
        client_ip="127.0.0.1",
        now_epoch=1_700_000_100,
        trace_id="pair-credential-replay",
    )
    assert replayed == issued
    assert issued["generation"] == 1
    assert issued["transcript_proposal_sha256"] == proposal.proposal_sha256.hex()
    verified = PairGenerationCredentialV1Verifier(
        public_keys=(authorized_pair.credential_private_key.public_key(),),
        other_purpose_public_keys=(),
    ).verify(
        issued["credential_token"],
        expected=PairGenerationCredentialExpectedV1(
            allocation_request_id=issued["allocation_request_id"],
            pair_id=issued["pair_id"],
            entitlement_id=authorized_pair.activation["entitlement_id"],
            binding_id=authorized_pair.activation["binding_id"],
            binding_revision=issued["binding_revision"],
            revocation_version=authorized_pair.activation["revocation_version"],
            generation=issued["generation"],
            connection_id=issued["connection_id"],
            host_identity_spki_sha256=authorized_pair.host_key_sha256,
            android_identity_spki_sha256=authorized_pair.android_key_sha256,
            transcript_proposal_sha256=issued["transcript_proposal_sha256"],
        ),
        now_epoch=issued["credential_issued_at_epoch"],
    )
    assert verified.generation == 1


def test_invalid_peer_signature_has_no_generation_side_effect(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    command = authorized_pair.challenge_command("invalid-signature")
    other_private, _ = _identity()
    command["android_signature_b64"] = _sign(
        other_private,
        _challenge_request(authorized_pair, command).canonical_bytes,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_device_proof_invalid",
    ):
        authorized_pair.service.create_generation_challenge(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )
    assert _count(authorized_pair, "dm_pair_generation_challenges") == 0
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0


def test_challenge_signature_binds_allocation_request_id(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    command = authorized_pair.challenge_command("allocation-binding")
    command["allocation_request_id"] = _hex_id("different-allocation")

    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_device_proof_invalid",
    ):
        authorized_pair.service.create_generation_challenge(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )
    assert _count(authorized_pair, "dm_pair_generation_challenges") == 0


def test_final_proof_cannot_move_challenge_to_another_allocation(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("allocation-final"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    original_command, proposal = authorized_pair.credential_command(
        "allocation-final",
        challenge,
    )
    changed_allocation = _hex_id("changed-final-allocation")
    changed_request = build_pair_generation_challenge_request_v1(
        replace(
            _challenge_request_from_response(
                authorized_pair,
                challenge,
            ).fields,
            allocation_request_id=changed_allocation,
        ),
    )
    changed_proof = build_pair_generation_final_credential_proof_v1(
        changed_request,
        challenge_id=challenge["challenge_id"],
        challenge_expires_at_epoch=challenge["challenge_expires_at_epoch"],
        server_nonce=bytes.fromhex(challenge["server_nonce"]),
        canonical_proposal_bytes=proposal.canonical_bytes,
    )
    changed_command = _signed_command(
        {
            **{
                key: value
                for key, value in original_command.items()
                if key not in {"host_signature_b64", "android_signature_b64"}
            },
            "allocation_request_id": changed_allocation,
        },
        changed_proof.canonical_bytes,
        authorized_pair.host_private_key,
        authorized_pair.android_private_key,
    )

    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_challenge_mismatch",
    ):
        authorized_pair.service.issue_generation_credential(
            changed_command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0


def test_wrong_server_nonce_or_proposal_after_signing_fails_closed(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("mutation"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    command, _proposal_owner = authorized_pair.credential_command(
        "mutation",
        challenge,
    )
    wrong_nonce = dict(command)
    wrong_nonce["server_nonce"] = "f" * 64
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_server_nonce_invalid",
    ):
        authorized_pair.service.issue_generation_credential(
            wrong_nonce,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )

    wrong_proposal = dict(command)
    wrong_proposal["proposal_b64"] = canonical_base64(
        _proposal(authorized_pair, "different", challenge).canonical_bytes,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_device_proof_invalid",
    ):
        authorized_pair.service.issue_generation_credential(
            wrong_proposal,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0
    assert _count(authorized_pair, "dm_pair_generation_credentials") == 0


def test_server_rejects_proposal_with_non_derived_connection_id(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("connection-authority"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    command, proposal = authorized_pair.credential_command(
        "connection-authority",
        challenge,
    )
    wrong_connection = proposal.fields.connection_id + 1
    wrong_proposal = build_pair_generation_proposal_v1(
        replace(proposal.fields, connection_id=wrong_connection),
    )
    command["proposal_b64"] = canonical_base64(
        wrong_proposal.canonical_bytes,
    )

    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_pop_connection_id_mismatch",
    ):
        authorized_pair.service.issue_generation_credential(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0


def test_live_revocation_after_challenge_blocks_credential(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("revoked"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    command, _proposal_owner = authorized_pair.credential_command(
        "revoked",
        challenge,
    )
    connection = connect_database(authorized_pair.settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET status = 'revoked', "
            "revocation_version = revocation_version + 1 "
            "WHERE entitlement_id = ?",
            (authorized_pair.activation["entitlement_id"],),
        )
    finally:
        connection.close()
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_authority_invalid",
    ):
        authorized_pair.service.issue_generation_credential(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0


def test_challenge_rechecks_registered_key_after_acquiring_write_lock(
    authorized_pair: AuthorizedPairFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _replacement_private, replacement_public = _identity()
    original = (
        repository_module.PairGenerationChallengeUnitOfWork
        .load_peer_authority_for_context
    )

    def replace_key(unit, **context):
        unit._connection.execute(  # noqa: SLF001 - deliberate TOCTOU fixture
            "UPDATE dm_entitlement_device_bindings SET "
            "host_identity_public_key_b64 = ? WHERE binding_id = ?",
            (replacement_public, authorized_pair.activation["binding_id"]),
        )
        return original(unit, **context)

    monkeypatch.setattr(
        repository_module.PairGenerationChallengeUnitOfWork,
        "load_peer_authority_for_context",
        replace_key,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_device_proof_invalid",
    ):
        authorized_pair.service.create_generation_challenge(
            authorized_pair.challenge_command("challenge-toctou"),
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010,
        )
    assert _count(authorized_pair, "dm_pair_generation_challenges") == 0


def test_credential_rechecks_registered_key_inside_issuance_transaction(
    authorized_pair: AuthorizedPairFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("credential-toctou"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    command, _proposal_owner = authorized_pair.credential_command(
        "credential-toctou",
        challenge,
    )
    _replacement_private, replacement_public = _identity()
    original = (
        repository_module.PairGenerationCredentialUnitOfWork
        .load_peer_authority_for_context
    )

    def replace_key(unit, **context):
        unit._connection.execute(  # noqa: SLF001 - deliberate TOCTOU fixture
            "UPDATE dm_entitlement_device_bindings SET "
            "host_identity_public_key_b64 = ? WHERE binding_id = ?",
            (replacement_public, authorized_pair.activation["binding_id"]),
        )
        return original(unit, **context)

    monkeypatch.setattr(
        repository_module.PairGenerationCredentialUnitOfWork,
        "load_peer_authority_for_context",
        replace_key,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_device_proof_invalid",
    ):
        authorized_pair.service.issue_generation_credential(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0
    assert _challenge_status(authorized_pair, challenge["challenge_id"]) == "issued"


def test_success_audit_failure_rolls_back_credential_and_challenge(
    authorized_pair: AuthorizedPairFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = authorized_pair.service.create_generation_challenge(
        authorized_pair.challenge_command("audit-rollback"),
        client_ip="127.0.0.1",
        now_epoch=1_700_000_010,
    )
    command, _proposal_owner = authorized_pair.credential_command(
        "audit-rollback",
        challenge,
    )

    def fail_audit(*_args, **_kwargs) -> None:
        raise sqlite3.OperationalError("synthetic audit failure")

    monkeypatch.setattr(
        repository_module.PairGenerationCredentialUnitOfWork,
        "record_security_audit",
        fail_audit,
    )
    with pytest.raises(
        DualMachineServiceError,
        match="pair_generation_persistence_failed",
    ):
        authorized_pair.service.issue_generation_credential(
            command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_011,
        )
    assert _count(authorized_pair, "dm_pair_generation_allocations") == 0
    assert _count(authorized_pair, "dm_pair_generation_credentials") == 0
    assert _challenge_status(authorized_pair, challenge["challenge_id"]) == "issued"


def test_concurrent_exact_requests_share_challenge_and_credential_bytes(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    challenge_command = authorized_pair.challenge_command("concurrent")

    def issue_challenge(ordinal: int):
        return authorized_pair.service.create_generation_challenge(
            challenge_command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_010 + ordinal,
        )

    with ThreadPoolExecutor(max_workers=6) as executor:
        challenges = list(executor.map(issue_challenge, range(6)))
    assert all(challenge == challenges[0] for challenge in challenges)
    credential_command, _proposal_owner = authorized_pair.credential_command(
        "concurrent",
        challenges[0],
    )

    def issue_credential(_ordinal: int):
        return authorized_pair.service.issue_generation_credential(
            credential_command,
            client_ip="127.0.0.1",
            now_epoch=1_700_000_020,
        )

    with ThreadPoolExecutor(max_workers=6) as executor:
        credentials = list(executor.map(issue_credential, range(6)))
    assert len({item["credential_token"] for item in credentials}) == 1
    assert _count(authorized_pair, "dm_pair_generation_credentials") == 1


def test_public_routes_use_composed_dedicated_key_and_strict_wire_types(
    authorized_pair: AuthorizedPairFixture,
) -> None:
    with TestClient(create_app(authorized_pair.settings)) as client:
        challenge_command = authorized_pair.challenge_command("route")
        challenge_response = client.post(
            "/api/dual-machine/v1/pair-generations/challenges",
            json=challenge_command,
        )
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()
        credential_command, _proposal_owner = authorized_pair.credential_command(
            "route",
            challenge,
        )
        credential_response = client.post(
            "/api/dual-machine/v1/pair-generations/credentials",
            json=credential_command,
        )
        assert credential_response.status_code == 200
        assert credential_response.json()["generation"] == 1

        wrong_type = dict(challenge_command)
        wrong_type["binding_revision"] = True
        assert client.post(
            "/api/dual-machine/v1/pair-generations/challenges",
            json=wrong_type,
        ).status_code == 422
        extra = {**challenge_command, "unexpected": "field"}
        assert client.post(
            "/api/dual-machine/v1/pair-generations/challenges",
            json=extra,
        ).status_code == 422


def _challenge_request(
    fixture: AuthorizedPairFixture,
    command: dict,
):
    return build_pair_generation_challenge_request_v1(
        PairGenerationChallengeRequestFieldsV1(
            request_id=command["request_id"],
            allocation_request_id=command["allocation_request_id"],
            entitlement_id=fixture.activation["entitlement_id"],
            pair_id=fixture.activation["pair_id"],
            binding_id=fixture.activation["binding_id"],
            binding_revision=fixture.activation["binding_revision"],
            revocation_version=fixture.activation["revocation_version"],
            host_identity_spki_sha256=fixture.host_key_sha256,
            android_identity_spki_sha256=fixture.android_key_sha256,
        ),
    )


def _challenge_request_from_response(
    fixture: AuthorizedPairFixture,
    challenge: dict,
):
    return build_pair_generation_challenge_request_v1(
        PairGenerationChallengeRequestFieldsV1(
            request_id=challenge["request_id"],
            allocation_request_id=challenge["allocation_request_id"],
            entitlement_id=fixture.activation["entitlement_id"],
            pair_id=fixture.activation["pair_id"],
            binding_id=fixture.activation["binding_id"],
            binding_revision=fixture.activation["binding_revision"],
            revocation_version=fixture.activation["revocation_version"],
            host_identity_spki_sha256=fixture.host_key_sha256,
            android_identity_spki_sha256=fixture.android_key_sha256,
        ),
    )


def _proposal(
    fixture: AuthorizedPairFixture,
    label: str,
    challenge: dict,
):
    host_nonce = hashlib.sha256(f"host:{label}".encode("ascii")).digest()
    android_nonce = hashlib.sha256(
        f"android:{label}".encode("ascii"),
    ).digest()
    connection_id = derive_pair_generation_connection_id_v1(
        bytes.fromhex(challenge["server_nonce"]),
        challenge_id=challenge["challenge_id"],
        host_nonce=host_nonce,
        android_nonce=android_nonce,
        pair_id=fixture.activation["pair_id"],
        host_identity_spki_sha256=fixture.host_key_sha256,
        android_identity_spki_sha256=fixture.android_key_sha256,
    )
    return build_pair_generation_proposal_v1(
        PairGenerationProposalFields(
            host_identity_spki_sha256=bytes.fromhex(fixture.host_key_sha256),
            android_identity_spki_sha256=(
                bytes.fromhex(fixture.android_key_sha256)
            ),
            host_ephemeral_public_key=_p256_point(11),
            android_ephemeral_public_key=_p256_point(12),
            host_nonce=host_nonce,
            android_nonce=android_nonce,
            connection_id=connection_id,
            transport_kind=ProposalTransportKind.CAT6,
            host_ipv4=bytes((192, 168, 1, 18)),
            android_ipv4=bytes((192, 168, 1, 42)),
            video_port=50_000,
            control_port=50_001,
            pair_id=fixture.activation["pair_id"],
            host_runtime_version="1.0.8",
            android_runtime_version="1.0.8",
        ),
    )


def _signed_command(
    unsigned: dict,
    payload: bytes,
    host_private: ec.EllipticCurvePrivateKey,
    android_private: ec.EllipticCurvePrivateKey,
) -> dict:
    return {
        **unsigned,
        "host_signature_b64": _sign(host_private, payload),
        "android_signature_b64": _sign(android_private, payload),
    }


def _identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, canonical_base64(public_der)


def _sign(private_key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    return base64.b64encode(
        private_key.sign(payload, ec.ECDSA(hashes.SHA256())),
    ).decode("ascii")


def _p256_point(private_scalar: int) -> bytes:
    return ec.derive_private_key(
        private_scalar,
        ec.SECP256R1(),
    ).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _hex_id(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]


def _count(fixture: AuthorizedPairFixture, table_name: str) -> int:
    assert table_name in {
        "dm_pair_generation_challenges",
        "dm_pair_generation_allocations",
        "dm_pair_generation_credentials",
    }
    connection = connect_database(fixture.settings)
    try:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])
    finally:
        connection.close()


def _challenge_status(
    fixture: AuthorizedPairFixture,
    challenge_id: str,
) -> str:
    connection = connect_database(fixture.settings)
    try:
        row = connection.execute(
            "SELECT status FROM dm_pair_generation_challenges "
            "WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return str(row["status"])
