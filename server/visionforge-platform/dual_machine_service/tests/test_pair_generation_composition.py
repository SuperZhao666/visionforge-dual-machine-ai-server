from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dual_machine_service.pair_generation_authorization_service import (
    PairGenerationAuthorizationService,
)
from dual_machine_service.pair_generation_composition import (
    PairGenerationCompositionError,
    build_pair_generation_authorization_service,
)
from dual_machine_service.pair_generation_credential_service import (
    MAX_JOURNAL_CREDENTIAL_PUBLIC_KEYS,
)
from dual_machine_service.settings import DualMachineSettings


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    private_key: rsa.RSAPrivateKey
    private_path: Path
    public_path: Path


@dataclass(frozen=True, slots=True)
class CompositionKeyring:
    ticket: KeyMaterial
    current: KeyMaterial
    previous: KeyMaterial
    archived: KeyMaterial
    unrelated: KeyMaterial


@pytest.fixture(scope="module")
def keyring(tmp_path_factory: pytest.TempPathFactory) -> CompositionKeyring:
    root = tmp_path_factory.mktemp("pair-composition-keys")
    return CompositionKeyring(
        ticket=_write_keypair(root, "ticket"),
        current=_write_keypair(root, "current"),
        previous=_write_keypair(root, "previous"),
        archived=_write_keypair(root, "archived"),
        unrelated=_write_keypair(root, "unrelated"),
    )


def test_composition_loads_dedicated_current_previous_and_archive_keys(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    settings = _settings(
        tmp_path,
        keyring,
        previous_paths=(keyring.previous.public_path,),
        archived_paths=(keyring.archived.public_path,),
    )

    settings.validate_runtime()
    service = build_pair_generation_authorization_service(settings)

    assert type(service) is PairGenerationAuthorizationService


def test_composition_rejects_mismatched_pair_private_and_public_keys(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_public_key_path=keyring.unrelated.public_path,
    )

    _assert_composition_rejected(settings)


@pytest.mark.parametrize(
    ("key_size", "public_exponent"),
    [(2048, 65537), (3072, 3)],
)
def test_composition_rejects_weak_or_nonstandard_pair_rsa_key(
    tmp_path: Path,
    keyring: CompositionKeyring,
    key_size: int,
    public_exponent: int,
) -> None:
    invalid = _write_keypair(
        tmp_path,
        f"invalid-{key_size}-{public_exponent}",
        key_size=key_size,
        public_exponent=public_exponent,
    )
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_private_key_path=invalid.private_path,
        pair_credential_public_key_path=invalid.public_path,
    )

    _assert_composition_rejected(settings)


def test_composition_rejects_ticket_spki_reused_through_other_paths(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    disguised_pair = _write_existing_keypair(
        tmp_path,
        "disguised-pair",
        keyring.ticket.private_key,
    )
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_private_key_path=disguised_pair.private_path,
        pair_credential_public_key_path=disguised_pair.public_path,
    )
    settings.validate_runtime()

    _assert_composition_rejected(settings)


@pytest.mark.parametrize("duplicate_location", ["previous", "archived"])
def test_composition_rejects_duplicate_pair_key_material_at_distinct_paths(
    tmp_path: Path,
    keyring: CompositionKeyring,
    duplicate_location: str,
) -> None:
    duplicate_public_path = tmp_path / f"duplicate-{duplicate_location}.pem"
    duplicate_public_path.write_bytes(
        keyring.current.public_path.read_bytes(),
    )
    settings = _settings(
        tmp_path,
        keyring,
        previous_paths=(duplicate_public_path,)
        if duplicate_location == "previous"
        else (),
        archived_paths=(duplicate_public_path,)
        if duplicate_location == "archived"
        else (),
    )
    settings.validate_runtime()

    _assert_composition_rejected(settings)


def test_composition_rejects_duplicate_previous_and_archive_spki(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    archive_alias = tmp_path / "previous-as-archive.pem"
    archive_alias.write_bytes(keyring.previous.public_path.read_bytes())
    settings = _settings(
        tmp_path,
        keyring,
        previous_paths=(keyring.previous.public_path,),
        archived_paths=(archive_alias,),
    )
    settings.validate_runtime()

    _assert_composition_rejected(settings)


def test_runtime_validation_requires_pair_credential_paths(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_private_key_path=None,
        pair_credential_public_key_path=None,
    )

    with pytest.raises(ValueError) as exc_info:
        settings.validate_runtime()

    message = str(exc_info.value)
    assert "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH is required" in message
    assert "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH is required" in message


def test_pair_key_path_limits_and_total_verifier_closure_are_strict(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    previous_paths = tuple(tmp_path / f"previous-{index}.pem" for index in range(3))
    archived_paths = tuple(tmp_path / f"archive-{index}.pem" for index in range(14))

    with pytest.raises(ValueError, match="at most 2 paths"):
        replace(
            _settings(tmp_path, keyring),
            pair_credential_previous_public_key_paths=previous_paths,
        ).validate_runtime()
    with pytest.raises(ValueError, match="at most 13 paths"):
        replace(
            _settings(tmp_path, keyring),
            pair_credential_archived_public_key_paths=archived_paths,
        ).validate_runtime()
    with pytest.raises(ValueError, match="at most 16 public keys"):
        replace(
            _settings(tmp_path, keyring),
            pair_credential_previous_public_key_paths=previous_paths,
            pair_credential_archived_public_key_paths=archived_paths[:13],
        ).validate_runtime()


def test_sixteen_key_verifier_closure_is_the_accepted_boundary(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    assert MAX_JOURNAL_CREDENTIAL_PUBLIC_KEYS == 16
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_previous_public_key_paths=tuple(
            tmp_path / f"previous-boundary-{index}.pem" for index in range(2)
        ),
        pair_credential_archived_public_key_paths=tuple(
            tmp_path / f"archive-boundary-{index}.pem" for index in range(13)
        ),
    )

    settings.validate_runtime()


@pytest.mark.parametrize(
    "variable_name",
    [
        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON",
        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON",
    ],
)
@pytest.mark.parametrize("invalid_json", ["{}", '"path"', '[""]', "not-json"])
def test_environment_rejects_non_array_empty_or_invalid_pair_key_json(
    monkeypatch: pytest.MonkeyPatch,
    keyring: CompositionKeyring,
    variable_name: str,
    invalid_json: str,
) -> None:
    _set_runtime_environment(monkeypatch, keyring)
    monkeypatch.setenv(variable_name, invalid_json)

    with pytest.raises(ValueError):
        DualMachineSettings.from_environment()


def test_environment_duplicate_pair_key_path_fails_runtime_validation(
    monkeypatch: pytest.MonkeyPatch,
    keyring: CompositionKeyring,
) -> None:
    _set_runtime_environment(monkeypatch, keyring)
    monkeypatch.setenv(
        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON",
        json.dumps([str(keyring.current.public_path)]),
    )

    settings = DualMachineSettings.from_environment()
    with pytest.raises(ValueError, match="contain duplicates"):
        settings.validate_runtime()


def test_environment_rejects_pair_keyring_arrays_above_limits(
    monkeypatch: pytest.MonkeyPatch,
    keyring: CompositionKeyring,
) -> None:
    _set_runtime_environment(monkeypatch, keyring)
    monkeypatch.setenv(
        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON",
        json.dumps([f"previous-{index}.pem" for index in range(3)]),
    )
    with pytest.raises(ValueError, match="at most 2 paths"):
        DualMachineSettings.from_environment()

    _set_runtime_environment(monkeypatch, keyring)
    monkeypatch.setenv(
        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON",
        json.dumps([f"archive-{index}.pem" for index in range(14)]),
    )
    with pytest.raises(ValueError, match="at most 13 paths"):
        DualMachineSettings.from_environment()


def test_composition_rejects_wrong_pair_private_key_password(
    tmp_path: Path,
    keyring: CompositionKeyring,
) -> None:
    encrypted = _write_keypair(
        tmp_path,
        "encrypted-pair",
        password=b"correct-password",
    )
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_private_key_path=encrypted.private_path,
        pair_credential_public_key_path=encrypted.public_path,
        pair_credential_private_key_password="wrong-password",
    )

    _assert_composition_rejected(settings)


@pytest.mark.parametrize("ttl_seconds", [0, 31])
def test_runtime_validation_rejects_pair_credential_ttl_outside_window(
    tmp_path: Path,
    keyring: CompositionKeyring,
    ttl_seconds: int,
) -> None:
    settings = replace(
        _settings(tmp_path, keyring),
        pair_credential_ttl_seconds=ttl_seconds,
    )

    with pytest.raises(ValueError, match="must be between 1 and 30"):
        settings.validate_runtime()


def _settings(
    tmp_path: Path,
    keyring: CompositionKeyring,
    *,
    previous_paths: tuple[Path, ...] = (),
    archived_paths: tuple[Path, ...] = (),
) -> DualMachineSettings:
    return DualMachineSettings(
        database_path=tmp_path / "composition.db",
        license_code_secret=b"composition-license-secret-at-least-32-bytes",
        token_secret=b"composition-token-secret-at-least-32-bytes",
        minimum_host_client_version="1.0.0",
        minimum_android_client_version="1.0.0",
        ticket_private_key_path=keyring.ticket.private_path,
        ticket_public_key_path=keyring.ticket.public_path,
        pair_credential_private_key_path=keyring.current.private_path,
        pair_credential_public_key_path=keyring.current.public_path,
        pair_credential_previous_public_key_paths=previous_paths,
        pair_credential_archived_public_key_paths=archived_paths,
    )


def _write_keypair(
    root: Path,
    name: str,
    *,
    key_size: int = 3072,
    public_exponent: int = 65537,
    password: bytes | None = None,
) -> KeyMaterial:
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return _write_existing_keypair(
        root,
        name,
        private_key,
        password=password,
    )


def _write_existing_keypair(
    root: Path,
    name: str,
    private_key: rsa.RSAPrivateKey,
    *,
    password: bytes | None = None,
) -> KeyMaterial:
    private_path = root / f"{name}-private.pem"
    public_path = root / f"{name}-public.pem"
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return KeyMaterial(
        private_key=private_key,
        private_path=private_path,
        public_path=public_path,
    )


def _set_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
    keyring: CompositionKeyring,
) -> None:
    values = {
        "DUAL_MACHINE_DATABASE_PATH": str(
            keyring.current.private_path.parent / "environment.db"
        ),
        "DUAL_MACHINE_LICENSE_CODE_SECRET": (
            "environment-license-secret-at-least-32-bytes"
        ),
        "DUAL_MACHINE_TOKEN_SECRET": "environment-token-secret-at-least-32-bytes",
        "DUAL_MACHINE_MIN_HOST_CLIENT_VERSION": "1.0.0",
        "DUAL_MACHINE_MIN_ANDROID_CLIENT_VERSION": "1.0.0",
        "DUAL_MACHINE_TICKET_PRIVATE_KEY_PATH": str(keyring.ticket.private_path),
        "DUAL_MACHINE_TICKET_PUBLIC_KEY_PATH": str(keyring.ticket.public_path),
        "DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON": "[]",
        "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH": str(
            keyring.current.private_path
        ),
        "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH": str(
            keyring.current.public_path
        ),
        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON": "[]",
        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON": "[]",
        "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS": "15",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _assert_composition_rejected(settings: DualMachineSettings) -> None:
    with pytest.raises(
        PairGenerationCompositionError,
        match="pair_generation_credential_keyring_invalid",
    ):
        build_pair_generation_authorization_service(settings)
