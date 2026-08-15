"""Production key loading and composition for pair-generation issuance."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .pair_generation_authorization_service import (
    PairGenerationAuthorizationService,
)
from .pair_generation_credential_service import (
    PairGenerationCredentialService,
)
from .settings import DualMachineSettings


class PairGenerationCompositionError(RuntimeError):
    """Sanitized failure raised before the public route can start."""


def build_pair_generation_authorization_service(
    settings: DualMachineSettings,
) -> PairGenerationAuthorizationService:
    """Load the dedicated keyring and enforce cross-purpose separation."""
    try:
        pair_private_key = _load_private_key(
            settings.pair_credential_private_key_path,
            password=settings.pair_credential_private_key_password,
        )
        pair_public_key = _load_public_key(
            settings.pair_credential_public_key_path,
        )
        previous_public_keys = tuple(
            _load_public_key(path)
            for path in settings.pair_credential_previous_public_key_paths
        )
        archived_public_keys = tuple(
            _load_public_key(path)
            for path in settings.pair_credential_archived_public_key_paths
        )
        ticket_public_keys = (
            _load_public_key(settings.ticket_public_key_path),
            *tuple(
                _load_public_key(path)
                for path in settings.ticket_previous_public_key_paths
            ),
        )
        credential_service = PairGenerationCredentialService(
            settings=settings,
            private_key=pair_private_key,
            current_public_key=pair_public_key,
            previous_public_keys=previous_public_keys,
            archived_public_keys=archived_public_keys,
            other_purpose_public_keys=ticket_public_keys,
            ttl_seconds=settings.pair_credential_ttl_seconds,
        )
        return PairGenerationAuthorizationService(
            settings,
            credential_service=credential_service,
        )
    except Exception as exc:
        raise PairGenerationCompositionError(
            "pair_generation_credential_keyring_invalid",
        ) from exc


def _load_private_key(
    path: Path | None,
    *,
    password: str | None,
) -> rsa.RSAPrivateKey:
    if path is None:
        raise ValueError("pair private key path missing")
    loaded = serialization.load_pem_private_key(
        path.read_bytes(),
        password=password.encode("utf-8") if password else None,
    )
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise ValueError("pair private key is not RSA")
    return loaded


def _load_public_key(path: Path | None) -> rsa.RSAPublicKey:
    if path is None:
        raise ValueError("public key path missing")
    loaded = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise ValueError("public key is not RSA")
    return loaded


__all__ = (
    "PairGenerationCompositionError",
    "build_pair_generation_authorization_service",
)
