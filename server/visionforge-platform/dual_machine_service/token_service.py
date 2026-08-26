"""Dedicated RSA-signed leases for isolated dual-machine usage sessions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .identity import canonical_json
from .validation import is_nonzero_lower_hex


USAGE_LEASE_TYPE = "vf-dual-machine-usage-lease-v1"
USAGE_LEASE_ISSUER = "visionforge-dual-machine-service"
USAGE_LEASE_AUDIENCE = "visionforge-dual-machine-data-plane"
DEFAULT_USAGE_LEASE_TTL_SECONDS = 5
MAX_TOKEN_CHARACTERS = 8192


class TokenSigningUnavailable(RuntimeError):
    """The dedicated dual-machine signing key is unavailable or invalid."""


class TokenInvalid(ValueError):
    """A signed dual-machine token failed strict verification."""


@dataclass(frozen=True, slots=True)
class RsaTokenCodec:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    lease_ttl_seconds: int = DEFAULT_USAGE_LEASE_TTL_SECONDS
    verification_public_keys: tuple[rsa.RSAPublicKey, ...] = ()

    def __post_init__(self) -> None:
        keys = (self.public_key, *self.verification_public_keys)
        if (
            not isinstance(self.private_key, rsa.RSAPrivateKey)
            or not isinstance(self.public_key, rsa.RSAPublicKey)
            or self.private_key.key_size < 3072
            or self.public_key.key_size < 3072
            or self.private_key.public_key().public_numbers()
            != self.public_key.public_numbers()
            or len(self.verification_public_keys) > 3
            or any(
                not isinstance(key, rsa.RSAPublicKey)
                or key.key_size < 3072
                for key in self.verification_public_keys
            )
            or len({_public_key_id(key) for key in keys}) != len(keys)
            or not 3 <= int(self.lease_ttl_seconds) <= 10
        ):
            raise TokenSigningUnavailable(
                "dual_machine_ticket_key_invalid",
            )

    @classmethod
    def from_pem_files(
        cls,
        *,
        private_key_path: str | Path,
        public_key_path: str | Path,
        previous_public_key_paths: tuple[str | Path, ...] = (),
        private_key_password: str = "",
        lease_ttl_seconds: int = DEFAULT_USAGE_LEASE_TTL_SECONDS,
    ) -> "RsaTokenCodec":
        try:
            private_key = serialization.load_pem_private_key(
                Path(private_key_path).read_bytes(),
                password=(
                    private_key_password.encode("utf-8")
                    if private_key_password
                    else None
                ),
            )
            public_key = serialization.load_pem_public_key(
                Path(public_key_path).read_bytes(),
            )
            previous_public_keys = tuple(
                serialization.load_pem_public_key(Path(path).read_bytes())
                for path in previous_public_key_paths
            )
        except Exception as exc:
            raise TokenSigningUnavailable(
                "dual_machine_ticket_key_unavailable",
            ) from exc
        if (
            not isinstance(private_key, rsa.RSAPrivateKey)
            or not isinstance(public_key, rsa.RSAPublicKey)
            or private_key.key_size < 3072
            or public_key.key_size < 3072
            or private_key.public_key().public_numbers()
            != public_key.public_numbers()
            or len(previous_public_keys) > 3
            or any(
                not isinstance(key, rsa.RSAPublicKey)
                or key.key_size < 3072
                for key in previous_public_keys
            )
        ):
            raise TokenSigningUnavailable(
                "dual_machine_ticket_key_invalid",
            )
        verification_keys = (public_key, *previous_public_keys)
        key_ids = tuple(_public_key_id(key) for key in verification_keys)
        if len(set(key_ids)) != len(key_ids):
            raise TokenSigningUnavailable(
                "dual_machine_ticket_keyring_duplicate",
            )
        normalized_ttl = int(lease_ttl_seconds)
        if not 3 <= normalized_ttl <= 10:
            raise TokenSigningUnavailable(
                "dual_machine_usage_lease_ttl_invalid",
            )
        return cls(
            private_key=private_key,
            public_key=public_key,
            lease_ttl_seconds=normalized_ttl,
            verification_public_keys=previous_public_keys,
        )

    def issue_usage_lease(
        self,
        entitlement: dict[str, Any],
        session: dict[str, Any],
        *,
        sequence: int,
        phase: str,
        lease_duration_seconds: int,
        previous_lease_sha256: str,
        now_epoch: int | None = None,
        not_before_epoch: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        remaining = int(entitlement["remaining_seconds"])
        duration = int(lease_duration_seconds)
        not_before = (
            now if not_before_epoch is None else int(not_before_epoch)
        )
        if (
            remaining < 0
            or not 1 <= duration <= int(self.lease_ttl_seconds)
            or not_before < now
            or str(phase) != "active"
        ):
            raise ValueError("dual_machine_usage_lease_parameters_invalid")
        channel_binding = session.get("channel_binding_sha256")
        previous_lease = str(previous_lease_sha256 or "")
        identifier_values = (
            entitlement.get("entitlement_id"),
            entitlement.get("pair_id"),
            session.get("session_id"),
        )
        digest_values = (
            entitlement.get("host_key_sha256"),
            entitlement.get("android_key_sha256"),
            channel_binding,
        )
        if (
            type(sequence) is not int
            or sequence < 0
            or not all(
                is_nonzero_lower_hex(value, 32)
                for value in identifier_values
            )
            or not all(
                is_nonzero_lower_hex(value, 64)
                for value in digest_values
            )
            or not _valid_previous_lease_sha256(
                previous_lease,
                sequence,
            )
        ):
            raise ValueError("dual_machine_usage_lease_binding_invalid")
        expires_at = not_before + duration
        authorization_kind = str(
            entitlement.get("authorization_kind") or "legacy_balance",
        )
        is_permanent = authorization_kind == "permanent"
        payload = {
            "typ": USAGE_LEASE_TYPE,
            "iss": USAGE_LEASE_ISSUER,
            "aud": USAGE_LEASE_AUDIENCE,
            "sub": entitlement["entitlement_id"],
            "pid": entitlement["pair_id"],
            "sid": session["session_id"],
            "pv": int(entitlement["protocol_version"]),
            "rv": int(entitlement["revocation_version"]),
            "hkh": entitlement["host_key_sha256"],
            "akh": entitlement["android_key_sha256"],
            "cbh": channel_binding,
            "pth": previous_lease,
            "seq": int(sequence),
            "phase": str(phase),
            "authorization_kind": authorization_kind,
            "is_permanent": is_permanent,
            "remaining": remaining,
            "iat": now,
            "nbf": not_before,
            "exp": expires_at,
        }
        payload["jti"] = hashlib.sha256(canonical_json(payload)).hexdigest()[:32]
        token = self._sign_payload(payload)
        return {
            "usage_lease": token,
            "usage_lease_sha256": hashlib.sha256(
                token.encode("ascii"),
            ).hexdigest(),
            "usage_lease_expires_at_epoch": expires_at,
            "usage_lease_not_before_epoch": not_before,
            "usage_lease_ttl_seconds": duration,
        }

    def verify_usage_lease(
        self,
        token: str,
        *,
        now_epoch: int | None = None,
        expiration_grace_seconds: int = 0,
        not_before_grace_seconds: int = 0,
        allow_expired_for_stop: bool = False,
    ) -> dict[str, Any]:
        header, payload, signing_input, signature = _decode_token(token)
        if header.get("alg") != "RS256" or header.get("typ") != "JWT":
            raise TokenInvalid("dual_machine_usage_lease_invalid")
        verification_key = self._verification_key(header.get("kid"))
        try:
            verification_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception as exc:
            raise TokenInvalid("dual_machine_usage_lease_invalid") from exc
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        _validate_usage_claims(
            payload,
            now_epoch=now,
            expiration_grace_seconds=expiration_grace_seconds,
            not_before_grace_seconds=not_before_grace_seconds,
            maximum_ttl_seconds=int(self.lease_ttl_seconds),
            allow_expired_for_stop=allow_expired_for_stop,
        )
        return payload

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self._key_id(),
        }
        signing_input = (
            _b64u(canonical_json(header))
            + "."
            + _b64u(canonical_json(payload))
        )
        signature = self.private_key.sign(
            signing_input.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return signing_input + "." + _b64u(signature)

    def _key_id(self) -> str:
        return _public_key_id(self.public_key)

    def _verification_key(self, key_id: Any) -> rsa.RSAPublicKey:
        candidate = str(key_id or "")
        keys = (self.public_key, *self.verification_public_keys)
        for key in keys:
            if hmac.compare_digest(_public_key_id(key), candidate):
                return key
        raise TokenInvalid("dual_machine_usage_lease_invalid")


def _decode_token(
    token: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    value = str(token or "")
    if not 1 <= len(value) <= MAX_TOKEN_CHARACTERS:
        raise TokenInvalid("dual_machine_usage_lease_invalid")
    try:
        header_b64, payload_b64, signature_b64 = value.split(".", 2)
        header_raw = _b64u_decode(header_b64)
        payload_raw = _b64u_decode(payload_b64)
        header = json.loads(header_raw.decode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
        if (
            not isinstance(header, dict)
            or not isinstance(payload, dict)
            or canonical_json(header) != header_raw
            or canonical_json(payload) != payload_raw
        ):
            raise TokenInvalid("dual_machine_usage_lease_invalid")
        return (
            header,
            payload,
            f"{header_b64}.{payload_b64}".encode("ascii"),
            _b64u_decode(signature_b64),
        )
    except TokenInvalid:
        raise
    except Exception as exc:
        raise TokenInvalid("dual_machine_usage_lease_invalid") from exc


def _validate_usage_claims(
    payload: dict[str, Any],
    *,
    now_epoch: int,
    expiration_grace_seconds: int,
    not_before_grace_seconds: int,
    maximum_ttl_seconds: int,
    allow_expired_for_stop: bool,
) -> None:
    try:
        issued_at = payload.get("iat")
        not_before = payload.get("nbf")
        expires_at = payload.get("exp")
        protocol_version = payload.get("pv")
        revocation_version = payload.get("rv")
        sequence = payload.get("seq")
        remaining = payload.get("remaining")
        if (
            payload.get("typ") != USAGE_LEASE_TYPE
            or payload.get("iss") != USAGE_LEASE_ISSUER
            or payload.get("aud") != USAGE_LEASE_AUDIENCE
            or not all(
                is_nonzero_lower_hex(payload.get(name), 32)
                for name in ("sub", "pid", "sid", "jti")
            )
            or not all(
                is_nonzero_lower_hex(payload.get(name), 64)
                for name in ("hkh", "akh", "cbh")
            )
            or type(protocol_version) is not int
            or protocol_version != 2
            or type(revocation_version) is not int
            or revocation_version <= 0
            or type(sequence) is not int
            or sequence < 0
            or not _valid_previous_lease_sha256(
                payload.get("pth"),
                sequence,
            )
            or payload.get("phase") != "active"
            or str(payload.get("authorization_kind") or "")
            not in {
                "legacy_balance",
                "day",
                "week",
                "month",
                "permanent",
            }
            or not isinstance(payload.get("is_permanent"), bool)
            or bool(payload.get("is_permanent"))
            != (payload.get("authorization_kind") == "permanent")
            or type(remaining) is not int
            or remaining < 0
            or type(issued_at) is not int
            or type(not_before) is not int
            or type(expires_at) is not int
            or issued_at <= 0
            or not_before < issued_at
            or expires_at <= not_before
            or expires_at - not_before > int(maximum_ttl_seconds)
            or not_before
            > now_epoch + max(0, int(not_before_grace_seconds))
            or (
                not allow_expired_for_stop
                and expires_at + max(0, int(expiration_grace_seconds))
                <= now_epoch
            )
        ):
            raise TokenInvalid("dual_machine_usage_lease_invalid")
        expected_jti = hashlib.sha256(canonical_json({
            key: value
            for key, value in payload.items()
            if key != "jti"
        })).hexdigest()[:32]
        if payload.get("jti") != expected_jti:
            raise TokenInvalid("dual_machine_usage_lease_invalid")
    except TokenInvalid:
        raise
    except Exception as exc:
        raise TokenInvalid("dual_machine_usage_lease_invalid") from exc


def _valid_previous_lease_sha256(value: object, sequence: int) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    if sequence == 0:
        return value == "0" * 64
    return is_nonzero_lower_hex(value, 64)


def _public_key_id(public_key: rsa.RSAPublicKey) -> str:
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()[:16]


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    text = str(value or "")
    if not text or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise TokenInvalid("dual_machine_usage_lease_invalid")
    try:
        decoded = base64.b64decode(
            text + "=" * (-len(text) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise TokenInvalid("dual_machine_usage_lease_invalid") from exc
    if _b64u(decoded) != text:
        raise TokenInvalid("dual_machine_usage_lease_invalid")
    return decoded
