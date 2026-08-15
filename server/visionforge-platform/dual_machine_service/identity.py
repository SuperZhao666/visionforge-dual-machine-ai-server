"""P-256 device-identity contracts for the isolated dual-machine service."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


MAX_IDENTITY_KEY_DER_BYTES = 256
MAX_ECDSA_SIGNATURE_BYTES = 128
MAX_IDENTITY_KEY_B64_CHARS = 4 * ((MAX_IDENTITY_KEY_DER_BYTES + 2) // 3)
MAX_ECDSA_SIGNATURE_B64_CHARS = 4 * ((MAX_ECDSA_SIGNATURE_BYTES + 2) // 3)


@dataclass(frozen=True, slots=True)
class P256Identity:
    public_key: ec.EllipticCurvePublicKey
    public_key_b64: str
    fingerprint_sha256: str


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_canonical_base64(
    value: str,
    *,
    maximum_characters: int,
    error_code: str,
) -> bytes:
    encoded = str(value or "").strip()
    if not encoded or len(encoded) > maximum_characters:
        raise ValueError(error_code)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(error_code) from exc
    if canonical_base64(decoded) != encoded:
        raise ValueError(error_code)
    return decoded


def parse_p256_identity(public_key_b64: str) -> P256Identity:
    raw = decode_canonical_base64(
        public_key_b64,
        maximum_characters=MAX_IDENTITY_KEY_B64_CHARS,
        error_code="identity_public_key_invalid",
    )
    if not raw or len(raw) > MAX_IDENTITY_KEY_DER_BYTES:
        raise ValueError("identity_public_key_invalid")
    try:
        public_key = serialization.load_der_public_key(raw)
    except Exception as exc:
        raise ValueError("identity_public_key_invalid") from exc
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
    ):
        raise ValueError("identity_public_key_must_be_p256")
    canonical_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical_der != raw:
        raise ValueError("identity_public_key_not_canonical")
    return P256Identity(
        public_key=public_key,
        public_key_b64=canonical_base64(canonical_der),
        fingerprint_sha256=hashlib.sha256(canonical_der).hexdigest(),
    )


def verify_p256_signature(
    identity: P256Identity,
    signature_b64: str,
    signed_payload: bytes,
) -> None:
    signature = decode_canonical_base64(
        signature_b64,
        maximum_characters=MAX_ECDSA_SIGNATURE_B64_CHARS,
        error_code="identity_signature_invalid",
    )
    if not signature or len(signature) > MAX_ECDSA_SIGNATURE_BYTES:
        raise ValueError("identity_signature_invalid")
    try:
        identity.public_key.verify(
            signature,
            signed_payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise ValueError("identity_signature_invalid") from exc
    except Exception as exc:
        raise ValueError("identity_signature_invalid") from exc
