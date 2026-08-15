"""High-entropy, digest-only card-code contracts for dual-machine licensing."""
from __future__ import annotations

import hashlib
import hmac


CARD_PREFIX = "VFD2"
CARD_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
CARD_PAYLOAD_CHARACTERS = 28
CARD_CHECKSUM_CHARACTERS = 2
CARD_BODY_CHARACTERS = CARD_PAYLOAD_CHARACTERS + CARD_CHECKSUM_CHARACTERS
CARD_KEY_VERSION = 1
_DERIVE_DOMAIN = b"visionforge:dual-machine:card:derive:v1\x00"
_LOOKUP_DOMAIN = b"visionforge:dual-machine:card:lookup:v1\x00"


def derive_card_code(secret: bytes, derivation_ref: str) -> str:
    material = hmac.new(
        _domain_key(secret, _DERIVE_DOMAIN),
        str(derivation_ref).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    payload = _encode_bits(material, CARD_PAYLOAD_CHARACTERS)
    body = payload + _checksum(payload)
    return CARD_PREFIX + "-" + "-".join(
        body[index:index + 5]
        for index in range(0, len(body), 5)
    )


def normalize_card_code(raw_code: str) -> str:
    return "".join(
        character
        for character in str(raw_code or "").upper()
        if character.isalnum()
    )


def is_valid_card_code(raw_code: str) -> bool:
    normalized = normalize_card_code(raw_code)
    if len(normalized) != len(CARD_PREFIX) + CARD_BODY_CHARACTERS:
        return False
    if not normalized.startswith(CARD_PREFIX):
        return False
    body = normalized[len(CARD_PREFIX):]
    if any(character not in CARD_ALPHABET for character in body):
        return False
    payload = body[:CARD_PAYLOAD_CHARACTERS]
    return hmac.compare_digest(
        body[CARD_PAYLOAD_CHARACTERS:],
        _checksum(payload),
    )


def card_code_digest(
    secret: bytes,
    raw_code: str,
    *,
    key_version: int = CARD_KEY_VERSION,
) -> str:
    normalized_version = int(key_version)
    if normalized_version <= 0:
        raise ValueError("dual_machine_license_key_version_invalid")
    normalized = normalize_card_code(raw_code)
    digest = hmac.new(
        _domain_key(secret, _LOOKUP_DOMAIN),
        normalized.encode("ascii", "ignore"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:v{normalized_version}:{digest}"


def card_code_suffix(raw_code: str) -> str:
    normalized = normalize_card_code(raw_code)
    return normalized[-4:] if len(normalized) >= 4 else ""


def _domain_key(secret: bytes, domain: bytes) -> bytes:
    if len(secret) < 32:
        raise ValueError("dual_machine_license_secret_too_short")
    return hmac.new(secret, domain, hashlib.sha256).digest()


def _encode_bits(material: bytes, characters: int) -> str:
    required_bits = int(characters) * 5
    value = int.from_bytes(material, "big")
    available_bits = len(material) * 8
    if required_bits > available_bits:
        raise ValueError("insufficient_card_entropy")
    value >>= available_bits - required_bits
    encoded: list[str] = []
    for shift in range(required_bits - 5, -1, -5):
        encoded.append(CARD_ALPHABET[(value >> shift) & 0x1F])
    return "".join(encoded)


def _checksum(payload: str) -> str:
    return _encode_bits(
        hashlib.sha256(payload.encode("ascii")).digest(),
        CARD_CHECKSUM_CHARACTERS,
    )
