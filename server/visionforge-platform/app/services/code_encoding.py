"""Shared pure encoding primitive for public VisionForge codes."""
from app.services.redemption_constants import CODE_ALPHABET


def base32_custom(data: bytes, length: int) -> str:
    value = int.from_bytes(data, "big")
    chars = []
    for _ in range(int(length)):
        chars.append(CODE_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))
