"""Pure trust-boundary validators shared by the dual-machine service."""
from __future__ import annotations


_LOWER_HEX_CHARACTERS = frozenset("0123456789abcdef")


def is_nonzero_lower_hex(value: object, length: int) -> bool:
    """Return whether *value* is exact-length lowercase hex and not all zero."""
    return (
        type(value) is str
        and len(value) == length
        and any(character != "0" for character in value)
        and all(character in _LOWER_HEX_CHARACTERS for character in value)
    )
