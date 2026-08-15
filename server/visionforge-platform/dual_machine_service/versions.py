"""Strict numeric client-version policy for server-side revocation gates."""
from __future__ import annotations

import re


_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")


def normalize_client_version(value: object) -> str:
    text = str(value or "").strip()
    if not _VERSION_PATTERN.fullmatch(text):
        raise ValueError("client_version_invalid")
    components = tuple(int(component) for component in text.split("."))
    if any(component > 999_999 for component in components):
        raise ValueError("client_version_invalid")
    return ".".join(str(component) for component in components)


def client_version_at_least(
    actual: object,
    minimum: object,
) -> bool:
    actual_parts = _padded_version(actual)
    minimum_parts = _padded_version(minimum)
    return actual_parts >= minimum_parts


def _padded_version(value: object) -> tuple[int, int, int, int]:
    normalized = normalize_client_version(value)
    parts = tuple(int(component) for component in normalized.split("."))
    return (*parts, *(0 for _ in range(4 - len(parts))))
