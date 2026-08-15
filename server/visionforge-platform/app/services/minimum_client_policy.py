"""Server-owned minimum client version policy for high-value runtime APIs."""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass


_VERSION_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+){1,3})(?!\d)")
_MAX_VERSION_COMPONENT = 2_147_483_647


@dataclass(frozen=True, slots=True)
class MinimumClientVerdict:
    allowed: bool
    client_version: str
    minimum_supported_version: str
    reason: str


def numeric_version_key(value: object) -> tuple[int, ...]:
    """Parse a bounded dotted version embedded in the product version label."""

    match = _VERSION_RE.search(str(value or "").strip())
    if not match:
        return ()
    parts = [int(part) for part in match.group(1).split(".")]
    if any(part > _MAX_VERSION_COMPONENT for part in parts):
        return ()
    parts.extend([0] * (4 - len(parts)))
    return tuple(parts[:4])


def published_minimum_supported_version(
    connection: sqlite3.Connection,
    *,
    channel: str = "stable",
) -> str:
    """Return the highest floor from the channel's immutable signed history."""

    rows = connection.execute(
        "SELECT min_supported_version FROM releases "
        "WHERE channel = ? AND payload_b64 != ''",
        (str(channel or "stable"),),
    ).fetchall()
    highest_value = ""
    highest_key: tuple[int, ...] = ()
    for row in rows:
        value = str(row["min_supported_version"] or "").strip()
        if not value:
            continue
        key = numeric_version_key(value)
        if not key:
            return value
        if not highest_key or key > highest_key:
            highest_value = value
            highest_key = key
    return highest_value


def evaluate_minimum_client_version(
    connection: sqlite3.Connection,
    client_version: object,
    *,
    channel: str = "stable",
) -> MinimumClientVerdict:
    version = str(client_version or "").strip()
    minimum = published_minimum_supported_version(
        connection,
        channel=channel,
    )
    if not minimum:
        return MinimumClientVerdict(True, version, "", "no_server_floor")
    minimum_key = numeric_version_key(minimum)
    if not minimum_key:
        return MinimumClientVerdict(
            False,
            version,
            minimum,
            "server_floor_invalid",
        )
    client_key = numeric_version_key(version)
    if not client_key:
        return MinimumClientVerdict(
            False,
            version,
            minimum,
            "client_version_invalid",
        )
    if client_key < minimum_key:
        return MinimumClientVerdict(
            False,
            version,
            minimum,
            "client_update_required",
        )
    return MinimumClientVerdict(True, version, minimum, "ok")
