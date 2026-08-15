from __future__ import annotations

import sqlite3

from app.services.minimum_client_policy import (
    evaluate_minimum_client_version,
    numeric_version_key,
)


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE releases ("
        "min_supported_version TEXT NOT NULL, channel TEXT NOT NULL, "
        "published INTEGER NOT NULL, payload_b64 TEXT NOT NULL)"
    )
    return connection


def test_numeric_version_key_accepts_product_suffix_and_rejects_garbage() -> None:
    assert numeric_version_key("v17.8.81_update_lease_bridge_hardened") == (
        17,
        8,
        81,
        0,
    )
    assert numeric_version_key("v-test") == ()


def test_signed_published_floor_rejects_old_or_unparseable_client() -> None:
    connection = _connection()
    connection.execute(
        "INSERT INTO releases VALUES (?, 'stable', 1, 'signed')",
        ("v17.8.81",),
    )

    old = evaluate_minimum_client_version(connection, "v17.8.80")
    malformed = evaluate_minimum_client_version(connection, "v-test")
    current = evaluate_minimum_client_version(
        connection,
        "v17.8.81_update_lease_bridge_hardened",
    )

    assert not old.allowed and old.reason == "client_update_required"
    assert not malformed.allowed and malformed.reason == "client_version_invalid"
    assert current.allowed


def test_signed_history_floor_survives_unpublish_and_unsigned_rows_are_ignored() -> None:
    connection = _connection()
    connection.executemany(
        "INSERT INTO releases VALUES (?, 'stable', ?, ?)",
        (("v99.0.0", 1, ""), ("v98.0.0", 0, "signed")),
    )

    verdict = evaluate_minimum_client_version(connection, "v1.0.0")

    assert not verdict.allowed
    assert verdict.minimum_supported_version == "v98.0.0"


def test_highest_signed_history_floor_wins_over_current_publication() -> None:
    connection = _connection()
    connection.executemany(
        "INSERT INTO releases VALUES (?, 'stable', ?, ?)",
        (("v20.0.0", 0, "signed-old"), ("v19.0.0", 1, "signed-current")),
    )

    verdict = evaluate_minimum_client_version(connection, "v19.5.0")

    assert not verdict.allowed
    assert verdict.minimum_supported_version == "v20.0.0"


def test_invalid_signed_history_floor_fails_closed() -> None:
    connection = _connection()
    connection.execute(
        "INSERT INTO releases VALUES (?, 'stable', 1, 'signed')",
        ("not-a-version",),
    )

    verdict = evaluate_minimum_client_version(connection, "v99.0.0")

    assert not verdict.allowed
    assert verdict.reason == "server_floor_invalid"
