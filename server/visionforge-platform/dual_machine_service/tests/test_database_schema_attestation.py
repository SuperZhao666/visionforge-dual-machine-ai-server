from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from dual_machine_service.database import (
    _normalized_schema_sql,
    connect_database,
    initialize_database,
)
from dual_machine_service.settings import DualMachineSettings


def _settings(tmp_path: Path) -> DualMachineSettings:
    return DualMachineSettings(
        database_path=tmp_path / "schema-attestation.db",
        license_code_secret=b"schema-attestation-license-secret-32-bytes",
        token_secret=b"schema-attestation-token-secret-32-bytes-min",
        minimum_host_client_version="1.0.0",
        minimum_android_client_version="1.0.0",
    )


def test_fresh_database_schema_is_attested_and_reentrant(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    initialize_database(settings)
    initialize_database(settings)

    connection = connect_database(settings)
    try:
        migrations = connection.execute(
            "SELECT COUNT(*) FROM dm_schema_migrations",
        ).fetchone()
        pair_tables = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
            "AND name IN ('dm_pair_security_state', "
            "'dm_pair_generation_challenges', "
            "'dm_pair_generation_allocations')",
        ).fetchone()
    finally:
        connection.close()
    assert int(migrations[0]) > 0
    assert int(pair_tables[0]) == 3


def test_same_name_weak_pair_table_is_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path)
    try:
        connection.execute(
            "CREATE TABLE dm_pair_security_state (pair_id TEXT PRIMARY KEY)",
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(
        RuntimeError,
        match="pair security core schema requires operator recovery",
    ):
        initialize_database(settings)


def test_schema_token_fingerprint_ignores_layout_but_not_literal_case() -> None:
    compact = (
        "CREATE TABLE dm_test (state TEXT CHECK(state IN ('active', 'revoked')))"
    )
    formatted = (
        "CREATE  TABLE dm_test /* canonical layout */ (\n"
        " state TEXT CHECK ( state IN ( 'active' , 'revoked' ) )\n"
        ")"
    )
    semantic_change = compact.replace("'active'", "'ACTIVE'")

    assert _normalized_schema_sql(compact) == _normalized_schema_sql(formatted)
    assert _normalized_schema_sql(compact) != _normalized_schema_sql(
        semantic_change,
    )
