from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from dual_machine_service.database import (
    _PAIR_SECURITY_STATE_TABLE_SQL,
    _normalized_schema_sql,
    initialize_database,
)
from dual_machine_service.settings import DualMachineSettings


def _settings(path: Path) -> DualMachineSettings:
    return DualMachineSettings(
        database_path=path,
        license_code_secret=b"l" * 32,
        token_secret=b"t" * 32,
        minimum_host_client_version="1.0.0",
        minimum_android_client_version="1.0.0",
    )


def test_schema_normalizer_ignores_formatting_but_not_security_tokens() -> None:
    formatted = _PAIR_SECURITY_STATE_TABLE_SQL.replace("(", "(\n  ").replace(", ", ",\n")
    assert _normalized_schema_sql(formatted) == _normalized_schema_sql(
        _PAIR_SECURITY_STATE_TABLE_SQL
    )
    weakened = _PAIR_SECURITY_STATE_TABLE_SQL.replace(
        "CHECK(host_key_sha256 <> android_key_sha256), ", ""
    )
    assert _normalized_schema_sql(weakened) != _normalized_schema_sql(
        _PAIR_SECURITY_STATE_TABLE_SQL
    )


def test_clean_database_bootstrap_passes_exact_schema_attestation(tmp_path: Path) -> None:
    path = tmp_path / "clean.db"
    initialize_database(_settings(path))
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'dm_pair_security_state'"
        ).fetchone()
        assert row is not None
        assert _normalized_schema_sql(str(row[0])) == _normalized_schema_sql(
            _PAIR_SECURITY_STATE_TABLE_SQL
        )
    finally:
        connection.close()


def test_precreated_weak_security_table_remains_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "weak.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE dm_pair_security_state (pair_id TEXT)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises((RuntimeError, ValueError)):
        initialize_database(_settings(path))
