from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path


os.environ.setdefault("SECRET_KEY", "test-secret-key-for-runtime-event-schema")

from app.config import config
from app.database import RUNTIME_EVENT_SCHEMA_MIGRATION, get_connection, init_db
from app.repositories.runtime_repository import RuntimeRepository


class RuntimeEventSchemaMigrationTests(unittest.TestCase):
    """Protect the migration needed by runtime compatibility telemetry."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_db_path = config.DATABASE_PATH
        self.database_path = str(Path(self.tmpdir.name) / "legacy-runtime-events.db")
        config.DATABASE_PATH = self.database_path
        legacy = sqlite3.connect(self.database_path)
        try:
            legacy.execute(
                "CREATE TABLE runtime_install_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "event_id TEXT UNIQUE NOT NULL,"
                "user_id INTEGER,"
                "attempt_id TEXT NOT NULL,"
                "event_type TEXT NOT NULL,"
                "status TEXT NOT NULL DEFAULT '',"
                "error_code TEXT NOT NULL DEFAULT '',"
                "app_version TEXT NOT NULL DEFAULT '',"
                "gpu_model TEXT NOT NULL DEFAULT '',"
                "driver_version TEXT NOT NULL DEFAULT '',"
                "component_id TEXT NOT NULL DEFAULT '',"
                "component_version TEXT NOT NULL DEFAULT '',"
                "duration_ms INTEGER NOT NULL DEFAULT 0,"
                "bytes_count INTEGER NOT NULL DEFAULT 0,"
                "anonymized INTEGER NOT NULL DEFAULT 0,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )
            legacy.commit()
        finally:
            legacy.close()

    def tearDown(self) -> None:
        config.DATABASE_PATH = self.previous_db_path
        self.tmpdir.cleanup()

    def test_legacy_runtime_event_table_gains_required_dimensions_and_marker(self) -> None:
        init_db()
        init_db()
        conn = get_connection()
        try:
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(runtime_install_events)")
            }
            marker = conn.execute(
                "SELECT 1 FROM schema_migrations WHERE migration_key = ?",
                (RUNTIME_EVENT_SCHEMA_MIGRATION,),
            ).fetchone()
            user_id = int(conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("runtime-schema-test", "x"),
            ).lastrowid)
            inserted = RuntimeRepository(conn).store_events(
                user_id,
                "legacy-upgrade-attempt",
                [{
                    "event_id": "legacy-upgrade-event",
                    "event_type": "activation_ready",
                    "status": "ok",
                    "final_provider": "TensorrtExecutionProvider",
                }],
            )
            conn.commit()
            stored = conn.execute(
                "SELECT final_provider FROM runtime_install_events WHERE event_id = ?",
                ("legacy-upgrade-event",),
            ).fetchone()
        finally:
            conn.close()

        self.assertTrue(
            {
                "failure_stage",
                "http_status",
                "os_name",
                "architecture",
                "cpu_model",
                "cpu_cores_physical",
                "cpu_cores_logical",
                "compute_capability",
                "final_provider",
            }.issubset(columns)
        )
        self.assertIsNotNone(marker)
        self.assertEqual(inserted, 1)
        self.assertEqual(stored["final_provider"], "TensorrtExecutionProvider")
