from __future__ import annotations

import os
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-log-retention-32")

from app.config import config
from app.database import get_connection, init_db
from app.services import log_retention_service
from app.services.log_retention_service import purge_expired_log_storage


RUNNER_PATH = Path(__file__).resolve().parents[1] / "deploy" / "purge_log_storage.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "visionforge_test_purge_log_storage", RUNNER_PATH
)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
purge_log_storage_runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(purge_log_storage_runner)


class LogRetentionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        config.DATABASE_PATH = str(root / "vf.db")
        config.LOG_STORAGE_PATH = str(root / "log_storage")
        self.storage_root = Path(config.LOG_STORAGE_PATH)
        self.storage_root.mkdir()
        self.session_counter = 0
        init_db()
        self.now = datetime(2026, 8, 4, tzinfo=timezone.utc)
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE log_upload_settings SET retention_days = 30 WHERE id = 1"
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _create_session(self, *, started_at: str) -> int:
        self.session_counter += 1
        conn = get_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO log_sessions (session_id, started_at) VALUES (?, ?)",
                (f"session-{self.session_counter}", started_at),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()

    def _create_file(
        self, session_id: int, path: str | Path, *, uploaded_at: str
    ) -> int:
        conn = get_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path, uploaded_at) "
                "VALUES (?, 'bundle', 'client.zip', 1, ?, ?)",
                (session_id, str(path), uploaded_at),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()

    def _row_count(self, table: str) -> int:
        conn = get_connection()
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            conn.close()

    def test_removes_expired_files_in_batches_then_their_empty_sessions(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        for index in range(3):
            session_id = self._create_session(started_at=old)
            path = self.storage_root / f"old-{index}.zip"
            path.write_bytes(b"x")
            self._create_file(session_id, path, uploaded_at=old)

        result = purge_expired_log_storage(batch_size=1, now=self.now)

        self.assertEqual(result["files_removed"], 3)
        self.assertEqual(result["database_rows_removed"], 3)
        self.assertEqual(result["deleted_bytes"], 3)
        self.assertEqual(result["empty_sessions_removed"], 3)
        self.assertEqual(self._row_count("log_files"), 0)
        self.assertEqual(self._row_count("log_sessions"), 0)
        self.assertFalse(any(self.storage_root.iterdir()))

    def test_dry_run_does_not_change_files_or_database(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        session_id = self._create_session(started_at=old)
        path = self.storage_root / "old.zip"
        path.write_bytes(b"x")
        self._create_file(session_id, path, uploaded_at=old)

        result = purge_expired_log_storage(dry_run=True, now=self.now)

        self.assertEqual(result["files_would_remove"], 1)
        self.assertEqual(result["empty_sessions_would_remove"], 0)
        self.assertTrue(path.exists())
        self.assertEqual(self._row_count("log_files"), 1)
        self.assertEqual(self._row_count("log_sessions"), 1)

    def test_cli_smoke_check_is_read_only_and_does_not_run_migrations(self) -> None:
        database_path = Path(config.DATABASE_PATH)
        before_mtime = database_path.stat().st_mtime_ns
        output = io.StringIO()

        with (
            patch.object(purge_log_storage_runner, "init_db") as init_db_mock,
            patch.object(
                purge_log_storage_runner, "purge_expired_log_storage"
            ) as purge_mock,
            patch.object(sys, "argv", [str(RUNNER_PATH), "--smoke-check"]),
            redirect_stdout(output),
        ):
            exit_code = purge_log_storage_runner.main()

        self.assertEqual(exit_code, 0)
        init_db_mock.assert_not_called()
        purge_mock.assert_not_called()
        self.assertEqual(database_path.stat().st_mtime_ns, before_mtime)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "database_present": True,
                "database_read_only": True,
                "smoke_check": "ok",
            },
        )

    def test_cli_smoke_check_does_not_create_a_missing_database(self) -> None:
        missing_database = Path(self.tempdir.name) / "missing" / "vf.db"
        config.DATABASE_PATH = str(missing_database)
        output = io.StringIO()

        with (
            patch.object(purge_log_storage_runner, "init_db") as init_db_mock,
            patch.object(sys, "argv", [str(RUNNER_PATH), "--smoke-check"]),
            redirect_stdout(output),
        ):
            exit_code = purge_log_storage_runner.main()

        self.assertEqual(exit_code, 0)
        init_db_mock.assert_not_called()
        self.assertFalse(missing_database.exists())
        self.assertEqual(json.loads(output.getvalue())["database_present"], False)

    def test_malformed_paths_are_retained_and_later_batches_still_run(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        empty_session = self._create_session(started_at=old)
        root_session = self._create_session(started_at=old)
        malformed_session = self._create_session(started_at=old)
        valid_session = self._create_session(started_at=old)

        empty_id = self._create_file(empty_session, "", uploaded_at=old)
        root_id = self._create_file(root_session, self.storage_root, uploaded_at=old)
        malformed_id = self._create_file(
            malformed_session, "bad\x00path.zip", uploaded_at=old
        )
        valid_path = self.storage_root / "valid-after-malformed.zip"
        valid_path.write_bytes(b"valid")
        self._create_file(valid_session, valid_path, uploaded_at=old)

        result = purge_expired_log_storage(batch_size=2, now=self.now)

        self.assertEqual(result["file_candidates"], 4)
        self.assertEqual(result["files_retained"], 3)
        self.assertEqual(result["files_removed"], 1)
        self.assertEqual(result["database_rows_removed"], 1)
        self.assertEqual(result["empty_sessions_removed"], 1)
        self.assertFalse(valid_path.exists())
        self.assertEqual(self._row_count("log_files"), 3)
        self.assertEqual(self._row_count("log_sessions"), 3)
        self.assertEqual(
            {entry["file_id"]: entry["reason"] for entry in result["errors"]},
            {
                empty_id: "storage_path_empty",
                root_id: "storage_path_is_root",
                malformed_id: "storage_path_malformed",
            },
        )

    def test_unlink_failure_keeps_database_row(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        session_id = self._create_session(started_at=old)
        path = self.storage_root / "locked.zip"
        path.write_bytes(b"x")
        self._create_file(session_id, path, uploaded_at=old)

        with patch(
            "app.services.log_retention_service.os.unlink",
            side_effect=PermissionError("denied"),
        ):
            result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["files_retained"], 1)
        self.assertEqual(result["errors"][0]["error_type"], "PermissionError")
        self.assertNotIn("error", result["errors"][0])
        self.assertEqual(result["database_rows_removed"], 0)
        self.assertEqual(result["empty_sessions_removed"], 0)
        self.assertEqual(self._row_count("log_files"), 1)

    def test_removes_file_from_nested_storage_directory(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        nested_directory = self.storage_root / "legacy" / "session"
        nested_directory.mkdir(parents=True)
        path = nested_directory / "old.zip"
        path.write_bytes(b"nested")
        session_id = self._create_session(started_at=old)
        self._create_file(session_id, path, uploaded_at=old)

        result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["files_removed"], 1)
        self.assertEqual(result["database_rows_removed"], 1)
        self.assertEqual(result["deleted_bytes"], 6)
        self.assertFalse(path.exists())
        self.assertTrue(nested_directory.is_dir())

    @unittest.skipUnless(
        os.name == "posix" and log_retention_service._SECURE_DIR_FD_DELETION,
        "requires POSIX directory-relative open and unlink support",
    )
    def test_posix_parent_fd_prevents_intermediate_symlink_swap_escape(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        nested_directory = self.storage_root / "nested"
        nested_directory.mkdir()
        stored_path = nested_directory / "victim.zip"
        stored_path.write_bytes(b"inside")

        outside_directory = Path(self.tempdir.name) / "outside"
        outside_directory.mkdir()
        protected_path = outside_directory / stored_path.name
        protected_path.write_bytes(b"protected")
        renamed_directory = self.storage_root / "nested-before-swap"

        session_id = self._create_session(started_at=old)
        self._create_file(session_id, stored_path, uploaded_at=old)
        original_unlink = os.unlink
        observed_parent_fds: list[int | None] = []

        def swap_directory_then_unlink(name, *, dir_fd=None):
            nested_directory.rename(renamed_directory)
            nested_directory.symlink_to(outside_directory, target_is_directory=True)
            observed_parent_fds.append(dir_fd)
            return original_unlink(name, dir_fd=dir_fd)

        with patch(
            "app.services.log_retention_service.os.unlink",
            side_effect=swap_directory_then_unlink,
        ):
            result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["filesystem_delete_mode"], "posix_dir_fd")
        self.assertEqual(result["files_removed"], 1)
        self.assertEqual(result["database_rows_removed"], 1)
        self.assertTrue(observed_parent_fds)
        self.assertIsInstance(observed_parent_fds[0], int)
        self.assertFalse((renamed_directory / stored_path.name).exists())
        self.assertEqual(protected_path.read_bytes(), b"protected")
        self.assertEqual(self._row_count("log_files"), 0)

    def test_rejects_symlink_without_touching_target_or_database_row(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        outside = Path(self.tempdir.name) / "outside.zip"
        outside.write_bytes(b"protected")
        link = self.storage_root / "link.zip"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        session_id = self._create_session(started_at=old)
        self._create_file(session_id, link, uploaded_at=old)

        result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["files_retained"], 1)
        self.assertTrue(outside.exists())
        self.assertEqual(self._row_count("log_files"), 1)
        self.assertEqual(result["errors"][0]["reason"], "symlink_rejected")

    def test_rejects_symlinked_storage_root_without_touching_external_file_or_database_row(
        self,
    ) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        external_root = Path(self.tempdir.name) / "external-storage"
        external_root.mkdir()
        external_file = external_root / "protected.zip"
        external_file.write_bytes(b"protected")
        configured_root = Path(self.tempdir.name) / "log-storage-link"
        try:
            configured_root.symlink_to(external_root, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        config.LOG_STORAGE_PATH = str(configured_root)
        session_id = self._create_session(started_at=old)
        self._create_file(session_id, external_file, uploaded_at=old)

        result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["files_retained"], 1)
        self.assertTrue(external_file.exists())
        self.assertEqual(self._row_count("log_files"), 1)
        self.assertEqual(result["errors"][0]["reason"], "storage_root_symlink_rejected")

    def test_missing_file_removes_only_its_database_row_and_old_empty_session(
        self,
    ) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        session_id = self._create_session(started_at=old)
        self._create_file(
            session_id, self.storage_root / "missing.zip", uploaded_at=old
        )

        result = purge_expired_log_storage(now=self.now)

        self.assertEqual(result["database_rows_removed"], 1)
        self.assertEqual(result["empty_sessions_removed"], 1)
        self.assertEqual(self._row_count("log_files"), 0)
        self.assertEqual(self._row_count("log_sessions"), 0)

    def test_missing_file_converges_after_storage_root_is_recreated(self) -> None:
        old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        session_id = self._create_session(started_at=old)
        self._create_file(
            session_id, self.storage_root / "missing.zip", uploaded_at=old
        )
        self.storage_root.rmdir()

        result = purge_expired_log_storage(now=self.now)

        self.assertTrue(self.storage_root.is_dir())
        self.assertEqual(result["database_rows_removed"], 1)
        self.assertEqual(result["empty_sessions_removed"], 1)
        self.assertEqual(self._row_count("log_files"), 0)
        self.assertEqual(self._row_count("log_sessions"), 0)

    def test_relative_storage_path_with_relative_root_prefix_is_removed(self) -> None:
        relative_root = "log_storage"
        previous_cwd = Path.cwd()
        os.chdir(self.tempdir.name)
        config.LOG_STORAGE_PATH = relative_root
        try:
            old = (self.now - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
            session_id = self._create_session(started_at=old)
            path = self.storage_root / "prefixed.zip"
            path.write_bytes(b"abc")
            self._create_file(
                session_id, Path(relative_root) / path.name, uploaded_at=old
            )

            result = purge_expired_log_storage(now=self.now)

            self.assertEqual(result["files_removed"], 1)
            self.assertEqual(result["deleted_bytes"], 3)
            self.assertFalse(path.exists())
            self.assertEqual(self._row_count("log_files"), 0)
        finally:
            os.chdir(previous_cwd)

    def test_systemd_unit_keeps_application_readable_and_storage_private(self) -> None:
        unit_path = (
            Path(__file__).resolve().parents[1] / "deploy" / "vf-log-retention.service"
        )
        unit = unit_path.read_text(encoding="utf-8")

        self.assertIn("ProtectHome=read-only", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn(
            "ReadWritePaths=/home/ubuntu/vf-platform/data /home/ubuntu/vf-platform/log_storage",
            unit,
        )
