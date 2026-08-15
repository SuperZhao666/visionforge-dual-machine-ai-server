import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-integrity-executable-role")

from app.config import config
from app.database import get_connection, init_db
from app.routes.time_api import (
    DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
    _check_client_integrity,
    _runtime_security_settings,
)


class IntegrityExecutableRoleTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_database_path = config.DATABASE_PATH
        self.previous_require_runtime_integrity = config.REQUIRE_RUNTIME_INTEGRITY
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.REQUIRE_RUNTIME_INTEGRITY = False
        init_db()
        self.official_hash = "a" * 64
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE runtime_security_settings SET enforce_integrity = 1 WHERE id = 1"
            )
            conn.execute(
                "INSERT INTO client_integrity_allowlist "
                "(client_version, manifest_hash, file_hashes_json, enabled) VALUES (?, ?, ?, 1)",
                (
                    "v20.0.0",
                    "b" * 64,
                    json.dumps(
                        [
                            {
                                "path": "@executable",
                                "role": "executable",
                                "sha256": self.official_hash,
                                "size": 200,
                            }
                        ]
                    ),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        config.DATABASE_PATH = self.previous_database_path
        config.REQUIRE_RUNTIME_INTEGRITY = self.previous_require_runtime_integrity
        self.tmpdir.cleanup()

    def _insert_wildcard(self, manifest_hash: str, executable_hash: str) -> None:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO client_integrity_allowlist "
                "(client_version, manifest_hash, file_hashes_json, enabled) "
                "VALUES ('*', ?, ?, 1)",
                (
                    manifest_hash,
                    json.dumps(
                        [
                            {
                                "path": "@executable",
                                "role": "executable",
                                "sha256": executable_hash,
                            }
                        ]
                    ),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _check(self, integrity):
        conn = get_connection()
        try:
            return _check_client_integrity(
                conn, {"integrity": integrity}, client_version="v20.0.0"
            )
        finally:
            conn.close()

    def test_development_executable_fallback_accepts_missing_manifest(self):
        result = self._check(
            {
                "schema": "visionforge-integrity-v2",
                "executable_sha256": self.official_hash,
                "executable_size": 200,
                "files": [
                    {
                        "path": "@executable",
                        "role": "executable",
                        "sha256": self.official_hash,
                        "size": 200,
                    }
                ],
            }
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["status"], "allowlisted_file_hash")
        self.assertEqual(
            result["lease_manifest_hash"],
            DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
        )

    def test_official_helper_cannot_hide_modified_main_executable(self):
        result = self._check(
            {
                "manifest_hash": "c" * 64,
                "files": [
                    {"path": "official-helper.exe", "sha256": self.official_hash},
                    {"path": "renamed-main.exe", "sha256": "f" * 64},
                ],
            }
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "not_allowlisted")

    def test_explicit_main_hash_takes_precedence_over_official_helper(self):
        result = self._check(
            {
                "manifest_hash": "c" * 64,
                "executable_sha256": "f" * 64,
                "files": [
                    {"path": "official-helper.exe", "sha256": self.official_hash},
                    {"path": "@executable", "role": "executable", "sha256": "f" * 64},
                ],
            }
        )
        self.assertFalse(result["accepted"])

    def test_development_executable_fallback_accepts_unallowlisted_manifest(self):
        accepted = self._check(
            {
                "manifest_hash": "c" * 64,
                "files": [{"path": "anything-user-chose.exe", "sha256": self.official_hash}],
            }
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["status"], "allowlisted_file_hash")
        self.assertEqual(accepted["lease_manifest_hash"], "c" * 64)

    def test_production_accepts_exact_version_allowlisted_manifest(self):
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            result = self._check({"manifest_hash": "b" * 64})
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertTrue(result["accepted"])
        self.assertEqual(result["status"], "allowlisted")
        self.assertEqual(result["lease_manifest_hash"], "b" * 64)

    def test_production_rejects_unallowlisted_manifest_despite_exact_executable(self):
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            result = self._check(
                {
                    "manifest_hash": "c" * 64,
                    "executable_sha256": self.official_hash,
                    "files": [
                        {
                            "path": "@executable",
                            "role": "executable",
                            "sha256": self.official_hash,
                        }
                    ],
                }
            )
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "not_allowlisted")
        self.assertEqual(result["lease_manifest_hash"], "c" * 64)

    def test_production_rejects_development_sentinel_even_if_allowlisted(self):
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE client_integrity_allowlist SET manifest_hash = ? "
                "WHERE client_version = ?",
                (DEVELOPMENT_UNVERIFIED_MANIFEST_HASH, "v20.0.0"),
            )
            conn.commit()
        finally:
            conn.close()
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            result = self._check(
                {
                    "manifest_hash": DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
                    "executable_sha256": self.official_hash,
                }
            )
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "development_manifest_forbidden")
        self.assertEqual(result["lease_manifest_hash"], "")

    def test_production_policy_overrides_legacy_disabled_database_row(self):
        conn = get_connection()
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            conn.execute(
                "UPDATE runtime_security_settings SET enforce_integrity = 0 WHERE id = 1"
            )
            conn.commit()
            config.REQUIRE_RUNTIME_INTEGRITY = True

            settings = _runtime_security_settings(conn)
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous
            conn.close()

        self.assertTrue(settings["enforce_integrity"])
        self.assertFalse(settings["database_enforced"])
        self.assertTrue(settings["production_enforced"])

    def test_production_ignores_wildcard_manifest_and_file_hash_allowlists(self):
        wildcard_manifest = "c" * 64
        wildcard_executable = "d" * 64
        self._insert_wildcard(wildcard_manifest, wildcard_executable)
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            manifest_result = self._check({"manifest_hash": wildcard_manifest})
            executable_result = self._check(
                {
                    "executable_sha256": wildcard_executable,
                    "files": [
                        {
                            "path": "@executable",
                            "role": "executable",
                            "sha256": wildcard_executable,
                        }
                    ],
                }
            )
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertFalse(manifest_result["accepted"])
        self.assertFalse(executable_result["accepted"])

    def test_production_requires_manifest_even_for_exact_executable_allowlist(self):
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            result = self._check(
                {
                    "executable_sha256": self.official_hash,
                    "files": [
                        {
                            "path": "@executable",
                            "role": "executable",
                            "sha256": self.official_hash,
                        }
                    ],
                }
            )
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "missing_integrity")
        self.assertEqual(result["lease_manifest_hash"], "")


if __name__ == "__main__":
    unittest.main()
