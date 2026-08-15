import os
import json
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-admin-security")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import CSRF_COOKIE_NAME, create_access_token, generate_csrf_token


class AdminSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        init_db()
        conn = get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                ("admin", "admin@example.test", "hash"),
            )
            self.admin_id = int(cur.lastrowid)
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def client(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
        client._vf_csrf_token = csrf_token
        return client

    def admin_post(self, client, path, data, **kwargs):
        payload = dict(data)
        payload["csrf_token"] = client._vf_csrf_token
        return client.post(path, data=payload, **kwargs)

    def test_security_settings_and_allowlist_crud(self):
        client = self.client()

        page = client.get("/admin/security")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("安全策略", page.text)

        response = self.admin_post(
            client,
            "/admin/security/settings",
            {"enforce_integrity": "1", "lease_ttl_seconds": "45"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        conn = get_connection()
        try:
            settings = conn.execute("SELECT * FROM runtime_security_settings WHERE id = 1").fetchone()
        finally:
            conn.close()
        self.assertEqual(settings["enforce_integrity"], 1)
        self.assertEqual(settings["lease_ttl_seconds"], 15)

        manifest_hash = "a" * 64
        response = self.admin_post(
            client,
            "/admin/security/allowlist/create",
            {
                "client_version": "v-test",
                "manifest_hash": manifest_hash,
                "file_hashes_json": '{"files":[]}',
                "enabled": "1",
                "note": "unit test",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM client_integrity_allowlist WHERE manifest_hash = ?", (manifest_hash,)).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["client_version"], "v-test")
        self.assertEqual(row["file_hashes_json"], "[]")
        self.assertEqual(row["enabled"], 1)

        response = self.admin_post(
            client,
            "/admin/security/allowlist/update",
            {
                "allowlist_id": str(row["id"]),
                "client_version": "*",
                "manifest_hash": "b" * 64,
                "file_hashes_json": '{"files":[{"path":"app_gui.py"}]}',
                "enabled": "0",
                "note": "updated",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            updated = conn.execute("SELECT * FROM client_integrity_allowlist WHERE id = ?", (row["id"],)).fetchone()
        finally:
            conn.close()
        self.assertEqual(updated["client_version"], "*")
        self.assertEqual(updated["manifest_hash"], "b" * 64)
        self.assertEqual(updated["file_hashes_json"], '[{"path":"app_gui.py"}]')
        self.assertEqual(updated["enabled"], 0)

        response = self.admin_post(
            client,
            "/admin/security/allowlist/delete",
            {"allowlist_id": str(row["id"])},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM client_integrity_allowlist").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_allowlist_rejects_oversized_file_hashes_without_truncating_json(self):
        response = self.admin_post(
            self.client(),
            "/admin/security/allowlist/create",
            {
                "client_version": "v-test",
                "manifest_hash": "c" * 64,
                "file_hashes_json": json.dumps({"files": [{"path": "x" * 100001}]}),
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 400, response.text)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM client_integrity_allowlist").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_production_rejects_enabled_wildcard_allowlist(self):
        previous = config.REQUIRE_RUNTIME_INTEGRITY
        try:
            config.REQUIRE_RUNTIME_INTEGRITY = True
            response = self.admin_post(
                self.client(),
                "/admin/security/allowlist/create",
                {
                    "client_version": "",
                    "manifest_hash": "9" * 64,
                    "file_hashes_json": "[]",
                    "enabled": "1",
                },
                follow_redirects=False,
            )
        finally:
            config.REQUIRE_RUNTIME_INTEGRITY = previous

        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("exact client_version", response.text)

    def test_missing_allowlist_does_not_create_success_audit(self):
        client = self.client()
        responses = [
            self.admin_post(
                client,
                "/admin/security/allowlist/update",
                {
                    "allowlist_id": "999999",
                    "client_version": "v-test",
                    "manifest_hash": "a" * 64,
                    "file_hashes_json": "[]",
                },
                follow_redirects=False,
            ),
            self.admin_post(
                client,
                "/admin/security/allowlist/delete",
                {"allowlist_id": "999999"},
                follow_redirects=False,
            ),
        ]
        self.assertTrue(all(response.status_code == 303 for response in responses))
        conn = get_connection()
        try:
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE target_id = '999999' "
                "AND action IN ('security.allowlist.update', 'security.allowlist.delete')"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(audit_count, 0)

    def test_allowlist_rejects_overlong_note_without_truncating(self):
        response = self.admin_post(
            self.client(),
            "/admin/security/allowlist/create",
            {
                "client_version": "v-test",
                "manifest_hash": "d" * 64,
                "file_hashes_json": "[]",
                "enabled": "1",
                "note": "N" * 501,
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 400, response.text)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM client_integrity_allowlist").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_allowlist_rejects_overlong_client_version_without_truncating(self):
        client = self.client()
        manifest_hash = "e" * 64
        overlong_version = "v" * 81

        response = self.admin_post(
            client,
            "/admin/security/allowlist/create",
            {
                "client_version": overlong_version,
                "manifest_hash": manifest_hash,
                "file_hashes_json": "[]",
                "enabled": "1",
                "note": "unit test",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 400, response.text)
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM client_integrity_allowlist").fetchone()[0], 0)
            allowlist_id = int(conn.execute(
                "INSERT INTO client_integrity_allowlist "
                "(client_version, manifest_hash, file_hashes_json, enabled, note) "
                "VALUES (?, ?, ?, 1, ?)",
                ("v-original", "f" * 64, "[]", "original"),
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()

        update_response = self.admin_post(
            client,
            "/admin/security/allowlist/update",
            {
                "allowlist_id": str(allowlist_id),
                "client_version": overlong_version,
                "manifest_hash": "a" * 64,
                "file_hashes_json": "[]",
                "enabled": "0",
                "note": "updated",
            },
            follow_redirects=False,
        )

        self.assertEqual(update_response.status_code, 400, update_response.text)
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM client_integrity_allowlist WHERE id = ?", (allowlist_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["client_version"], "v-original")
        self.assertEqual(row["manifest_hash"], "f" * 64)
        self.assertEqual(int(row["enabled"]), 1)
        self.assertEqual(row["note"], "original")

    def test_kick_session_preserves_signed_lease_handoff_block(self):
        conn = get_connection()
        try:
            user_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("runtime-user", "runtime@example.test", "hash"),
            ).lastrowid)
            session_id = int(conn.execute(
                "INSERT INTO time_sessions (user_id, lease_expires_at, status) "
                "VALUES (?, datetime('now', '+15 seconds'), 'active')",
                (user_id,),
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()
        reason = "security_test_" + ("r" * 180)

        response = self.admin_post(
            self.client(),
            "/admin/users/kick-session",
            {
                "user_id": str(user_id),
                "session_id": str(session_id),
                "reason": reason,
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT runtime_blocked_until_epoch FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            session = conn.execute(
                "SELECT status, ended_reason, CAST(strftime('%s', lease_expires_at) AS INTEGER) AS lease_expiry "
                "FROM time_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            audit = conn.execute(
                "SELECT reason FROM admin_audit WHERE action = 'user.kick_session' AND target_id = ?",
                (str(user_id),),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["status"], "ended")
        self.assertEqual(session["ended_reason"], reason)
        self.assertEqual(audit["reason"], reason)
        self.assertGreaterEqual(
            int(user["runtime_blocked_until_epoch"]),
            int(session["lease_expiry"]),
        )


if __name__ == "__main__":
    unittest.main()
