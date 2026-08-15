import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-admin-auth-csrf")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import CSRF_COOKIE_NAME, hash_password, verify_password


class AdminAuthCsrfTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        self.previous_cookie_secure = config.COOKIE_SECURE
        self.previous_totp_secret = config.ADMIN_TOTP_SECRET
        config.COOKIE_SECURE = False
        config.ADMIN_TOTP_SECRET = ""
        init_db()
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                ("admin", "admin@example.test", hash_password("correct-password")),
            )
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("managed-user", "managed@example.test", hash_password("managed-password")),
            )
            conn.execute(
                "INSERT INTO users (username, email, password_hash, deleted_at) VALUES (?, ?, ?, datetime('now'))",
                ("deleted-user", "deleted@example.test", hash_password("deleted-password")),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        config.COOKIE_SECURE = self.previous_cookie_secure
        config.ADMIN_TOTP_SECRET = self.previous_totp_secret
        self.tmpdir.cleanup()

    def _login_admin(self, client):
        client.get("/login")
        token = client.cookies.get(CSRF_COOKIE_NAME)
        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303, login.text)
        return token

    def test_login_requires_matching_csrf_cookie_and_form_token(self):
        client = TestClient(app)
        missing = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password"},
            follow_redirects=False,
        )
        self.assertEqual(missing.status_code, 403)

        page = client.get("/login")
        self.assertEqual(page.status_code, 200, page.text)
        token = client.cookies.get(CSRF_COOKIE_NAME)
        self.assertTrue(token)
        self.assertIn("csrf_token", page.text)

        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303, login.text)
        self.assertTrue(client.cookies.get("vf_token"))

    def test_admin_cookie_uses_secure_and_strict_flags_in_production_mode(self):
        config.COOKIE_SECURE = True
        client = TestClient(app, base_url="https://testserver")
        client.get("/login")
        token = client.cookies.get(CSRF_COOKIE_NAME)
        response = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )

        set_cookie = response.headers.get("set-cookie", "").lower()
        self.assertIn("vf_token=", set_cookie)
        self.assertIn("secure", set_cookie)
        self.assertIn("samesite=strict", set_cookie)

    def test_user_management_forms_render_csrf_tokens(self):
        client = TestClient(app)
        client.get("/login")
        token = client.cookies.get(CSRF_COOKIE_NAME)
        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303, login.text)

        users_page = client.get("/admin/users")
        self.assertEqual(users_page.status_code, 200, users_page.text)
        self.assertIn('action="/admin/users/delete"', users_page.text)
        self.assertIn('name="csrf_token"', users_page.text)

        detail_page = client.get("/admin/users/1")
        self.assertEqual(detail_page.status_code, 200, detail_page.text)
        self.assertIn('action="/admin/users/reset-password"', detail_page.text)
        self.assertIn('name="csrf_token"', detail_page.text)

    def test_dashboard_user_counts_exclude_soft_deleted_accounts(self):
        client = TestClient(app)
        self._login_admin(client)
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET status = 'banned' WHERE username = 'managed-user'")
            conn.execute("UPDATE users SET status = 'banned' WHERE username = 'deleted-user'")
            conn.commit()
        finally:
            conn.close()

        response = client.get("/admin")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('<div class="stat-value" data-countup="2" data-decimals="0">2</div>', response.text)
        self.assertIn('class="stat-value" style="color:var(--error);">1</div>', response.text)

    def test_user_create_form_rejects_invalid_input_before_insert(self):
        client = TestClient(app)
        token = self._login_admin(client)

        invalid_username = client.post(
            "/admin/users/create",
            data={
                "csrf_token": token,
                "username": "bad name",
                "password": "valid-password",
                "email": "new@example.test",
            },
            follow_redirects=False,
        )
        self.assertEqual(invalid_username.status_code, 422, invalid_username.text)

        short_password = client.post(
            "/admin/users/create",
            data={
                "csrf_token": token,
                "username": "valid_user",
                "password": "short",
                "email": "valid@example.test",
            },
            follow_redirects=False,
        )
        self.assertEqual(short_password.status_code, 422, short_password.text)

        conn = get_connection()
        try:
            created = conn.execute(
                "SELECT id FROM users WHERE username IN (?, ?)",
                ("bad name", "valid_user"),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(created, [])

    def test_user_create_form_rejects_out_of_range_initial_balance(self):
        client = TestClient(app)
        token = self._login_admin(client)

        response = client.post(
            "/admin/users/create",
            data={
                "csrf_token": token,
                "username": "bounded_user",
                "password": "valid-password",
                "email": "bounded@example.test",
                "balance_hours": 0,
                "balance_seconds": str(100 * 365 * 24 * 3600),
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 422, response.text)
        conn = get_connection()
        try:
            user = conn.execute("SELECT id FROM users WHERE username = 'bounded_user'").fetchone()
            balance_count = conn.execute("SELECT COUNT(*) FROM time_balance").fetchone()[0]
        finally:
            conn.close()
        self.assertIsNone(user)
        self.assertEqual(balance_count, 0)

    def test_user_update_form_rejects_invalid_email_before_update(self):
        client = TestClient(app)
        token = self._login_admin(client)

        conn = get_connection()
        try:
            managed = conn.execute(
                "SELECT id, username, email FROM users WHERE username = ?",
                ("managed-user",),
            ).fetchone()
        finally:
            conn.close()

        response = client.post(
            "/admin/users/update",
            data={
                "csrf_token": token,
                "user_id": str(managed["id"]),
                "username": "managed-user-renamed",
                "email": "not an email",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 422, response.text)

        conn = get_connection()
        try:
            unchanged = conn.execute(
                "SELECT username, email FROM users WHERE id = ?",
                (managed["id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(unchanged["username"], managed["username"])
        self.assertEqual(unchanged["email"], managed["email"])

    def test_user_update_and_status_ignore_missing_or_deleted_users(self):
        client = TestClient(app)
        token = self._login_admin(client)

        conn = get_connection()
        try:
            deleted_user = conn.execute(
                "SELECT id FROM users WHERE username = ?", ("deleted-user",)
            ).fetchone()
        finally:
            conn.close()

        missing_update = client.post(
            "/admin/users/update",
            data={
                "csrf_token": token,
                "user_id": "999999",
                "username": "phantom",
                "email": "phantom@example.test",
            },
            follow_redirects=False,
        )
        deleted_status = client.post(
            "/admin/users/set-status",
            data={
                "csrf_token": token,
                "user_id": str(deleted_user["id"]),
                "status": "banned",
                "ban_reason": "should not persist",
            },
            follow_redirects=False,
        )
        missing_kick = client.post(
            "/admin/users/kick-session",
            data={"csrf_token": token, "user_id": "999999"},
            follow_redirects=False,
        )
        missing_policy = client.post(
            "/admin/users/log-policy",
            data={"csrf_token": token, "user_id": "999999", "log_upload_enabled": "1"},
            follow_redirects=False,
        )
        deleted_toggle = client.post(
            "/admin/users/toggle-admin",
            data={"csrf_token": token, "user_id": str(deleted_user["id"])},
            follow_redirects=False,
        )
        deleted_delete = client.post(
            "/admin/users/delete",
            data={"csrf_token": token, "user_id": str(deleted_user["id"])},
            follow_redirects=False,
        )
        deleted_adjust = client.post(
            "/admin/users/adjust-time",
            data={
                "csrf_token": token,
                "user_id": str(deleted_user["id"]),
                "delta_seconds": "600",
                "reason": "should not credit",
            },
            follow_redirects=False,
        )
        self.assertEqual(missing_update.status_code, 303, missing_update.text)
        self.assertEqual(deleted_status.status_code, 303, deleted_status.text)
        self.assertEqual(missing_kick.status_code, 303, missing_kick.text)
        self.assertEqual(missing_policy.status_code, 303, missing_policy.text)
        self.assertEqual(deleted_toggle.status_code, 303, deleted_toggle.text)
        self.assertEqual(deleted_delete.status_code, 303, deleted_delete.text)
        self.assertEqual(deleted_adjust.status_code, 303, deleted_adjust.text)

        conn = get_connection()
        try:
            audits = conn.execute(
                "SELECT COUNT(*) AS count FROM admin_audit "
                "WHERE action IN ('user.update', 'user.set_status', 'user.kick_session', "
                "'user.log_policy', 'user.toggle_admin', 'user.soft_delete', 'user.adjust_time') "
                "AND target_id IN (?, ?)",
                ("999999", str(deleted_user["id"])),
            ).fetchone()
            deleted_state = conn.execute(
                "SELECT status, ban_reason FROM users WHERE id = ?", (deleted_user["id"],)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(audits["count"], 0)
        self.assertEqual(deleted_state["status"], "active")
        self.assertEqual(deleted_state["ban_reason"], "")

    def test_invalid_user_status_does_not_reactivate_account_or_create_audit(self):
        client = TestClient(app)
        token = self._login_admin(client)
        conn = get_connection()
        try:
            managed = conn.execute(
                "SELECT id FROM users WHERE username = ?", ("managed-user",)
            ).fetchone()
            conn.execute("UPDATE users SET status = 'banned' WHERE id = ?", (managed["id"],))
            conn.commit()
        finally:
            conn.close()

        response = client.post(
            "/admin/users/set-status",
            data={
                "csrf_token": token,
                "user_id": str(managed["id"]),
                "status": "unexpected-status",
                "ban_reason": "must not alter account",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            status = conn.execute("SELECT status FROM users WHERE id = ?", (managed["id"],)).fetchone()["status"]
            audits = conn.execute(
                "SELECT COUNT(*) AS count FROM admin_audit WHERE action = 'user.set_status' AND target_id = ?",
                (str(managed["id"]),),
            ).fetchone()["count"]
        finally:
            conn.close()
        self.assertEqual(status, "banned")
        self.assertEqual(audits, 0)

    def test_logout_form_is_csrf_protected_and_revokes_the_login(self):
        client = TestClient(app)
        client.get("/login")
        token = client.cookies.get(CSRF_COOKIE_NAME)
        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303, login.text)

        page = client.get("/admin")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn('action="/auth/logout"', page.text)
        self.assertIn(f'name="csrf_token" value="{token}"', page.text)

        rejected = client.post("/auth/logout", follow_redirects=False)
        self.assertEqual(rejected.status_code, 403, rejected.text)
        self.assertTrue(client.cookies.get("vf_token"))

        conn = get_connection()
        try:
            version_before = int(
                conn.execute("SELECT auth_version FROM users WHERE username = 'admin'").fetchone()[
                    "auth_version"
                ]
            )
        finally:
            conn.close()

        logged_out = client.post(
            "/auth/logout",
            data={"csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(logged_out.status_code, 303, logged_out.text)
        self.assertFalse(client.cookies.get("vf_token"))
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT auth_version, login_instance_id FROM users WHERE username = 'admin'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(int(user["auth_version"]), version_before + 1)
        self.assertEqual(str(user["login_instance_id"] or ""), "")

    def test_user_management_page_delete_and_reset_password_with_csrf(self):
        client = TestClient(app)
        client.get("/login")
        token = client.cookies.get(CSRF_COOKIE_NAME)
        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "correct-password", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303, login.text)

        conn = get_connection()
        try:
            managed_id = conn.execute("SELECT id FROM users WHERE username = 'managed-user'").fetchone()["id"]
        finally:
            conn.close()

        reset = client.post(
            "/admin/users/reset-password",
            data={
                "csrf_token": token,
                "user_id": str(managed_id),
                "new_password": "new-managed-password",
                "reason": "page reset test",
            },
            follow_redirects=False,
        )
        self.assertEqual(reset.status_code, 303, reset.text)
        conn = get_connection()
        try:
            password_hash = conn.execute("SELECT password_hash FROM users WHERE id = ?", (managed_id,)).fetchone()["password_hash"]
        finally:
            conn.close()
        self.assertTrue(verify_password("new-managed-password", password_hash))

        deleted = client.post(
            "/admin/users/delete",
            data={"csrf_token": token, "user_id": str(managed_id), "reason": "page delete test"},
            follow_redirects=False,
        )
        self.assertEqual(deleted.status_code, 303, deleted.text)
        users_page = client.get("/admin/users")
        self.assertEqual(users_page.status_code, 200, users_page.text)
        self.assertNotIn("managed-user", users_page.text)

    def test_delete_user_bounds_overlong_reason(self):
        client = TestClient(app)
        token = self._login_admin(client)
        reason = "admin delete reason " + ("r" * 620)
        expected_reason = reason[:500]
        conn = get_connection()
        try:
            managed_id = conn.execute("SELECT id FROM users WHERE username = 'managed-user'").fetchone()["id"]
        finally:
            conn.close()

        response = client.post(
            "/admin/users/delete",
            data={"csrf_token": token, "user_id": str(managed_id), "reason": reason},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            deleted = conn.execute("SELECT status, ban_reason FROM users WHERE id = ?", (managed_id,)).fetchone()
            audit = conn.execute(
                "SELECT reason FROM admin_audit WHERE action = 'user.soft_delete' AND target_id = ?",
                (str(managed_id),),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(deleted["status"], "disabled")
        self.assertEqual(deleted["ban_reason"], expected_reason)
        self.assertEqual(audit["reason"], expected_reason)

    def test_user_log_policy_rejects_out_of_range_interval_without_clamping(self):
        client = TestClient(app)
        token = self._login_admin(client)
        conn = get_connection()
        try:
            managed_id = conn.execute("SELECT id FROM users WHERE username = 'managed-user'").fetchone()["id"]
        finally:
            conn.close()

        response = client.post(
            "/admin/users/log-policy",
            data={
                "csrf_token": token,
                "user_id": str(managed_id),
                "log_upload_enabled": "1",
                "log_upload_interval_seconds": "299",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=invalid_log_policy", response.headers["location"])
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT log_upload_enabled, log_upload_interval_seconds FROM users WHERE id = ?",
                (managed_id,),
            ).fetchone()
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE action = 'user.log_policy' AND target_id = ?",
                (str(managed_id),),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(int(user["log_upload_enabled"]), -1)
        self.assertEqual(int(user["log_upload_interval_seconds"]), 0)
        self.assertEqual(int(audit_count), 0)


if __name__ == "__main__":
    unittest.main()
