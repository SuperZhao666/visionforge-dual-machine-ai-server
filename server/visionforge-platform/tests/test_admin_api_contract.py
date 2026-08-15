import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-admin-api-contract")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import create_access_token, verify_password
from app.services.admin_service import MAX_AUDIT_DETAIL_JSON_LENGTH, write_admin_audit
from app.services.log_service import store_log_file


class AdminApiContractTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.previous_site_url = config.SITE_URL
        config.DATABASE_PATH = str(self.root / "vf.db")
        config.LOG_STORAGE_PATH = str(self.root / "logs")
        config.SITE_URL = "https://visionforge.test"
        self.release_root = self.root / "releases"
        self.release_root.mkdir()
        self.release_root_patch = mock.patch(
            "app.services.release_service.RELEASE_STATIC_ROOT", self.release_root
        )
        self.release_root_patch.start()
        init_db()
        conn = get_connection()
        try:
            self.admin_id = int(
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin) VALUES ('admin', 'admin@example.test', 'hash', 1)"
                ).lastrowid
            )
            self.user_id = int(
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES ('user', 'user@example.test', 'hash')"
                ).lastrowid
            )
            conn.execute("INSERT INTO time_balance (user_id, balance_seconds) VALUES (?, 100)", (self.user_id,))
            conn.commit()
        finally:
            conn.close()
        self.client = TestClient(app)
        self.admin_headers = {"Authorization": f"Bearer {create_access_token(self.admin_id, True)}"}

    def tearDown(self):
        self.release_root_patch.stop()
        config.SITE_URL = self.previous_site_url
        self.tmpdir.cleanup()

    def test_admin_audit_large_detail_is_valid_summary_json(self):
        conn = get_connection()
        try:
            write_admin_audit(
                conn,
                admin_user_id=self.admin_id,
                ip_address="127.0.0.1",
                action="audit.large_detail",
                target_type="test",
                target_id="large",
                detail={"payload": "x" * 120_000, "trace_id": "trace-large"},
            )
            conn.commit()
            row = conn.execute(
                "SELECT detail_json FROM admin_audit WHERE action = 'audit.large_detail'",
            ).fetchone()
        finally:
            conn.close()

        detail = json.loads(row["detail_json"])
        self.assertEqual(
            detail,
            {
                "truncated": True,
                "original_length": len(json.dumps({"payload": "x" * 120_000, "trace_id": "trace-large"}, ensure_ascii=False, separators=(",", ":"))),
                "key_count": 2,
                "keys": ["payload", "trace_id"],
            },
        )
        self.assertNotIn("x" * 1000, row["detail_json"])

    def test_admin_audit_detail_handles_many_keys_and_non_json_values(self):
        conn = get_connection()
        try:
            detail = {f"key-{index:05d}": object() for index in range(2500)}
            write_admin_audit(
                conn,
                admin_user_id=self.admin_id,
                ip_address="127.0.0.1",
                action="audit.edge_detail",
                target_type="test",
                target_id="edge",
                detail=detail,
            )
            conn.commit()
            row = conn.execute(
                "SELECT detail_json FROM admin_audit WHERE action = 'audit.edge_detail'",
            ).fetchone()
        finally:
            conn.close()

        payload = row["detail_json"]
        self.assertLessEqual(len(payload), MAX_AUDIT_DETAIL_JSON_LENGTH)
        parsed = json.loads(payload)
        self.assertTrue(parsed["truncated"])
        self.assertEqual(parsed["key_count"], len(detail))
        self.assertLessEqual(len(parsed["keys"]), 200)

    def test_user_api_contract_and_soft_delete(self):
        unauthorized = self.client.get("/api/admin/users")
        self.assertEqual(unauthorized.status_code, 401)

        extra_create = self.client.post(
            "/api/admin/users",
            headers=self.admin_headers,
            json={
                "username": "created-user",
                "password": "password-123",
                "balance_seconds": 60,
                "is_admin": True,
            },
        )
        self.assertEqual(extra_create.status_code, 422, extra_create.text)
        self.assertIn("extra_forbidden", extra_create.text)
        self.assertIn("is_admin", extra_create.text)

        created = self.client.post(
            "/api/admin/users",
            headers=self.admin_headers,
            json={
                "username": "created-user",
                "password": "password-123",
                "email": "created@example.test",
                "balance_seconds": 60,
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        created_id = created.json()["user"]["id"]

        listed = self.client.get("/api/admin/users?limit=500", headers=self.admin_headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(created_id, [item["id"] for item in listed.json()["users"]])

        updated = self.client.patch(
            f"/api/admin/users/{created_id}",
            headers=self.admin_headers,
            json={"username": "renamed-user", "balance_seconds": 120},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["user"]["balance_seconds"], 120)

        reset = self.client.post(
            f"/api/admin/users/{created_id}/reset-password",
            headers=self.admin_headers,
            json={"new_password": "reset-password-123", "reason": "contract reset"},
        )
        self.assertEqual(reset.status_code, 200, reset.text)
        conn = get_connection()
        try:
            password_hash = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (created_id,),
            ).fetchone()["password_hash"]
        finally:
            conn.close()
        self.assertTrue(verify_password("reset-password-123", password_hash))
        self.assertFalse(verify_password("password-123", password_hash))

        adjusted = self.client.post(
            f"/api/admin/users/{created_id}/adjust-time",
            headers=self.admin_headers,
            json={"delta_seconds": -20, "reason": "contract test"},
        )
        self.assertEqual(adjusted.json()["user"]["balance_seconds"], 100)

        banned = self.client.post(
            f"/api/admin/users/{created_id}/ban",
            headers=self.admin_headers,
            json={"reason": "contract test ban"},
        )
        self.assertEqual(banned.json()["user"]["status"], "banned")
        unbanned = self.client.post(
            f"/api/admin/users/{created_id}/unban",
            headers=self.admin_headers,
            json={"reason": "contract test unban"},
        )
        self.assertEqual(unbanned.json()["user"]["status"], "active")

        deleted = self.client.request(
            "DELETE",
            f"/api/admin/users/{created_id}",
            headers=self.admin_headers,
            json={"reason": "privacy delete"},
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertTrue(deleted.json()["soft_deleted"])
        row = self.client.get(f"/api/admin/users/{created_id}", headers=self.admin_headers).json()["user"]
        self.assertEqual(row["status"], "disabled")
        self.assertTrue(row["username"].startswith("deleted_"))
        self.assertEqual(row["email"], "")
        self.assertIsNotNone(row["deleted_at"])
        after_delete_list = self.client.get("/api/admin/users?limit=500", headers=self.admin_headers)
        self.assertNotIn(created_id, [item["id"] for item in after_delete_list.json()["users"]])

        deleted_update = self.client.patch(
            f"/api/admin/users/{created_id}",
            headers=self.admin_headers,
            json={"username": "must-not-update"},
        )
        deleted_ban = self.client.post(
            f"/api/admin/users/{created_id}/ban",
            headers=self.admin_headers,
            json={"reason": "must-not-ban"},
        )
        deleted_again = self.client.request(
            "DELETE",
            f"/api/admin/users/{created_id}",
            headers=self.admin_headers,
            json={"reason": "must-not-delete-again"},
        )
        self.assertEqual(deleted_update.status_code, 404, deleted_update.text)
        self.assertEqual(deleted_ban.status_code, 404, deleted_ban.text)
        self.assertEqual(deleted_again.status_code, 404, deleted_again.text)

    def test_user_api_rejects_empty_update_without_audit(self):
        response = self.client.patch(
            f"/api/admin/users/{self.user_id}",
            headers=self.admin_headers,
            json={},
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["detail"], "no fields to update")
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT username, email, status FROM users WHERE id = ?",
                (self.user_id,),
            ).fetchone()
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE action = 'user.update'",
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(dict(user), {"username": "user", "email": "user@example.test", "status": "active"})
        self.assertEqual(audit_count, 0)

    def test_user_api_rejects_invalid_usernames_before_write(self):
        invalid_create = self.client.post(
            "/api/admin/users",
            headers=self.admin_headers,
            json={
                "username": "bad name",
                "password": "password-123",
                "email": "bad-name@example.test",
            },
        )
        short_after_trim = self.client.post(
            "/api/admin/users",
            headers=self.admin_headers,
            json={
                "username": "  ab  ",
                "password": "password-123",
                "email": "short-name@example.test",
            },
        )
        invalid_update = self.client.patch(
            f"/api/admin/users/{self.user_id}",
            headers=self.admin_headers,
            json={"username": "bad name"},
        )

        self.assertEqual(invalid_create.status_code, 422, invalid_create.text)
        self.assertEqual(short_after_trim.status_code, 422, short_after_trim.text)
        self.assertEqual(invalid_update.status_code, 422, invalid_update.text)
        conn = get_connection()
        try:
            created_count = conn.execute(
                "SELECT COUNT(*) FROM users WHERE email IN ('bad-name@example.test', 'short-name@example.test')"
            ).fetchone()[0]
            unchanged = conn.execute("SELECT username FROM users WHERE id = ?", (self.user_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(created_count, 0)
        self.assertEqual(unchanged["username"], "user")

    def test_user_api_rejects_explicit_empty_status_without_audit(self):
        response = self.client.patch(
            f"/api/admin/users/{self.user_id}",
            headers=self.admin_headers,
            json={"status": ""},
        )

        self.assertEqual(response.status_code, 422, response.text)
        conn = get_connection()
        try:
            status = conn.execute("SELECT status FROM users WHERE id = ?", (self.user_id,)).fetchone()["status"]
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE action = 'user.update' AND target_id = ?",
                (str(self.user_id),),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(status, "active")
        self.assertEqual(audit_count, 0)

    def test_adjust_time_rejects_result_balance_out_of_range(self):
        max_balance_seconds = 10 * 365 * 24 * 3600
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (max_balance_seconds - 30, max_balance_seconds - 30, self.user_id),
            )
            conn.commit()
        finally:
            conn.close()

        overflow = self.client.post(
            f"/api/admin/users/{self.user_id}/adjust-time",
            headers=self.admin_headers,
            json={"delta_seconds": 60, "reason": "overflow"},
        )
        underflow = self.client.post(
            f"/api/admin/users/{self.user_id}/adjust-time",
            headers=self.admin_headers,
            json={"delta_seconds": -max_balance_seconds, "reason": "underflow"},
        )

        self.assertEqual(overflow.status_code, 422, overflow.text)
        self.assertEqual(underflow.status_code, 422, underflow.text)
        conn = get_connection()
        try:
            balance = conn.execute(
                "SELECT balance_seconds, total_recharged_seconds FROM time_balance WHERE user_id = ?",
                (self.user_id,),
            ).fetchone()
            recharge_count = conn.execute("SELECT COUNT(*) FROM time_recharges").fetchone()[0]
            audit_count = conn.execute("SELECT COUNT(*) FROM admin_audit WHERE action = 'user.adjust_time'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(balance["balance_seconds"], max_balance_seconds - 30)
        self.assertEqual(balance["total_recharged_seconds"], max_balance_seconds - 30)
        self.assertEqual(recharge_count, 0)
        self.assertEqual(audit_count, 0)

    def test_admin_api_rejects_non_positive_path_ids(self):
        user_response = self.client.get("/api/admin/users/0", headers=self.admin_headers)
        self.assertEqual(user_response.status_code, 422, user_response.text)

        announcement_response = self.client.delete(
            "/api/admin/announcements/0",
            headers=self.admin_headers,
        )
        self.assertEqual(announcement_response.status_code, 422, announcement_response.text)

        log_response = self.client.get("/api/admin/logs/0", headers=self.admin_headers)
        self.assertEqual(log_response.status_code, 422, log_response.text)

    def test_announcement_release_log_and_audit_contracts(self):
        announcement = self.client.post(
            "/api/admin/announcements",
            headers=self.admin_headers,
            json={"title": "Notice", "body": "Body", "level": "warning"},
        )
        self.assertEqual(announcement.status_code, 200, announcement.text)
        announcement_id = announcement.json()["announcement"]["id"]
        patched = self.client.patch(
            f"/api/admin/announcements/{announcement_id}",
            headers=self.admin_headers,
            json={"enabled": False},
        )
        self.assertEqual(patched.json()["announcement"]["enabled"], 0)
        level_patch = self.client.patch(
            f"/api/admin/announcements/{announcement_id}",
            headers=self.admin_headers,
            json={"level": " SUCCESS "},
        )
        self.assertEqual(level_patch.status_code, 200, level_patch.text)
        self.assertEqual(level_patch.json()["announcement"]["level"], "success")
        extra_patch = self.client.patch(
            f"/api/admin/announcements/{announcement_id}",
            headers=self.admin_headers,
            json={"enabled": True, "created_at": "2099-01-01"},
        )
        self.assertEqual(extra_patch.status_code, 422, extra_patch.text)
        self.assertIn("extra_forbidden", extra_patch.text)
        self.assertIn("created_at", extra_patch.text)
        listed = self.client.get("/api/admin/announcements", headers=self.admin_headers)
        self.assertEqual(len(listed.json()["announcements"]), 1)

        for version in ("v2.0.0", "v1.0.0"):
            artifact = f"legacy-{version}".encode()
            digest = hashlib.sha256(artifact).hexdigest()
            (self.release_root / f"{digest}.exe").write_bytes(artifact)
            url = f"/static/releases/{digest}.exe"
            response = self.client.post(
                "/api/admin/releases",
                headers=self.admin_headers,
                json={
                    "version": version,
                    "channel": "stable",
                    "url": url,
                    "sha256": digest,
                    "installer_url": url,
                    "installer_sha256": digest,
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        rollback = self.client.post(
            "/api/admin/releases/v2.0.0/rollback",
            headers=self.admin_headers,
            json={"channel": "stable"},
        )
        self.assertEqual(rollback.status_code, 200, rollback.text)
        manifest = self.client.get("/update/stable.json")
        self.assertEqual(manifest.json()["version"], "v2.0.0")

        stored = store_log_file(
            "admin-api-log",
            "txt",
            "run.txt",
            b"runtime log",
            user_id=self.user_id,
        )
        log_id = stored["session_db_id"]
        log_list = self.client.get("/api/admin/logs", headers=self.admin_headers)
        self.assertIn(log_id, [item["id"] for item in log_list.json()["logs"]])
        log_detail = self.client.get(f"/api/admin/logs/{log_id}", headers=self.admin_headers)
        self.assertEqual(len(log_detail.json()["files"]), 1)
        deleted_log = self.client.request(
            "DELETE",
            f"/api/admin/logs/{log_id}",
            headers=self.admin_headers,
            json={"reason": "contract cleanup"},
        )
        self.assertEqual(deleted_log.status_code, 200, deleted_log.text)
        self.assertEqual(list(Path(config.LOG_STORAGE_PATH).glob("*")), [])

        deleted_announcement = self.client.delete(
            f"/api/admin/announcements/{announcement_id}",
            headers=self.admin_headers,
        )
        self.assertEqual(deleted_announcement.status_code, 200, deleted_announcement.text)
        audit = self.client.get("/api/admin/audit?limit=500", headers=self.admin_headers)
        actions = {item["action"] for item in audit.json()["audit"]}
        self.assertIn("announcement.create", actions)
        self.assertIn("release.rollback", actions)
        self.assertIn("log_session.delete", actions)


if __name__ == "__main__":
    unittest.main()
