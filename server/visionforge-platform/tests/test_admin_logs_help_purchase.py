import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-admin-logs-help")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import CSRF_COOKIE_NAME, create_access_token, generate_csrf_token
from app.services.payment_service import PLAN_BY_KEY, create_order_record, process_payment_event


class AdminLogsHelpPurchaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        config.DATABASE_PATH = str(self.root / "vf.db")
        config.LOG_STORAGE_PATH = str(self.root / "log_storage")
        config.IP_GEOLOOKUP_URL_TEMPLATE = ""
        init_db()
        conn = get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                ("admin", "admin@example.test", "hash"),
            )
            self.admin_id = int(cur.lastrowid)
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("user1", "user1@example.test", "hash"),
            )
            self.user_id = int(cur.lastrowid)
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def admin_client(self):
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

    def test_admin_log_settings_rejects_out_of_range_values_without_clamping(self):
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO log_upload_settings "
                "(id, enabled, interval_seconds, max_bundle_mb, retention_days) "
                "VALUES (1, 1, 3600, 50, 30) "
                "ON CONFLICT(id) DO UPDATE SET "
                "enabled = 1, interval_seconds = 3600, max_bundle_mb = 50, retention_days = 30"
            )
            conn.commit()
        finally:
            conn.close()
        client = self.admin_client()

        response = self.admin_post(
            client,
            "/admin/logs/settings",
            {
                "enabled": "1",
                "interval_seconds": "299",
                "max_bundle_mb": "50",
                "retention_days": "30",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=invalid_log_policy", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT enabled, interval_seconds, max_bundle_mb, retention_days "
                "FROM log_upload_settings WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(int(row["enabled"]), 1)
        self.assertEqual(int(row["interval_seconds"]), 3600)
        self.assertEqual(int(row["max_bundle_mb"]), 50)
        self.assertEqual(int(row["retention_days"]), 30)

    def test_admin_log_settings_rejects_invalid_enabled_value_without_audit(self):
        client = self.admin_client()

        response = self.admin_post(
            client,
            "/admin/logs/settings",
            {
                "enabled": "2",
                "interval_seconds": "3600",
                "max_bundle_mb": "50",
                "retention_days": "30",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=invalid_log_policy", response.headers["location"])
        conn = get_connection()
        try:
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE action = 'log_policy.update'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(audit_count, 0)

    def test_admin_can_start_refund_for_deleted_account_payment(self):
        conn = get_connection()
        try:
            order_id, _ = create_order_record(
                conn,
                self.user_id,
                "1h",
                PLAN_BY_KEY["1h"].price,
                "",
                "vmq",
            )
            conn.execute("UPDATE orders SET status = 'refund_required' WHERE id = ?", (order_id,))
            conn.commit()
        finally:
            conn.close()
        client = self.admin_client()

        response = self.admin_post(
            client,
            "/admin/orders/refund",
            {"order_id": str(order_id)},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            status = conn.execute("SELECT status FROM orders WHERE id = ?", (order_id,)).fetchone()["status"]
        finally:
            conn.close()
        self.assertEqual(status, "refunding")

    def test_missing_order_actions_do_not_create_success_audits(self):
        client = self.admin_client()
        responses = [
            self.admin_post(client, "/admin/orders/confirm", {"order_id": "999999"}, follow_redirects=False),
            self.admin_post(client, "/admin/orders/cancel", {"order_id": "999999"}, follow_redirects=False),
            self.admin_post(client, "/admin/orders/refund", {"order_id": "999999"}, follow_redirects=False),
            self.admin_post(client, "/admin/orders/refund-done", {"order_id": "999999"}, follow_redirects=False),
        ]

        self.assertTrue(all(response.status_code == 303 for response in responses))
        conn = get_connection()
        try:
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE target_id = '999999' "
                "AND action IN ('order.confirm', 'order.cancel', 'order.refund.request', 'order.refund.done')"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(audit_count, 0)

    def test_help_faq_admin_crud_and_client_api(self):
        client = self.admin_client()
        response = self.admin_post(
            client,
            "/admin/help-faqs/create",
            {
                "question": "如何更新客户端？",
                "answer": "在更新页面点击检查更新。",
                "sort_order": "10",
                "enabled": "1",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)

        api = TestClient(app).get("/api/client/help-faqs?limit=10")
        self.assertEqual(api.status_code, 200, api.text)
        items = api.json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["question"], "如何更新客户端？")

        conn = get_connection()
        try:
            faq_id = conn.execute("SELECT id FROM help_faqs LIMIT 1").fetchone()["id"]
        finally:
            conn.close()

        response = self.admin_post(
            client,
            "/admin/help-faqs/update",
            {
                "faq_id": str(faq_id),
                "question": "如何下发新版？",
                "answer": "在后台版本更新页面填写版本、URL 和 SHA256。",
                "sort_order": "20",
                "enabled": "0",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        api = TestClient(app).get("/api/client/help-faqs?limit=10")
        self.assertEqual(api.json()["items"], [])

        response = self.admin_post(client, "/admin/help-faqs/delete", {"faq_id": str(faq_id)}, follow_redirects=False)
        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM help_faqs").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_missing_help_faq_and_announcement_do_not_create_success_audits(self):
        client = self.admin_client()
        responses = [
            self.admin_post(
                client,
                "/admin/help-faqs/update",
                {"faq_id": "999999", "question": "Missing FAQ", "answer": "None"},
                follow_redirects=False,
            ),
            self.admin_post(
                client,
                "/admin/help-faqs/delete",
                {"faq_id": "999999"},
                follow_redirects=False,
            ),
            self.admin_post(
                client,
                "/admin/announcements/update",
                {"announcement_id": "999999", "title": "Missing announcement"},
                follow_redirects=False,
            ),
            self.admin_post(
                client,
                "/admin/announcements/delete",
                {"announcement_id": "999999"},
                follow_redirects=False,
            ),
        ]
        self.assertTrue(all(response.status_code == 303 for response in responses))

        conn = get_connection()
        try:
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE target_id = '999999' "
                "AND action IN ('help_faq.update', 'help_faq.delete', "
                "'announcement.update', 'announcement.delete')"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(audit_count, 0)

    def test_announcement_form_rejects_unknown_level(self):
        client = self.admin_client()
        response = self.admin_post(
            client,
            "/admin/announcements/create",
            {"title": "Invalid", "body": "Body", "level": "unexpected"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 422, response.text)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM announcements").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_help_faq_rejects_overlong_fields_without_truncating(self):
        client = self.admin_client()
        overlong_question = "Q" * 501
        overlong_answer = "A" * 8001

        create_response = self.admin_post(
            client,
            "/admin/help-faqs/create",
            {
                "question": overlong_question,
                "answer": "valid answer",
                "sort_order": "10",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(create_response.status_code, 303, create_response.text)
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM help_faqs").fetchone()[0], 0)
            faq_id = int(conn.execute(
                "INSERT INTO help_faqs (question, answer, sort_order, enabled) VALUES (?, ?, 10, 1)",
                ("Original question", "Original answer"),
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()

        update_response = self.admin_post(
            client,
            "/admin/help-faqs/update",
            {
                "faq_id": str(faq_id),
                "question": "Updated question",
                "answer": overlong_answer,
                "sort_order": "20",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(update_response.status_code, 303, update_response.text)
        conn = get_connection()
        try:
            row = conn.execute("SELECT question, answer, sort_order FROM help_faqs WHERE id = ?", (faq_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["question"], "Original question")
        self.assertEqual(row["answer"], "Original answer")
        self.assertEqual(int(row["sort_order"]), 10)

    def test_help_faq_rejects_out_of_range_sort_order_without_clamping(self):
        client = self.admin_client()

        create_response = self.admin_post(
            client,
            "/admin/help-faqs/create",
            {
                "question": "Sort order question",
                "answer": "Sort order answer",
                "sort_order": "100001",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(create_response.status_code, 303, create_response.text)
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM help_faqs").fetchone()[0], 0)
            faq_id = int(conn.execute(
                "INSERT INTO help_faqs (question, answer, sort_order, enabled) VALUES (?, ?, 10, 1)",
                ("Original question", "Original answer"),
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()

        update_response = self.admin_post(
            client,
            "/admin/help-faqs/update",
            {
                "faq_id": str(faq_id),
                "question": "Updated question",
                "answer": "Updated answer",
                "sort_order": "-1",
                "enabled": "0",
            },
            follow_redirects=False,
        )

        self.assertEqual(update_response.status_code, 303, update_response.text)
        conn = get_connection()
        try:
            row = conn.execute("SELECT question, answer, sort_order, enabled FROM help_faqs WHERE id = ?", (faq_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["question"], "Original question")
        self.assertEqual(row["answer"], "Original answer")
        self.assertEqual(int(row["sort_order"]), 10)
        self.assertEqual(int(row["enabled"]), 1)

    def test_client_heartbeat_rejects_non_object_json(self):
        response = TestClient(app).post("/api/client/heartbeat", json=["not", "an", "object"])

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"ok": False})

    def test_client_heartbeat_rejects_overlong_identity_fields(self):
        client = TestClient(app)

        overlong_license = client.post(
            "/api/client/heartbeat",
            json={"license_id": "L" * 33, "session_id": "session-1", "status": {}},
        )
        overlong_session = client.post(
            "/api/client/heartbeat",
            json={"license_id": "license-1", "session_id": "S" * 65, "status": {}},
        )
        valid = client.post(
            "/api/client/heartbeat",
            json={"license_id": "license-1", "session_id": "session-1", "status": {}},
        )

        self.assertEqual(overlong_license.status_code, 400)
        self.assertEqual(overlong_license.json(), {"ok": False})
        self.assertEqual(overlong_session.status_code, 400)
        self.assertEqual(overlong_session.json(), {"ok": False})
        self.assertEqual(valid.status_code, 200)
        self.assertTrue(valid.json()["ok"])

    def test_batch_delete_log_sessions_removes_db_rows_and_files(self):
        storage_root = Path(config.LOG_STORAGE_PATH)
        storage_root.mkdir(parents=True, exist_ok=True)
        first_file = storage_root / "one.zip"
        second_file = storage_root / "two.zip"
        first_file.write_bytes(b"one")
        second_file.write_bytes(b"two")
        conn = get_connection()
        try:
            s1 = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "s1"),
            ).lastrowid
            s2 = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "s2"),
            ).lastrowid
            conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (s1, "bug_report_zip", "one.zip", 3, str(first_file)),
            )
            conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (s2, "bug_report_zip", "two.zip", 3, str(second_file)),
            )
            conn.commit()
        finally:
            conn.close()

        client = self.admin_client()
        response = self.admin_post(
            client,
            "/admin/logs/delete-sessions",
            {"session_ids": [str(s1), str(s2)]},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertFalse(first_file.exists())
        self.assertFalse(second_file.exists())
        conn = get_connection()
        try:
            session_count = conn.execute("SELECT COUNT(*) FROM log_sessions").fetchone()[0]
            file_count = conn.execute("SELECT COUNT(*) FROM log_files").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)
        self.assertEqual(file_count, 0)

    def test_batch_delete_log_sessions_bounds_overlong_audit_reason(self):
        storage_root = Path(config.LOG_STORAGE_PATH)
        storage_root.mkdir(parents=True, exist_ok=True)
        log_file = storage_root / "audit-reason.zip"
        log_file.write_bytes(b"reason")
        conn = get_connection()
        try:
            session_id = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "audit-reason-session"),
            ).lastrowid
            conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (session_id, "bug_report_zip", "audit-reason.zip", 6, str(log_file)),
            )
            conn.commit()
        finally:
            conn.close()
        reason = "admin bulk delete sessions " + ("r" * 620)
        expected_reason = reason[:500]

        client = self.admin_client()
        response = self.admin_post(
            client,
            "/admin/logs/delete-sessions",
            {"session_ids": [str(session_id)], "reason": reason},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        conn = get_connection()
        try:
            audit = conn.execute(
                "SELECT reason FROM admin_audit WHERE action = 'log_session.bulk_delete' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(audit["reason"], expected_reason)

    def test_download_selected_log_sessions_as_zip(self):
        storage_root = Path(config.LOG_STORAGE_PATH)
        storage_root.mkdir(parents=True, exist_ok=True)
        first_file = storage_root / "one.zip"
        second_file = storage_root / "two.zip"
        first_file.write_bytes(b"one")
        second_file.write_bytes(b"two")
        conn = get_connection()
        try:
            s1 = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "session-one"),
            ).lastrowid
            s2 = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "session-two"),
            ).lastrowid
            conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (s1, "bug_report_zip", "one.zip", 3, str(first_file)),
            )
            conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (s2, "bug_report_zip", "two.zip", 3, str(second_file)),
            )
            conn.commit()
        finally:
            conn.close()

        client = self.admin_client()
        response = self.admin_post(
            client,
            "/admin/logs/download-sessions",
            {"session_ids": [str(s1), str(s2)]},
        )
        self.assertEqual(response.status_code, 200, response.text)
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            names = sorted(zf.namelist())
            self.assertIn("session-one/one.zip", names)
            self.assertIn("session-two/two.zip", names)

    def test_log_downloads_ignore_storage_paths_outside_log_root(self):
        storage_root = Path(config.LOG_STORAGE_PATH)
        storage_root.mkdir(parents=True, exist_ok=True)
        outside_file = self.root / "outside-secret.txt"
        outside_file.write_text("outside secret", encoding="utf-8")
        conn = get_connection()
        try:
            session_id = conn.execute(
                "INSERT INTO log_sessions (user_id, session_id, upload_count) VALUES (?, ?, 1)",
                (self.user_id, "outside-session"),
            ).lastrowid
            file_id = conn.execute(
                "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path) VALUES (?, ?, ?, ?, ?)",
                (session_id, "txt", "outside-secret.txt", outside_file.stat().st_size, str(outside_file)),
            ).lastrowid
            conn.commit()
        finally:
            conn.close()

        client = self.admin_client()
        single = client.get(f"/admin/logs/files/{file_id}/download", follow_redirects=False)
        self.assertEqual(single.status_code, 303, single.text)

        archive = self.admin_post(
            client,
            "/admin/logs/download-sessions",
            {"session_ids": [str(session_id)]},
        )
        self.assertEqual(archive.status_code, 200, archive.text)
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
            self.assertEqual(zf.namelist(), ["README.txt"])

    def test_usage_records_page_shows_profile_and_private_ip_location(self):
        profile = {
            "os": {"system": "Windows", "release": "11", "machine": "AMD64"},
            "cpu": {"name": "Ryzen Test"},
            "memory": {"total_bytes": 16 * 1024 * 1024 * 1024},
            "gpus": [{"name": "NVIDIA RTX Test"}],
            "dependencies": {"python": "3.11", "onnxruntime": "1.22.0"},
        }
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO time_sessions "
                "(user_id, machine_code, client_version, device_profile, ip_address, started_at, last_heartbeat_at, seconds_consumed, status) "
                "VALUES (?, ?, ?, ?, ?, datetime('now', '-10 minutes'), datetime('now'), 600, 'ended')",
                (self.user_id, "MACHINE-1", "v-test", json.dumps(profile), "127.0.0.1"),
            )
            conn.commit()
        finally:
            conn.close()
        response = self.admin_client().get("/admin/usage-records")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Ryzen Test", response.text)
        self.assertIn("NVIDIA RTX Test", response.text)
        self.assertIn("内网/本机", response.text)

    def test_admin_adjust_time_rejects_missing_user_and_oversized_delta(self):
        client = self.admin_client()

        missing_user = self.admin_post(
            client,
            "/admin/users/adjust-time",
            {"user_id": "9999", "delta_seconds": "60", "reason": "missing user"},
            follow_redirects=False,
        )
        oversized = self.admin_post(
            client,
            "/admin/users/adjust-time",
            {"user_id": str(self.user_id), "delta_seconds": str(10 * 365 * 24 * 3600 + 1), "reason": "oversized"},
            follow_redirects=False,
        )
        valid = self.admin_post(
            client,
            "/admin/users/adjust-time",
            {"user_id": str(self.user_id), "delta_seconds": "60", "reason": "valid"},
            follow_redirects=False,
        )

        self.assertEqual(missing_user.status_code, 303)
        self.assertEqual(oversized.status_code, 303)
        self.assertEqual(valid.status_code, 303)
        conn = get_connection()
        try:
            missing_balance = conn.execute("SELECT COUNT(*) FROM time_balance WHERE user_id = 9999").fetchone()[0]
            balance = conn.execute(
                "SELECT balance_seconds, total_recharged_seconds FROM time_balance WHERE user_id = ?",
                (self.user_id,),
            ).fetchone()
            recharge_rows = conn.execute("SELECT user_id, seconds FROM time_recharges ORDER BY id").fetchall()
            audit_actions = conn.execute("SELECT action, target_id FROM admin_audit ORDER BY id").fetchall()
        finally:
            conn.close()

        self.assertEqual(missing_balance, 0)
        self.assertEqual(balance["balance_seconds"], 60)
        self.assertEqual(balance["total_recharged_seconds"], 60)
        self.assertEqual([(row["user_id"], row["seconds"]) for row in recharge_rows], [(self.user_id, 60)])
        self.assertEqual([(row["action"], row["target_id"]) for row in audit_actions], [("user.adjust_time", str(self.user_id))])

    def test_admin_adjust_time_rejects_result_balance_out_of_range(self):
        max_balance_seconds = 10 * 365 * 24 * 3600
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO time_balance (user_id, balance_seconds, total_recharged_seconds) VALUES (?, ?, ?)",
                (self.user_id, max_balance_seconds - 30, max_balance_seconds - 30),
            )
            conn.commit()
        finally:
            conn.close()
        client = self.admin_client()

        overflow = self.admin_post(
            client,
            "/admin/users/adjust-time",
            {"user_id": str(self.user_id), "delta_seconds": "60", "reason": "overflow"},
            follow_redirects=False,
        )
        underflow = self.admin_post(
            client,
            "/admin/users/adjust-time",
            {"user_id": str(self.user_id), "delta_seconds": str(-max_balance_seconds), "reason": "underflow"},
            follow_redirects=False,
        )

        self.assertEqual(overflow.status_code, 303)
        self.assertEqual(underflow.status_code, 303)
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

    def test_purchase_abandon_keeps_waiting_and_preserves_late_payment(self):
        plan = PLAN_BY_KEY["1h"]
        conn = get_connection()
        try:
            order_id, _ = create_order_record(conn, self.user_id, plan.key, plan.price, "127.0.0.1", "vmq")
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, order_id, status, expires_at) "
                "VALUES (?, ?, ?, 'pending', datetime('now', '+15 minutes'))",
                ("tok-close", self.user_id, order_id),
            )
            conn.commit()
        finally:
            conn.close()

        response = TestClient(app).post("/client/purchase/tok-close/abandon")
        self.assertEqual(response.status_code, 200, response.text)
        conn = get_connection()
        try:
            order = conn.execute("SELECT status, amount FROM orders WHERE id = ?", (order_id,)).fetchone()
            order_status = order["status"]
            order_amount = float(order["amount"])
            session_status = conn.execute("SELECT status FROM purchase_sessions WHERE token = ?", ("tok-close",)).fetchone()["status"]
        finally:
            conn.close()
        self.assertEqual(order_status, "pending")
        self.assertEqual(session_status, "pending")

        token = create_access_token(self.user_id, False)
        status = TestClient(app).get(
            "/api/client/purchase-status/tok-close",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(status.json()["status"], "pending")

        delivered = process_payment_event(
            "vmq",
            "vmq:late-payment:1",
            order_amount,
            {"price": f"{order_amount:.2f}", "trade_no": "LATE-1"},
        )
        self.assertEqual(delivered["status"], "delivered")
        final_status = TestClient(app).get(
            "/api/client/purchase-status/tok-close",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(final_status.json()["status"], "delivered")

    def test_payment_qr_admin_shows_safe_exception_summary_without_raw_payload(self):
        result = process_payment_event(
            "vmq",
            "vmq:admin-exception:1",
            PLAN_BY_KEY["1h"].price,
            {
                "payment_method": "wechat",
                "trade_no": "UNMATCHED-1",
                "private_marker": "must-not-be-rendered",
            },
        )
        self.assertEqual(result["status"], "unmatched")

        response = self.admin_client().get("/admin/payment-qr")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("最近异常支付事件", response.text)
        self.assertIn("unmatched", response.text)
        self.assertNotIn("must-not-be-rendered", response.text)


if __name__ == "__main__":
    unittest.main()
