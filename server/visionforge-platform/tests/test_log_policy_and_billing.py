import io
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-log-policy-32")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.routes.time_api import (
    DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
    HEARTBEAT_INTERVAL,
    MAX_DEVICE_PROFILE_JSON_LENGTH,
    MAX_INTEGRITY_FILES_JSON_LENGTH,
    _device_profile_json,
    _integrity_files_json,
)
from app.security import create_access_token, hash_password
from app.services import email_service
from app.services.auth_session_service import LOGIN_DEVICE_MISMATCH, establish_login_locked, validate_login_context_locked
from app.services.lease_service import (
    MAX_CLIENT_VERSION_LENGTH,
    MIN_LEASE_TTL_SECONDS,
    decode_runtime_lease_unverified,
    sign_runtime_lease,
    verify_runtime_lease,
)
from app.services.log_service import log_upload_policy, store_log_file, update_user_log_upload_policy


class LogPolicyAndBillingTests(unittest.TestCase):
    RUNTIME_INSTANCE_A = "runtime-instance-a"
    RUNTIME_INSTANCE_B = "runtime-instance-b"

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.LOG_STORAGE_PATH = str(Path(self.tmpdir.name) / "log_storage")
        config.ALLOW_INSECURE_RUNTIME_LEASE_HMAC = True
        config.REQUIRE_RUNTIME_INSTANCE_ID = True
        init_db()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_large_runtime_json_payloads_remain_valid_after_bounding(self):
        profile_json = _device_profile_json(
            {
                "device_code": "DEV-LARGE",
                "client_version": "v-test",
                "blob": "x" * (MAX_DEVICE_PROFILE_JSON_LENGTH + 1000),
            }
        )
        profile = json.loads(profile_json)

        self.assertLessEqual(len(profile_json), MAX_DEVICE_PROFILE_JSON_LENGTH)
        self.assertTrue(profile["truncated"])
        self.assertEqual(profile["device_code"], "DEV-LARGE")
        self.assertEqual(profile["client_version"], "v-test")

        files_json = _integrity_files_json(
            [
                {"path": "app_gui.py", "sha256": "a" * 64},
                {"path": "huge.bin", "sha256": "b" * 64, "blob": "y" * MAX_INTEGRITY_FILES_JSON_LENGTH},
            ]
        )
        files = json.loads(files_json)

        self.assertLessEqual(len(files_json), MAX_INTEGRITY_FILES_JSON_LENGTH)
        self.assertEqual(files, [{"path": "app_gui.py", "sha256": "a" * 64}])

    def create_user(self, balance_seconds=120, username="u1", password_hash="hash"):
        conn = get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, f"{username}@example.test", password_hash),
            )
            uid = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO time_balance (user_id, balance_seconds, total_recharged_seconds) VALUES (?, ?, ?)",
                (uid, balance_seconds, balance_seconds),
            )
            conn.commit()
            return uid
        finally:
            conn.close()

    def create_login_user(self, balance_seconds=120, username="billing-user", password="BillingPassword1"):
        uid = self.create_user(
            balance_seconds=balance_seconds,
            username=username,
            password_hash=hash_password(password),
        )
        return uid, username, password

    def login(self, client, username, password, device_code):
        response = client.post(
            "/api/client/login",
            json={
                "username": username,
                "password": password,
                "device_code": device_code,
                "client_version": "v-test",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        token = str(response.json().get("token") or "")
        self.assertTrue(token)
        return token

    def start_session(self, client, token, device_code, runtime_instance_id=None):
        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": device_code,
                "client_version": "v-test",
                "runtime_instance_id": runtime_instance_id or self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_signed_release_floor_blocks_old_client_before_billing(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app)
        token = self.login(client, username, password, "DEV-OLD")
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO releases "
                "(version, channel, min_supported_version, mandatory, "
                "published, payload_b64) VALUES (?, 'stable', ?, 1, 1, ?)",
                ("v20.0.0", "v20.0.0", "signed-payload"),
            )
            conn.commit()
        finally:
            conn.close()

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-OLD",
                "client_version": "v19.9.9",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertEqual(response.status_code, 426, response.text)
        self.assertEqual(response.json()["error"], "client_update_required")
        self.assertEqual(response.json()["minimum_supported_version"], "v20.0.0")
        self.assertEqual(self.balance_snapshot(uid), (120, 0))

    def test_heartbeat_cannot_self_report_new_version_to_cross_release_floor(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app)
        token = self.login(client, username, password, "DEV-SPOOF")
        started = self.start_session(client, token, "DEV-SPOOF")
        billed_after_start = self.balance_snapshot(uid)
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO releases "
                "(version, channel, min_supported_version, mandatory, "
                "published, payload_b64) VALUES (?, 'stable', ?, 1, 1, ?)",
                ("v20.0.0", "v20.0.0", "signed-payload"),
            )
            conn.commit()
        finally:
            conn.close()

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=self.heartbeat_body(
                started,
                "DEV-SPOOF",
                client_version="v20.0.0",
            ),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "client_version_mismatch")
        self.assertEqual(self.balance_snapshot(uid), billed_after_start)
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT client_version, status, ended_reason FROM time_sessions "
                "WHERE id = ?",
                (started.json()["session_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["client_version"], "v-test")
        self.assertEqual(row["status"], "ended")
        self.assertEqual(row["ended_reason"], "client_version_mismatch")

    def heartbeat_body(self, lease_response, device_code, **overrides):
        lease = lease_response.json()
        body = {
            "session_id": lease["session_id"],
            "device_code": device_code,
            "client_version": "v-test",
            "lease_token": lease["lease_token"],
            "runtime_instance_id": lease.get("runtime_instance_id") or self.RUNTIME_INSTANCE_A,
        }
        body.update(overrides)
        return body

    def balance_snapshot(self, uid):
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT balance_seconds, total_consumed_seconds FROM time_balance WHERE user_id = ?",
                (uid,),
            ).fetchone()
            return int(row["balance_seconds"]), int(row["total_consumed_seconds"])
        finally:
            conn.close()

    def expire_runtime_handoff(self, uid):
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE users SET runtime_blocked_until_epoch = "
                "CAST(strftime('%s', 'now') AS INTEGER) - 1 WHERE id = ?",
                (uid,),
            )
            conn.commit()
        finally:
            conn.close()

    def create_device_token(self, uid, device_code):
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            login = establish_login_locked(conn, uid, device_code)
            conn.commit()
        finally:
            conn.close()
        return create_access_token(
            uid,
            False,
            login.auth_version,
            device_code=device_code,
            login_instance_id=login.login_instance_id,
        )

    def test_user_log_policy_overrides_global_interval(self):
        uid = self.create_user()
        conn = get_connection()
        try:
            self.assertEqual(log_upload_policy(conn, uid)["interval_seconds"], 3600)
            update_user_log_upload_policy(conn, uid, 1, 900)
            conn.commit()
            policy = log_upload_policy(conn, uid)
        finally:
            conn.close()
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["interval_seconds"], 900)
        self.assertTrue(policy["bundle_mode"])

    def test_store_zip_log_bundle_records_user_device_ip_and_hash(self):
        uid = self.create_user()
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.txt", "ok")
        meta = store_log_file(
            "session-a",
            "bug_report_zip",
            "bundle.zip",
            payload.getvalue(),
            user_id=uid,
            machine_info={
                "device_profile": {"device_code": "DEV-1", "client_version": "v1"},
                "reason": "scheduled",
            },
            ip_address="127.0.0.1",
            metadata={"reason": "scheduled"},
        )
        self.assertEqual(meta["file_type"], "bug_report_zip")
        self.assertEqual(len(meta["sha256"]), 64)
        conn = get_connection()
        try:
            session = conn.execute("SELECT * FROM log_sessions WHERE session_id = ?", ("session-a",)).fetchone()
            file_row = conn.execute("SELECT * FROM log_files WHERE session_id = ?", (session["id"],)).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["user_id"], uid)
        self.assertEqual(session["device_code"], "DEV-1")
        self.assertEqual(session["client_version"], "v1")
        self.assertEqual(session["ip_address"], "127.0.0.1")
        self.assertEqual(session["upload_count"], 1)
        self.assertEqual(file_row["sha256"], meta["sha256"])

    def test_store_log_file_preserves_long_machine_metadata_without_truncation(self):
        uid = self.create_user()
        device_code = "D" * 160
        client_version = "v" * 90
        reason = "scheduled-" + ("r" * 140)
        original_name = "bundle-" + ("n" * 280) + ".zip"

        meta = store_log_file(
            "long-metadata-session",
            "bug_report_zip",
            original_name,
            b"plain log bytes",
            user_id=uid,
            machine_info={
                "device_profile": {"device_code": device_code, "client_version": client_version},
                "reason": "machine-reason",
            },
            metadata={"reason": reason},
        )

        self.assertEqual(meta["original_name"], original_name)
        conn = get_connection()
        try:
            session = conn.execute(
                "SELECT * FROM log_sessions WHERE session_id = ?",
                ("long-metadata-session",),
            ).fetchone()
            file_row = conn.execute("SELECT * FROM log_files WHERE session_id = ?", (session["id"],)).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["device_code"], device_code)
        self.assertEqual(session["client_version"], client_version)
        self.assertEqual(session["latest_bundle_reason"], reason)
        self.assertEqual(file_row["original_name"], original_name)

    def test_client_log_bundle_endpoint_accepts_authenticated_zip(self):
        uid = self.create_user()
        token = create_access_token(uid, False)
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("logs/events.jsonl", "{}\n")
        client = TestClient(app)
        response = client.post(
            "/api/client/log-bundles",
            headers={"Authorization": f"Bearer {token}"},
            data={
                "client_id": "DEV-HTTP",
                "session_id": "http-session",
                "machine_info": '{"device_profile":{"device_code":"DEV-HTTP","client_version":"v-http"}}',
                "reason": "scheduled",
            },
            files={"file": ("bug-report.zip", payload.getvalue(), "application/zip")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["ok"])
        conn = get_connection()
        try:
            session = conn.execute("SELECT * FROM log_sessions WHERE session_id = ?", ("http-session",)).fetchone()
            file_row = conn.execute("SELECT * FROM log_files WHERE session_id = ?", (session["id"],)).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["user_id"], uid)
        self.assertEqual(session["device_code"], "DEV-HTTP")
        self.assertEqual(file_row["file_type"], "bug_report_zip")
        self.assertEqual(len(file_row["sha256"]), 64)

    def test_same_session_name_is_isolated_between_users(self):
        first_user = self.create_user(username="owner-a")
        second_user = self.create_user(username="owner-b")

        first = store_log_file("shared-session", "txt", "a.txt", b"owner-a", user_id=first_user)
        second = store_log_file("shared-session", "txt", "b.txt", b"owner-b", user_id=second_user)

        self.assertNotEqual(first["session_db_id"], second["session_db_id"])
        conn = get_connection()
        try:
            sessions = conn.execute(
                "SELECT user_id FROM log_sessions WHERE session_id = ? ORDER BY user_id",
                ("shared-session",),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual([row["user_id"] for row in sessions], [first_user, second_user])

    def test_retried_identical_bundle_is_idempotent(self):
        user_id = self.create_user()
        payload = b"same-upload"

        first = store_log_file("retry-session", "bug_report_zip", "bundle.zip", payload, user_id=user_id)
        second = store_log_file("retry-session", "bug_report_zip", "bundle.zip", payload, user_id=user_id)

        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["file_id"], second["file_id"])
        conn = get_connection()
        try:
            file_count = conn.execute("SELECT COUNT(*) FROM log_files").fetchone()[0]
            upload_count = conn.execute(
                "SELECT upload_count FROM log_sessions WHERE user_id = ? AND session_id = ?",
                (user_id, "retry-session"),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(file_count, 1)
        self.assertEqual(upload_count, 1)

    def test_storage_failure_rolls_back_database_and_final_file(self):
        user_id = self.create_user()
        conn = get_connection()
        try:
            conn.execute(
                "CREATE TRIGGER reject_log_file BEFORE INSERT ON log_files "
                "BEGIN SELECT RAISE(ABORT, 'forced failure'); END"
            )
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(Exception):
            store_log_file("failed-session", "txt", "failed.txt", b"content", user_id=user_id)

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM log_sessions WHERE session_id = 'failed-session'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM log_files").fetchone()[0], 0)
        finally:
            conn.close()
        self.assertEqual(list(Path(config.LOG_STORAGE_PATH).glob("*")), [])

    def test_legacy_log_upload_requires_authentication(self):
        client = TestClient(app)
        response = client.post(
            "/api/logs/upload",
            data={"session_id": "legacy", "file_type": "txt"},
            files={"file": ("legacy.txt", b"hello", "text/plain")},
        )

        self.assertEqual(response.status_code, 401)

    def test_crash_report_rejects_overlong_identity_fields(self):
        user_id = self.create_user()
        token = create_access_token(user_id, False)
        client = TestClient(app)

        overlong_session = client.post(
            "/api/logs/crash",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "S" * 65, "crash_type": "handled", "crash_data": "boom"},
        )
        overlong_crash_type = client.post(
            "/api/logs/crash",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "session-a", "crash_type": "C" * 33, "crash_data": "boom"},
        )
        valid = client.post(
            "/api/logs/crash",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "session-a", "crash_type": "handled", "crash_data": "boom"},
        )

        self.assertEqual(overlong_session.status_code, 400)
        self.assertEqual(overlong_session.json(), {"ok": False, "message": "Invalid crash report fields"})
        self.assertEqual(overlong_crash_type.status_code, 400)
        self.assertEqual(overlong_crash_type.json(), {"ok": False, "message": "Invalid crash report fields"})
        self.assertEqual(valid.status_code, 200, valid.text)
        conn = get_connection()
        try:
            sessions = conn.execute("SELECT session_id FROM log_sessions").fetchall()
            files = conn.execute("SELECT original_name, file_type FROM log_files").fetchall()
        finally:
            conn.close()
        self.assertEqual([row["session_id"] for row in sessions], ["session-a"])
        self.assertEqual([(row["original_name"], row["file_type"]) for row in files], [("crash_handled.json", "crash")])

    def test_bundle_rejects_parent_path_entries(self):
        user_id = self.create_user()
        token = create_access_token(user_id, False)
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.txt", "unsafe")

        response = TestClient(app).post(
            "/api/client/log-bundles",
            headers={"Authorization": f"Bearer {token}"},
            data={"session_id": "unsafe-session"},
            files={"file": ("unsafe.zip", payload.getvalue(), "application/zip")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("unsafe path", response.json()["error"])

    def test_copied_login_token_cannot_start_session_on_another_device(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("copied-token-client", 50001))
        token = self.login(client, username, password, "DEV-A")
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-B",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "login_device_mismatch")
        self.assertFalse(response.json().get("lease_token"))
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_overlong_device_code_cannot_match_by_shared_prefix(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("device-prefix-client", 50117))
        device_prefix = "D" * 128
        token = self.login(client, username, password, device_prefix)
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": device_prefix + "X",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"], "invalid_device_code")
        self.assertFalse(response.json().get("lease_token"))
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_auth_service_rejects_overlong_device_codes_without_truncation(self):
        uid = self.create_user(balance_seconds=120, username="service-device")
        device_prefix = "D" * 128
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            login = establish_login_locked(conn, uid, device_prefix)
            payload = {
                "sub": str(uid),
                "av": login.auth_version,
                "did": device_prefix,
                "lid": login.login_instance_id,
            }
            valid_context, valid_error = validate_login_context_locked(
                conn,
                payload,
                request_device_code=device_prefix,
                require_device=True,
            )
            overlong_context, overlong_error = validate_login_context_locked(
                conn,
                payload,
                request_device_code=device_prefix + "X",
                require_device=True,
            )
            with self.assertRaises(ValueError):
                establish_login_locked(conn, uid, device_prefix + "X")
            conn.rollback()
        finally:
            conn.close()

        self.assertIsNotNone(valid_context)
        self.assertEqual(valid_error, "")
        self.assertIsNone(overlong_context)
        self.assertEqual(overlong_error, LOGIN_DEVICE_MISMATCH)

    def test_auth_service_rejects_soft_deleted_user_with_legacy_active_status(self):
        uid = self.create_user(balance_seconds=120, username="deleted-service-user")
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (uid,),
            )
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            context, error = validate_login_context_locked(
                conn,
                {"sub": str(uid), "av": 0, "did": "DEV-A", "lid": ""},
                request_device_code="DEV-A",
                require_device=True,
            )
            with self.assertRaises(LookupError):
                establish_login_locked(conn, uid, "DEV-A")
            conn.rollback()
        finally:
            conn.close()

        self.assertIsNone(context)
        self.assertEqual(error, "account_disabled")

    def test_heartbeat_requires_session_id_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("missing-session-client", 50002))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(client, token, "DEV-A")
        before = self.balance_snapshot(uid)
        body = self.heartbeat_body(started, "DEV-A")
        body.pop("session_id")

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )

        self.assertTrue(started.json().get("session_id"))
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"], "missing_session_id")
        self.assertFalse(response.json().get("lease_token"))
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_heartbeat_rejects_wrong_session_id_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("wrong-session-client", 50003))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(client, token, "DEV-A")
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=self.heartbeat_body(
                started,
                "DEV-A",
                session_id=int(started.json()["session_id"]) + 1000,
            ),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "session_superseded")
        self.assertFalse(response.json().get("lease_token"))
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_heartbeat_rejects_wrong_device_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("wrong-device-client", 50004))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(client, token, "DEV-A")
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=self.heartbeat_body(started, "DEV-B"),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn(
            response.json()["error"],
            {"login_device_mismatch", "session_device_mismatch"},
        )
        self.assertFalse(response.json().get("lease_token"))
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_heartbeat_requires_runtime_lease_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("missing-lease-client", 50007))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(client, token, "DEV-A")
        before = self.balance_snapshot(uid)
        body = self.heartbeat_body(started, "DEV-A")
        body.pop("lease_token")

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "missing_runtime_lease")
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_heartbeat_rejects_forged_runtime_lease_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("forged-lease-client", 50008))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(client, token, "DEV-A")
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=self.heartbeat_body(
                started,
                "DEV-A",
                lease_token="forged-runtime-lease",
            ),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "invalid_runtime_lease")
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_heartbeat_rejects_wrong_runtime_instance_without_charging(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("wrong-runtime-heartbeat", 50010))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(
            client,
            token,
            "DEV-A",
            runtime_instance_id=self.RUNTIME_INSTANCE_A,
        )
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=self.heartbeat_body(
                started,
                "DEV-A",
                runtime_instance_id=self.RUNTIME_INSTANCE_B,
            ),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "runtime_instance_mismatch")
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_overlong_runtime_instance_id_is_not_truncated_to_valid_prefix(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("runtime-overlong-prefix", 50012))
        token = self.login(client, username, password, "DEV-A")
        exact_runtime_id = "R" * 128
        overlong_runtime_id = f"{exact_runtime_id}X"

        accepted = self.start_session(
            client,
            token,
            "DEV-A",
            runtime_instance_id=exact_runtime_id,
        )
        rejected = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": overlong_runtime_id,
            },
        )

        self.assertEqual(accepted.json()["runtime_instance_id"], exact_runtime_id)
        self.assertEqual(rejected.status_code, 426, rejected.text)
        self.assertEqual(rejected.json()["error"], "client_upgrade_required")
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT runtime_instance_id FROM time_sessions WHERE user_id = ? ORDER BY id",
                (uid,),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual([row["runtime_instance_id"] for row in rows], [exact_runtime_id])

    def test_session_end_rejects_wrong_runtime_instance_and_keeps_session_active(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        client = TestClient(app, client=("wrong-runtime-end", 50011))
        token = self.login(client, username, password, "DEV-A")
        started = self.start_session(
            client,
            token,
            "DEV-A",
            runtime_instance_id=self.RUNTIME_INSTANCE_A,
        )
        before = self.balance_snapshot(uid)

        response = client.post(
            "/api/client/session-end",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "session_id": started.json()["session_id"],
                "device_code": "DEV-A",
                "runtime_instance_id": self.RUNTIME_INSTANCE_B,
            },
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "runtime_instance_mismatch")
        self.assertEqual(self.balance_snapshot(uid), before)
        conn = get_connection()
        try:
            status = conn.execute(
                "SELECT status FROM time_sessions WHERE id = ?",
                (started.json()["session_id"],),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(status, "active")

    def test_old_session_end_without_id_cannot_end_new_session(self):
        uid, username, password = self.create_login_user(balance_seconds=120)
        first_client = TestClient(app, client=("old-session-client", 50005))
        second_client = TestClient(app, client=("new-session-client", 50006))
        first_token = self.login(first_client, username, password, "DEV-A")
        first = self.start_session(first_client, first_token, "DEV-A")
        second_token = self.login(second_client, username, password, "DEV-B")
        self.expire_runtime_handoff(uid)
        second = self.start_session(
            second_client,
            second_token,
            "DEV-B",
            runtime_instance_id=self.RUNTIME_INSTANCE_B,
        )
        before = self.balance_snapshot(uid)

        stale_end = first_client.post(
            "/api/client/session-end",
            headers={"Authorization": f"Bearer {first_token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertNotEqual(stale_end.status_code, 200, stale_end.text)
        conn = get_connection()
        try:
            first_row = conn.execute(
                "SELECT status FROM time_sessions WHERE id = ?",
                (first.json()["session_id"],),
            ).fetchone()
            second_row = conn.execute(
                "SELECT status FROM time_sessions WHERE id = ?",
                (second.json()["session_id"],),
            ).fetchone()
            active_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ? AND status = 'active'",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertNotEqual(first_row["status"], "active")
        self.assertEqual(second_row["status"], "active")
        self.assertEqual(active_count, 1)
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_session_start_charges_full_initial_lease_window(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-2")
        client = TestClient(app, client=("start-charge-client", 50100))
        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-2",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
                "device_profile": {"device_code": "DEV-2", "client_version": "v-test"},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json()["billing_capabilities"]["heartbeat_idempotency"],
            "v1",
        )
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["deducted"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(data["balance_seconds"], 120 - MIN_LEASE_TTL_SECONDS)
        conn = get_connection()
        try:
            balance = conn.execute("SELECT balance_seconds, total_consumed_seconds FROM time_balance WHERE user_id = ?", (uid,)).fetchone()
            session = conn.execute("SELECT * FROM time_sessions WHERE user_id = ?", (uid,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(balance["balance_seconds"], 120 - MIN_LEASE_TTL_SECONDS)
        self.assertEqual(balance["total_consumed_seconds"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(session["seconds_consumed"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(session["machine_code"], "DEV-2")
        self.assertEqual(session["client_version"], "v-test")
        self.assertEqual(session["status"], "active")
        self.assertTrue(data["lease_token"])
        self.assertEqual(data["heartbeat_interval"], HEARTBEAT_INTERVAL)
        self.assertEqual(data["lease_ttl_seconds"], MIN_LEASE_TTL_SECONDS)

    def test_end_blocks_restart_until_prepaid_lease_expires(self):
        uid = self.create_user(balance_seconds=60)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("restart-prepay-client", 50110))
        headers = {"Authorization": f"Bearer {token}"}

        first = self.start_session(client, token, "DEV-A")
        after_first = self.balance_snapshot(uid)
        ended = client.post(
            "/api/client/session-end",
            headers=headers,
            json={
                "session_id": first.json()["session_id"],
                "device_code": "DEV-A",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(ended.status_code, 200, ended.text)
        self.assertEqual(self.balance_snapshot(uid), after_first)

        pending = client.post(
            "/api/client/session-start",
            headers=headers,
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_B,
            },
        )

        self.assertEqual(pending.status_code, 409, pending.text)
        self.assertEqual(pending.json()["error"], "runtime_handoff_pending")
        retry_after = int(pending.headers["Retry-After"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertEqual(pending.json()["retry_after_seconds"], retry_after)
        first_payload = decode_runtime_lease_unverified(first.json()["lease_token"])
        self.assertEqual(pending.json()["runtime_blocked_until_epoch"], first_payload["exp"])
        self.assertEqual(self.balance_snapshot(uid), after_first)

        self.expire_runtime_handoff(uid)
        second = self.start_session(
            client,
            token,
            "DEV-A",
            runtime_instance_id=self.RUNTIME_INSTANCE_B,
        )

        self.assertEqual(first.json()["deducted"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(second.json()["deducted"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(second.json()["balance_seconds"], 60 - (2 * MIN_LEASE_TTL_SECONDS))
        self.assertEqual(
            self.balance_snapshot(uid),
            (60 - (2 * MIN_LEASE_TTL_SECONDS), 2 * MIN_LEASE_TTL_SECONDS),
        )
        conn = get_connection()
        try:
            sessions = conn.execute(
                "SELECT id, seconds_consumed, status FROM time_sessions WHERE user_id = ? ORDER BY id",
                (uid,),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual([row["status"] for row in sessions], ["ended", "active"])
        self.assertEqual(
            [row["seconds_consumed"] for row in sessions],
            [MIN_LEASE_TTL_SECONDS, MIN_LEASE_TTL_SECONDS],
        )

    def test_new_login_invalidates_old_token_and_waits_for_old_runtime_lease(self):
        uid, username, password = self.create_login_user(balance_seconds=60)
        first_client = TestClient(app, client=("handoff-login-a", 50114))
        second_client = TestClient(app, client=("handoff-login-b", 50115))
        first_token = self.login(first_client, username, password, "DEV-A")
        first = self.start_session(
            first_client,
            first_token,
            "DEV-A",
            runtime_instance_id=self.RUNTIME_INSTANCE_A,
        )
        after_first = self.balance_snapshot(uid)

        second_token = self.login(second_client, username, password, "DEV-B")
        old_token_response = first_client.get(
            "/api/client/balance",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        pending = second_client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {second_token}"},
            json={
                "device_code": "DEV-B",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_B,
            },
        )

        self.assertEqual(old_token_response.status_code, 401, old_token_response.text)
        self.assertEqual(pending.status_code, 409, pending.text)
        self.assertEqual(pending.json()["error"], "runtime_handoff_pending")
        retry_after = int(pending.headers["Retry-After"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertEqual(pending.json()["retry_after_seconds"], retry_after)
        self.assertEqual(self.balance_snapshot(uid), after_first)
        conn = get_connection()
        try:
            first_session = conn.execute(
                "SELECT status, ended_reason FROM time_sessions WHERE id = ?",
                (first.json()["session_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(first_session["status"], "ended")
        self.assertEqual(first_session["ended_reason"], "login_superseded")

        self.expire_runtime_handoff(uid)
        second = self.start_session(
            second_client,
            second_token,
            "DEV-B",
            runtime_instance_id=self.RUNTIME_INSTANCE_B,
        )

        self.assertEqual(second.json()["deducted"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(
            self.balance_snapshot(uid),
            (60 - (2 * MIN_LEASE_TTL_SECONDS), 2 * MIN_LEASE_TTL_SECONDS),
        )

    def test_exact_initial_lease_balance_starts_with_zero_and_keeps_valid_lease(self):
        uid = self.create_user(balance_seconds=MIN_LEASE_TTL_SECONDS)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("exact-start-balance-client", 50111))
        headers = {"Authorization": f"Bearer {token}"}

        started = self.start_session(client, token, "DEV-A")
        self.assertEqual(started.json()["deducted"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(started.json()["balance_seconds"], 0)
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT auth_version, login_instance_id FROM users WHERE id = ?",
                (uid,),
            ).fetchone()
        finally:
            conn.close()
        lease_ok, lease_reason, lease_payload = verify_runtime_lease(
            started.json()["lease_token"],
            user_id=uid,
            session_id=started.json()["session_id"],
            auth_version=int(user["auth_version"]),
            device_code="DEV-A",
            login_instance_id=str(user["login_instance_id"]),
            expected_runtime_instance_id=self.RUNTIME_INSTANCE_A,
            expected_client_version="v-test",
            expected_manifest_hash=DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
        )
        self.assertTrue(lease_ok, lease_reason)
        self.assertEqual(lease_payload["ttl"], MIN_LEASE_TTL_SECONDS)

        early_heartbeat = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json=self.heartbeat_body(started, "DEV-A"),
        )

        self.assertEqual(early_heartbeat.status_code, 200, early_heartbeat.text)
        self.assertEqual(early_heartbeat.json()["deducted"], 0)
        self.assertEqual(early_heartbeat.json()["balance_seconds"], 0)
        self.assertEqual(early_heartbeat.json()["lease_token"], started.json()["lease_token"])
        self.assertEqual(early_heartbeat.json()["lease_expires_at"], started.json()["lease_expires_at"])
        self.assertEqual(early_heartbeat.json()["lease_renewal"], "not_due")
        self.assertEqual(self.balance_snapshot(uid), (0, MIN_LEASE_TTL_SECONDS))

        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            heartbeat = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(started, "DEV-A"),
            )

        self.assertEqual(heartbeat.status_code, 402, heartbeat.text)
        self.assertEqual(heartbeat.json()["error"], "insufficient_balance")
        self.assertEqual(heartbeat.json()["balance_seconds"], 0)
        self.assertEqual(heartbeat.json()["lease_expires_at"], started.json()["lease_expires_at"])
        self.assertNotIn("lease_token", heartbeat.json())
        conn = get_connection()
        try:
            session = conn.execute(
                "SELECT seconds_consumed, status, ended_reason FROM time_sessions WHERE id = ?",
                (started.json()["session_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["seconds_consumed"], MIN_LEASE_TTL_SECONDS)
        self.assertEqual(session["status"], "ended")
        self.assertEqual(session["ended_reason"], "insufficient_balance")

    def test_less_than_initial_lease_balance_rejects_start_without_charging(self):
        initial_balance = MIN_LEASE_TTL_SECONDS - 1
        uid = self.create_user(balance_seconds=initial_balance)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("short-start-balance-client", 50112))

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertEqual(response.status_code, 402, response.text)
        self.assertEqual(response.json()["error"], "insufficient_balance")
        self.assertEqual(response.json()["balance_seconds"], initial_balance)
        self.assertNotIn("lease_token", response.json())
        self.assertEqual(self.balance_snapshot(uid), (initial_balance, 0))
        conn = get_connection()
        try:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ?",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)

    def test_strict_runtime_instance_requirement_rejects_legacy_start_without_charging(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("strict-runtime-instance-client", 50118))

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={"device_code": "DEV-A", "client_version": "v-legacy"},
        )

        self.assertEqual(response.status_code, 426, response.text)
        self.assertEqual(response.json()["error"], "client_upgrade_required")
        self.assertEqual(self.balance_snapshot(uid), (120, 0))
        conn = get_connection()
        try:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ?",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)

    def test_v2_rejects_missing_runtime_instance_even_when_legacy_flag_is_disabled(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("compat-runtime-instance-client", 50119))
        headers = {"Authorization": f"Bearer {token}"}

        with patch.object(config, "REQUIRE_RUNTIME_INSTANCE_ID", False):
            response = client.post(
                "/api/client/session-start",
                headers=headers,
                json={"device_code": "DEV-A", "client_version": "v-legacy"},
            )

        self.assertEqual(response.status_code, 426, response.text)
        self.assertEqual(response.json()["error"], "client_upgrade_required")
        self.assertEqual(self.balance_snapshot(uid), (120, 0))

    def test_runtime_signing_failure_rolls_back_initial_charge_and_session(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("runtime-signing-failure-client", 50120))

        with patch.object(config, "ALLOW_INSECURE_RUNTIME_LEASE_HMAC", False), patch(
            "app.services.lease_service._load_private_key_or_none",
            return_value=None,
        ):
            response = client.post(
                "/api/client/session-start",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "device_code": "DEV-A",
                    "client_version": "v-test",
                    "runtime_instance_id": self.RUNTIME_INSTANCE_A,
                },
            )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"], "runtime_lease_signing_unavailable")
        self.assertEqual(self.balance_snapshot(uid), (120, 0))
        conn = get_connection()
        try:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ?",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)

    def test_second_session_start_same_login_is_rejected_without_charging(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("second-start-client", 50101))
        first = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(first.status_code, 200, first.text)
        first_session_id = first.json()["session_id"]
        before = self.balance_snapshot(uid)
        second = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )

        self.assertEqual(second.status_code, 409, second.text)
        self.assertEqual(second.json()["error"], "session_already_active")
        self.assertEqual(second.json()["session_id"], first_session_id)
        self.assertEqual(second.json()["balance_seconds"], before[0])
        self.assertEqual(self.balance_snapshot(uid), before)
        conn = get_connection()
        try:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ? AND status = 'active'",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(active_count, 1)

    def test_no_active_session_reports_real_balance_instead_of_zero(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("no-active-client", 50102))
        headers = {"Authorization": f"Bearer {token}"}
        started = self.start_session(client, token, "DEV-A")
        ended = client.post(
            "/api/client/session-end",
            headers=headers,
            json={
                "session_id": started.json()["session_id"],
                "device_code": "DEV-A",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(ended.status_code, 200, ended.text)

        response = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json=self.heartbeat_body(started, "DEV-A"),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "no_active_session")
        self.assertEqual(response.json()["balance_seconds"], 120 - MIN_LEASE_TTL_SECONDS)

    def test_expired_active_session_is_persisted_as_stale_after_heartbeat(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("expired-session-client", 50103))
        headers = {"Authorization": f"Bearer {token}"}
        started = client.post(
            "/api/client/session-start",
            headers=headers,
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        session_id = started.json()["session_id"]
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_sessions SET last_heartbeat_at = datetime('now', '-120 seconds') WHERE id = ?",
                (session_id,),
            )
            conn.commit()
        finally:
            conn.close()

        response = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json=self.heartbeat_body(started, "DEV-A"),
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "no_active_session")
        conn = get_connection()
        try:
            session = conn.execute(
                "SELECT status, ended_reason FROM time_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["status"], "stale")
        self.assertEqual(session["ended_reason"], "heartbeat_timeout")

    def test_heartbeat_identity_makes_retry_idempotent_and_next_sequence_charge_once(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("heartbeat-idempotency-client", 50104))
        started = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(started.status_code, 200, started.text)
        session_id = started.json()["session_id"]
        headers = {"Authorization": f"Bearer {token}"}
        first_body = self.heartbeat_body(
            started,
            "DEV-A",
            heartbeat_id="heartbeat-a",
            heartbeat_sequence=1,
        )

        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            first = client.post("/api/client/session-heartbeat", headers=headers, json=first_body)
            retry = client.post("/api/client/session-heartbeat", headers=headers, json=first_body)
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + (2 * HEARTBEAT_INTERVAL),
        ):
            second = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(
                    first,
                    "DEV-A",
                    heartbeat_id="heartbeat-b",
                    heartbeat_sequence=2,
                ),
            )

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(first.json(), retry.json())
        self.assertEqual(
            first.json()["balance_seconds"],
            120 - MIN_LEASE_TTL_SECONDS - HEARTBEAT_INTERVAL,
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(
            second.json()["balance_seconds"],
            120 - MIN_LEASE_TTL_SECONDS - (2 * HEARTBEAT_INTERVAL),
        )
        conn = get_connection()
        try:
            balance = conn.execute(
                "SELECT balance_seconds, total_consumed_seconds FROM time_balance WHERE user_id = ?",
                (uid,),
            ).fetchone()
            session = conn.execute("SELECT * FROM time_sessions WHERE id = ?", (session_id,)).fetchone()
        finally:
            conn.close()
        expected_consumed = MIN_LEASE_TTL_SECONDS + (2 * HEARTBEAT_INTERVAL)
        self.assertEqual(balance["balance_seconds"], 120 - expected_consumed)
        self.assertEqual(balance["total_consumed_seconds"], expected_consumed)
        self.assertEqual(session["seconds_consumed"], expected_consumed)
        self.assertEqual(session["last_heartbeat_id"], "heartbeat-b")
        self.assertEqual(session["last_heartbeat_sequence"], 2)

    def test_heartbeat_renewals_issue_contiguous_non_overlapping_lease_segments(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("lease-segments-client", 50116))
        headers = {"Authorization": f"Bearer {token}"}
        started = self.start_session(
            client,
            token,
            "DEV-A",
            runtime_instance_id=self.RUNTIME_INSTANCE_A,
        )

        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            first = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(
                    started,
                    "DEV-A",
                    heartbeat_id="lease-segment-one",
                    heartbeat_sequence=1,
                ),
            )
        self.assertEqual(first.status_code, 200, first.text)
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + (2 * HEARTBEAT_INTERVAL),
        ):
            second = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(
                    first,
                    "DEV-A",
                    heartbeat_id="lease-segment-two",
                    heartbeat_sequence=2,
                ),
            )
        self.assertEqual(second.status_code, 200, second.text)

        payloads = [
            decode_runtime_lease_unverified(response.json()["lease_token"])
            for response in (started, first, second)
        ]
        self.assertTrue(all(payload["rid"] == self.RUNTIME_INSTANCE_A for payload in payloads))
        for previous, renewed in zip(payloads, payloads[1:]):
            self.assertEqual(renewed["nbf"], previous["exp"])
            self.assertGreater(renewed["exp"], renewed["nbf"])

    def test_delayed_heartbeat_charges_full_fourteen_second_lease_extension(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("delayed-heartbeat-client", 50113))
        headers = {"Authorization": f"Bearer {token}"}
        started = self.start_session(client, token, "DEV-A")
        session_id = int(started.json()["session_id"])
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT auth_version, login_instance_id FROM users WHERE id = ?",
                (uid,),
            ).fetchone()
        finally:
            conn.close()
        next_lease = sign_runtime_lease(
            user_id=uid,
            session_id=session_id,
            device_code="DEV-A",
            client_version="v-test",
            manifest_hash=DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
            auth_version=int(user["auth_version"]),
            login_instance_id=str(user["login_instance_id"]),
            runtime_instance_id=self.RUNTIME_INSTANCE_A,
            ttl_seconds=MIN_LEASE_TTL_SECONDS,
        )
        previous_expiry_epoch = int(next_lease["lease_payload"]["exp"]) - 14
        previous_expiry = (
            datetime.fromtimestamp(previous_expiry_epoch, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_sessions SET lease_expires_at = ? WHERE id = ?",
                (previous_expiry, session_id),
            )
            conn.commit()
        finally:
            conn.close()

        route_now = int(next_lease["lease_payload"]["exp"]) - MIN_LEASE_TTL_SECONDS
        with (
            patch("app.routes.time_api.time.time", return_value=route_now),
            patch("app.routes.time_api.sign_runtime_lease", return_value=next_lease),
        ):
            heartbeat = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(
                    started,
                    "DEV-A",
                    heartbeat_id="delayed-heartbeat",
                    heartbeat_sequence=1,
                ),
            )

        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        self.assertEqual(heartbeat.json()["deducted"], 14)
        self.assertEqual(heartbeat.json()["balance_seconds"], 120 - MIN_LEASE_TTL_SECONDS - 14)
        self.assertEqual(heartbeat.json()["lease_expires_at"], next_lease["lease_expires_at"])
        expected_consumed = MIN_LEASE_TTL_SECONDS + 14
        self.assertEqual(self.balance_snapshot(uid), (120 - expected_consumed, expected_consumed))
        conn = get_connection()
        try:
            session_consumed = conn.execute(
                "SELECT seconds_consumed FROM time_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_consumed, expected_consumed)

    def test_non_idempotent_heartbeat_cannot_reuse_old_lease_without_charging(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("old-lease-client", 50105))
        headers = {"Authorization": f"Bearer {token}"}
        started = self.start_session(client, token, "DEV-A")
        first_body = self.heartbeat_body(
            started,
            "DEV-A",
            heartbeat_id="heartbeat-a",
            heartbeat_sequence=1,
        )
        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            accepted = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=first_body,
            )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        before = self.balance_snapshot(uid)

        replay = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json={
                **first_body,
                "heartbeat_id": "heartbeat-b",
                "heartbeat_sequence": 2,
            },
        )

        self.assertEqual(replay.status_code, 409, replay.text)
        self.assertEqual(replay.json()["error"], "runtime_lease_superseded")
        self.assertEqual(self.balance_snapshot(uid), before)

    def test_registered_auth_version_zero_can_start_heartbeat_and_end(self):
        email = "registered-av-zero@example.test"
        email_code = "123456"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, 'register')",
                (email, email_service._code_digest(email, email_code, "register")),
            )
            conn.commit()
        finally:
            conn.close()

        client = TestClient(app, client=("registered-av-zero", 50009))
        registered = client.post(
            "/api/client/register",
            json={
                "username": "registered_av_zero",
                "password": "RegisteredPassword1",
                "email": email,
                "email_code": email_code,
                "device_code": "REG-AV0",
                "client_version": "v-test",
            },
        )
        self.assertEqual(registered.status_code, 200, registered.text)
        user_id = int(registered.json()["user_id"])
        token = str(registered.json()["token"])
        headers = {"Authorization": f"Bearer {token}"}

        conn = get_connection()
        try:
            auth_version = conn.execute(
                "SELECT auth_version FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(auth_version, 0)

        started = self.start_session(client, token, "REG-AV0")
        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            heartbeat = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(
                    started,
                    "REG-AV0",
                    heartbeat_id="registered-heartbeat",
                    heartbeat_sequence=1,
                ),
            )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        ended = client.post(
            "/api/client/session-end",
            headers=headers,
            json={
                "session_id": started.json()["session_id"],
                "device_code": "REG-AV0",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(ended.status_code, 200, ended.text)

        initial_balance = int(registered.json()["balance_seconds"])
        expected_consumed = MIN_LEASE_TTL_SECONDS + HEARTBEAT_INTERVAL
        self.assertEqual(
            self.balance_snapshot(user_id),
            (initial_balance - expected_consumed, expected_consumed),
        )
        conn = get_connection()
        try:
            session = conn.execute(
                "SELECT login_auth_version, status, ended_reason FROM time_sessions WHERE id = ?",
                (started.json()["session_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["login_auth_version"], 0)
        self.assertEqual(session["status"], "ended")
        self.assertEqual(session["ended_reason"], "client_session_end")

    def test_heartbeat_rejects_old_sequence_and_same_sequence_with_different_id(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("heartbeat-sequence-client", 50106))
        headers = {"Authorization": f"Bearer {token}"}
        started = client.post(
            "/api/client/session-start",
            headers=headers,
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        accepted_body = self.heartbeat_body(
            started,
            "DEV-A",
            heartbeat_id="heartbeat-two",
            heartbeat_sequence=2,
        )
        accepted = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json=accepted_body,
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)

        old = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json=self.heartbeat_body(
                accepted,
                "DEV-A",
                heartbeat_id="heartbeat-one",
                heartbeat_sequence=1,
            ),
        )
        conflict = client.post(
            "/api/client/session-heartbeat",
            headers=headers,
            json={**accepted_body, "heartbeat_id": "heartbeat-other"},
        )

        self.assertEqual(old.status_code, 409, old.text)
        self.assertEqual(old.json()["error"], "heartbeat_sequence_replayed")
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(conflict.json()["error"], "heartbeat_identity_conflict")

    def test_legacy_heartbeat_without_identity_remains_compatible(self):
        uid = self.create_user(balance_seconds=120)
        token = self.create_device_token(uid, "DEV-A")
        client = TestClient(app, client=("heartbeat-no-identity-client", 50107))
        headers = {"Authorization": f"Bearer {token}"}
        started = client.post(
            "/api/client/session-start",
            headers=headers,
            json={
                "device_code": "DEV-A",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        started_payload = decode_runtime_lease_unverified(started.json()["lease_token"])
        with patch(
            "app.routes.time_api.time.time",
            return_value=int(started_payload["iat"]) + HEARTBEAT_INTERVAL,
        ):
            response = client.post(
                "/api/client/session-heartbeat",
                headers=headers,
                json=self.heartbeat_body(started, "DEV-A"),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json()["balance_seconds"],
            120 - MIN_LEASE_TTL_SECONDS - HEARTBEAT_INTERVAL,
        )

    def test_integrity_enforcement_rejects_missing_manifest(self):
        uid = self.create_user(balance_seconds=120)
        conn = get_connection()
        try:
            conn.execute("UPDATE runtime_security_settings SET enforce_integrity = 1 WHERE id = 1")
            conn.commit()
        finally:
            conn.close()
        token = self.create_device_token(uid, "DEV-X")
        client = TestClient(app, client=("integrity-missing-client", 50108))
        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-X",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
            },
        )
        self.assertEqual(response.status_code, 426, response.text)
        self.assertEqual(response.json()["error"], "client_integrity_rejected")

    def test_production_integrity_rejects_development_or_unallowlisted_manifest_before_signing(self):
        uid = self.create_user(balance_seconds=120)
        exe_hash = "8" * 64
        conn = get_connection()
        try:
            for manifest_hash in (
                "a" * 64,
                DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
            ):
                conn.execute(
                    "INSERT INTO client_integrity_allowlist "
                    "(client_version, manifest_hash, file_hashes_json, enabled, note) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (
                        "v-test",
                        manifest_hash,
                        json.dumps(
                            [
                                {
                                    "path": "@executable",
                                    "role": "executable",
                                    "sha256": exe_hash,
                                }
                            ]
                        ),
                        "production fail-closed regression",
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        token = self.create_device_token(uid, "DEV-PRODUCTION-INTEGRITY")
        client = TestClient(app, client=("production-integrity-client", 50121))
        headers = {"Authorization": f"Bearer {token}"}

        with (
            patch.object(config, "REQUIRE_RUNTIME_INTEGRITY", True),
            patch("app.routes.time_api.sign_runtime_lease") as sign_lease,
        ):
            cases = (
                ("b" * 64, "not_allowlisted"),
                (
                    DEVELOPMENT_UNVERIFIED_MANIFEST_HASH,
                    "development_manifest_forbidden",
                ),
            )
            for manifest_hash, expected_status in cases:
                with self.subTest(manifest_hash=manifest_hash):
                    response = client.post(
                        "/api/client/session-start",
                        headers=headers,
                        json={
                            "device_code": "DEV-PRODUCTION-INTEGRITY",
                            "client_version": "v-test",
                            "runtime_instance_id": self.RUNTIME_INSTANCE_A,
                            "integrity": {
                                "schema": "visionforge-integrity-v2",
                                "manifest_hash": manifest_hash,
                                "executable_sha256": exe_hash,
                                "files": [
                                    {
                                        "path": "@executable",
                                        "role": "executable",
                                        "sha256": exe_hash,
                                    }
                                ],
                            },
                        },
                    )
                    self.assertEqual(response.status_code, 426, response.text)
                    self.assertEqual(
                        response.json()["error"],
                        "client_integrity_rejected",
                    )
                    self.assertEqual(
                        response.json()["integrity_status"],
                        expected_status,
                    )

        sign_lease.assert_not_called()
        self.assertEqual(self.balance_snapshot(uid), (120, 0))
        conn = get_connection()
        try:
            session_count = conn.execute(
                "SELECT COUNT(*) FROM time_sessions WHERE user_id = ?",
                (uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)

    def test_integrity_enforcement_accepts_allowlisted_exe_hash(self):
        uid = self.create_user(balance_seconds=120)
        exe_hash = "8" * 64
        conn = get_connection()
        try:
            conn.execute("UPDATE runtime_security_settings SET enforce_integrity = 1 WHERE id = 1")
            conn.execute(
                "INSERT INTO client_integrity_allowlist "
                "(client_version, manifest_hash, file_hashes_json, enabled, note) VALUES (?, ?, ?, 1, ?)",
                (
                    "v-test",
                    "a" * 64,
                    json.dumps([{"path": "VisionForge.exe", "size": 123, "sha256": exe_hash}]),
                    "official release exe",
                ),
            )
            conn.commit()
        finally:
            conn.close()
        token = self.create_device_token(uid, "DEV-X")
        client = TestClient(app, client=("integrity-allowlisted-client", 50109))
        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-X",
                "client_version": "v-test",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
                "integrity": {
                    "schema": "visionforge-integrity-v1",
                    "manifest_hash": "b" * 64,
                    "files": [{"path": "RenamedVisionForge.exe", "size": 123, "sha256": exe_hash}],
                },
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["runtime_security"]["integrity_status"], "allowlisted_file_hash")
        conn = get_connection()
        try:
            session = conn.execute("SELECT integrity_status FROM time_sessions WHERE user_id = ?", (uid,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(session["integrity_status"], "allowlisted_file_hash")

    def test_overlong_client_version_cannot_match_integrity_allowlist_by_shared_prefix(self):
        uid = self.create_user(balance_seconds=120)
        exe_hash = "9" * 64
        allowlisted_version = "v" * MAX_CLIENT_VERSION_LENGTH
        conn = get_connection()
        try:
            conn.execute("UPDATE runtime_security_settings SET enforce_integrity = 1 WHERE id = 1")
            conn.execute(
                "INSERT INTO client_integrity_allowlist "
                "(client_version, manifest_hash, file_hashes_json, enabled, note) VALUES (?, ?, ?, 1, ?)",
                (
                    allowlisted_version,
                    "a" * 64,
                    json.dumps([{"path": "VisionForge.exe", "size": 123, "sha256": exe_hash}]),
                    "official release exe",
                ),
            )
            conn.commit()
        finally:
            conn.close()
        token = self.create_device_token(uid, "DEV-X")
        client = TestClient(app, client=("integrity-client-version-prefix", 50110))

        response = client.post(
            "/api/client/session-start",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "device_code": "DEV-X",
                "client_version": allowlisted_version + "x",
                "runtime_instance_id": self.RUNTIME_INSTANCE_A,
                "integrity": {
                    "schema": "visionforge-integrity-v1",
                    "manifest_hash": "b" * 64,
                    "files": [{"path": "RenamedVisionForge.exe", "size": 123, "sha256": exe_hash}],
                },
            },
        )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"], "invalid_client_version")
        conn = get_connection()
        try:
            session_count = conn.execute("SELECT COUNT(*) FROM time_sessions WHERE user_id = ?", (uid,)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session_count, 0)


if __name__ == "__main__":
    unittest.main()
