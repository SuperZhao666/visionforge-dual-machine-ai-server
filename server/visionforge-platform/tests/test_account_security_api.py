from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import secrets
import smtplib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-account-security")

from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import config
from app.database import SINGLE_LOGIN_MIGRATION, get_connection, init_db
from app.main import app
from app.security import authenticated_client_rate_key, create_access_token, hash_password, verify_password
from app.services import email_service


class AuthenticatedClientRateKeyTests(unittest.TestCase):
    def test_bearer_rate_key_is_stable_isolated_hashed_and_falls_back_to_ip(self) -> None:
        def request(authorization: str = "") -> Request:
            headers = [(b"authorization", authorization.encode("ascii"))] if authorization else []
            return Request({"type": "http", "headers": headers, "client": ("203.0.113.7", 50000)})

        first_token = "first-secret-bearer-token"
        second_token = "second-secret-bearer-token"
        first_key = authenticated_client_rate_key(request(f"Bearer {first_token}"))
        repeated_key = authenticated_client_rate_key(request(f"Bearer {first_token}"))
        second_key = authenticated_client_rate_key(request(f"Bearer {second_token}"))

        self.assertEqual(first_key, repeated_key)
        self.assertNotEqual(first_key, second_key)
        self.assertTrue(first_key.startswith("bearer:"))
        self.assertNotIn(first_token, first_key)
        self.assertNotIn(second_token, second_key)
        self.assertEqual(authenticated_client_rate_key(request()), "ip:203.0.113.7")


class AccountSecurityApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.LOG_STORAGE_PATH = str(Path(self.tmpdir.name) / "logs")
        init_db()
        self.password = "CurrentPassword1"
        conn = get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("account-user", "old@example.test", hash_password(self.password)),
            )
            self.uid = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO time_balance (user_id, balance_seconds) VALUES (?, ?)",
                (self.uid, 600),
            )
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("other-user", "taken@example.test", hash_password("OtherPassword1")),
            )
            conn.commit()
        finally:
            conn.close()
        self.token = create_access_token(self.uid, False, 0)
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _user_row(self):
        conn = get_connection()
        try:
            return conn.execute(
                "SELECT email, password_hash, auth_version FROM users WHERE id = ?",
                (self.uid,),
            ).fetchone()
        finally:
            conn.close()

    def _insert_code(self, email: str, code: str = "123456") -> None:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, 'change_email')",
                (
                    email_service.normalize_email(email),
                    email_service._code_digest(email, code, "change_email"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def test_account_security_endpoints_require_auth_and_reject_non_object_json(self) -> None:
        for path in (
            "/api/client/account/password",
            "/api/client/account/email-code",
            "/api/client/account/email",
        ):
            response = self.client.post(path, json={})
            self.assertEqual(response.status_code, 401, (path, response.text))
            response = self.client.post(path, headers=self.headers, json=[])
            self.assertEqual(response.status_code, 400, (path, response.text))

    def test_deleted_account_token_is_rejected_even_if_legacy_status_is_active(self) -> None:
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (self.uid,),
            )
            conn.commit()
        finally:
            conn.close()

        response = self.client.get("/api/client/balance", headers=self.headers)

        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json()["error"], "account_disabled")

    def test_public_account_endpoints_reject_non_object_json(self) -> None:
        for path in ("/api/client/register-code", "/api/client/register", "/api/client/login"):
            with self.subTest(path=path):
                response = self.client.post(path, json=["not", "an", "object"])

                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["error"], "invalid json")

    def test_wrong_current_password_keeps_hash_and_token_version(self) -> None:
        before = self._user_row()
        response = self.client.post(
            "/api/client/account/password",
            headers=self.headers,
            json={"current_password": "WrongPassword1", "new_password": "NewPassword2"},
        )
        after = self._user_row()

        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(after["password_hash"], before["password_hash"])
        self.assertEqual(after["auth_version"], 0)

    def test_password_change_invalidates_old_token_and_returns_working_new_token(self) -> None:
        response = self.client.post(
            "/api/client/account/password",
            headers=self.headers,
            json={"current_password": self.password, "new_password": "NewPassword2"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        new_token = response.json().get("token")
        self.assertTrue(new_token)

        old_balance = self.client.get("/api/client/balance", headers=self.headers)
        new_balance = self.client.get(
            "/api/client/balance",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        old_login = self.client.post(
            "/api/client/login",
            json={
                "username": "account-user",
                "password": self.password,
                "device_code": "PASSWORD-OLD",
            },
        )
        new_login = self.client.post(
            "/api/client/login",
            json={
                "username": "account-user",
                "password": "NewPassword2",
                "device_code": "PASSWORD-NEW",
            },
        )

        self.assertEqual(old_balance.status_code, 401, old_balance.text)
        self.assertEqual(new_balance.status_code, 200, new_balance.text)
        self.assertEqual(new_balance.json()["email"], "old@example.test")
        self.assertNotEqual(new_balance.json()["masked_email"], "old@example.test")
        self.assertEqual(old_login.status_code, 401, old_login.text)
        self.assertEqual(new_login.status_code, 200, new_login.text)
        self.assertEqual(new_login.json()["email"], "old@example.test")
        self.assertTrue(new_login.json()["masked_email"])
        row = self._user_row()
        self.assertEqual(row["auth_version"], 2)
        self.assertTrue(verify_password("NewPassword2", row["password_hash"]))

    def test_failed_logins_for_different_usernames_do_not_share_source_rate_limit(self) -> None:
        responses = [
            self.client.post(
                "/api/client/login",
                json={
                    "username": f"unknown-user-{index}",
                    "password": "WrongPassword1",
                    "device_code": f"UNKNOWN-{index}",
                    "client_version": "v-test",
                },
            )
            for index in range(12)
        ]

        self.assertTrue(
            all(response.status_code == 401 for response in responses),
            [(response.status_code, response.text) for response in responses],
        )
        self.assertTrue(all(response.json()["error"] == "用户名或密码错误" for response in responses))

    def test_same_trimmed_username_is_rate_limited_after_ten_failures(self) -> None:
        username_variants = ("account-user", " account-user ", "account-user  ")
        failures = [
            self.client.post(
                "/api/client/login",
                json={
                    "username": username_variants[index % len(username_variants)],
                    "password": "WrongPassword1",
                    "device_code": f"RATE-LIMIT-{index}",
                    "client_version": "v-test",
                },
            )
            for index in range(10)
        ]
        blocked = self.client.post(
            "/api/client/login",
            json={
                "username": " account-user ",
                "password": "WrongPassword1",
                "device_code": "RATE-LIMIT-BLOCKED",
                "client_version": "v-test",
            },
        )

        self.assertTrue(all(response.status_code == 401 for response in failures))
        self.assertEqual(blocked.status_code, 429, blocked.text)
        self.assertEqual(blocked.json()["error"], "login_rate_limited")
        retry_after = int(blocked.headers["Retry-After"])
        self.assertGreater(retry_after, 0)
        self.assertEqual(blocked.json()["retry_after_seconds"], retry_after)

    def test_successful_login_clears_that_accounts_failed_attempts(self) -> None:
        failures_before_success = [
            self.client.post(
                "/api/client/login",
                json={
                    "username": "account-user",
                    "password": "WrongPassword1",
                    "device_code": f"RESET-BEFORE-{index}",
                    "client_version": "v-test",
                },
            )
            for index in range(9)
        ]
        succeeded = self.client.post(
            "/api/client/login",
            json={
                "username": "account-user",
                "password": self.password,
                "device_code": "RESET-SUCCESS",
                "client_version": "v-test",
            },
        )
        failures_after_success = [
            self.client.post(
                "/api/client/login",
                json={
                    "username": "account-user",
                    "password": "WrongPassword1",
                    "device_code": f"RESET-AFTER-{index}",
                    "client_version": "v-test",
                },
            )
            for index in range(2)
        ]

        self.assertTrue(all(response.status_code == 401 for response in failures_before_success))
        self.assertEqual(succeeded.status_code, 200, succeeded.text)
        self.assertTrue(all(response.status_code == 401 for response in failures_after_success))
        conn = get_connection()
        try:
            remaining_failures = conn.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0",
                ("account-user",),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(remaining_failures, 2)

    def test_second_device_login_invalidates_first_token(self) -> None:
        first = self.client.post(
            "/api/client/login",
            json={
                "username": "account-user",
                "password": self.password,
                "device_code": "DEV-A",
                "client_version": "v-test",
            },
        )
        second = self.client.post(
            "/api/client/login",
            json={
                "username": "account-user",
                "password": self.password,
                "device_code": "DEV-B",
                "client_version": "v-test",
            },
        )

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        first_token = str(first.json().get("token") or "")
        second_token = str(second.json().get("token") or "")
        self.assertTrue(first_token)
        self.assertTrue(second_token)
        self.assertNotEqual(first_token, second_token)

        first_balance = self.client.get(
            "/api/client/balance",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        second_balance = self.client.get(
            "/api/client/balance",
            headers={"Authorization": f"Bearer {second_token}"},
        )
        self.assertEqual(first_balance.status_code, 401, first_balance.text)
        self.assertEqual(second_balance.status_code, 200, second_balance.text)
        self.assertEqual(second_balance.json()["balance_seconds"], 600)

    def test_concurrent_logins_leave_exactly_one_token_valid(self) -> None:
        def login(index: int):
            client = TestClient(app, client=(f"concurrent-login-{index}", 50000 + index))
            return client.post(
                "/api/client/login",
                json={
                    "username": "account-user",
                    "password": self.password,
                    "device_code": f"DEV-{index}",
                    "client_version": "v-test",
                },
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(login, range(4)))

        self.assertTrue(all(response.status_code == 200 for response in responses), [response.text for response in responses])
        tokens = [str(response.json().get("token") or "") for response in responses]
        self.assertTrue(all(tokens))
        self.assertEqual(len(set(tokens)), len(tokens))

        validation_client = TestClient(app, client=("concurrent-validation", 51000))
        validation_statuses = [
            validation_client.get(
                "/api/client/balance",
                headers={"Authorization": f"Bearer {token}"},
            ).status_code
            for token in tokens
        ]
        self.assertEqual(validation_statuses.count(200), 1, validation_statuses)
        self.assertEqual(validation_statuses.count(401), len(tokens) - 1, validation_statuses)

    def test_single_login_migration_recovers_partial_upgrade_and_runs_once(self) -> None:
        conn = get_connection()
        try:
            conn.execute(
                "DELETE FROM schema_migrations WHERE migration_key = ?",
                (SINGLE_LOGIN_MIGRATION,),
            )
            conn.execute(
                "UPDATE users SET auth_version = 7, login_device_code = 'OLD-DEVICE', "
                "login_instance_id = 'old-login' WHERE id = ?",
                (self.uid,),
            )
            conn.execute(
                "INSERT INTO time_sessions "
                "(user_id, login_auth_version, login_instance_id, machine_code, status, lease_expires_at) "
                "VALUES (?, 7, 'old-login', 'OLD-DEVICE', 'active', datetime('now', '+60 seconds'))",
                (self.uid,),
            )
            conn.execute("UPDATE runtime_security_settings SET lease_ttl_seconds = 60 WHERE id = 1")
            conn.commit()
        finally:
            conn.close()

        init_db()
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT auth_version, login_device_code, login_instance_id FROM users WHERE id = ?",
                (self.uid,),
            ).fetchone()
            session = conn.execute(
                "SELECT status, ended_reason, revoked_at FROM time_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (self.uid,),
            ).fetchone()
            ttl = conn.execute(
                "SELECT lease_ttl_seconds FROM runtime_security_settings WHERE id = 1"
            ).fetchone()[0]
            marker_count = conn.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = ?",
                (SINGLE_LOGIN_MIGRATION,),
            ).fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(user["auth_version"], 8)
        self.assertEqual(user["login_device_code"], "")
        self.assertEqual(user["login_instance_id"], "")
        self.assertEqual(session["status"], "ended")
        self.assertEqual(session["ended_reason"], "login_policy_migration")
        self.assertTrue(session["revoked_at"])
        self.assertEqual(ttl, 15)
        self.assertEqual(marker_count, 1)

        init_db()
        conn = get_connection()
        try:
            auth_version = conn.execute(
                "SELECT auth_version FROM users WHERE id = ?",
                (self.uid,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(auth_version, 8)

    def test_single_login_migration_is_serialized_across_concurrent_initializers(self) -> None:
        conn = get_connection()
        try:
            conn.execute(
                "DELETE FROM schema_migrations WHERE migration_key = ?",
                (SINGLE_LOGIN_MIGRATION,),
            )
            conn.execute(
                "UPDATE users SET auth_version = 7, login_device_code = 'OLD-DEVICE', "
                "login_instance_id = 'old-login' WHERE id = ?",
                (self.uid,),
            )
            conn.commit()
        finally:
            conn.close()

        barrier = threading.Barrier(4)

        def initialize(_: int) -> None:
            barrier.wait(timeout=5)
            init_db()

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(initialize, range(4)))

        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT auth_version, login_device_code, login_instance_id FROM users WHERE id = ?",
                (self.uid,),
            ).fetchone()
            marker_count = conn.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = ?",
                (SINGLE_LOGIN_MIGRATION,),
            ).fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(int(user["auth_version"]), 8)
        self.assertEqual(str(user["login_device_code"] or ""), "")
        self.assertEqual(str(user["login_instance_id"] or ""), "")
        self.assertEqual(int(marker_count), 1)

    def test_email_code_route_normalizes_and_checks_same_or_taken_email(self) -> None:
        with patch(
            "app.routes.time_api.send_verification_code",
            return_value=email_service.VerificationSendStatus.SENT,
        ) as sender:
            sent = self.client.post(
                "/api/client/account/email-code",
                headers=self.headers,
                json={"new_email": "NEW@EXAMPLE.TEST"},
            )
        same = self.client.post(
            "/api/client/account/email-code",
            headers=self.headers,
            json={"new_email": "OLD@EXAMPLE.TEST"},
        )
        taken = self.client.post(
            "/api/client/account/email-code",
            headers=self.headers,
            json={"new_email": "TAKEN@EXAMPLE.TEST"},
        )

        self.assertEqual(sent.status_code, 200, sent.text)
        sender.assert_called_once_with("new@example.test", "change_email", trace_id=ANY)
        self.assertEqual(sent.json()["email"], "new@example.test")
        self.assertEqual(same.status_code, 400, same.text)
        self.assertEqual(taken.status_code, 409, taken.text)

    def test_register_code_rate_limit_is_not_shared_across_different_emails(self) -> None:
        with patch(
            "app.routes.time_api.send_verification_code",
            return_value=email_service.VerificationSendStatus.SENT,
        ) as sender:
            responses = [
                self.client.post(
                    "/api/client/register-code",
                    json={"email": f"new-user-{index}@example.test"},
                )
                for index in range(6)
            ]

        self.assertTrue(all(response.status_code == 200 for response in responses), responses[-1].text)
        self.assertEqual(sender.call_count, 6)

    def test_register_code_reports_email_cooldown_separately(self) -> None:
        with patch(
            "app.routes.time_api.send_verification_code",
            return_value=email_service.VerificationSendStatus.COOLDOWN,
        ):
            response = self.client.post(
                "/api/client/register-code",
                json={"email": "cooldown@example.test"},
            )

        self.assertEqual(response.status_code, 429, response.text)
        self.assertEqual(response.json()["error"], "email_code_cooldown")
        self.assertIn("该邮箱", response.json()["message"])
        self.assertEqual(response.headers["Retry-After"], str(config.EMAIL_CODE_SEND_COOLDOWN_SECONDS))

    def test_register_code_reports_delivery_failure_separately(self) -> None:
        with patch(
            "app.routes.time_api.send_verification_code",
            return_value=email_service.VerificationSendStatus.DELIVERY_FAILED,
        ):
            response = self.client.post(
                "/api/client/register-code",
                json={"email": "delivery-failure@example.test"},
            )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"], "email_delivery_failed")
        self.assertIn("投递验证码", response.json()["message"])

    def test_registration_rate_limit_is_not_shared_across_different_users(self) -> None:
        responses = [
            self.client.post(
                "/api/client/register",
                json={
                    "username": f"new_user_{index}",
                    "password": "ValidPassword1",
                    "email": f"new-user-{index}@example.test",
                    "email_code": "",
                },
            )
            for index in range(6)
        ]

        self.assertTrue(all(response.status_code == 400 for response in responses), responses[-1].text)
        self.assertTrue(all(response.json()["error"] == "请输入邮箱验证码" for response in responses))

    def test_register_username_contract_matches_admin_usernames(self) -> None:
        email = "hyphen-user@example.test"
        code = "456789"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, 'register')",
                (email, email_service._code_digest(email, code, "register")),
            )
            conn.commit()
        finally:
            conn.close()

        accepted = self.client.post(
            "/api/client/register",
            json={
                "username": "hyphen-user",
                "password": "ValidPassword1",
                "email": email,
                "email_code": code,
                "device_code": "REGISTER-HYPHEN",
                "client_version": "v-test",
            },
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["username"], "hyphen-user")

        rejected_usernames = ("ab", "bad name", "bad.name", "x" * 65)
        for index, username in enumerate(rejected_usernames):
            with self.subTest(username=username):
                response = self.client.post(
                    "/api/client/register",
                    json={
                        "username": username,
                        "password": "ValidPassword1",
                        "email": f"invalid-user-{index}@example.test",
                        "email_code": "unused",
                        "device_code": f"REGISTER-INVALID-{index}",
                        "client_version": "v-test",
                    },
                )

                self.assertEqual(response.status_code, 400, response.text)

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT username FROM users WHERE username IN (?, ?, ?, ?)",
                rejected_usernames,
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [])

    def test_email_change_is_transactional_and_consumes_hashed_code_once(self) -> None:
        self._insert_code("new@example.test")
        wrong = self.client.post(
            "/api/client/account/email",
            headers=self.headers,
            json={
                "current_password": self.password,
                "new_email": "new@example.test",
                "email_code": "000000",
            },
        )
        self.assertEqual(wrong.status_code, 400, wrong.text)
        self.assertEqual(self._user_row()["email"], "old@example.test")

        changed = self.client.post(
            "/api/client/account/email",
            headers=self.headers,
            json={
                "current_password": self.password,
                "new_email": "NEW@EXAMPLE.TEST",
                "email_code": "123456",
            },
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["email"], "new@example.test")
        self.assertEqual(self._user_row()["email"], "new@example.test")
        self.assertFalse(email_service.verify_code("new@example.test", "123456", "change_email"))

    def test_duplicate_email_conflict_does_not_consume_code(self) -> None:
        self._insert_code("taken@example.test")
        response = self.client.post(
            "/api/client/account/email",
            headers=self.headers,
            json={
                "current_password": self.password,
                "new_email": "taken@example.test",
                "email_code": "123456",
            },
        )
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self._user_row()["email"], "old@example.test")
        self.assertTrue(email_service.verify_code("taken@example.test", "123456", "change_email"))

    def test_new_verification_codes_are_hmac_stored_and_single_use(self) -> None:
        with (
            patch.object(email_service, "generate_code", return_value="654321"),
            patch.object(email_service, "send_email", return_value=True),
        ):
            accepted = email_service.send_verification_code("secure@example.test", "change_email")

        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT code FROM email_codes WHERE email = ? ORDER BY id DESC LIMIT 1",
                ("secure@example.test",),
            ).fetchone()
        finally:
            conn.close()
        self.assertIs(accepted, email_service.VerificationSendStatus.SENT)
        self.assertTrue(str(row["code"]).startswith("hmac-sha256:"))
        self.assertNotIn("654321", str(row["code"]))
        self.assertTrue(email_service.verify_code("secure@example.test", "654321", "change_email"))
        self.assertFalse(email_service.verify_code("secure@example.test", "654321", "change_email"))

    def test_failed_delivery_removes_code_and_allows_immediate_retry(self) -> None:
        with (
            patch.object(email_service, "generate_code", side_effect=["111111", "222222"]),
            patch.object(email_service, "send_email", side_effect=[False, True]) as sender,
        ):
            failed = email_service.send_verification_code("retry@example.test", "register")
            retried = email_service.send_verification_code("retry@example.test", "register")

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT code FROM email_codes WHERE email = ? AND purpose = 'register'",
                ("retry@example.test",),
            ).fetchall()
        finally:
            conn.close()

        self.assertIs(failed, email_service.VerificationSendStatus.DELIVERY_FAILED)
        self.assertIs(retried, email_service.VerificationSendStatus.SENT)
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(len(rows), 1)
        self.assertTrue(email_service.verify_code("retry@example.test", "222222", "register"))

    def test_same_email_is_rate_limited_by_email_cooldown(self) -> None:
        with patch.object(email_service, "send_email", return_value=True) as sender:
            first = email_service.send_verification_code("same-user@example.test", "register")
            second = email_service.send_verification_code("SAME-USER@example.test", "register")

        self.assertIs(first, email_service.VerificationSendStatus.SENT)
        self.assertIs(second, email_service.VerificationSendStatus.COOLDOWN)
        self.assertEqual(sender.call_count, 1)

    def test_smtp_rejection_log_keeps_codes_but_not_recipient_details(self) -> None:
        smtp_context = MagicMock()
        smtp_server = smtp_context.__enter__.return_value
        smtp_server.sendmail.side_effect = smtplib.SMTPDataError(
            550,
            b"5.7.1 rejected private-address@example.test",
        )
        smtp_secret = secrets.token_urlsafe(16)
        with (
            patch.object(config, "SMTP_USER", "sender@example.test"),
            patch.object(config, "SMTP_PASSWORD", smtp_secret),
            patch.object(config, "SMTP_USE_TLS", False),
            patch.object(email_service.smtplib, "SMTP", return_value=smtp_context),
            self.assertLogs("email", level="ERROR") as captured,
        ):
            sent = email_service.send_email(
                "private-address@example.test",
                "verification",
                "code body",
            )

        log_output = "\n".join(captured.output)
        self.assertFalse(sent)
        self.assertIn("smtp_code=550", log_output)
        self.assertIn("enhanced_status=5.7.1", log_output)
        self.assertNotIn("private-address", log_output)

    def test_purchase_history_supports_more_than_twenty_scrollable_rows(self) -> None:
        conn = get_connection()
        try:
            conn.executemany(
                "INSERT INTO orders (user_id, plan, amount, status) VALUES (?, '1h', 1.5, 'delivered')",
                [(self.uid,)] * 30,
            )
            conn.commit()
        finally:
            conn.close()

        response = self.client.get(
            "/api/client/purchase-history?limit=50",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()["items"]), 30)


if __name__ == "__main__":
    unittest.main()
