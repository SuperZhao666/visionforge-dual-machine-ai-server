import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-growth-features")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import CSRF_COOKIE_NAME, create_access_token, generate_csrf_token, hash_password
from app.services.email_service import _code_digest
from app.services.external_code_issuance_service import (
    MAX_TRACE_ID_LENGTH,
    ExternalCodeIssuanceError,
    issue_external_code,
)
from app.services.integration_auth_service import sign_integration_request
from app.services.redemption_constants import MAX_ISSUANCE_NOTE_LENGTH
from app.services.redemption_service import issue_codes, redeem_code
from app.services.referral_service import (
    MAX_REGISTRATION_EVENT_ID_LENGTH,
    ReferralError,
    apply_referral_locked,
    ensure_invite_code,
)
from app.services.time_credit_service import MAX_CREDIT_SECONDS, credit_time_locked


CODE_PATTERN = re.compile(r"VF1-[A-Z0-9-]+")


class GrowthFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_db_path = config.DATABASE_PATH
        self.previous_code_issuance_service_id = config.CODE_ISSUANCE_SERVICE_ID
        self.previous_code_issuance_secret = config.CODE_ISSUANCE_HMAC_SECRET
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.CODE_ISSUANCE_SERVICE_ID = "test-xianyu-bridge"
        config.CODE_ISSUANCE_HMAC_SECRET = "test-code-issuance-secret-at-least-32-bytes"
        init_db()
        conn = get_connection()
        try:
            self.admin_id = self._create_user(conn, "admin", is_admin=True)
            self.inviter_id = self._create_user(conn, "inviter")
            self.redeemer_id = self._create_user(conn, "redeemer")
            self.other_user_id = self._create_user(conn, "other")
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        config.DATABASE_PATH = self.previous_db_path
        config.CODE_ISSUANCE_SERVICE_ID = self.previous_code_issuance_service_id
        config.CODE_ISSUANCE_HMAC_SECRET = self.previous_code_issuance_secret
        self.tmpdir.cleanup()

    @staticmethod
    def _create_user(conn, username: str, *, is_admin: bool = False) -> int:
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (username, f"{username}@example.test", hash_password("Password123"), 1 if is_admin else 0),
        )
        user_id = int(cursor.lastrowid)
        conn.execute("INSERT INTO time_balance (user_id) VALUES (?)", (user_id,))
        return user_id

    @staticmethod
    def _balance(user_id: int) -> int:
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return int(row["balance_seconds"] if row else 0)
        finally:
            conn.close()

    def test_redemption_code_is_single_use_and_idempotent_for_owner(self):
        issuance = issue_codes(
            product_key="1h",
            quantity=1,
            channel="admin",
            issuer_type="admin",
            issuer_id=self.admin_id,
            request_key="test-admin-batch-1",
        )
        code = issuance.codes[0]

        first = redeem_code(self.redeemer_id, code)
        repeated = redeem_code(self.redeemer_id, code)
        stolen = redeem_code(self.other_user_id, code)

        self.assertTrue(first.ok)
        self.assertTrue(first.credited)
        self.assertTrue(repeated.ok)
        self.assertFalse(repeated.credited)
        self.assertEqual(stolen.error_code, "CODE_INVALID_OR_USED")
        self.assertEqual(self._balance(self.redeemer_id), 3600)
        self.assertEqual(self._balance(self.other_user_id), 0)

        conn = get_connection()
        try:
            code_row = conn.execute(
                "SELECT status, redeemed_by_user_id FROM redemption_codes WHERE id = ?",
                (first.code_id,),
            ).fetchone()
            recharge_count = conn.execute(
                "SELECT COUNT(*) AS c FROM time_recharges WHERE source_type = 'redemption' AND source_ref = ?",
                (f"redemption:{first.code_id}",),
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(code_row["status"], "redeemed")
        self.assertEqual(int(code_row["redeemed_by_user_id"]), self.redeemer_id)
        self.assertEqual(int(recharge_count), 1)

    def test_client_redemption_rejects_non_object_json(self):
        token = create_access_token(self.redeemer_id, False)
        response = TestClient(app).post(
            "/api/client/redemptions",
            headers={"Authorization": f"Bearer {token}"},
            json=["not", "an", "object"],
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "INVALID_REQUEST")

    def test_existing_time_recharge_table_migrates_without_data_loss(self):
        current_path = config.DATABASE_PATH
        legacy_path = str(Path(self.tmpdir.name) / "legacy.db")
        legacy = sqlite3.connect(legacy_path)
        try:
            legacy.execute(
                "CREATE TABLE time_recharges (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, "
                "order_id INTEGER, hours REAL NOT NULL, seconds INTEGER NOT NULL, amount REAL NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
            )
            legacy.execute(
                "INSERT INTO time_recharges (user_id, hours, seconds, amount) VALUES (1, 1, 3600, 0)"
            )
            legacy.commit()
        finally:
            legacy.close()
        try:
            config.DATABASE_PATH = legacy_path
            init_db()
            conn = get_connection()
            try:
                columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(time_recharges)")}
                row = conn.execute("SELECT seconds, source_type, source_ref FROM time_recharges").fetchone()
            finally:
                conn.close()
        finally:
            config.DATABASE_PATH = current_path

        self.assertIn("source_type", columns)
        self.assertIn("source_ref", columns)
        self.assertEqual(int(row["seconds"]), 3600)
        self.assertEqual(row["source_type"], "")

    def test_time_credit_service_rejects_missing_or_deleted_user_and_oversized_credit(self):
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(LookupError):
                credit_time_locked(
                    conn,
                    user_id=9999,
                    seconds=60,
                    source_type="test",
                    source_ref="missing-user",
                )
            conn.execute("UPDATE users SET deleted_at = datetime('now') WHERE id = ?", (self.other_user_id,))
            with self.assertRaises(LookupError):
                credit_time_locked(
                    conn,
                    user_id=self.other_user_id,
                    seconds=60,
                    source_type="test",
                    source_ref="deleted-user",
                )
            with self.assertRaises(ValueError):
                credit_time_locked(
                    conn,
                    user_id=self.redeemer_id,
                    seconds=MAX_CREDIT_SECONDS + 1,
                    source_type="test",
                    source_ref="oversized",
                )
            valid = credit_time_locked(
                conn,
                user_id=self.redeemer_id,
                seconds=60,
                source_type="test",
                source_ref="valid",
            )
            repeated = credit_time_locked(
                conn,
                user_id=self.redeemer_id,
                seconds=60,
                source_type="test",
                source_ref="valid",
            )
            conn.commit()
        finally:
            conn.close()

        self.assertTrue(valid.credited)
        self.assertFalse(repeated.credited)
        self.assertEqual(valid.recharge_id, repeated.recharge_id)
        self.assertEqual(self._balance(self.redeemer_id), 60)
        conn = get_connection()
        try:
            missing_balance = conn.execute("SELECT COUNT(*) FROM time_balance WHERE user_id = 9999").fetchone()[0]
            recharge_rows = conn.execute("SELECT user_id, seconds, source_ref FROM time_recharges ORDER BY id").fetchall()
        finally:
            conn.close()
        self.assertEqual(missing_balance, 0)
        self.assertEqual(
            [(row["user_id"], row["seconds"], row["source_ref"]) for row in recharge_rows],
            [(self.redeemer_id, 60, "valid")],
        )

    def test_time_credit_service_rejects_result_balance_above_cap_without_recharge(self):
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (MAX_CREDIT_SECONDS - 30, MAX_CREDIT_SECONDS - 30, self.redeemer_id),
            )
            with self.assertRaisesRegex(ValueError, "maximum balance"):
                credit_time_locked(
                    conn,
                    user_id=self.redeemer_id,
                    seconds=60,
                    source_type="test",
                    source_ref="above-cap",
                )
            conn.commit()
        finally:
            conn.close()

        conn = get_connection()
        try:
            balance = conn.execute(
                "SELECT balance_seconds, total_recharged_seconds FROM time_balance WHERE user_id = ?",
                (self.redeemer_id,),
            ).fetchone()
            recharge_count = conn.execute("SELECT COUNT(*) FROM time_recharges WHERE source_ref = 'above-cap'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(balance["balance_seconds"], MAX_CREDIT_SECONDS - 30)
        self.assertEqual(balance["total_recharged_seconds"], MAX_CREDIT_SECONDS - 30)
        self.assertEqual(recharge_count, 0)

    def test_redemption_balance_limit_does_not_consume_code_or_create_recharge(self):
        issuance = issue_codes(
            product_key="1h",
            quantity=1,
            channel="admin",
            issuer_type="admin",
            issuer_id=self.admin_id,
            request_key="balance-limit-redemption",
        )
        code = issuance.codes[0]
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (MAX_CREDIT_SECONDS - 30, MAX_CREDIT_SECONDS - 30, self.redeemer_id),
            )
            conn.commit()
        finally:
            conn.close()

        result = redeem_code(self.redeemer_id, code)

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "BALANCE_LIMIT_EXCEEDED")
        conn = get_connection()
        try:
            code_row = conn.execute(
                "SELECT status, redeemed_by_user_id FROM redemption_codes WHERE id = ?",
                (
                    conn.execute(
                        "SELECT id FROM redemption_codes WHERE batch_id = ?",
                        (issuance.batch_id,),
                    ).fetchone()["id"],
                ),
            ).fetchone()
            recharge_count = conn.execute(
                "SELECT COUNT(*) FROM time_recharges WHERE source_type = 'redemption'"
            ).fetchone()[0]
            balance = conn.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (self.redeemer_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(code_row["status"], "issued")
        self.assertIsNone(code_row["redeemed_by_user_id"])
        self.assertEqual(recharge_count, 0)
        self.assertEqual(balance, MAX_CREDIT_SECONDS - 30)

    def test_client_redemption_balance_limit_returns_business_error(self):
        issuance = issue_codes(
            product_key="1h",
            quantity=1,
            channel="admin",
            issuer_type="admin",
            issuer_id=self.admin_id,
            request_key="balance-limit-redemption-api",
        )
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (MAX_CREDIT_SECONDS - 30, MAX_CREDIT_SECONDS - 30, self.redeemer_id),
            )
            conn.commit()
        finally:
            conn.close()
        token = create_access_token(self.redeemer_id, False)

        response = TestClient(app).post(
            "/api/client/redemptions",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": issuance.codes[0]},
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"], "BALANCE_LIMIT_EXCEEDED")

    def test_concurrent_redemption_credits_exactly_one_user(self):
        conn = get_connection()
        try:
            contender_ids = [self._create_user(conn, f"contender_{index}") for index in range(12)]
            conn.commit()
        finally:
            conn.close()
        code = issue_codes(
            product_key="1h",
            quantity=1,
            channel="concurrency-test",
            issuer_type="test",
            request_key="concurrent-redemption",
        ).codes[0]

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda user_id: redeem_code(user_id, code), contender_ids))

        winners = [result for result in results if result.ok and result.credited]
        self.assertEqual(len(winners), 1)
        self.assertEqual(sum(self._balance(user_id) for user_id in contender_ids), 3600)

    def test_overlong_product_key_prefix_does_not_issue_codes(self):
        exact_key = "a" * 32
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO duration_products (product_key, display_name, duration_seconds, enabled) "
                "VALUES (?, ?, ?, 1)",
                (exact_key, "Exact 32", 3600),
            )
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(ValueError):
            issue_codes(
                product_key=f"{exact_key}x",
                quantity=1,
                channel="admin",
                issuer_type="admin",
                issuer_id=self.admin_id,
                request_key="overlong-product-key",
            )

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 0)
        finally:
            conn.close()

    def test_overlong_request_key_prefix_does_not_reuse_existing_batch(self):
        exact_request_key = "r" * 160
        first = issue_codes(
            product_key="1h",
            quantity=1,
            channel="admin",
            issuer_type="admin",
            issuer_id=self.admin_id,
            request_key=exact_request_key,
        )

        with self.assertRaises(ValueError):
            issue_codes(
                product_key="1h",
                quantity=1,
                channel="admin",
                issuer_type="admin",
                issuer_id=self.admin_id,
                request_key=f"{exact_request_key}x",
            )

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 1)
            row = conn.execute("SELECT request_key FROM code_issuance_batches WHERE id = ?", (first.batch_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["request_key"], exact_request_key)

    def test_overlong_issuance_metadata_is_rejected_without_truncation(self):
        exact_channel = "c" * 32
        exact_issuer_type = "i" * 32
        first = issue_codes(
            product_key="1h",
            quantity=1,
            channel=exact_channel,
            issuer_type=exact_issuer_type,
            issuer_id=self.admin_id,
            request_key="exact-metadata-boundary",
        )

        for field_name, overrides in (
            ("channel", {"channel": exact_channel + "x", "request_key": "overlong-channel"}),
            ("issuer_type", {"issuer_type": exact_issuer_type + "x", "request_key": "overlong-issuer-type"}),
        ):
            issuance_request = {
                "channel": exact_channel,
                "issuer_type": exact_issuer_type,
                **overrides,
            }
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, field_name):
                    issue_codes(
                        product_key="1h",
                        quantity=1,
                        issuer_id=self.admin_id,
                        **issuance_request,
                    )

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 1)
            row = conn.execute("SELECT channel, issuer_type FROM code_issuance_batches WHERE id = ?", (first.batch_id,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["channel"], exact_channel)
        self.assertEqual(row["issuer_type"], exact_issuer_type)

    def test_overlong_issuance_note_is_rejected_without_truncation(self):
        with self.assertRaisesRegex(ValueError, "note"):
            issue_codes(
                product_key="1h",
                quantity=1,
                channel="admin",
                issuer_type="admin",
                issuer_id=self.admin_id,
                request_key="overlong-note",
                note="N" * (MAX_ISSUANCE_NOTE_LENGTH + 1),
            )

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 0)
        finally:
            conn.close()

    def test_out_of_range_code_expiry_days_is_rejected_without_clamping(self):
        exact_request_key = "expiry-request"
        first = issue_codes(
            product_key="1h",
            quantity=1,
            channel="admin",
            issuer_type="admin",
            issuer_id=self.admin_id,
            request_key=exact_request_key,
            expires_days=3650,
        )

        for expires_days in (0, 3651):
            with self.subTest(expires_days=expires_days):
                with self.assertRaisesRegex(ValueError, "expires_days"):
                    issue_codes(
                        product_key="1h",
                        quantity=1,
                        channel="admin",
                        issuer_type="admin",
                        issuer_id=self.admin_id,
                        request_key=exact_request_key,
                        expires_days=expires_days,
                    )

        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 1)
            row = conn.execute("SELECT expires_at FROM redemption_codes WHERE batch_id = ?", (first.batch_id,)).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row["expires_at"])

    def test_register_with_invite_code_rewards_inviter_once(self):
        invite_code = ensure_invite_code(self.inviter_id)
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, 'register')",
                (
                    "invitee@example.test",
                    _code_digest("invitee@example.test", "123456", "register"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        response = TestClient(app).post(
            "/api/client/register",
            json={
                "username": "invitee",
                "password": "Password123",
                "email": "invitee@example.test",
                "email_code": "123456",
                "invite_code": invite_code,
                "device_code": "device-invitee",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        invitee_id = int(response.json()["user_id"])
        self.assertEqual(self._balance(invitee_id), 3600)
        self.assertEqual(self._balance(self.inviter_id), 3600)
        conn = get_connection()
        try:
            referral = conn.execute(
                "SELECT inviter_user_id, invitee_user_id, status, reward_seconds FROM referrals"
            ).fetchone()
            reward_count = conn.execute(
                "SELECT COUNT(*) AS c FROM time_recharges WHERE source_type = 'referral'"
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(int(referral["inviter_user_id"]), self.inviter_id)
        self.assertEqual(int(referral["invitee_user_id"]), invitee_id)
        self.assertEqual(referral["status"], "rewarded")
        self.assertEqual(int(referral["reward_seconds"]), 3600)
        self.assertEqual(int(reward_count), 1)

    def test_referral_rejects_overlong_registration_event_without_truncation(self):
        invite_code = ensure_invite_code(self.inviter_id)
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ReferralError) as raised:
                apply_referral_locked(
                    conn,
                    invitee_user_id=self.redeemer_id,
                    invite_code=invite_code,
                    registration_event_id="r" * (MAX_REGISTRATION_EVENT_ID_LENGTH + 1),
                )
            conn.rollback()
        finally:
            conn.close()

        self.assertEqual(raised.exception.error_code, "REGISTRATION_EVENT_INVALID")
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM referrals").fetchone()[0], 0)
        finally:
            conn.close()
        self.assertEqual(self._balance(self.inviter_id), 0)

    def test_referral_rejects_soft_deleted_inviter_with_legacy_active_status(self):
        invite_code = ensure_invite_code(self.inviter_id)
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (self.inviter_id,),
            )
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ReferralError) as raised:
                apply_referral_locked(
                    conn,
                    invitee_user_id=self.redeemer_id,
                    invite_code=invite_code,
                    registration_event_id="deleted-inviter-registration",
                )
            self.assertEqual(raised.exception.error_code, "INVITE_CODE_INVALID")
            conn.rollback()
        finally:
            conn.close()

        self.assertEqual(self._balance(self.inviter_id), 0)

    def test_referral_rejects_inviter_balance_limit_without_reward(self):
        invite_code = ensure_invite_code(self.inviter_id)
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (MAX_CREDIT_SECONDS - 30, MAX_CREDIT_SECONDS - 30, self.inviter_id),
            )
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ReferralError) as raised:
                apply_referral_locked(
                    conn,
                    invitee_user_id=self.redeemer_id,
                    invite_code=invite_code,
                    registration_event_id="balance-limit-referral",
                )
            self.assertEqual(raised.exception.error_code, "REFERRAL_BALANCE_LIMIT")
            conn.rollback()
        finally:
            conn.close()

        conn = get_connection()
        try:
            referral_count = conn.execute("SELECT COUNT(*) FROM referrals").fetchone()[0]
            recharge_count = conn.execute(
                "SELECT COUNT(*) FROM time_recharges WHERE source_type = 'referral'"
            ).fetchone()[0]
            balance = conn.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (self.inviter_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(referral_count, 0)
        self.assertEqual(recharge_count, 0)
        self.assertEqual(balance, MAX_CREDIT_SECONDS - 30)

    def test_invite_landing_rejects_overlong_prefixed_code(self):
        invite_code = ensure_invite_code(self.inviter_id)
        client = TestClient(app)

        valid = client.get(f"/i/{invite_code}")
        overlong = client.get(f"/i/{invite_code}{'X' * 40}")

        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertIn(invite_code, valid.text)
        self.assertEqual(overlong.status_code, 404, overlong.text)

    def test_invite_landing_rejects_soft_deleted_inviter_with_legacy_active_status(self):
        invite_code = ensure_invite_code(self.inviter_id)
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (self.inviter_id,),
            )
            conn.commit()
        finally:
            conn.close()

        response = TestClient(app).get(f"/i/{invite_code}")

        self.assertEqual(response.status_code, 404, response.text)

    def test_invalid_invite_code_does_not_consume_registration_code(self):
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, 'register')",
                (
                    "invalid-invite@example.test",
                    _code_digest("invalid-invite@example.test", "654321", "register"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        response = TestClient(app).post(
            "/api/client/register",
            json={
                "username": "invalid_invite",
                "password": "Password123",
                "email": "invalid-invite@example.test",
                "email_code": "654321",
                "invite_code": "NOTVALID",
            },
        )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error_code"], "INVITE_CODE_INVALID")
        conn = get_connection()
        try:
            used = conn.execute(
                "SELECT used FROM email_codes WHERE email = ?",
                ("invalid-invite@example.test",),
            ).fetchone()["used"]
            user_count = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE username = 'invalid_invite'"
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(int(used), 0)
        self.assertEqual(int(user_count), 0)

    def test_external_code_issue_is_just_in_time_and_idempotent(self):
        client = TestClient(app)
        payload = {
            "product_key": "10h",
            "request_id": "xi1_" + "a" * 64,
        }
        first = self._post_code_issuance(client, payload)
        repeated = self._post_code_issuance(client, payload)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(first.json()["data"], repeated.json()["data"])
        self.assertFalse(first.json()["duplicate"])
        self.assertTrue(repeated.json()["duplicate"])
        code = first.json()["data"]["redemption_code"]
        self.assertRegex(code, CODE_PATTERN)
        self.assertIn("https://www.visionforge.cloud/download", first.json()["data"]["download_url"])
        self.assertTrue(redeem_code(self.redeemer_id, code).credited)
        self.assertEqual(self._balance(self.redeemer_id), 10 * 3600)

        conn = get_connection()
        try:
            code_count = conn.execute("SELECT COUNT(*) AS c FROM redemption_codes").fetchone()["c"]
            issuance_count = conn.execute("SELECT COUNT(*) AS c FROM external_code_issuances").fetchone()["c"]
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(external_code_issuances)")}
        finally:
            conn.close()
        self.assertEqual(int(code_count), 1)
        self.assertEqual(int(issuance_count), 1)
        self.assertNotIn("external_order_id", columns)
        self.assertNotIn("external_buyer_id", columns)

    def test_external_code_issuance_bounds_trace_id(self):
        trace_id = "trace-" + ("x" * 120)
        expected_trace_id = trace_id[:MAX_TRACE_ID_LENGTH]

        result = issue_external_code(
            product_key="1h",
            request_id="xi1_" + "t" * 64,
            trace_id=trace_id,
        )

        self.assertEqual(result.trace_id, expected_trace_id)
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT trace_id FROM external_code_issuances WHERE id = ?",
                (result.issuance_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["trace_id"], expected_trace_id)

    def test_concurrent_external_callbacks_issue_one_code(self):
        request = {
            "product_key": "10h",
            "request_id": "xi1_" + "b" * 64,
        }

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _index: issue_external_code(**request), range(12)))

        self.assertEqual(len({result.redemption_code for result in results}), 1)
        self.assertEqual(sum(not result.duplicate for result in results), 1)
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM external_code_issuances").fetchone()[0], 1)
        finally:
            conn.close()

    def test_external_request_cannot_switch_product_after_first_issue(self):
        request_id = "xi1_" + "e" * 64
        first = issue_external_code(product_key="1h", request_id=request_id)

        with self.assertRaises(ExternalCodeIssuanceError) as captured:
            issue_external_code(product_key="5h", request_id=request_id)

        self.assertEqual(captured.exception.error_code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(first.duration_seconds, 3600)
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 1)
        finally:
            conn.close()

    def test_disabled_product_rejects_external_issue_without_creating_code(self):
        conn = get_connection()
        try:
            conn.execute("UPDATE duration_products SET enabled = 0 WHERE product_key = '5h'")
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(ExternalCodeIssuanceError) as captured:
            issue_external_code(product_key="5h", request_id="xi1_" + "f" * 64)

        self.assertEqual(captured.exception.error_code, "PRODUCT_NOT_AVAILABLE")
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 0)
        finally:
            conn.close()

    def test_external_code_hmac_replay_is_rejected(self):
        payload = {
            "product_key": "10h",
            "request_id": "xi1_" + "c" * 64,
        }
        client = TestClient(app)
        body, headers = self._code_issuance_request(payload)
        path = "/api/integrations/code-issuances/issue"
        first = client.post(path, content=body, headers=headers)
        replay = client.post(path, content=body, headers=headers)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(replay.status_code, 401, replay.text)
        self.assertEqual(replay.json()["error_code"], "UNAUTHORIZED")

    def test_external_code_issuance_rejects_oversized_body_before_issuing(self):
        payload = {
            "product_key": "10h",
            "request_id": "xi1_" + "d" * 64,
            "padding": "x" * (70 * 1024),
        }
        body, headers = self._code_issuance_request(payload)

        response = TestClient(app).post(
            "/api/integrations/code-issuances/issue",
            content=body,
            headers=headers,
        )

        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(response.json()["error_code"], "PAYLOAD_TOO_LARGE")
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 0)
        finally:
            conn.close()

    def test_admin_growth_page_and_one_time_csv_generation(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        page = client.get("/admin/growth")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("兑换码与邀请", page.text)
        self.assertNotIn("开启闲鱼自动发货", page.text)
        self.assertNotIn("闲鱼商品规格映射", page.text)
        self.assertNotIn("最近闲鱼履约", page.text)
        paths = client.get("/openapi.json").json()["paths"]
        self.assertIn("/api/integrations/code-issuances/issue", paths)
        self.assertNotIn("/api/integrations/fulfillments/issue", paths)
        self.assertNotIn("/api/integrations/fulfillments/status", paths)

        generated = client.post(
            "/admin/growth/codes/generate",
            data={
                "csrf_token": csrf_token,
                "product_key": "5h",
                "quantity": "2",
                "note": "test batch",
            },
        )
        self.assertEqual(generated.status_code, 200, generated.text)
        self.assertIn("text/csv", generated.headers["content-type"])
        codes = CODE_PATTERN.findall(generated.text)
        self.assertEqual(len(codes), 2)
        self.assertNotEqual(codes[0], codes[1])

        page_after = client.get("/admin/growth")
        self.assertEqual(page_after.status_code, 200)
        self.assertNotIn(codes[0], page_after.text)
        self.assertNotIn(codes[1], page_after.text)
        conn = get_connection()
        try:
            audit = conn.execute(
                "SELECT detail_json FROM admin_audit WHERE action = 'growth.codes.generate' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            code_columns = {
                str(row["name"]) for row in conn.execute("PRAGMA table_info(redemption_codes)").fetchall()
            }
        finally:
            conn.close()
        audit_detail = json.loads(audit["detail_json"])
        self.assertTrue(audit_detail["trace_id"])
        self.assertNotIn("redemption_code", code_columns)
        self.assertNotIn(codes[0], audit["detail_json"])

    def test_admin_growth_code_generation_rejects_overlong_note_without_truncation(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/growth/codes/generate",
            data={
                "csrf_token": csrf_token,
                "product_key": "1h",
                "quantity": "1",
                "note": "N" * (MAX_ISSUANCE_NOTE_LENGTH + 1),
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM code_issuance_batches").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0], 0)
        finally:
            conn.close()

    def test_admin_growth_product_update_rejects_overlong_prefixed_key(self):
        exact_key = "b" * 32
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO duration_products (product_key, display_name, duration_seconds, enabled) "
                "VALUES (?, ?, ?, 1)",
                (exact_key, "Original Name", 3600),
            )
            conn.commit()
        finally:
            conn.close()
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/growth/products/update",
            data={
                "csrf_token": csrf_token,
                "product_key": f"{exact_key}x",
                "display_name": "Changed Name",
                "duration_hours": "5",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT display_name, duration_seconds FROM duration_products WHERE product_key = ?",
                (exact_key,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["display_name"], "Original Name")
        self.assertEqual(int(row["duration_seconds"]), 3600)

    def test_admin_growth_product_update_rejects_overlong_display_name_without_truncation(self):
        product_key = "display-name-limit"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO duration_products (product_key, display_name, duration_seconds, enabled) "
                "VALUES (?, ?, ?, 1)",
                (product_key, "Original Name", 3600),
            )
            conn.commit()
        finally:
            conn.close()
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/growth/products/update",
            data={
                "csrf_token": csrf_token,
                "product_key": product_key,
                "display_name": "N" * 81,
                "duration_hours": "5",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT display_name, duration_seconds FROM duration_products WHERE product_key = ?",
                (product_key,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["display_name"], "Original Name")
        self.assertEqual(int(row["duration_seconds"]), 3600)

    def test_admin_growth_product_update_rejects_out_of_range_duration_without_clamping(self):
        product_key = "duration-limit"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO duration_products (product_key, display_name, duration_seconds, enabled) "
                "VALUES (?, ?, ?, 1)",
                (product_key, "Original Name", 3600),
            )
            conn.commit()
        finally:
            conn.close()
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/growth/products/update",
            data={
                "csrf_token": csrf_token,
                "product_key": product_key,
                "display_name": "Changed Name",
                "duration_hours": "10001",
                "enabled": "1",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT display_name, duration_seconds FROM duration_products WHERE product_key = ?",
                (product_key,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["display_name"], "Original Name")
        self.assertEqual(int(row["duration_seconds"]), 3600)

    def test_admin_growth_settings_rejects_overlong_download_url_without_truncation(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
        original_url = "https://www.visionforge.cloud/download"
        overlong_url = "https://example.test/" + ("a" * 480) + "x"

        response = client.post(
            "/admin/growth/settings",
            data={
                "csrf_token": csrf_token,
                "redemption_enabled": "1",
                "referral_enabled": "1",
                "referral_reward_hours": "1",
                "code_expiry_days": "365",
                "download_url": overlong_url,
            },
            follow_redirects=False,
        )

        self.assertGreater(len(overlong_url), 500)
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute("SELECT download_url FROM growth_settings WHERE id = 1").fetchone()
        finally:
            conn.close()
        self.assertEqual(row["download_url"], original_url)

    def test_admin_growth_settings_rejects_out_of_range_numbers_without_clamping(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/growth/settings",
            data={
                "csrf_token": csrf_token,
                "redemption_enabled": "1",
                "referral_enabled": "1",
                "referral_reward_hours": "1001",
                "code_expiry_days": "365",
                "download_url": "https://www.visionforge.cloud/download",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT referral_reward_seconds, code_expiry_days FROM growth_settings WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(int(row["referral_reward_seconds"]), 3600)
        self.assertEqual(int(row["code_expiry_days"]), 365)

    def _code_issuance_request(self, payload: dict) -> tuple[bytes, dict[str, str]]:
        path = "/api/integrations/code-issuances/issue"
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        signature = sign_integration_request(
            secret=config.CODE_ISSUANCE_HMAC_SECRET,
            method="POST",
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return body, {
            "Content-Type": "application/json",
            "X-VF-Service": config.CODE_ISSUANCE_SERVICE_ID,
            "X-VF-Timestamp": timestamp,
            "X-VF-Nonce": nonce,
            "X-VF-Signature": signature,
        }

    def _post_code_issuance(self, client: TestClient, payload: dict):
        body, headers = self._code_issuance_request(payload)
        return client.post("/api/integrations/code-issuances/issue", content=body, headers=headers)


if __name__ == "__main__":
    unittest.main()
