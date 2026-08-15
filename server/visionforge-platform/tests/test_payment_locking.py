import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-payment-locking")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.routes.time_api import _cancel_purchase_session
from app.services.payment_service import (
    PLAN_BY_KEY,
    PLAN_SECONDS,
    build_payment_event_id,
    create_order_record,
    deliver_order,
    process_payment_event,
)
from app.services.time_credit_service import MAX_CREDIT_SECONDS


TEST_PRICE = PLAN_BY_KEY["1h"].price
TEST_PRICE_TEXT = f"{TEST_PRICE:.2f}"


class PaymentLockingTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        self.previous_webhook_secret = config.VMQ_WEBHOOK_SECRET
        config.VMQ_WEBHOOK_SECRET = "test-payment-webhook-secret"
        init_db()

    def tearDown(self):
        config.VMQ_WEBHOOK_SECRET = self.previous_webhook_secret
        self.tmpdir.cleanup()

    def create_user(self, conn, username):
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, f"{username}@example.test", "hash"),
        )
        uid = int(cur.lastrowid)
        conn.execute("INSERT INTO time_balance (user_id) VALUES (?)", (uid,))
        return uid

    def create_order(self, conn, user_id, plan="1h", amount=TEST_PRICE):
        order_id, _ = create_order_record(conn, user_id, plan, amount, "", "vmq")
        return order_id

    def row(self, sql, params=()):
        conn = get_connection()
        try:
            return conn.execute(sql, params).fetchone()
        finally:
            conn.close()

    def scalar(self, sql, params=()):
        row = self.row(sql, params)
        return row[0] if row else None

    def test_payment_event_is_idempotent_and_does_not_match_next_order(self):
        conn = get_connection()
        try:
            uid1 = self.create_user(conn, "u1")
            order1 = self.create_order(conn, uid1)
            conn.commit()
        finally:
            conn.close()

        first = process_payment_event("json", "json:trade_no:T1", TEST_PRICE, {"amount": TEST_PRICE_TEXT, "trade_no": "T1"})
        self.assertEqual(first["status"], "delivered")
        self.assertEqual(first["order_id"], order1)

        conn = get_connection()
        try:
            uid2 = self.create_user(conn, "u2")
            order2 = self.create_order(conn, uid2)
            conn.commit()
        finally:
            conn.close()

        second = process_payment_event("json", "json:trade_no:T1", TEST_PRICE, {"amount": TEST_PRICE_TEXT, "trade_no": "T1"})
        self.assertIs(second["duplicate"], True)
        self.assertEqual(second["order_id"], order1)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order2,)), "pending")
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid2,)), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id IS NOT NULL"), 1)

    def test_same_plan_fixed_amount_orders_are_not_created_concurrently(self):
        conn = get_connection()
        try:
            uid1 = self.create_user(conn, "u1")
            uid2 = self.create_user(conn, "u2")
            order1 = self.create_order(conn, uid1)
            with self.assertRaises(RuntimeError):
                self.create_order(conn, uid2)
            conn.commit()
        finally:
            conn.close()

        amount1 = float(self.scalar("SELECT amount FROM orders WHERE id = ?", (order1,)))
        self.assertEqual(amount1, TEST_PRICE)

        first = process_payment_event("json", "json:trade_no:T2A", amount1, {"amount": f"{amount1:.2f}", "trade_no": "T2A"})

        self.assertEqual(first["order_id"], order1)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order1,)), "delivered")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges"), 1)

    def test_order_creation_rejects_unknown_plan_and_soft_deleted_user(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "deleted-order-user")
            with self.assertRaises(ValueError):
                create_order_record(conn, uid, "unknown", TEST_PRICE)
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (uid,),
            )
            with self.assertRaises(LookupError):
                create_order_record(conn, uid, "1h", TEST_PRICE)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 0)
            conn.rollback()
        finally:
            conn.close()

    def test_different_plan_fixed_amount_orders_deliver_independently(self):
        conn = get_connection()
        try:
            uid1 = self.create_user(conn, "u1")
            uid2 = self.create_user(conn, "u2")
            order1 = self.create_order(conn, uid1, "1h", PLAN_BY_KEY["1h"].price)
            order2 = self.create_order(conn, uid2, "5h", PLAN_BY_KEY["5h"].price)
            conn.commit()
        finally:
            conn.close()

        amount1 = float(self.scalar("SELECT amount FROM orders WHERE id = ?", (order1,)))
        amount2 = float(self.scalar("SELECT amount FROM orders WHERE id = ?", (order2,)))
        self.assertEqual(amount1, PLAN_BY_KEY["1h"].price)
        self.assertEqual(amount2, PLAN_BY_KEY["5h"].price)

        first = process_payment_event("json", "json:trade_no:T2A", amount1, {"amount": f"{amount1:.2f}", "trade_no": "T2A"})
        second = process_payment_event("json", "json:trade_no:T2B", amount2, {"amount": f"{amount2:.2f}", "trade_no": "T2B"})

        self.assertEqual(first["order_id"], order1)
        self.assertEqual(second["order_id"], order2)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order1,)), "delivered")
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order2,)), "delivered")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges"), 2)

    def test_unmatched_payment_event_is_retried_after_order_appears(self):
        event_id = "json:trade:EARLY-1"
        payload = {"amount": TEST_PRICE_TEXT, "trade_no": "EARLY-1"}
        first = process_payment_event("json", event_id, TEST_PRICE_TEXT, payload)
        self.assertEqual(first["status"], "unmatched")
        self.assertIs(first["duplicate"], False)

        conn = get_connection()
        try:
            user_id = self.create_user(conn, "late-order-user")
            order_id = self.create_order(conn, user_id)
            conn.commit()
        finally:
            conn.close()

        retry = process_payment_event("json", event_id, TEST_PRICE_TEXT, payload)

        self.assertEqual(retry["status"], "delivered")
        self.assertIs(retry["duplicate"], True)
        self.assertEqual(retry["order_id"], order_id)
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (user_id,)), 3600)
        self.assertEqual(self.scalar("SELECT attempt_count FROM payment_events WHERE event_id = ?", (event_id,)), 2)

    def test_idempotency_key_reuse_with_different_amount_is_rejected(self):
        event_id = "json:trade:CONFLICT-1"
        first = process_payment_event(
            "json",
            event_id,
            TEST_PRICE_TEXT,
            {"amount": TEST_PRICE_TEXT, "trade_no": "CONFLICT-1"},
        )
        self.assertEqual(first["status"], "unmatched")

        conflict = process_payment_event(
            "json",
            event_id,
            "6.00",
            {"amount": "6.00", "trade_no": "CONFLICT-1"},
        )

        self.assertIs(conflict["ok"], False)
        self.assertEqual(conflict["status"], "idempotency_conflict")
        self.assertEqual(self.scalar("SELECT attempt_count FROM payment_events WHERE event_id = ?", (event_id,)), 1)

    def test_long_provider_trade_numbers_do_not_collide_by_prefix(self):
        shared_prefix = "T" * 260
        first_payload = {"amount": TEST_PRICE_TEXT, "trade_no": f"{shared_prefix}A"}
        second_payload = {"amount": TEST_PRICE_TEXT, "trade_no": f"{shared_prefix}B"}
        first_event_id = build_payment_event_id("json", first_payload)
        second_event_id = build_payment_event_id("json", second_payload)

        first = process_payment_event("json", first_event_id, TEST_PRICE_TEXT, first_payload)
        second = process_payment_event("json", second_event_id, TEST_PRICE_TEXT, second_payload)

        self.assertNotEqual(first_event_id, second_event_id)
        self.assertLessEqual(len(first_event_id), 255)
        self.assertLessEqual(len(second_event_id), 255)
        self.assertEqual(first["status"], "unmatched")
        self.assertEqual(second["status"], "unmatched")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM payment_events"), 2)
        self.assertEqual(self.scalar("SELECT COUNT(DISTINCT event_id) FROM payment_events"), 2)

    def test_merchant_order_number_matches_exact_order(self):
        conn = get_connection()
        try:
            uid1 = self.create_user(conn, "u1")
            uid2 = self.create_user(conn, "u2")
            order1 = self.create_order(conn, uid1, "1h", PLAN_BY_KEY["1h"].price)
            order2 = self.create_order(conn, uid2, "5h", PLAN_BY_KEY["5h"].price)
            order2_no = conn.execute("SELECT merchant_order_no FROM orders WHERE id = ?", (order2,)).fetchone()["merchant_order_no"]
            conn.commit()
        finally:
            conn.close()

        order2_amount = float(self.scalar("SELECT amount FROM orders WHERE id = ?", (order2,)))
        result = process_payment_event(
            "json",
            "json:trade:T3",
            order2_amount,
            {
                "amount": f"{order2_amount:.2f}",
                "merchant_order_no": order2_no,
                "trade_no": "T3",
                "payment_method": "wechat",
            },
        )
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(result["order_id"], order2)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order1,)), "pending")
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid1,)), 0)
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid2,)), PLAN_SECONDS["5h"])
        row = self.row("SELECT yungouos_trade_no, payment_method FROM orders WHERE id = ?", (order2,))
        self.assertEqual(row["yungouos_trade_no"], "T3")
        self.assertEqual(row["payment_method"], "wechat")

    def test_payment_for_soft_deleted_account_requires_refund_without_credit(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "deleted-payer")
            order_id = self.create_order(conn, uid)
            merchant_order_no = conn.execute(
                "SELECT merchant_order_no FROM orders WHERE id = ?", (order_id,)
            ).fetchone()["merchant_order_no"]
            conn.execute(
                "UPDATE users SET deleted_at = datetime('now'), status = 'active' WHERE id = ?",
                (uid,),
            )
            conn.commit()
        finally:
            conn.close()

        result = process_payment_event(
            "json",
            "json:trade:DELETED-ACCOUNT",
            TEST_PRICE,
            {
                "amount": TEST_PRICE_TEXT,
                "merchant_order_no": merchant_order_no,
                "trade_no": "DELETED-ACCOUNT",
            },
        )

        self.assertEqual(result["status"], "refund_required")
        self.assertEqual(result["order_id"], order_id)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "refund_required")
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid,)), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (order_id,)), 0)
        self.assertEqual(
            self.scalar("SELECT status FROM payment_events WHERE event_id = ?", ("json:trade:DELETED-ACCOUNT",)),
            "refund_required",
        )
        repeated = process_payment_event(
            "json",
            "json:trade:DELETED-ACCOUNT",
            TEST_PRICE_TEXT,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "DELETED-ACCOUNT",
            },
        )
        self.assertTrue(repeated["duplicate"])
        self.assertEqual(repeated["status"], "refund_required")
        self.assertEqual(repeated["order_id"], order_id)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (order_id,)), 0)

    def test_payment_for_disabled_account_requires_refund_without_credit(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "disabled-payer")
            order_id = self.create_order(conn, uid)
            merchant_order_no = conn.execute(
                "SELECT merchant_order_no FROM orders WHERE id = ?", (order_id,)
            ).fetchone()["merchant_order_no"]
            conn.execute("UPDATE users SET status = 'banned' WHERE id = ?", (uid,))
            conn.commit()
        finally:
            conn.close()

        result = process_payment_event(
            "json",
            "json:trade:BANNED-ACCOUNT",
            TEST_PRICE_TEXT,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "BANNED-ACCOUNT",
            },
        )

        self.assertEqual(result["status"], "refund_required")
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "refund_required")
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid,)), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (order_id,)), 0)

    def test_payment_above_balance_cap_requires_refund_without_credit(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "balance-cap-payer")
            order_id = self.create_order(conn, uid)
            merchant_order_no = conn.execute(
                "SELECT merchant_order_no FROM orders WHERE id = ?", (order_id,)
            ).fetchone()["merchant_order_no"]
            existing_balance = MAX_CREDIT_SECONDS - PLAN_SECONDS["1h"] + 1
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, total_recharged_seconds = ? WHERE user_id = ?",
                (existing_balance, existing_balance, uid),
            )
            conn.commit()
        finally:
            conn.close()

        result = process_payment_event(
            "json",
            "json:trade:BALANCE-CAP",
            TEST_PRICE_TEXT,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "BALANCE-CAP",
            },
        )

        self.assertEqual(result["status"], "refund_required")
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "refund_required")
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid,)), existing_balance)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (order_id,)), 0)
        self.assertEqual(
            self.scalar("SELECT status FROM payment_events WHERE event_id = ?", ("json:trade:BALANCE-CAP",)),
            "refund_required",
        )

    def test_json_webhook_requires_hmac_signature(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "signed-user")
            order_id = self.create_order(conn, uid)
            merchant_order_no = conn.execute(
                "SELECT merchant_order_no FROM orders WHERE id = ?", (order_id,)
            ).fetchone()["merchant_order_no"]
            conn.commit()
        finally:
            conn.close()

        payload = {
            "amount": TEST_PRICE_TEXT,
            "merchant_order_no": merchant_order_no,
            "trade_no": "SIGNED-1",
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        client = TestClient(app)
        unsigned = client.post("/api/payment/webhook", content=body, headers={"Content-Type": "application/json"})
        self.assertEqual(unsigned.status_code, 401)
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "pending")

        signature = hmac.new(config.VMQ_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
        signed = client.post(
            "/api/payment/webhook",
            content=body,
            headers={"Content-Type": "application/json", "X-VisionForge-Signature": f"sha256={signature}"},
        )
        self.assertEqual(signed.status_code, 200, signed.text)
        self.assertEqual(signed.json()["status"], "delivered")
        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "delivered")

    def test_json_webhook_rejects_negative_content_length(self):
        response = TestClient(app).post(
            "/api/payment/webhook",
            content=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "-1"},
        )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"], "invalid content-length")

    def test_order_delivery_is_single_use(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "u1")
            order_id = self.create_order(conn, uid)
            conn.commit()
        finally:
            conn.close()

        self.assertIsNotNone(deliver_order(order_id, "test"))
        self.assertIsNone(deliver_order(order_id, "test"))
        self.assertEqual(self.scalar("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid,)), 3600)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (order_id,)), 1)

    def test_cancel_purchase_session_does_not_overwrite_delivered_order(self):
        conn = get_connection()
        try:
            uid = self.create_user(conn, "u1")
            order_id = self.create_order(conn, uid)
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, order_id, status, expires_at) "
                "VALUES (?, ?, ?, 'pending', datetime('now', '+5 minutes'))",
                ("tok", uid, order_id),
            )
            conn.commit()
        finally:
            conn.close()

        self.assertIsNotNone(deliver_order(order_id, "test"))

        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            _cancel_purchase_session(conn, "tok", order_id)
            conn.commit()
        finally:
            conn.close()

        self.assertEqual(self.scalar("SELECT status FROM orders WHERE id = ?", (order_id,)), "delivered")
        self.assertEqual(self.scalar("SELECT status FROM purchase_sessions WHERE token = ?", ("tok",)), "delivered")


if __name__ == "__main__":
    unittest.main()
