import os
import tempfile
import time
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-purchase-checkout")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.domain.purchase import PurchaseStatus
from app.main import app
from app.repositories.purchase_checkout_repository import SqlitePurchaseCheckoutRepository
from app.repositories.purchase_status_repository import SqlitePurchaseStatusRepository
from app.security import create_access_token
from app.services import payment_qr_service
from app.services.payment_service import PLAN_BY_KEY, create_order_record, process_payment_event
from app.services.purchase_checkout_service import (
    PurchaseAccountUnavailable,
    PurchaseCheckoutNotFound,
    PurchaseCheckoutService,
)
from app.services.purchase_status_service import PurchaseStatusService


def _png_chunk(chunk_type: bytes, content: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + content) & 0xFFFFFFFF
    return len(content).to_bytes(4, "big") + chunk_type + content + crc.to_bytes(4, "big")


def _test_png(width: int = 128, height: int = 128) -> bytes:
    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    row = b"\x00" + (b"\xff\xff\xff" * width)
    pixels = zlib.compress(row * height)
    return payment_qr_service.PNG_SIGNATURE + _png_chunk(b"IHDR", header) + _png_chunk(b"IDAT", pixels) + _png_chunk(b"IEND", b"")


class PurchaseCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.previous_qr_directory = payment_qr_service.PAYMENT_QR_DIRECTORY
        payment_qr_service.PAYMENT_QR_DIRECTORY = self.root / "payment_qr"
        config.DATABASE_PATH = str(self.root / "vf.db")
        init_db()
        conn = get_connection()
        try:
            self.user_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES ('checkout-user', 'checkout@example.test', 'hash')"
            ).lastrowid)
            self.other_user_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES ('other-user', 'other@example.test', 'hash')"
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()
        for method in ("wechat", "alipay"):
            payment_qr_service.save_payment_qr_png("1h", method, _test_png())

    def tearDown(self):
        payment_qr_service.PAYMENT_QR_DIRECTORY = self.previous_qr_directory
        self.tmpdir.cleanup()

    @staticmethod
    def _headers(user_id: int) -> dict[str, str]:
        return {"Authorization": f"Bearer {create_access_token(user_id, False)}"}

    def _purchase_link(self, user_id: int):
        return TestClient(app).post("/api/client/purchase-link", headers=self._headers(user_id))

    def test_repeated_purchase_links_reuse_one_active_checkout(self):
        first = self._purchase_link(self.user_id)
        second = self._purchase_link(self.user_id)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertFalse(first.json()["reused"])
        self.assertTrue(second.json()["reused"])
        self.assertEqual(first.json()["token"], second.json()["token"])
        self.assertEqual(second.json()["status"], "open")
        self.assertEqual(second.json()["order_id"], 0)
        conn = get_connection()
        try:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM purchase_sessions WHERE user_id = ? AND status IN ('open', 'pending')",
                (self.user_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(active_count, 1)

    def test_deleted_account_cannot_acquire_checkout(self):
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (self.user_id,))
            conn.commit()
        finally:
            conn.close()

        checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())
        with self.assertRaises(PurchaseAccountUnavailable) as raised:
            checkout_service.acquire_checkout(self.user_id, "127.0.0.1")

        self.assertEqual(raised.exception.account_state, "deleted")

    def test_deleted_account_cannot_create_order_from_existing_checkout(self):
        checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())
        checkout = checkout_service.acquire_checkout(self.user_id, "127.0.0.1")
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (self.user_id,))
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(PurchaseAccountUnavailable) as raised:
            checkout_service.create_order(checkout.token, "1h", "wechat", "127.0.0.1")

        self.assertEqual(raised.exception.account_state, "deleted")

    def test_purchase_token_routes_reject_oversized_path_tokens(self):
        token = "x" * 129
        client = TestClient(app)

        public_page = client.get(f"/client/purchase/{token}")
        self.assertEqual(public_page.status_code, 422, public_page.text)

        authenticated_status = client.get(
            f"/api/client/purchase-status/{token}",
            headers=self._headers(self.user_id),
        )
        self.assertEqual(authenticated_status.status_code, 422, authenticated_status.text)

    def test_purchase_services_reject_oversized_tokens_without_prefix_lookup(self):
        token = "T" * 128
        oversized_token = token + "X"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES (?, ?, 'open', datetime('now', '+5 minutes'))",
                (token, self.user_id),
            )
            conn.commit()
        finally:
            conn.close()

        checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())
        status_service = PurchaseStatusService(SqlitePurchaseStatusRepository())

        self.assertIsNone(checkout_service.get_page(oversized_token).session)
        self.assertEqual(checkout_service.get_authenticated_status(self.user_id, oversized_token)["status"], "not_found")
        with self.assertRaises(PurchaseCheckoutNotFound):
            checkout_service.cancel_checkout(oversized_token)

        public_status = status_service.get_public_status(oversized_token)
        self.assertFalse(public_status.is_found)
        self.assertEqual(public_status.status, PurchaseStatus.INVALID)

        conn = get_connection()
        try:
            SqlitePurchaseCheckoutRepository.transition_checkout_status(conn, oversized_token, session_status="cancelled")
            conn.commit()
            row = conn.execute("SELECT status FROM purchase_sessions WHERE token = ?", (token,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["status"], "open")

    def test_public_status_maps_abandoned_session_to_cancelled(self):
        token = "abandoned-public-status"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES (?, ?, 'abandoned', datetime('now', '+5 minutes'))",
                (token, self.user_id),
            )
            conn.commit()
        finally:
            conn.close()

        status = PurchaseStatusService(SqlitePurchaseStatusRepository()).get_public_status(token)

        self.assertTrue(status.is_found)
        self.assertEqual(status.status, PurchaseStatus.CANCELLED)
        self.assertTrue(status.is_terminal)

    def test_public_status_marks_refund_required_order_as_terminal(self):
        token = "refund-required-public-status"
        conn = get_connection()
        try:
            order_id, _ = create_order_record(conn, self.user_id, "1h", PLAN_BY_KEY["1h"].price, "", "vmq")
            conn.execute("UPDATE orders SET status = 'refund_required' WHERE id = ?", (order_id,))
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, order_id, status, expires_at) "
                "VALUES (?, ?, ?, 'cancelled', datetime('now', '+5 minutes'))",
                (token, self.user_id, order_id),
            )
            conn.commit()
        finally:
            conn.close()

        status = PurchaseStatusService(SqlitePurchaseStatusRepository()).get_public_status(token)

        self.assertTrue(status.is_found)
        self.assertEqual(status.status, PurchaseStatus.REFUND_REQUIRED)
        self.assertTrue(status.is_terminal)
        authenticated = TestClient(app).get(
            f"/api/client/purchase-status/{token}",
            headers=self._headers(self.user_id),
        )
        self.assertEqual(authenticated.status_code, 200, authenticated.text)
        self.assertEqual(authenticated.json()["status"], "refund_required")

    def test_orphan_pending_session_is_expired_before_new_checkout(self):
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES ('orphan-pending', ?, 'pending', datetime('now', '+15 minutes'))",
                (self.user_id,),
            )
            conn.commit()
        finally:
            conn.close()

        status = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository()).get_authenticated_status(
            self.user_id,
            "orphan-pending",
        )
        self.assertEqual(status["status"], "expired")

        response = self._purchase_link(self.user_id)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["reused"])
        conn = get_connection()
        try:
            orphan_status = conn.execute(
                "SELECT status FROM purchase_sessions WHERE token = 'orphan-pending'"
            ).fetchone()["status"]
        finally:
            conn.close()
        self.assertEqual(orphan_status, "expired")

    def test_authenticated_status_is_read_only_while_payment_writer_holds_lock(self):
        checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())
        checkout = checkout_service.acquire_checkout(self.user_id, "127.0.0.1")
        writer = get_connection()
        try:
            writer.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            status = checkout_service.get_authenticated_status(self.user_id, checkout.token)
            elapsed = time.monotonic() - started
        finally:
            writer.rollback()
            writer.close()

        self.assertEqual(status["status"], "open")
        self.assertLess(elapsed, 1.0)

    def test_authenticated_status_reports_expiry_without_writing_poll_state(self):
        token = "expired-status-read"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES (?, ?, 'open', datetime('now', '-1 minute'))",
                (token, self.user_id),
            )
            conn.commit()
        finally:
            conn.close()

        status = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository()).get_authenticated_status(
            self.user_id,
            token,
        )

        self.assertEqual(status["status"], "expired")
        conn = get_connection()
        try:
            stored_status = conn.execute(
                "SELECT status FROM purchase_sessions WHERE token = ?",
                (token,),
            ).fetchone()["status"]
        finally:
            conn.close()
        self.assertEqual(stored_status, "open")

    def test_concurrent_purchase_links_return_one_token(self):
        with ThreadPoolExecutor(max_workers=20) as pool:
            responses = list(pool.map(lambda _: self._purchase_link(self.user_id), range(20)))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(len({response.json()["token"] for response in responses}), 1)
        self.assertEqual(sum(not response.json()["reused"] for response in responses), 1)

    def test_open_tabs_follow_the_order_created_in_another_tab(self):
        link = self._purchase_link(self.user_id).json()
        token = link["token"]
        client = TestClient(app)

        open_page = client.get(f"/client/purchase/{token}")
        self.assertIn("vfPollPurchaseStatus", open_page.text)
        self.assertNotIn("pagehide", open_page.text)
        self.assertNotIn(f"/client/purchase/{token}/abandon", open_page.text)

        order_page = client.post(
            f"/client/purchase/{token}/order",
            data={"plan": "1h", "payment_method": "wechat"},
        )
        self.assertEqual(order_page.status_code, 200, order_page.text)
        self.assertIn("请使用微信扫一扫付款", order_page.text)
        self.assertIn("使用其他应用扫描不会进入付款页面", order_page.text)

        status = client.get(f"/client/purchase/{token}/status")
        self.assertEqual(status.json()["status"], "pending")
        self.assertGreater(status.json()["order_id"], 0)
        self.assertTrue(status.json()["expires_at"])
        self.assertGreater(status.json()["remaining_seconds"], 0)

        reused = self._purchase_link(self.user_id).json()
        self.assertEqual(reused["token"], token)
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["status"], "pending")
        self.assertEqual(reused["order_id"], status.json()["order_id"])

    def test_slot_conflict_is_business_409_and_other_channel_remains_available(self):
        owner = self._purchase_link(self.user_id).json()
        owner_order = TestClient(app).post(
            f"/client/purchase/{owner['token']}/order",
            data={"plan": "1h", "payment_method": "wechat"},
        )
        self.assertEqual(owner_order.status_code, 200, owner_order.text)

        other = self._purchase_link(self.other_user_id).json()
        selection = TestClient(app).get(f"/client/purchase/{other['token']}")
        self.assertIn("微信支付暂被占用", selection.text)
        self.assertIn("支付宝支付", selection.text)

        busy = TestClient(app).post(
            f"/client/purchase/{other['token']}/order",
            data={"plan": "1h", "payment_method": "wechat"},
        )
        self.assertEqual(busy.status_code, 409, busy.text)
        self.assertIn("PAYMENT_SLOT_OCCUPIED", busy.text)
        self.assertIn("请选择支付宝支付或其他套餐", busy.text)

        alipay = TestClient(app).post(
            f"/client/purchase/{other['token']}/order",
            data={"plan": "1h", "payment_method": "alipay"},
        )
        self.assertEqual(alipay.status_code, 200, alipay.text)
        self.assertIn("请使用支付宝扫一扫付款", alipay.text)

    def test_explicit_cancel_is_terminal_but_late_payment_delivers_once(self):
        link = self._purchase_link(self.user_id).json()
        token = link["token"]
        client = TestClient(app)
        client.post(
            f"/client/purchase/{token}/order",
            data={"plan": "1h", "payment_method": "wechat"},
        )
        close_notice = client.post(f"/client/purchase/{token}/abandon")
        self.assertEqual(close_notice.status_code, 200, close_notice.text)

        conn = get_connection()
        try:
            before = conn.execute(
                "SELECT ps.status AS session_status, o.status AS order_status "
                "FROM purchase_sessions ps JOIN orders o ON o.id = ps.order_id WHERE ps.token = ?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(before["session_status"], "pending")
        self.assertEqual(before["order_status"], "pending")

        cancelled = client.post(f"/client/purchase/{token}/cancel")
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        conn = get_connection()
        try:
            order = conn.execute(
                "SELECT o.id, o.amount, o.merchant_order_no, o.status AS order_status, ps.status AS session_status "
                "FROM purchase_sessions ps JOIN orders o ON o.id = ps.order_id WHERE ps.token = ?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(order["session_status"], "cancelled")
        self.assertEqual(order["order_status"], "cancelled")

        payload = {
            "merchant_order_no": order["merchant_order_no"],
            "trade_no": "late-checkout-payment",
            "payment_method": "wechat",
        }
        first = process_payment_event("checkout-test", "checkout-test:late-payment", order["amount"], payload)
        second = process_payment_event("checkout-test", "checkout-test:late-payment", order["amount"], payload)
        self.assertEqual(first["status"], "delivered")
        self.assertTrue(second["duplicate"])
        conn = get_connection()
        try:
            recharge_count = conn.execute(
                "SELECT COUNT(*) FROM time_recharges WHERE order_id = ?",
                (order["id"],),
            ).fetchone()[0]
            final = conn.execute(
                "SELECT ps.status AS session_status, o.status AS order_status "
                "FROM purchase_sessions ps JOIN orders o ON o.id = ps.order_id WHERE ps.token = ?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(recharge_count, 1)
        self.assertEqual(final["session_status"], "delivered")
        self.assertEqual(final["order_status"], "delivered")

    def test_init_db_reconciles_duplicate_active_sessions_before_unique_index(self):
        conn = get_connection()
        try:
            conn.execute("DROP INDEX IF EXISTS idx_purchase_sessions_active_user_unique")
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES ('duplicate-open', ?, 'open', datetime('now', '+5 minutes'))",
                (self.user_id,),
            )
            order_id, _ = create_order_record(
                conn,
                self.user_id,
                PLAN_BY_KEY["1h"].key,
                PLAN_BY_KEY["1h"].price,
                payment_method="wechat",
            )
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, order_id, status, expires_at) "
                "VALUES ('duplicate-pending', ?, ?, 'pending', datetime('now', '+15 minutes'))",
                (self.user_id, order_id),
            )
            conn.commit()
        finally:
            conn.close()

        init_db()

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT token, status FROM purchase_sessions WHERE user_id = ? ORDER BY token",
                (self.user_id,),
            ).fetchall()
            index_row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_purchase_sessions_active_user_unique'"
            ).fetchone()
        finally:
            conn.close()
        active = [row["token"] for row in rows if row["status"] in {"open", "pending"}]
        self.assertEqual(active, ["duplicate-pending"])
        self.assertIsNotNone(index_row)


if __name__ == "__main__":
    unittest.main()
