import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-alipay-payment")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.routes import payment as payment_route
from app.security import CSRF_COOKIE_NAME, create_access_token, generate_csrf_token
from app.services import payment_qr_service
from app.services.payment_service import (
    PLAN_BY_KEY,
    PaymentSlotOccupiedError,
    create_order_record,
    process_payment_event,
)


def _png_chunk(chunk_type: bytes, content: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + content) & 0xFFFFFFFF
    return len(content).to_bytes(4, "big") + chunk_type + content + crc.to_bytes(4, "big")


def _test_png(width: int = 128, height: int = 128) -> bytes:
    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    row = b"\x00" + (b"\xff\xff\xff" * width)
    pixels = zlib.compress(row * height)
    return payment_qr_service.PNG_SIGNATURE + _png_chunk(b"IHDR", header) + _png_chunk(b"IDAT", pixels) + _png_chunk(b"IEND", b"")


class AlipayPaymentTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.previous_qr_directory = payment_qr_service.PAYMENT_QR_DIRECTORY
        self.previous_webhook_secret = config.VMQ_WEBHOOK_SECRET
        self.previous_monitor_host = config.VMQ_MONITOR_HOST
        payment_qr_service.PAYMENT_QR_DIRECTORY = self.root / "payment_qr"
        config.DATABASE_PATH = str(self.root / "vf.db")
        config.VMQ_WEBHOOK_SECRET = "alipay-webhook-secret"
        config.VMQ_MONITOR_HOST = "81.70.189.154"
        init_db()
        conn = get_connection()
        try:
            self.admin_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES ('admin', 'admin@example.test', 'hash', 1)"
            ).lastrowid)
            self.wechat_user_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES ('wechat-user', 'wechat@example.test', 'hash')"
            ).lastrowid)
            self.alipay_user_id = int(conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES ('alipay-user', 'alipay@example.test', 'hash')"
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        payment_qr_service.PAYMENT_QR_DIRECTORY = self.previous_qr_directory
        config.VMQ_WEBHOOK_SECRET = self.previous_webhook_secret
        config.VMQ_MONITOR_HOST = self.previous_monitor_host
        self.tmpdir.cleanup()

    def _create_channel_orders(self) -> tuple[int, int]:
        plan = PLAN_BY_KEY["1h"]
        conn = get_connection()
        try:
            wechat_order_id, _ = create_order_record(conn, self.wechat_user_id, plan.key, plan.price, payment_method="wechat")
            alipay_order_id, _ = create_order_record(conn, self.alipay_user_id, plan.key, plan.price, payment_method="alipay")
            conn.commit()
            return wechat_order_id, alipay_order_id
        finally:
            conn.close()

    def _order_status(self, order_id: int) -> str:
        conn = get_connection()
        try:
            return str(conn.execute("SELECT status FROM orders WHERE id = ?", (order_id,)).fetchone()["status"])
        finally:
            conn.close()

    def _vmq_params(
        self,
        *,
        vmq_type: str = "2",
        price: str | None = None,
        timestamp: str | None = None,
        **extra: str,
    ) -> dict[str, str]:
        amount = price or f"{PLAN_BY_KEY['1h'].price:.2f}"
        callback_timestamp = timestamp or str(int(time.time() * 1000))
        signature = hashlib.md5(
            f"{vmq_type}{amount}{callback_timestamp}{config.VMQ_WEBHOOK_SECRET}".encode()
        ).hexdigest()
        return {
            "t": callback_timestamp,
            "type": vmq_type,
            "price": amount,
            "sign": signature,
            **extra,
        }

    def test_vmq_type_two_delivers_only_alipay_order(self):
        wechat_order_id, alipay_order_id = self._create_channel_orders()

        response = TestClient(app).get("/appPush", params=self._vmq_params())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["code"], 1)
        self.assertEqual(response.json()["msg"], "成功")
        self.assertEqual(self._order_status(alipay_order_id), "delivered")
        self.assertEqual(self._order_status(wechat_order_id), "pending")

    def test_vmq_callback_keeps_purchase_status_responsive_while_delivery_runs(self):
        delivery_started = threading.Event()
        release_delivery = threading.Event()
        delivery_finished = threading.Event()

        def blocked_delivery(*_args):
            delivery_started.set()
            release_delivery.wait(timeout=2.0)
            delivery_finished.set()
            return {"status": "delivered", "order_id": 0, "late_settlement": False}

        with patch("app.routes.payment.process_payment_event", side_effect=blocked_delivery):
            with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as executor:
                callback = executor.submit(
                    client.get,
                    "/appPush",
                    params=self._vmq_params(),
                )
                self.assertTrue(delivery_started.wait(timeout=1.0))
                status = executor.submit(client.get, "/client/purchase/not-found/status")
                try:
                    response = status.result(timeout=0.5)
                    self.assertFalse(delivery_finished.is_set())
                finally:
                    release_delivery.set()

                callback_response = callback.result(timeout=1.0)

        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(callback_response.status_code, 200, callback_response.text)

    def test_json_webhook_offloads_payment_delivery(self):
        body = json.dumps({"amount": f"{PLAN_BY_KEY['1h'].price:.2f}", "trade_no": "threadpool-webhook"}).encode("utf-8")
        signature = hmac.new(config.VMQ_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
        expected = {"status": "delivered", "order_id": 0, "late_settlement": False}

        with patch("app.routes.payment.run_in_threadpool", new_callable=AsyncMock) as offload:
            offload.return_value = expected
            response = TestClient(app).post(
                "/api/payment/webhook",
                content=body,
                headers={"X-VisionForge-Signature": signature, "Content-Type": "application/json"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), expected)
        offload.assert_awaited_once()
        self.assertIs(offload.call_args.args[0], process_payment_event)
        self.assertEqual(offload.call_args.args[1], "json")

    def test_vmq_callback_supports_legacy_event_key_schema(self):
        conn = get_connection()
        try:
            conn.execute("DROP TABLE payment_events")
            conn.execute(
                "CREATE TABLE payment_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "source TEXT NOT NULL, "
                "event_key TEXT NOT NULL, "
                "order_id INTEGER REFERENCES orders(id), "
                "amount REAL NOT NULL DEFAULT 0, "
                "raw_payload TEXT NOT NULL DEFAULT '', "
                "created_at TEXT NOT NULL DEFAULT (datetime('now')), "
                "event_id TEXT NOT NULL DEFAULT '', "
                "status TEXT NOT NULL DEFAULT 'received', "
                "merchant_order_no TEXT NOT NULL DEFAULT '', "
                "provider_trade_no TEXT NOT NULL DEFAULT '', "
                "payment_method TEXT NOT NULL DEFAULT '', "
                "processed_at TEXT, "
                "attempt_count INTEGER NOT NULL DEFAULT 0, "
                "UNIQUE(source, event_key))"
            )
            conn.commit()
        finally:
            conn.close()
        _, alipay_order_id = self._create_channel_orders()

        response = TestClient(app).get("/appPush", params=self._vmq_params())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["code"], 1)
        self.assertEqual(self._order_status(alipay_order_id), "delivered")
        conn = get_connection()
        try:
            event = conn.execute("SELECT event_id, event_key FROM payment_events").fetchone()
        finally:
            conn.close()
        self.assertEqual(event["event_key"], event["event_id"])

    def test_vmq_type_two_rejects_type_one_signature(self):
        params = self._vmq_params()
        params["sign"] = hashlib.md5(
            f"1{params['price']}{params['t']}{config.VMQ_WEBHOOK_SECRET}".encode()
        ).hexdigest()

        response = TestClient(app).get("/appPush", params=params)

        self.assertEqual(response.json(), {"code": -1, "msg": "bad signature"})

    def test_vmq_unsigned_query_fields_cannot_change_event_identity_or_matching(self):
        _, alipay_order_id = self._create_channel_orders()
        signed_params = self._vmq_params()

        first = TestClient(app).get(
            "/appPush",
            params={**signed_params, "trade_no": "unsigned-first"},
        )
        second = TestClient(app).get(
            "/appPush",
            params={**signed_params, "trade_no": "unsigned-second"},
        )

        self.assertEqual(first.json()["code"], 1, first.text)
        self.assertEqual(second.json()["code"], 1, second.text)
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(self._order_status(alipay_order_id), "delivered")
        conn = get_connection()
        try:
            events = conn.execute(
                "SELECT event_id, provider_trade_no FROM payment_events WHERE source = 'vmq'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(events), 1)
        self.assertEqual(str(events[0]["provider_trade_no"] or ""), "")

    def test_vmq_new_timestamp_replay_cannot_deliver_a_second_order(self):
        _, first_order_id = self._create_channel_orders()
        first_params = self._vmq_params()
        first = TestClient(app).get("/appPush", params=first_params)
        self.assertEqual(first.json()["code"], 1, first.text)
        self.assertEqual(self._order_status(first_order_id), "delivered")

        conn = get_connection()
        try:
            second_order_id = int(conn.execute(
                "INSERT INTO orders "
                "(user_id, plan, amount, merchant_order_no, payment_method) "
                "VALUES (?, '1h', ?, 'VF-REPLAY-TARGET', 'alipay')",
                (self.wechat_user_id, PLAN_BY_KEY["1h"].price),
            ).lastrowid)
            conn.commit()
        finally:
            conn.close()

        replay_timestamp = str(int(first_params["t"]) + 1)
        replay = TestClient(app).get(
            "/appPush",
            params=self._vmq_params(timestamp=replay_timestamp),
        )

        self.assertEqual(replay.json(), {"code": -1, "msg": "no match"})
        self.assertEqual(self._order_status(second_order_id), "pending")
        conn = get_connection()
        try:
            second_balance = conn.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (self.wechat_user_id,),
            ).fetchone()
            event_statuses = [
                str(row["status"])
                for row in conn.execute(
                    "SELECT status FROM payment_events WHERE source = 'vmq' ORDER BY id"
                ).fetchall()
            ]
        finally:
            conn.close()
        self.assertIsNone(second_balance)
        self.assertEqual(event_statuses, ["delivered", "possible_duplicate"])

    def test_delivered_amount_slot_remains_reserved_during_vmq_replay_window(self):
        _, first_order_id = self._create_channel_orders()
        response = TestClient(app).get("/appPush", params=self._vmq_params())
        self.assertEqual(response.json()["code"], 1, response.text)
        self.assertEqual(self._order_status(first_order_id), "delivered")

        conn = get_connection()
        try:
            with self.assertRaises(PaymentSlotOccupiedError):
                create_order_record(
                    conn,
                    self.wechat_user_id,
                    "1h",
                    PLAN_BY_KEY["1h"].price,
                    payment_method="alipay",
                )
        finally:
            conn.close()

    def test_vmq_rejects_expired_and_future_signed_timestamps(self):
        now_millis = int(time.time() * 1000)
        expired = str(
            now_millis - (payment_route.VMQ_CALLBACK_MAX_AGE_SECONDS + 1) * 1000
        )
        future = str(
            now_millis + (payment_route.VMQ_CALLBACK_MAX_FUTURE_SKEW_SECONDS + 1) * 1000
        )

        expired_response = TestClient(app).get(
            "/appPush", params=self._vmq_params(timestamp=expired)
        )
        future_response = TestClient(app).get(
            "/appPush", params=self._vmq_params(timestamp=future)
        )

        self.assertEqual(expired_response.json(), {"code": -1, "msg": "bad timestamp"})
        self.assertEqual(future_response.json(), {"code": -1, "msg": "bad timestamp"})

    def test_vmq_heartbeat_verifies_signature_and_timestamp(self):
        timestamp = str(int(time.time() * 1000))
        signature = hashlib.md5(
            f"{timestamp}{config.VMQ_WEBHOOK_SECRET}".encode()
        ).hexdigest()

        accepted = TestClient(app).get(
            "/appHeart", params={"t": timestamp, "sign": signature}
        )
        bad_signature = TestClient(app).get(
            "/appHeart", params={"t": timestamp, "sign": "0" * 32}
        )

        self.assertEqual(accepted.json(), payment_route.VMQ_SUCCESS_RESPONSE)
        self.assertEqual(bad_signature.json(), {"code": -1, "msg": "bad signature"})

    def test_reference_callback_rejects_cross_channel_delivery(self):
        plan = PLAN_BY_KEY["1h"]
        conn = get_connection()
        try:
            order_id, merchant_order_no = create_order_record(conn, self.wechat_user_id, plan.key, plan.price, payment_method="wechat")
            conn.commit()
        finally:
            conn.close()

        result = process_payment_event(
            "json",
            "json:trade:wrong-channel",
            plan.price,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "wrong-channel",
                "payment_method": "alipay",
            },
        )

        self.assertEqual(result["status"], "payment_method_mismatch")
        self.assertEqual(self._order_status(order_id), "pending")

    def test_reference_callback_rejects_unknown_explicit_payment_method(self):
        plan = PLAN_BY_KEY["1h"]
        conn = get_connection()
        try:
            order_id, merchant_order_no = create_order_record(conn, self.wechat_user_id, plan.key, plan.price, payment_method="wechat")
            conn.commit()
        finally:
            conn.close()

        result = process_payment_event(
            "json",
            "json:trade:unknown-channel",
            plan.price,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "unknown-channel",
                "payment_method": "wechat-enterprise",
            },
        )

        self.assertEqual(result["status"], "payment_method_mismatch")
        self.assertFalse(result["matched"])
        self.assertEqual(self._order_status(order_id), "pending")
        conn = get_connection()
        try:
            event = conn.execute(
                "SELECT status, order_id, payment_method FROM payment_events WHERE event_id = ?",
                ("json:trade:unknown-channel",),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(event["status"], "payment_method_mismatch")
        self.assertIsNone(event["order_id"])
        self.assertEqual(event["payment_method"], "wechat-enterprise")

    def test_reference_callback_preserves_overlong_unknown_payment_method(self):
        plan = PLAN_BY_KEY["1h"]
        conn = get_connection()
        try:
            order_id, merchant_order_no = create_order_record(
                conn, self.wechat_user_id, plan.key, plan.price, payment_method="wechat"
            )
            conn.commit()
        finally:
            conn.close()
        unknown_method = "wechat-enterprise-" + ("x" * 80)

        result = process_payment_event(
            "json",
            "json:trade:unknown-channel-long",
            plan.price,
            {
                "merchant_order_no": merchant_order_no,
                "trade_no": "unknown-channel-long",
                "payment_method": unknown_method,
            },
        )

        self.assertEqual(result["status"], "payment_method_mismatch")
        self.assertFalse(result["matched"])
        self.assertEqual(self._order_status(order_id), "pending")
        conn = get_connection()
        try:
            event = conn.execute(
                "SELECT status, order_id, payment_method FROM payment_events WHERE event_id = ?",
                ("json:trade:unknown-channel-long",),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(event["status"], "payment_method_mismatch")
        self.assertIsNone(event["order_id"])
        self.assertEqual(event["payment_method"], unknown_method)

    def test_purchase_page_and_order_contract_include_alipay(self):
        plan = PLAN_BY_KEY["1h"]
        payment_qr_service.save_payment_qr_png(plan.key, "wechat", _test_png())
        payment_qr_service.save_payment_qr_png(plan.key, "alipay", _test_png())
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) VALUES (?, ?, 'open', datetime('now', '+15 minutes'))",
                ("alipay-purchase", self.alipay_user_id),
            )
            conn.commit()
        finally:
            conn.close()

        client = TestClient(app)
        page = client.get("/client/purchase/alipay-purchase")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn('value="alipay"', page.text)
        order_response = client.post(
            "/client/purchase/alipay-purchase/order",
            data={"plan": plan.key, "payment_method": "alipay"},
        )
        self.assertEqual(order_response.status_code, 200, order_response.text)
        conn = get_connection()
        try:
            method = conn.execute("SELECT payment_method FROM orders ORDER BY id DESC LIMIT 1").fetchone()["payment_method"]
        finally:
            conn.close()
        self.assertEqual(method, "alipay")

    def test_purchase_page_tracks_payment_until_order_is_delivered(self):
        plan = PLAN_BY_KEY["1h"]
        payment_qr_service.save_payment_qr_png(plan.key, "alipay", _test_png())
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO purchase_sessions (token, user_id, status, expires_at) "
                "VALUES (?, ?, 'open', datetime('now', '+15 minutes'))",
                ("status-sync-purchase", self.alipay_user_id),
            )
            conn.commit()
        finally:
            conn.close()

        client = TestClient(app)
        order_page = client.post(
            "/client/purchase/status-sync-purchase/order",
            data={"plan": plan.key, "payment_method": "alipay"},
        )
        self.assertEqual(order_page.status_code, 200, order_page.text)
        self.assertIn("/client/purchase/status-sync-purchase/status", order_page.text)
        self.assertIn("vfPollPurchaseStatus", order_page.text)
        self.assertIn("window.location.replace('/client/purchase/status-sync-purchase')", order_page.text)

        pending = client.get("/client/purchase/status-sync-purchase/status")
        self.assertEqual(pending.status_code, 200, pending.text)
        self.assertEqual(
            pending.json(),
            {
                "ok": True,
                "status": "pending",
                "status_text": "待支付",
                "terminal": False,
                "order_id": pending.json()["order_id"],
                "expires_at": pending.json()["expires_at"],
                "remaining_seconds": pending.json()["remaining_seconds"],
            },
        )
        self.assertGreater(pending.json()["order_id"], 0)
        self.assertEqual(pending.headers["cache-control"], "no-store, max-age=0")

        conn = get_connection()
        try:
            order = conn.execute(
                "SELECT id, merchant_order_no FROM orders WHERE id = ?",
                (pending.json()["order_id"],),
            ).fetchone()
        finally:
            conn.close()
        delivery = process_payment_event(
            "status-sync-test",
            "status-sync-test:trade:delivered",
            plan.price,
            {
                "merchant_order_no": order["merchant_order_no"],
                "trade_no": "status-sync-delivered",
                "payment_method": "alipay",
            },
        )
        self.assertEqual(delivery["status"], "delivered")

        delivered = client.get("/client/purchase/status-sync-purchase/status")
        self.assertEqual(delivered.status_code, 200, delivered.text)
        self.assertEqual(delivered.json()["status"], "delivered")
        self.assertEqual(delivered.json()["status_text"], "已到账")
        self.assertTrue(delivered.json()["terminal"])
        completed_page = client.get("/client/purchase/status-sync-purchase")
        self.assertIn("支付已完成", completed_page.text)
        self.assertIn("已到账", completed_page.text)

    def test_purchase_page_status_does_not_expose_private_order_data(self):
        response = TestClient(app).get("/client/purchase/unknown-token/status")

        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(
            response.json(),
            {
                "ok": False,
                "status": "invalid",
                "status_text": "无效会话",
                "terminal": True,
                "order_id": 0,
                "expires_at": "",
                "remaining_seconds": 0,
            },
        )
        self.assertNotIn("user_id", response.text)
        self.assertNotIn("balance_seconds", response.text)

    def test_admin_can_upload_validated_alipay_qr(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/payment-qr/upload",
            data={"csrf_token": csrf_token, "plan": "1h", "payment_method": "alipay"},
            files={"qr_file": ("alipay.png", _test_png(), "image/png")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertTrue(payment_qr_service.payment_qr_path("1h", "alipay").is_file())
        conn = get_connection()
        try:
            audit = conn.execute("SELECT action, target_id FROM admin_audit ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        self.assertEqual(audit["action"], "payment_qr.upload")
        self.assertEqual(audit["target_id"], "alipay:1h")

    @unittest.skipIf(os.name == "nt", "POSIX file modes are not enforced on Windows")
    def test_saved_payment_qr_is_group_readable_but_not_world_readable(self):
        payment_qr_service.save_payment_qr_png("1h", "alipay", _test_png())

        saved_path = payment_qr_service.payment_qr_path("1h", "alipay")
        saved_mode = stat.S_IMODE(saved_path.stat().st_mode)
        self.assertEqual(saved_mode, payment_qr_service.PAYMENT_QR_FILE_MODE)

    @unittest.skipIf(os.name == "nt", "POSIX chmod is not used on Windows")
    def test_payment_qr_permission_failure_does_not_leave_temporary_file(self):
        with patch(
            "app.services.payment_qr_service.os.chmod",
            side_effect=PermissionError("permission hardening failed"),
        ):
            with self.assertRaises(PermissionError):
                payment_qr_service.save_payment_qr_png("1h", "alipay", _test_png())

        qr_directory = payment_qr_service.PAYMENT_QR_DIRECTORY
        self.assertFalse(payment_qr_service.payment_qr_path("1h", "alipay").exists())
        self.assertEqual(list(qr_directory.iterdir()), [])

    def test_admin_qr_upload_rejects_oversized_declared_body_before_save(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/payment-qr/upload",
            data={"csrf_token": csrf_token, "plan": "1h", "payment_method": "alipay"},
            files={"qr_file": ("alipay.png", _test_png(), "image/png")},
            headers={"content-length": str(payment_qr_service.MAX_PAYMENT_QR_BYTES + 128 * 1024)},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("payload+too+large", response.headers["location"])
        self.assertFalse(payment_qr_service.payment_qr_path("1h", "alipay").exists())

    def test_invalid_upload_does_not_replace_existing_alipay_qr(self):
        existing_content = _test_png()
        payment_qr_service.save_payment_qr_png("1h", "alipay", existing_content)
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        response = client.post(
            "/admin/payment-qr/upload",
            data={"csrf_token": csrf_token, "plan": "1h", "payment_method": "alipay"},
            files={"qr_file": ("broken.png", b"not-a-png", "image/png")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("error=", response.headers["location"])
        self.assertEqual(payment_qr_service.payment_qr_path("1h", "alipay").read_bytes(), existing_content)

    def test_monitor_config_requires_explicit_admin_post_and_is_not_cached(self):
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)

        ordinary_page = client.get("/admin/payment-qr")
        self.assertEqual(ordinary_page.status_code, 200, ordinary_page.text)
        self.assertNotIn(config.VMQ_WEBHOOK_SECRET, ordinary_page.text)
        response = client.post(
            "/admin/payment-qr/monitor-config",
            data={"csrf_token": csrf_token},
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(config.VMQ_MONITOR_HOST, response.text)
        self.assertIn(config.VMQ_WEBHOOK_SECRET, response.text)
        self.assertIn("no-store", response.headers["cache-control"])
        conn = get_connection()
        try:
            audit = conn.execute("SELECT action, detail_json FROM admin_audit ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        self.assertEqual(audit["action"], "payment_monitor.reveal_config")
        self.assertNotIn(config.VMQ_WEBHOOK_SECRET, audit["detail_json"])


if __name__ == "__main__":
    unittest.main()
