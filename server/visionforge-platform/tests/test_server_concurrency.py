import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-server-concurrency")

from app.config import config
from app.database import get_connection, init_db
from app.services.log_service import store_log_file
from app.services.payment_service import PLAN_BY_KEY, create_order_record, process_payment_event


class ServerConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        root = Path(self.tmpdir.name)
        config.DATABASE_PATH = str(root / "vf.db")
        config.LOG_STORAGE_PATH = str(root / "logs")
        init_db()
        conn = get_connection()
        try:
            self.user_id = int(
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES ('pressure-user', 'pressure@example.test', 'hash')"
                ).lastrowid
            )
            conn.execute("INSERT INTO time_balance (user_id) VALUES (?)", (self.user_id,))
            self.order_id, _ = create_order_record(
                conn,
                self.user_id,
                "1h",
                PLAN_BY_KEY["1h"].price,
                "",
                "vmq",
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_concurrent_duplicate_payment_callbacks_deliver_once(self):
        event_id = "json:trade:PRESSURE-PAYMENT"
        amount_text = f"{PLAN_BY_KEY['1h'].price:.2f}"
        payload = {"amount": amount_text, "trade_no": "PRESSURE-PAYMENT"}

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(
                executor.map(
                    lambda _: process_payment_event("json", event_id, amount_text, payload),
                    range(64),
                )
            )

        self.assertTrue(all(result["status"] == "delivered" for result in results))
        self.assertEqual(sum(1 for result in results if not result["duplicate"]), 1)
        conn = get_connection()
        try:
            balance = conn.execute("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (self.user_id,)).fetchone()[0]
            recharge_count = conn.execute("SELECT COUNT(*) FROM time_recharges WHERE order_id = ?", (self.order_id,)).fetchone()[0]
            event_count = conn.execute("SELECT COUNT(*) FROM payment_events WHERE event_id = ?", (event_id,)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(balance, 3600)
        self.assertEqual(recharge_count, 1)
        self.assertEqual(event_count, 1)

    def test_concurrent_identical_log_retries_store_one_file(self):
        payload = b"same-log-upload" * 1024

        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(
                executor.map(
                    lambda _: store_log_file(
                        "pressure-session",
                        "bug_report_zip",
                        "bundle.zip",
                        payload,
                        user_id=self.user_id,
                    ),
                    range(32),
                )
            )

        self.assertEqual(sum(1 for result in results if not result["duplicate"]), 1)
        self.assertEqual(len({result["file_id"] for result in results}), 1)
        conn = get_connection()
        try:
            session = conn.execute(
                "SELECT id, upload_count FROM log_sessions WHERE user_id = ? AND session_id = ?",
                (self.user_id, "pressure-session"),
            ).fetchone()
            file_count = conn.execute("SELECT COUNT(*) FROM log_files WHERE session_id = ?", (session["id"],)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(session["upload_count"], 1)
        self.assertEqual(file_count, 1)
        self.assertEqual(len(list(Path(config.LOG_STORAGE_PATH).glob("*"))), 1)


if __name__ == "__main__":
    unittest.main()
