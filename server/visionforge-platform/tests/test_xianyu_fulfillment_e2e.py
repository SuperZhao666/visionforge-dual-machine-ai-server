from __future__ import annotations

import importlib.util
import logging
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-xianyu-fulfillment-e2e")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import create_access_token


BRIDGE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "xianyu-fulfillment"
    / "bridge"
    / "bridge.py"
)
BRIDGE_SPEC = importlib.util.spec_from_file_location(
    "visionforge_xianyu_fulfillment_e2e_bridge",
    BRIDGE_PATH,
)
bridge = importlib.util.module_from_spec(BRIDGE_SPEC)
assert BRIDGE_SPEC and BRIDGE_SPEC.loader
BRIDGE_SPEC.loader.exec_module(bridge)

CODE_PATTERN = re.compile(r"VF1-(?:[A-Z0-9]{4}-){5}[A-Z0-9]{4}-[A-Z0-9]{2}")
PRODUCT_DURATIONS = {
    "1h": 1 * 3600,
    "5h": 5 * 3600,
    "10h": 10 * 3600,
    "50h": 50 * 3600,
    "100h": 100 * 3600,
}


class _UrlOpenResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(f"{record.name}:{self.format(record)}")


class XianyuFulfillmentE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.previous_config = {
            "DATABASE_PATH": config.DATABASE_PATH,
            "CODE_ISSUANCE_SERVICE_ID": config.CODE_ISSUANCE_SERVICE_ID,
            "CODE_ISSUANCE_HMAC_SECRET": config.CODE_ISSUANCE_HMAC_SECRET,
            "REDEMPTION_CODE_SECRET": config.REDEMPTION_CODE_SECRET,
        }
        config.DATABASE_PATH = str(Path(self.temp_directory.name) / "fulfillment-e2e.db")
        config.CODE_ISSUANCE_SERVICE_ID = "test-xianyu-bridge"
        config.CODE_ISSUANCE_HMAC_SECRET = "test-code-issuance-hmac-secret-at-least-32-bytes"
        config.REDEMPTION_CODE_SECRET = "test-redemption-code-secret-at-least-32-bytes"
        init_db()
        self.redeemer_id = self._create_user("fulfillment-redeemer")
        self.other_user_id = self._create_user("fulfillment-other-user")
        self.client = TestClient(app)
        self.platform_traces: list[tuple[str, str]] = []

    def tearDown(self) -> None:
        self.client.close()
        for name, value in self.previous_config.items():
            setattr(config, name, value)
        self.temp_directory.cleanup()

    def test_five_package_product_keys_map_to_server_authoritative_durations(self) -> None:
        from app.services.external_code_issuance_service import issue_external_code

        request_ids: set[str] = set()
        with patch.dict(os.environ, self._bridge_environment()):
            for product_key, duration_seconds in PRODUCT_DURATIONS.items():
                payload = bridge._issuance_payload(
                    {
                        "order_id": [f"isolated-order-{product_key}"],
                        "product_key": [product_key],
                        "unit_index": ["1"],
                    }
                )
                result = issue_external_code(**payload)

                self.assertEqual(payload["product_key"], product_key)
                self.assertEqual(result.product_key, product_key)
                self.assertEqual(result.duration_seconds, duration_seconds)
                self.assertRegex(payload["request_id"], r"^xi1_[0-9a-f]{64}$")
                request_ids.add(payload["request_id"])

        self.assertEqual(len(request_ids), len(PRODUCT_DURATIONS))

    def test_order_bridge_platform_and_client_redemption_end_to_end(self) -> None:
        order_id = "private-order-must-not-be-logged"
        log_capture = _LogCapture()
        monitored_loggers = (
            logging.getLogger("visionforge.code_issuance_bridge"),
            logging.getLogger("growth_api"),
            logging.getLogger("main"),
        )
        previous_levels = {logger: logger.level for logger in monitored_loggers}
        for logger in monitored_loggers:
            logger.setLevel(logging.INFO)
            logger.addHandler(log_capture)
        try:
            exchange = self._issue_same_order_twice(order_id)
            first_code = self._assert_idempotent_delivery(exchange)
            self._assert_current_request_traces(log_capture)
            self._assert_single_use_redemption(first_code)
            logs = "\n".join(log_capture.messages)
            self.assertNotIn(first_code, logs)
            self.assertNotIn(order_id, logs)
        finally:
            for logger in monitored_loggers:
                logger.removeHandler(log_capture)
                logger.setLevel(previous_levels[logger])

    def test_bridge_rejects_more_than_one_delivery_unit_before_issuance(self) -> None:
        with patch.dict(os.environ, self._bridge_environment()):
            with self.assertRaises(bridge.BridgeError) as captured:
                bridge._issuance_payload(
                    {
                        "order_id": ["quantity-two-order"],
                        "product_key": ["1h"],
                        "unit_index": ["2"],
                    }
                )

        self.assertEqual(captured.exception.error_code, "quantity_unsupported")

    def test_bridge_rejects_ambiguous_repeated_order_parameters(self) -> None:
        with patch.dict(os.environ, self._bridge_environment()):
            for field_name in ("order_id", "product_key", "unit_index"):
                query = {
                    "order_id": ["unambiguous-order"],
                    "product_key": ["1h"],
                    "unit_index": ["1"],
                }
                query[field_name].append(query[field_name][0])
                with self.subTest(field_name=field_name):
                    with self.assertRaises(bridge.BridgeError) as captured:
                        bridge._issuance_payload(query)
                    self.assertEqual(captured.exception.error_code, "invalid_request")
        self.assertEqual(self._database_state()["code_count"], 0)

    def _issue_same_order_twice(self, order_id: str):
        query = {
            "order_id": [order_id],
            "product_key": ["10h"],
            "unit_index": ["1"],
        }
        with (
            patch.dict(os.environ, self._bridge_environment()),
            patch.object(bridge.urllib.request, "urlopen", side_effect=self._platform_urlopen),
        ):
            first_payload = bridge._issuance_payload(query)
            repeated_payload = bridge._issuance_payload(query)
            first_status, first_response = bridge._post_to_platform(first_payload)
            repeated_status, repeated_response = bridge._post_to_platform(repeated_payload)
            _, first_delivery = bridge._delivery_response(first_status, first_response)
            _, repeated_delivery = bridge._delivery_response(repeated_status, repeated_response)
        return (
            first_payload,
            repeated_payload,
            first_status,
            repeated_status,
            first_response,
            repeated_response,
            first_delivery,
            repeated_delivery,
        )

    def _assert_idempotent_delivery(self, exchange) -> str:
        (first_payload, repeated_payload, first_status, repeated_status,
         first_response, repeated_response, first_delivery, repeated_delivery) = exchange
        self.assertEqual(first_payload, repeated_payload)
        self.assertEqual((first_status, repeated_status), (200, 200))
        self.assertFalse(first_response["duplicate"])
        self.assertTrue(repeated_response["duplicate"])
        first_code = first_response["data"]["redemption_code"]
        repeated_code = repeated_response["data"]["redemption_code"]
        self.assertRegex(first_code, CODE_PATTERN)
        self.assertEqual(first_code, repeated_code)
        self.assertIn(first_code, first_delivery["data"])
        self.assertEqual(first_delivery["data"], repeated_delivery["data"])
        return first_code

    def _assert_single_use_redemption(self, code: str) -> None:
        first = self._redeem(self.redeemer_id, code)
        owner_retry = self._redeem(self.redeemer_id, code)
        other_user_attempt = self._redeem(self.other_user_id, code)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["credited"])
        self.assertEqual(first.json()["credited_seconds"], 10 * 3600)
        self.assertEqual(owner_retry.status_code, 200, owner_retry.text)
        self.assertFalse(owner_retry.json()["credited"])
        self.assertEqual(other_user_attempt.status_code, 409, other_user_attempt.text)
        self.assertEqual(other_user_attempt.json()["error_code"], "CODE_INVALID_OR_USED")

        database_state = self._database_state()
        self.assertEqual(database_state["balance_seconds"], 10 * 3600)
        self.assertEqual(database_state["other_balance_seconds"], 0)
        self.assertEqual(database_state["issuance_count"], 1)
        self.assertEqual(database_state["code_count"], 1)
        self.assertEqual(database_state["redemption_recharge_count"], 1)

    def _assert_current_request_traces(self, log_capture: _LogCapture) -> None:
        self.assertEqual(len(self.platform_traces), 2)
        trace_ids = []
        for header_trace_id, body_trace_id in self.platform_traces:
            self.assertEqual(body_trace_id, header_trace_id)
            self.assertRegex(body_trace_id, r"^[0-9a-f]{32}$")
            trace_ids.append(body_trace_id)
        self.assertEqual(len(set(trace_ids)), 2)

        growth_logs = "\n".join(
            message for message in log_capture.messages if message.startswith("growth_api:")
        )
        for trace_id in trace_ids:
            self.assertIn(f"external code issued trace_id={trace_id}", growth_logs)

    def _platform_urlopen(self, request, timeout: int) -> _UrlOpenResponse:
        self.assertEqual(timeout, 12)
        headers = {name: value for name, value in request.header_items()}
        response = self.client.post(
            "/api/integrations/code-issuances/issue",
            content=bytes(request.data),
            headers=headers,
        )
        self.platform_traces.append(
            (response.headers["x-trace-id"], str(response.json().get("trace_id") or ""))
        )
        return _UrlOpenResponse(response.status_code, response.content)

    def _redeem(self, user_id: int, code: str):
        return self.client.post(
            "/api/client/redemptions",
            json={"code": code},
            headers={"Authorization": f"Bearer {create_access_token(user_id, False)}"},
        )

    def _bridge_environment(self) -> dict[str, str]:
        return {
            "XIANYU_PROVIDER_ACCOUNT": "isolated-seller-account",
            "CODE_ISSUANCE_HMAC_SECRET": config.CODE_ISSUANCE_HMAC_SECRET,
            "CODE_ISSUANCE_SERVICE_ID": config.CODE_ISSUANCE_SERVICE_ID,
            "PLATFORM_CODE_ISSUANCE_URL": (
                "https://platform.invalid/api/integrations/code-issuances/issue"
            ),
        }

    @staticmethod
    def _create_user(username: str) -> int:
        connection = get_connection()
        try:
            cursor = connection.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, f"{username}@example.test", "not-used-in-this-test"),
            )
            user_id = int(cursor.lastrowid)
            connection.execute("INSERT INTO time_balance (user_id) VALUES (?)", (user_id,))
            connection.commit()
            return user_id
        finally:
            connection.close()

    def _database_state(self) -> dict[str, int]:
        connection = get_connection()
        try:
            balance = connection.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (self.redeemer_id,),
            ).fetchone()["balance_seconds"]
            other_balance = connection.execute(
                "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
                (self.other_user_id,),
            ).fetchone()["balance_seconds"]
            return {
                "balance_seconds": int(balance),
                "other_balance_seconds": int(other_balance),
                "issuance_count": int(
                    connection.execute("SELECT COUNT(*) FROM external_code_issuances").fetchone()[0]
                ),
                "code_count": int(connection.execute("SELECT COUNT(*) FROM redemption_codes").fetchone()[0]),
                "redemption_recharge_count": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM time_recharges WHERE source_type = 'redemption'"
                    ).fetchone()[0]
                ),
            }
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
