import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-api-contract")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app


class LicenseApiContractTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_database_path = config.DATABASE_PATH
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        init_db()
        self.client = TestClient(app)

    def tearDown(self):
        config.DATABASE_PATH = self.previous_database_path
        self.tmpdir.cleanup()

    def test_license_endpoints_reject_extra_request_fields(self):
        payload = {
            "key_text": "VFG-invalid-but-long-enough",
            "machine_code": "A" * 32,
            "unexpected_admin_override": True,
        }
        for path in ("/api/license/activate", "/api/license/verify"):
            with self.subTest(path=path):
                response = self.client.post(path, json=payload)

                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("extra_forbidden", response.text)
                self.assertIn("unexpected_admin_override", response.text)

    def test_verify_rejects_an_unactivated_license_key(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        payload = {"license_id": "UNACTIVATED-TEST", "plan": "month"}
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, status) VALUES (?, ?, ?, 'unused')",
                (key_text, payload["license_id"], payload["plan"]),
            )
            conn.commit()
        finally:
            conn.close()

        with patch("app.routes.license_api.verify_key_text", return_value=payload):
            response = self.client.post(
                "/api/license/verify",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["valid"])

    def test_verify_rejects_an_active_key_without_a_machine_binding(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        payload = {"license_id": "UNBOUND-ACTIVE-TEST", "plan": "month"}
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, status) VALUES (?, ?, ?, 'active')",
                (key_text, payload["license_id"], payload["plan"]),
            )
            conn.commit()
        finally:
            conn.close()

        with patch("app.routes.license_api.verify_key_text", return_value=payload):
            response = self.client.post(
                "/api/license/verify",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["valid"])

    def test_activation_uses_the_persisted_plan_and_expiry(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        license_id = "PERSISTED-PLAN-TEST"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, status) VALUES (?, ?, 'month', 'unused')",
                (key_text, license_id),
            )
            conn.commit()
        finally:
            conn.close()

        with patch(
            "app.routes.license_api.verify_key_text",
            return_value={"license_id": license_id, "plan": "permanent", "expires_at": "permanent"},
        ):
            response = self.client.post(
                "/api/license/activate",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["plan"], "month")
        self.assertNotEqual(response.json()["expires_at"], "permanent")

    def test_activation_rejects_an_unknown_persisted_plan(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        license_id = "INVALID-PLAN-TEST"
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, status) VALUES (?, ?, 'unsupported', 'unused')",
                (key_text, license_id),
            )
            conn.commit()
        finally:
            conn.close()

        with patch("app.routes.license_api.verify_key_text", return_value={"license_id": license_id}):
            response = self.client.post(
                "/api/license/activate",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 400, response.text)


    def test_verify_enforces_sqlite_style_expiration_timestamps(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        payload = {"license_id": "EXPIRED-TEST", "plan": "month"}
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, hwid_hash, status, expires_at) "
                "VALUES (?, ?, ?, ?, 'active', ?)",
                (key_text, payload["license_id"], payload["plan"], "A" * 32, "2000-01-01 00:00:00"),
            )
            conn.commit()
        finally:
            conn.close()

        with patch("app.routes.license_api.verify_key_text", return_value=payload):
            response = self.client.post(
                "/api/license/verify",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["valid"])

    def test_activation_rejects_expired_active_license(self):
        key_text = "VFG-test-key-text-that-is-long-enough"
        payload = {"license_id": "EXPIRED-ACTIVATION-TEST", "plan": "month"}
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO license_keys (key_text, license_id, plan, hwid_hash, status, expires_at) "
                "VALUES (?, ?, ?, ?, 'active', ?)",
                (key_text, payload["license_id"], payload["plan"], "A" * 32, "2000-01-01 00:00:00"),
            )
            conn.commit()
        finally:
            conn.close()

        with patch("app.routes.license_api.verify_key_text", return_value=payload):
            response = self.client.post(
                "/api/license/activate",
                json={"key_text": key_text, "machine_code": "A" * 32},
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertFalse(response.json()["success"])


if __name__ == "__main__":
    unittest.main()
