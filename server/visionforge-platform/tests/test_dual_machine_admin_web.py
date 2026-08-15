from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-dual-machine-admin-web")

import httpx
from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import CSRF_COOKIE_NAME, create_access_token, generate_csrf_token
from app.services.dual_machine_admin_client import (
    DualMachineAdminClient,
    DualMachineAdminClientError,
)
from fastapi.testclient import TestClient

ENTITLEMENT_ID = "a" * 32
BINDING_ID = "b" * 32
PLAINTEXT_CODE = "VFD2-23456-789AB-CDEFG-HJKLM-NPQRS-TUVWX"


class FakeDualMachineAdminClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def list_products(self, **kwargs):
        self.calls.append(("list_products", kwargs))
        return {
            "ok": True,
            "products": [
                {
                    "product_key": "day",
                    "display_name": "天卡",
                    "duration_seconds": 86400,
                },
                {
                    "product_key": "week",
                    "display_name": "周卡",
                    "duration_seconds": 604800,
                },
                {
                    "product_key": "month",
                    "display_name": "月卡",
                    "duration_seconds": 2592000,
                },
                {
                    "product_key": "permanent",
                    "display_name": "永久卡",
                    "duration_seconds": 0,
                },
                {
                    "product_key": "legacy_1h",
                    "display_name": "旧一小时卡",
                    "duration_seconds": 3600,
                },
            ],
        }

    async def list_batches(self, **kwargs):
        self.calls.append(("list_batches", kwargs))
        return {
            "ok": True,
            "total": 1,
            "batches": [
                {
                    "id": 7,
                    "request_id": "b" * 32,
                    "product_key": "day",
                    "display_name": "天卡",
                    "quantity": 1,
                    "channel": "admin_web",
                    "note": "测试批次",
                    "expires_at_epoch": None,
                    "status": "active",
                    "created_at": "2026-07-28 10:00:00",
                    "issued_count": 0,
                    "activated_count": 1,
                    "revoked_count": 0,
                    "expired_count": 0,
                }
            ],
        }

    async def list_codes(self, batch_id, **kwargs):
        self.calls.append(("list_codes", (batch_id, kwargs)))
        return {
            "ok": True,
            "batch": {"id": batch_id, "product_key": "day", "status": "active"},
            "total": 1,
            "codes": [
                {
                    "id": 9,
                    "batch_id": batch_id,
                    "ordinal": 1,
                    "code_suffix": "UVWX",
                    "code": PLAINTEXT_CODE,
                    "code_digest": "must-not-render-digest",
                    "derivation_ref": "must-not-render-ref",
                    "product_key": "day",
                    "status": "activated",
                    "activation_id": "activation-1",
                    "entitlement_id": ENTITLEMENT_ID,
                    "device_bindings": [
                        {
                            "binding_id": BINDING_ID,
                            "host_device_code": "HOST-DEVICE",
                            "android_device_code": "ANDROID-DEVICE",
                            "is_current": True,
                        }
                    ],
                }
            ],
        }

    async def list_all_codes(self, **kwargs):
        self.calls.append(("list_all_codes", kwargs))
        payload = await self.list_codes(7, **kwargs)
        payload.pop("batch", None)
        payload["scope"] = "global"
        payload["codes"][0]["batch_status"] = "active"
        return payload

    async def list_audit(self, **kwargs):
        self.calls.append(("list_audit", kwargs))
        return {
            "ok": True,
            "total": 2,
            "events": [
                {
                    "created_at": "2026-07-28 10:01:00",
                    "event_type": "license_batch_issued",
                    "subject_type": "license_batch",
                    "subject_id": "7",
                    "result": "ok",
                    "trace_id": "trace-safe",
                    "ip_address": "127.0.0.1",
                    "detail": {
                        "quantity": 1,
                        "code": PLAINTEXT_CODE,
                        "message": PLAINTEXT_CODE,
                    },
                },
                {
                    "created_at": "2026-07-28 10:02:00",
                    "event_type": "license_code_activated",
                    "subject_type": "license_code",
                    "subject_id": "9",
                    "result": "ok",
                    "detail_json": json.dumps(
                        {
                            "safe": "shown",
                            "card_code": PLAINTEXT_CODE,
                            "code_digest": "must-not-render-digest",
                            "derivation_ref": "must-not-render-ref",
                        }
                    ),
                },
            ],
        }

    async def entitlement_summary(self, entitlement_id):
        self.calls.append(("entitlement_summary", entitlement_id))
        return {
            "ok": True,
            "entitlement_id": entitlement_id,
            "pair_id": "pair-safe",
            "status": "active",
            "remaining_seconds": 7200,
            "total_credited_seconds": 86400,
            "total_consumed_seconds": 120,
            "revocation_version": 0,
            "authorization_kind": "day",
            "product_key": "day",
            "source_license_code_id": 9,
            "is_permanent": False,
            "device_bindings": [
                {
                    "binding_id": BINDING_ID,
                    "pair_id": "pair-safe",
                    "host_device_code": "HOST-DEVICE",
                    "android_device_code": "ANDROID-DEVICE",
                    "host_client_version": "17.8.60",
                    "android_client_version": "1.2.0",
                    "host_key_sha256": "c" * 64,
                    "android_key_sha256": "d" * 64,
                    "android_device_profile": {"model": "Pixel Test"},
                    "is_current": True,
                    "created_at": "2026-07-28 10:00:00",
                    "last_seen_at": "2026-07-28 10:03:00",
                }
            ],
        }

    async def issue_batch(self, **kwargs):
        self.calls.append(("issue_batch", kwargs))
        return {
            "ok": True,
            "batch_id": 8,
            "product_key": kwargs["product_key"],
            "product_name": "天卡",
            "duration_seconds": 86400,
            "authorization_kind": "day",
            "codes": [PLAINTEXT_CODE],
        }

    async def export_batch_codes(self, batch_id):
        self.calls.append(("export_batch_codes", batch_id))
        return {
            "ok": True,
            "batch_id": batch_id,
            "codes": [
                {
                    "id": 9,
                    "ordinal": 1,
                    "status": "activated",
                    "code_suffix": "UVWX",
                    "code": PLAINTEXT_CODE,
                }
            ],
        }

    async def update_batch(self, batch_id, **kwargs):
        self.calls.append(("update_batch", (batch_id, kwargs)))
        return {"ok": True}

    async def revoke_batch(self, batch_id, **kwargs):
        self.calls.append(("revoke_batch", (batch_id, kwargs)))
        return {"ok": True}

    async def restore_batch(self, batch_id, **kwargs):
        self.calls.append(("restore_batch", (batch_id, kwargs)))
        return {"ok": True}

    async def archive_batch(self, batch_id, **kwargs):
        self.calls.append(("archive_batch", (batch_id, kwargs)))
        return {"ok": True}

    async def unarchive_batch(self, batch_id, **kwargs):
        self.calls.append(("unarchive_batch", (batch_id, kwargs)))
        return {"ok": True}

    async def revoke_code(self, code_id, **kwargs):
        self.calls.append(("revoke_code", (code_id, kwargs)))
        return {"ok": True}

    async def update_code(self, code_id, **kwargs):
        self.calls.append(("update_code", (code_id, kwargs)))
        return {"ok": True}

    async def restore_code(self, code_id, **kwargs):
        self.calls.append(("restore_code", (code_id, kwargs)))
        return {"ok": True}

    async def archive_code(self, code_id, **kwargs):
        self.calls.append(("archive_code", (code_id, kwargs)))
        return {"ok": True}

    async def unarchive_code(self, code_id, **kwargs):
        self.calls.append(("unarchive_code", (code_id, kwargs)))
        return {"ok": True}

    async def revoke_entitlement(self, entitlement_id, **kwargs):
        self.calls.append(("revoke_entitlement", (entitlement_id, kwargs)))
        return {"ok": True}

    async def restore_entitlement(self, entitlement_id, **kwargs):
        self.calls.append(("restore_entitlement", (entitlement_id, kwargs)))
        return {"ok": True}

    async def unbind_entitlement_device(
        self,
        entitlement_id,
        binding_id,
        **kwargs,
    ):
        self.calls.append(
            (
                "unbind_entitlement_device",
                (entitlement_id, binding_id, kwargs),
            )
        )
        return {"ok": True}


class DualMachineAdminWebTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_database_path = config.DATABASE_PATH
        self.original_bridge_secret = config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET = "bridge-test-secret-32-bytes-long!!"
        init_db()
        connection = get_connection()
        try:
            cursor = connection.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) "
                "VALUES (?, ?, ?, 1)",
                ("admin", "admin@example.test", "hash"),
            )
            self.admin_id = int(cursor.lastrowid)
            connection.commit()
        finally:
            connection.close()
        self.fake = FakeDualMachineAdminClient()

    def tearDown(self):
        config.DATABASE_PATH = self.original_database_path
        config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET = self.original_bridge_secret
        self.tmpdir.cleanup()

    def admin_client(self) -> TestClient:
        client = TestClient(app)
        client.cookies.set("vf_token", create_access_token(self.admin_id, True))
        csrf_token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
        client._vf_csrf_token = csrf_token
        return client

    @staticmethod
    def admin_post(client: TestClient, path: str, data: dict[str, object]):
        payload = dict(data)
        payload["csrf_token"] = client._vf_csrf_token
        return client.post(path, data=payload, follow_redirects=False)

    def client_patch(self):
        return patch(
            "app.routes.dual_machine_admin.get_dual_machine_admin_client",
            return_value=self.fake,
        )

    def test_page_requires_admin_cookie_and_post_requires_csrf(self):
        anonymous = TestClient(app)
        response = anonymous.get("/admin/dual-machine-cards", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

        client = self.admin_client()
        with self.client_patch():
            response = client.post(
                "/admin/dual-machine-cards/issue",
                data={"product_key": "day", "quantity": "1"},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 403)

    def test_card_network_dashboard_reuses_safe_sidecar_contracts(self):
        anonymous = TestClient(app)
        redirect = anonymous.get("/admin/card-network", follow_redirects=False)
        self.assertEqual(redirect.status_code, 303)
        self.assertEqual(redirect.headers["location"], "/login")

        client = self.admin_client()
        with self.client_patch():
            response = client.get("/admin/card-network")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        self.assertIn("卡网总览", response.text)
        self.assertIn("快捷发卡", response.text)
        self.assertIn("全局卡密查询", response.text)
        self.assertIn("查看设备绑定", response.text)
        self.assertIn("最近审计", response.text)
        self.assertIn('href="/admin/card-network"', response.text)
        self.assertIn('action="/admin/dual-machine-cards/issue"', response.text)
        self.assertNotIn(PLAINTEXT_CODE, response.text)
        self.assertNotIn("must-not-render-digest", response.text)
        status_filters = {
            value.get("status", "")
            for name, value in self.fake.calls
            if name == "list_all_codes" and isinstance(value, dict)
        }
        self.assertTrue({"issued", "activated", "revoked", "expired"}.issubset(status_filters))

    def test_selected_batch_page_reveals_cards_without_derivation_material(self):
        client = self.admin_client()
        with self.client_patch():
            response = client.get(
                "/admin/dual-machine-cards",
                params={"batch_id": "7", "entitlement_id": ENTITLEMENT_ID},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertIn("双机卡密管理", response.text)
        self.assertIn("签发并在页面查看", response.text)
        self.assertIn("天卡", response.text)
        self.assertIn("周卡", response.text)
        self.assertIn("月卡", response.text)
        self.assertIn("永久卡", response.text)
        self.assertNotIn("旧一小时卡", response.text)
        self.assertIn(PLAINTEXT_CODE, response.text)
        self.assertEqual(response.text.count(PLAINTEXT_CODE), 1)
        self.assertIn('data-copy-card-id="9"', response.text)
        self.assertIn(
            'href="/admin/dual-machine-cards?batch_id=7#dm-code-list"',
            response.text,
        )
        self.assertIn("导出明文 CSV", response.text)
        self.assertIn("HOST-DEVICE", response.text)
        self.assertIn("Pixel Test", response.text)
        self.assertIn("解绑当前设备", response.text)
        self.assertIn("已激活卡密不能直接停用", response.text)
        self.assertIn("查看对应授权并执行停用", response.text)
        self.assertNotIn(
            '/admin/dual-machine-cards/codes/9/revoke',
            response.text,
        )
        self.assertIn("license_batch_issued", response.text)
        self.assertIn("shown", response.text)
        self.assertNotIn("must-not-render-digest", response.text)
        self.assertNotIn("must-not-render-ref", response.text)
        self.assertIn(("export_batch_codes", 7), self.fake.calls)

        connection = get_connection()
        try:
            sidecar_tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'dm_%'"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(sidecar_tables, [])

    def test_revoked_entitlement_renders_safe_restore_action(self):
        original_summary = self.fake.entitlement_summary

        async def revoked_summary(entitlement_id):
            payload = await original_summary(entitlement_id)
            payload["status"] = "revoked"
            return payload

        self.fake.entitlement_summary = revoked_summary
        client = self.admin_client()
        with self.client_patch():
            response = client.get(
                "/admin/dual-machine-cards",
                params={"entitlement_id": ENTITLEMENT_ID},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("恢复双机授权", response.text)
        self.assertIn("不会补时", response.text)

    def test_global_code_search_is_available_without_selecting_a_batch(self):
        client = self.admin_client()
        with self.client_patch():
            response = client.get(
                "/admin/dual-machine-cards",
                params={"code_query": "device-fingerprint-safe"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("全局卡密查询", response.text)
        self.assertIn("跨全部批次", response.text)
        call = next(
            value for name, value in self.fake.calls if name == "list_all_codes"
        )
        self.assertEqual(call["query"], "device-fingerprint-safe")
        self.assertNotIn(PLAINTEXT_CODE, response.text)

    def test_issue_shows_cards_and_export_remains_an_optional_csv(self):
        client = self.admin_client()
        with self.client_patch():
            issued = self.admin_post(
                client,
                "/admin/dual-machine-cards/issue",
                {
                    "product_key": "day",
                    "quantity": "1",
                    "note": "test issue",
                    "expires_at_epoch": "",
                },
            )
            revealed = client.get(issued.headers["location"])
            exported = self.admin_post(
                client,
                "/admin/dual-machine-cards/batches/7/export",
                {},
            )

        self.assertEqual(issued.status_code, 303, issued.text)
        self.assertEqual(
            issued.headers["location"],
            (
                "/admin/dual-machine-cards?success=batch_issued&batch_id=8"
                "#dm-code-list"
            ),
        )
        self.assertNotIn(PLAINTEXT_CODE, issued.headers["location"])
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.headers["cache-control"], "no-store, max-age=0")
        self.assertIn("卡密已签发，可在下方直接复制", revealed.text)
        self.assertIn(PLAINTEXT_CODE, revealed.text)
        self.assertIn("复制卡密", revealed.text)
        self.assertIn("导出明文 CSV", revealed.text)

        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertTrue(exported.headers["content-type"].startswith("text/csv"))
        self.assertEqual(exported.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(exported.headers["pragma"], "no-cache")
        self.assertIn("attachment", exported.headers["content-disposition"])
        self.assertIn(PLAINTEXT_CODE, exported.content.decode("utf-8-sig"))
        self.assertNotIn("location", exported.headers)

        issue_call = next(
            value for name, value in self.fake.calls if name == "issue_batch"
        )
        self.assertEqual(issue_call["product_key"], "day")
        self.assertEqual(issue_call["quantity"], 1)
        self.assertEqual(issue_call["channel"], "admin_web")
        self.assertRegex(issue_call["request_id"], r"^[0-9a-f]{32}$")
        connection = get_connection()
        try:
            audits = connection.execute(
                "SELECT admin_user_id, action, detail_json, ip FROM admin_audit "
                "WHERE action IN ('dual_machine.batch_issued', "
                "'dual_machine.batch_exported') ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(
            [row["action"] for row in audits],
            [
                "dual_machine.batch_issued",
                "dual_machine.batch_exported",
            ],
        )
        self.assertTrue(
            all(int(row["admin_user_id"]) == self.admin_id for row in audits)
        )
        self.assertTrue(all(str(row["ip"] or "") for row in audits))
        self.assertNotIn(PLAINTEXT_CODE, "".join(str(dict(row)) for row in audits))

    def test_only_four_products_are_issuable(self):
        client = self.admin_client()
        with self.client_patch():
            response = self.admin_post(
                client,
                "/admin/dual-machine-cards/issue",
                {"product_key": "legacy_1h", "quantity": "1"},
            )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/admin/dual-machine-cards?error=invalid_product",
        )
        self.assertFalse(any(name == "issue_batch" for name, _ in self.fake.calls))

    def test_search_forms_never_redirect_plaintext_card_into_query(self):
        client = self.admin_client()
        full_card = "VFD2-23456-23456-23456-23456-23456-23456"
        rejected = self.admin_post(
            client,
            "/admin/dual-machine-cards/filter",
            {"filter_scope": "batch", "batch_query": full_card},
        )
        self.assertEqual(rejected.status_code, 303)
        self.assertIn("error=invalid_search", rejected.headers["location"])
        self.assertNotIn("VFD2", rejected.headers["location"])

        accepted = self.admin_post(
            client,
            "/admin/dual-machine-cards/filter",
            {
                "filter_scope": "code",
                "batch_id": "7",
                "code_query": "RSTU",
            },
        )
        self.assertEqual(accepted.status_code, 303)
        self.assertIn("batch_id=7", accepted.headers["location"])
        self.assertIn("code_query=RSTU", accepted.headers["location"])

        accepted_global = self.admin_post(
            client,
            "/admin/dual-machine-cards/filter",
            {
                "filter_scope": "code",
                "code_query": "fingerprint-safe-value",
                "code_status": "activated",
            },
        )
        self.assertEqual(accepted_global.status_code, 303)
        self.assertNotIn("batch_id=", accepted_global.headers["location"])
        self.assertIn(
            "code_query=fingerprint-safe-value",
            accepted_global.headers["location"],
        )

        rejected_reason = self.admin_post(
            client,
            "/admin/dual-machine-cards/batches/7/revoke",
            {"reason": full_card},
        )
        self.assertEqual(rejected_reason.status_code, 303)
        self.assertIn("error=sensitive_text", rejected_reason.headers["location"])
        self.assertNotIn("VFD2", rejected_reason.headers["location"])

    def test_state_changes_proxy_to_explicit_sidecar_methods(self):
        client = self.admin_client()
        requests = (
            (
                "/admin/dual-machine-cards/batches/7/update",
                {"note": "new", "reason": "update reason"},
                "update_batch",
            ),
            (
                "/admin/dual-machine-cards/batches/7/revoke",
                {"reason": "revoke reason", "revoke_activated_entitlements": "1"},
                "revoke_batch",
            ),
            (
                "/admin/dual-machine-cards/batches/7/restore",
                {"reason": "restore reason"},
                "restore_batch",
            ),
            (
                "/admin/dual-machine-cards/batches/7/archive",
                {"reason": "archive reason"},
                "archive_batch",
            ),
            (
                "/admin/dual-machine-cards/batches/7/unarchive",
                {"reason": "unarchive reason"},
                "unarchive_batch",
            ),
            (
                "/admin/dual-machine-cards/codes/9/revoke",
                {"reason": "revoke reason", "batch_id": "7"},
                "revoke_code",
            ),
            (
                "/admin/dual-machine-cards/codes/9/update",
                {
                    "admin_note": "support note",
                    "reason": "update reason",
                    "batch_id": "7",
                },
                "update_code",
            ),
            (
                "/admin/dual-machine-cards/codes/9/restore",
                {"reason": "restore reason", "batch_id": "7"},
                "restore_code",
            ),
            (
                "/admin/dual-machine-cards/codes/9/archive",
                {"reason": "archive reason", "batch_id": "7"},
                "archive_code",
            ),
            (
                "/admin/dual-machine-cards/codes/9/unarchive",
                {"reason": "unarchive reason", "batch_id": "7"},
                "unarchive_code",
            ),
            (
                f"/admin/dual-machine-cards/entitlements/{ENTITLEMENT_ID}/revoke",
                {"reason": "entitlement reason", "batch_id": "7"},
                "revoke_entitlement",
            ),
            (
                f"/admin/dual-machine-cards/entitlements/{ENTITLEMENT_ID}/restore",
                {"reason": "entitlement restore", "batch_id": "7"},
                "restore_entitlement",
            ),
            (
                (
                    f"/admin/dual-machine-cards/entitlements/{ENTITLEMENT_ID}/"
                    f"device-bindings/{BINDING_ID}/unbind"
                ),
                {"reason": "device replacement", "batch_id": "7"},
                "unbind_entitlement_device",
            ),
        )
        with self.client_patch():
            for path, data, expected_call in requests:
                with self.subTest(path=path):
                    response = self.admin_post(client, path, data)
                    self.assertEqual(response.status_code, 303, response.text)
                    self.assertTrue(
                        any(name == expected_call for name, _ in self.fake.calls),
                        expected_call,
                    )
                    self.assertNotIn(PLAINTEXT_CODE, response.headers["location"])

        revoke_payload = next(
            value for name, value in self.fake.calls if name == "revoke_batch"
        )
        self.assertTrue(revoke_payload[1]["revoke_activated_entitlements"])
        connection = get_connection()
        try:
            audits = connection.execute(
                "SELECT admin_user_id, action, target_type, target_id, "
                "detail_json, ip FROM admin_audit "
                "WHERE action LIKE 'dual_machine.%' ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        actions = {str(row["action"]) for row in audits}
        self.assertIn("dual_machine.batch_archived", actions)
        self.assertIn("dual_machine.batch_unarchived", actions)
        self.assertIn("dual_machine.code_archived", actions)
        self.assertIn("dual_machine.code_unarchived", actions)
        self.assertIn("dual_machine.entitlement_revoked", actions)
        self.assertIn("dual_machine.entitlement_restored", actions)
        self.assertIn("dual_machine.device_unbound", actions)
        unbind_audit = next(
            row
            for row in audits
            if str(row["action"]) == "dual_machine.device_unbound"
        )
        self.assertEqual(
            json.loads(str(unbind_audit["detail_json"]))["binding_id"],
            BINDING_ID,
        )
        self.assertTrue(audits)
        self.assertTrue(
            all(int(row["admin_user_id"]) == self.admin_id for row in audits)
        )
        self.assertTrue(all(str(row["ip"] or "") for row in audits))
        self.assertNotIn(PLAINTEXT_CODE, "".join(str(dict(row)) for row in audits))

    def test_bridge_failure_renders_safe_page_error(self):
        failing = FakeDualMachineAdminClient()

        async def unavailable(**_kwargs):
            raise DualMachineAdminClientError(
                "dual_machine_admin_bridge_unavailable",
                503,
            )

        failing.list_products = unavailable
        failing.list_batches = unavailable
        failing.list_audit = unavailable
        client = self.admin_client()
        with patch(
            "app.routes.dual_machine_admin.get_dual_machine_admin_client",
            return_value=failing,
        ):
            response = client.get("/admin/dual-machine-cards")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("双机侧车管理桥接不可用", response.text)
        self.assertNotIn("dual_machine_admin_bridge_unavailable", response.text)


class DualMachineAdminClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_hmac_covers_actual_request_target_and_body(self):
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"ok": True, "batches": []})

        secret = b"s" * 32
        client = DualMachineAdminClient(
            base_url="http://127.0.0.1:8010",
            secret=secret,
            transport=httpx.MockTransport(handler),
        )
        await client.list_batches(
            limit=50,
            offset=0,
            status="active",
            deleted="all",
            query="批次",
        )

        self.assertEqual(len(captured), 1)
        request = captured[0]
        target = request.url.raw_path.decode("ascii")
        timestamp = request.headers["X-VisionForge-Admin-Timestamp"]
        nonce = request.headers["X-VisionForge-Admin-Nonce"]
        canonical = "\n".join(
            (
                "visionforge-dual-machine-admin-v1",
                "GET",
                target,
                timestamp,
                nonce,
                hashlib.sha256(request.content).hexdigest(),
            )
        ).encode("ascii")
        expected = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
        self.assertEqual(request.headers["Authorization"], "VF-Admin-HMAC v1")
        self.assertEqual(request.headers["X-VisionForge-Admin-Signature"], expected)
        self.assertRegex(nonce, r"^[0-9a-f]{32}$")
        self.assertIn("/internal/dual-machine-admin/v1/batches?", target)
        self.assertIn("query=", target)

    async def test_non_loopback_or_short_secret_fails_before_transport(self):
        called = False

        async def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return httpx.Response(200, json={"ok": True})

        client = DualMachineAdminClient(
            base_url="http://example.test:8010",
            secret="short",
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(DualMachineAdminClientError) as raised:
            await client.list_products()
        self.assertEqual(raised.exception.code, "dual_machine_admin_bridge_unavailable")
        self.assertFalse(called)

    async def test_client_signature_matches_the_real_sidecar_contract(self):
        from dual_machine_service.database import initialize_database
        from dual_machine_service.internal_admin_routes import (
            router as internal_admin_router,
        )
        from dual_machine_service.settings import DualMachineSettings
        from fastapi import FastAPI

        with tempfile.TemporaryDirectory() as directory:
            secret = b"sidecar-web-contract-secret-at-least-32-bytes"
            settings = DualMachineSettings(
                database_path=Path(directory) / "dual-machine.db",
                license_code_secret=b"license-code-secret-for-web-contract-test",
                token_secret=b"token-secret-for-web-contract-test-minimum",
                minimum_host_client_version="17.8.81",
                minimum_android_client_version="1.0.0",
                admin_bridge_secret=secret,
                admin_bridge_max_skew_seconds=30,
            )
            initialize_database(settings)
            sidecar = FastAPI()
            sidecar.state.settings = settings
            sidecar.include_router(internal_admin_router)
            transport = httpx.ASGITransport(
                app=sidecar,
                client=("127.0.0.1", 55123),
            )
            client = DualMachineAdminClient(
                base_url="http://127.0.0.1:8010",
                secret=secret,
                transport=transport,
            )

            products = await client.list_products(enabled=True)
            batches = await client.list_batches(query="测试批次", deleted="all")
            issued = await client.issue_batch(
                request_id="e" * 32,
                product_key="day",
                quantity=1,
                channel="admin_web",
                note="contract test",
                expires_at_epoch=None,
            )
            code_rows = await client.list_codes(issued["batch_id"])
            global_code_rows = await client.list_all_codes(
                query=str(issued["batch_id"]),
                deleted="all",
            )
            updated = await client.update_code(
                code_rows["codes"][0]["id"],
                admin_note="support note",
                expires_at_epoch=None,
                reason="contract update",
            )
            exported = await client.export_batch_codes(issued["batch_id"])
            archived_code = await client.archive_code(
                code_rows["codes"][0]["id"],
                reason="contract archive",
            )
            archived_batch = await client.archive_batch(
                issued["batch_id"],
                reason="contract archive",
            )
            archived_batches = await client.list_batches(deleted="deleted")
            archived_codes = await client.list_codes(
                issued["batch_id"],
                deleted="deleted",
            )
            unarchived_batch = await client.unarchive_batch(
                issued["batch_id"],
                reason="contract unarchive",
            )
            unarchived_code = await client.unarchive_code(
                code_rows["codes"][0]["id"],
                reason="contract unarchive",
            )

        self.assertEqual(
            [item["product_key"] for item in products["products"]],
            ["day", "week", "month", "permanent"],
        )
        self.assertEqual(batches["batches"], [])
        self.assertEqual(issued["authorization_kind"], "day")
        self.assertEqual(updated["admin_note"], "support note")
        self.assertEqual(global_code_rows["codes"][0]["id"], code_rows["codes"][0]["id"])
        self.assertEqual(exported["codes"][0]["code"], issued["codes"][0])
        self.assertTrue(archived_code["deleted"])
        self.assertTrue(archived_batch["deleted"])
        self.assertEqual(archived_batches["batches"][0]["id"], issued["batch_id"])
        self.assertEqual(archived_codes["codes"][0]["id"], code_rows["codes"][0]["id"])
        self.assertFalse(unarchived_batch["deleted"])
        self.assertFalse(unarchived_code["deleted"])


if __name__ == "__main__":
    unittest.main()
