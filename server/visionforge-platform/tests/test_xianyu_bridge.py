from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-xianyu-bridge")

from app.services.integration_auth_service import sign_integration_request


BRIDGE_PATH = Path(__file__).resolve().parents[1] / "deploy" / "xianyu-fulfillment" / "bridge" / "bridge.py"
HARDEN_PATCH_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "xianyu-fulfillment"
    / "patches"
    / "harden_upstream.py"
)
HARDENED_ENTRYPOINT_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "xianyu-fulfillment"
    / "hardened_entrypoint.sh"
)
DOCKERFILE_PATCH_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "xianyu-fulfillment"
    / "patches"
    / "patch_upstream_dockerfile.py"
)
ZIP_EXTRACTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "xianyu-fulfillment"
    / "patches"
    / "extract_zip_with_permissions.py"
)
NGINX_LOCATION_PATH = Path(__file__).resolve().parents[1] / "deploy" / "nginx" / "code_issuance_internal_location.conf"
COMPOSE_PATH = Path(__file__).resolve().parents[1] / "deploy" / "xianyu-fulfillment" / "docker-compose.yml"
SPEC = importlib.util.spec_from_file_location("visionforge_xianyu_bridge", BRIDGE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(bridge)
PATCH_SPEC = importlib.util.spec_from_file_location("visionforge_xianyu_harden_patch", HARDEN_PATCH_PATH)
harden_patch = importlib.util.module_from_spec(PATCH_SPEC)
assert PATCH_SPEC and PATCH_SPEC.loader
PATCH_SPEC.loader.exec_module(harden_patch)
DOCKERFILE_PATCH_SPEC = importlib.util.spec_from_file_location(
    "visionforge_xianyu_dockerfile_patch", DOCKERFILE_PATCH_PATH
)
dockerfile_patch = importlib.util.module_from_spec(DOCKERFILE_PATCH_SPEC)
assert DOCKERFILE_PATCH_SPEC and DOCKERFILE_PATCH_SPEC.loader
DOCKERFILE_PATCH_SPEC.loader.exec_module(dockerfile_patch)
ZIP_EXTRACTOR_SPEC = importlib.util.spec_from_file_location(
    "visionforge_xianyu_zip_extractor", ZIP_EXTRACTOR_PATH
)
zip_extractor = importlib.util.module_from_spec(ZIP_EXTRACTOR_SPEC)
assert ZIP_EXTRACTOR_SPEC and ZIP_EXTRACTOR_SPEC.loader
ZIP_EXTRACTOR_SPEC.loader.exec_module(zip_extractor)


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @staticmethod
    def read(_limit: int) -> bytes:
        return b'{"ok":true,"data":"private-content","trace_id":"trace-1"}'


class XianyuBridgeTests(unittest.TestCase):
    def test_zip_extractor_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "browser.zip"
            member = zipfile.ZipInfo("browser/chrome")
            member.create_system = 3
            member.external_attr = 0o100755 << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(member, b"executable")

            destination = root / "output"
            with patch.object(zip_extractor.os, "chmod") as chmod:
                zip_extractor.extract_archive(archive_path, destination)

            chmod.assert_called_once_with((destination / "browser" / "chrome").resolve(), 0o755)

    def test_upstream_dockerfile_patch_uses_verified_pinned_browser_archives(self) -> None:
        source = (
            f"RUN curl {dockerfile_patch.DEBIAN_SOURCE}/debian\n"
            f"{dockerfile_patch.PLAYWRIGHT_INSTALL_BLOCK}"
            '    CHROME_BIN="$(find /ms-playwright -name chrome)"\n'
        )

        patched = dockerfile_patch.patch_content(source)

        self.assertEqual(patched.count(dockerfile_patch.DEBIAN_MIRROR), 1)
        self.assertIn("VF_CHROMIUM_SHA256", patched)
        self.assertIn("VF_CHROMIUM_HEADLESS_SHA256", patched)
        self.assertIn("chromium_headless_shell-1217/INSTALLATION_COMPLETE", patched)
        self.assertIn("sha256sum --check --strict", patched)
        self.assertNotIn("playwright install chromium &&", patched)

    def test_hardened_entrypoint_rejects_default_credentials_and_avoids_world_writable_chmod(self) -> None:
        content = HARDENED_ENTRYPOINT_PATH.read_text(encoding="utf-8")
        self.assertIn('"${ADMIN_PASSWORD}" == "admin123"', content)
        self.assertIn("JWT_SECRET_KEY must be at least 32 characters", content)
        self.assertNotIn("chmod 777", content)
        self.assertIn("exec python Start.py", content)

    def test_code_issuance_endpoint_is_restricted_to_private_docker_subnet(self) -> None:
        nginx = NGINX_LOCATION_PATH.read_text(encoding="utf-8")
        compose = COMPOSE_PATH.read_text(encoding="utf-8")

        self.assertIn("location = /api/integrations/code-issuances/issue", nginx)
        self.assertIn("allow 172.29.47.0/28", nginx)
        self.assertIn("deny all", nginx)
        self.assertIn("subnet: 172.29.47.0/28", compose)
        self.assertIn("ipv4_address: 172.29.47.2", compose)
        self.assertIn("www.visionforge.cloud}:172.29.47.1", compose)

    def test_upstream_hardening_applies_expected_security_patches(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "static").mkdir()
            (root / "db_manager.py").write_text(
                '                default_password_hash = hashlib.sha256("admin123".encode()).hexdigest()\n'
                + harden_patch.SQL_PARAMETER_LOG_BLOCK
                + "\n"
                '                logger.info(f"[DEBUG DB] 执行SQL: {sql}")\n'
                '                logger.info(f"[DEBUG DB] 参数: {params}")\n',
                encoding="utf-8",
            )
            (root / "reply_server.py").write_text(
                'DEFAULT_ADMIN_PASSWORD = "admin123"  # 系统初始化时的默认密码\n',
                encoding="utf-8",
            )
            (root / "file_log_collector.py").write_text(
                '            self.log_file = "realtime.log"\n',
                encoding="utf-8",
            )
            (root / "static" / "login.html").write_text(
                '<code class="bg-white px-2 py-1 rounded">admin123</code>\n'
                "document.getElementById('password').value = 'admin123';\n",
                encoding="utf-8",
            )

            harden_patch.patch_tree(root)
            first_hardened_database_content = (root / "db_manager.py").read_text(encoding="utf-8")
            harden_patch.patch_tree(root)

            database_content = (root / "db_manager.py").read_text(encoding="utf-8")
            login_content = (root / "static" / "login.html").read_text(encoding="utf-8")
            log_collector_content = (root / "file_log_collector.py").read_text(encoding="utf-8")
            self.assertIn(harden_patch.DB_PASSWORD_SENTINEL, database_content)
            self.assertIn(harden_patch.CARD_UPDATE_LOG_SENTINEL, database_content)
            self.assertIn(harden_patch.SQL_PARAMETER_LOG_SENTINEL, database_content)
            self.assertIn('os.getenv("ADMIN_PASSWORD", "")', database_content)
            self.assertNotIn('[DEBUG DB] 执行SQL: {sql}', database_content)
            self.assertNotIn('[DEBUG DB] 参数: {params}', database_content)
            self.assertIn("卡券更新语句已准备", database_content)
            self.assertIn("参数值已脱敏", database_content)
            for fragment in harden_patch.FORBIDDEN_DATABASE_LOG_FRAGMENTS:
                self.assertNotIn(fragment, database_content)
            self.assertEqual(database_content, first_hardened_database_content)
            self.assertNotIn(">admin123<", login_content)
            self.assertIn("由部署管理员保管", login_content)
            self.assertIn(harden_patch.LOG_PATH_SENTINEL, log_collector_content)
            self.assertIn('"logs/realtime.log"', log_collector_content)

    def test_upstream_database_log_patch_fails_closed_when_source_drifts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "static").mkdir()
            drifted_log_block = harden_patch.SQL_PARAMETER_LOG_BLOCK.replace(
                "# 格式化参数",
                "# 上游已修改参数格式化",
            )
            (root / "db_manager.py").write_text(
                '                default_password_hash = hashlib.sha256("admin123".encode()).hexdigest()\n'
                + drifted_log_block
                + "\n"
                '                logger.info(f"[DEBUG DB] 执行SQL: {sql}")\n'
                '                logger.info(f"[DEBUG DB] 参数: {params}")\n',
                encoding="utf-8",
            )
            (root / "reply_server.py").write_text(
                'DEFAULT_ADMIN_PASSWORD = "admin123"  # 系统初始化时的默认密码\n',
                encoding="utf-8",
            )
            (root / "file_log_collector.py").write_text(
                '            self.log_file = "realtime.log"\n',
                encoding="utf-8",
            )
            (root / "static" / "login.html").write_text(
                '<code class="bg-white px-2 py-1 rounded">admin123</code>\n'
                "document.getElementById('password').value = 'admin123';\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                harden_patch.patch_tree(root)

    def test_bridge_payload_is_server_scoped_and_single_unit(self) -> None:
        query = {
            "order_id": ["order-1"],
            "product_key": ["10h"],
            "unit_index": ["1"],
        }
        environment = {
            "XIANYU_PROVIDER_ACCOUNT": "seller-1",
            "CODE_ISSUANCE_HMAC_SECRET": "test-bridge-hmac-secret-at-least-32-bytes",
        }
        with patch.dict(os.environ, environment):
            payload = bridge._issuance_payload(query)

        self.assertEqual(payload["product_key"], "10h")
        self.assertRegex(payload["request_id"], r"^xi1_[0-9a-f]{64}$")
        self.assertNotIn("order-1", json.dumps(payload))
        self.assertNotIn("seller-1", json.dumps(payload))

    def test_bridge_hmac_matches_platform_contract(self) -> None:
        secret = "test-bridge-hmac-secret-at-least-32-bytes"
        payload = {
            "product_key": "10h",
            "request_id": "xi1_" + "d" * 64,
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response()

        environment = {
            "PLATFORM_CODE_ISSUANCE_URL": "https://example.test/api/integrations/code-issuances/issue",
            "CODE_ISSUANCE_SERVICE_ID": "test-bridge",
            "CODE_ISSUANCE_HMAC_SECRET": secret,
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(bridge.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            status, response = bridge._post_to_platform(payload)

        request = captured["request"]
        body = bytes(request.data)
        headers = {name.lower(): value for name, value in request.header_items()}
        expected = sign_integration_request(
            secret=secret,
            method="POST",
            path=bridge.ISSUE_PATH,
            timestamp=headers["x-vf-timestamp"],
            nonce=headers["x-vf-nonce"],
            body=body,
        )
        self.assertEqual(status, 200)
        self.assertTrue(response["ok"])
        self.assertEqual(headers["x-vf-signature"], expected)
        self.assertEqual(json.loads(body.decode("utf-8")), payload)
        self.assertEqual(captured["timeout"], 12)

    def test_bridge_formats_private_platform_payload_for_api_card(self) -> None:
        response = {
            "ok": True,
            "data": {
                "product_name": "10 小时",
                "redemption_code": "VF1-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-QQ",
                "download_url": "https://example.test/download",
            },
            "issuance_id": 7,
            "trace_id": "trace-7",
            "duplicate": False,
        }

        status, formatted = bridge._delivery_response(200, response)

        self.assertEqual(status, 200)
        self.assertIn("10 小时", formatted["data"])
        self.assertIn("VF1-AAAA", formatted["data"])
        self.assertIn("https://example.test/download", formatted["data"])
        self.assertEqual(formatted["issuance_id"], 7)


if __name__ == "__main__":
    unittest.main()
