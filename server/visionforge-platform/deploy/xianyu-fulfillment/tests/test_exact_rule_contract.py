"""Offline acceptance tests for managed Xianyu rule resolution.

The suite uses a temporary upstream SQLite database and a silent logger.  It
never imports cookies, runtime data, or production configuration.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet


UPSTREAM_ROOT = Path(__file__).resolve().parents[1] / "upstream"
DATABASE_MANAGER_PATH = UPSTREAM_ROOT / "db_manager.py"
AUTO_DELIVERY_PATH = UPSTREAM_ROOT / "XianyuAutoAsync.py"
BRIDGE_URL = "http://fulfillment-bridge:8080/issue"
TEST_BEARER_TOKEN = "x" * 32
TEST_AUTHORIZATION = f"Bearer {TEST_BEARER_TOKEN}"
PRODUCT_KEYS = {
    "1小时": "1h",
    "5小时": "5h",
    "10小时": "10h",
    "50小时": "50h",
    "100小时": "100h",
}


class _SilentLogger:
    @staticmethod
    def debug(*_args, **_kwargs) -> None:
        return None

    info = debug
    warning = debug
    error = debug


def _load_database_manager(database_path: Path):
    if not DATABASE_MANAGER_PATH.is_file():
        return None
    fake_loguru = types.ModuleType("loguru")
    fake_loguru.logger = _SilentLogger()
    previous_loguru = sys.modules.get("loguru")
    environment = {
        "DB_PATH": str(database_path),
        "SECRET_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
        "SQL_LOG_ENABLED": "false",
    }
    try:
        sys.path.insert(0, str(UPSTREAM_ROOT))
        sys.modules["loguru"] = fake_loguru
        with patch.dict(os.environ, environment):
            spec = importlib.util.spec_from_file_location(
                "visionforge_exact_rule_contract_database",
                DATABASE_MANAGER_PATH,
            )
            module = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(module)
            return module
    finally:
        if sys.path and sys.path[0] == str(UPSTREAM_ROOT):
            sys.path.pop(0)
        if previous_loguru is None:
            sys.modules.pop("loguru", None)
        else:
            sys.modules["loguru"] = previous_loguru


@unittest.skipUnless(
    DATABASE_MANAGER_PATH.is_file(),
    "pinned upstream checkout is absent; run prepare.sh source checkout first",
)
class ExactRuleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bootstrap_directory = tempfile.TemporaryDirectory()
        bootstrap_path = Path(cls.bootstrap_directory.name) / "bootstrap.db"
        cls.database_module = _load_database_manager(bootstrap_path)
        if cls.database_module is None:
            raise unittest.SkipTest("upstream database manager is unavailable")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.database_module.db_manager.close()
        cls.bootstrap_directory.cleanup()

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_directory.name) / "rules.db"
        environment = {
            "SECRET_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            "SQL_LOG_ENABLED": "false",
        }
        with patch.dict(os.environ, environment):
            self.manager = self.database_module.DBManager(str(database_path))
        self.user_id = int(
            self.manager.conn.execute(
                "SELECT id FROM users WHERE username = 'admin'"
            ).fetchone()[0]
        )
        self.account_id = "isolated-account"
        self.item_id = "isolated-item"
        self.manager.conn.execute(
            "INSERT INTO cookies (id, value, user_id) VALUES (?, ?, ?)",
            (self.account_id, "test-cookie-not-used", self.user_id),
        )
        self.manager.conn.execute(
            "INSERT INTO item_info (cookie_id, item_id, item_title, is_multi_spec) "
            "VALUES (?, ?, 'VisionForge isolated item', 1)",
            (self.account_id, self.item_id),
        )
        self.manager.conn.commit()

    def tearDown(self) -> None:
        self.manager.close()
        self.temp_directory.cleanup()

    def test_exact_account_item_and_spec_resolves_one_rule(self) -> None:
        rule_id = self._create_bound_rule("1小时")

        matched = self._resolve("1小时")
        wrong_account = self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id="other-account",
            item_id=self.item_id,
            spec_name="套餐",
            spec_value="1小时",
        )
        wrong_item = self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id="other-item",
            spec_name="套餐",
            spec_value="1小时",
        )

        self.assertEqual(matched["status"], "matched")
        self.assertEqual([rule["id"] for rule in matched["rules"]], [rule_id])
        self.assertEqual(wrong_account["status"], "missing")
        self.assertEqual(wrong_item["status"], "missing")

    def test_unknown_missing_or_partial_spec_fails_closed(self) -> None:
        self._create_bound_rule("10小时")

        unknown = self._resolve("100小时")
        missing = self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id=self.item_id,
        )
        partial = self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id=self.item_id,
            spec_name="套餐",
            spec_value="",
        )

        self.assertEqual(unknown["status"], "missing")
        self.assertEqual(unknown["error_code"], "RULE_MATCH_MISSING")
        self.assertEqual(missing["status"], "missing")
        self.assertEqual(partial["status"], "missing")
        self.assertEqual(partial["error_code"], "RULE_MATCH_SPEC_INVALID")
        self.assertEqual(partial["rules"], [])

    def test_duplicate_spec_binding_is_rejected_at_configuration_time(self) -> None:
        first_card_id = self._create_card("5小时")
        duplicate_card_id = self._create_card("5 小时")
        bindings = [
            self._binding_for_card(first_card_id, "5小时"),
            self._binding_for_card(duplicate_card_id, "5 小时"),
        ]
        operation = self._create_operation("duplicate-spec")
        kwargs = {}
        if "managed_operation_id" in inspect.signature(
            self.manager.bind_managed_multi_spec_rules
        ).parameters:
            kwargs["managed_operation_id"] = operation["id"]

        with self.assertRaisesRegex(ValueError, "RULE_BINDING_DUPLICATE_SPEC"):
            self.manager.bind_managed_multi_spec_rules(
                user_id=self.user_id,
                account_id=self.account_id,
                item_id=self.item_id,
                bindings=bindings,
                **kwargs,
            )

        self.assertEqual(self._resolve("5小时")["status"], "missing")

    def test_legacy_duplicate_rows_resolve_ambiguous_and_never_choose_first(self) -> None:
        self._create_bound_rule("50小时")
        connection = self.manager.conn
        connection.execute("DROP INDEX uq_delivery_rules_exact_spec")
        connection.execute("DROP INDEX uq_delivery_rules_managed_operation_spec")
        connection.execute(
            "INSERT INTO delivery_rules "
            "(keyword, card_id, user_id, account_id, item_id, binding_spec_name, "
            "binding_spec_value, binding_spec_name_2, binding_spec_value_2, binding_spec_key, "
            "is_managed, managed_operation_id, managed_card_config_fingerprint) "
            "SELECT keyword, card_id, user_id, account_id, item_id, binding_spec_name, "
            "binding_spec_value, binding_spec_name_2, binding_spec_value_2, binding_spec_key, "
            "is_managed, managed_operation_id, managed_card_config_fingerprint "
            "FROM delivery_rules LIMIT 1"
        )
        connection.commit()

        result = self._resolve("50小时")

        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["error_code"], "RULE_MATCH_AMBIGUOUS")
        self.assertEqual(len(result["rules"]), 2)

    def test_auto_delivery_checks_order_quantity_before_exact_rule_resolution(self) -> None:
        auto_delivery = self._auto_delivery_node()
        call_lines: dict[str, list[int]] = {}
        for node in ast.walk(auto_delivery):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func)
            call_lines.setdefault(name, []).append(node.lineno)

        self.assertIn("validate_single_unit_order_quantity", call_lines)
        self.assertIn("resolve_exact_delivery_rule", call_lines)
        self.assertIn("_get_api_card_content", call_lines)
        self.assertLess(
            min(call_lines["validate_single_unit_order_quantity"]),
            min(call_lines["resolve_exact_delivery_rule"]),
        )
        self.assertLess(
            min(call_lines["resolve_exact_delivery_rule"]),
            min(call_lines["_get_api_card_content"]),
        )

        delivery_count_guard = next(
            (
                node
                for node in ast.walk(auto_delivery)
                if isinstance(node, ast.If)
                and "managed_exact_binding" in {
                    name.id for name in ast.walk(node.test) if isinstance(name, ast.Name)
                }
                and "delivery_count" in {
                    value.value
                    for value in ast.walk(node.test)
                    if isinstance(value, ast.Constant) and isinstance(value.value, str)
                }
            ),
            None,
        )
        self.assertIsNotNone(delivery_count_guard)
        self.assertLess(delivery_count_guard.lineno, min(call_lines["_get_api_card_content"]))

    def test_exact_branch_requires_managed_binding_and_keeps_legacy_multi_spec_path(self) -> None:
        auto_delivery = self._auto_delivery_node()
        exact_branch = next(
            (
                node
                for node in ast.walk(auto_delivery)
                if isinstance(node, ast.If)
                and self._contains_call(node.body, "resolve_exact_delivery_rule")
            ),
            None,
        )

        self.assertIsNotNone(exact_branch)
        condition_names = {
            node.id for node in ast.walk(exact_branch.test) if isinstance(node, ast.Name)
        }
        self.assertIn("managed_exact_binding", condition_names)
        self.assertTrue(
            self._contains_call(auto_delivery.body, "get_delivery_rules_by_keyword_and_spec")
        )

    def _create_bound_rule(self, spec_value: str) -> int:
        card_id = self._create_card(spec_value)
        operation = self._create_operation(f"resolve-{spec_value}")
        binding = self._binding_for_card(card_id, spec_value)
        cursor = self.manager.conn.execute(
            "INSERT INTO delivery_rules "
            "(keyword, card_id, delivery_count, enabled, description, user_id, account_id, "
            "item_id, binding_spec_name, binding_spec_value, binding_spec_name_2, "
            "binding_spec_value_2, binding_spec_key, is_managed, managed_operation_id, "
            "managed_card_config_fingerprint) "
            "VALUES ('VisionForge', ?, 1, 1, 'managed resolver fixture', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                card_id,
                self.user_id,
                self.account_id,
                self.item_id,
                binding["spec_name"],
                binding["spec_value"],
                binding["spec_name_2"],
                binding["spec_value_2"],
                binding["binding_spec_key"],
                operation["id"],
                binding["managed_card_config_fingerprint"],
            ),
        )
        self.manager.conn.commit()
        return int(cursor.lastrowid)

    def _create_card(self, spec_value: str) -> int:
        normalized_spec_value = spec_value.replace(" ", "")
        api_config = {
            "url": BRIDGE_URL,
            "method": "GET",
            "headers": {"Authorization": TEST_AUTHORIZATION},
            "params": {
                "order_id": "{order_id}",
                "product_key": PRODUCT_KEYS[normalized_spec_value],
                "unit_index": "1",
            },
        }
        cursor = self.manager.conn.execute(
            "INSERT INTO cards "
            "(name, type, api_config, enabled, is_multi_spec, spec_name, spec_value, user_id) "
            "VALUES (?, 'api', ?, 1, 1, '套餐', ?, ?)",
            (
                f"VisionForge {spec_value}",
                json.dumps(api_config, ensure_ascii=False),
                spec_value,
                self.user_id,
            ),
        )
        self.manager.conn.commit()
        return int(cursor.lastrowid)

    def _binding_for_card(self, card_id: int, spec_value: str):
        snapshot = self.database_module.build_binding_snapshot(
            (True, "套餐", spec_value, None, None)
        )
        card = self.manager.get_card_by_id(card_id, self.user_id)
        return {
            "card_id": card_id,
            "spec_name": snapshot[0],
            "spec_value": snapshot[1],
            "spec_name_2": snapshot[2],
            "spec_value_2": snapshot[3],
            "binding_spec_key": snapshot[4],
            "managed_card_config_fingerprint": (
                self.database_module.fingerprint_managed_api_config(
                    card["api_config"]
                )
            ),
        }

    def _create_operation(self, suffix: str):
        return self.manager.create_or_get_visionforge_operation(
            operation_id=f"exact-operation-{suffix}",
            user_id=self.user_id,
            client_request_id=f"exact-request-{suffix}",
            operation_type="bind_existing",
            account_id=self.account_id,
            item_id=self.item_id,
            status="bound",
            payload={"fixture": suffix},
        )

    def _resolve(self, spec_value: str):
        return self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id=self.item_id,
            spec_name="套餐",
            spec_value=spec_value,
        )

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @classmethod
    def _contains_call(cls, nodes, expected_name: str) -> bool:
        if not isinstance(nodes, list):
            nodes = [nodes]
        return any(
            isinstance(node, ast.Call) and cls._call_name(node.func) == expected_name
            for root in nodes
            for node in ast.walk(root)
        )

    @staticmethod
    def _auto_delivery_node():
        tree = ast.parse(AUTO_DELIVERY_PATH.read_text(encoding="utf-8"))
        return next(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_auto_delivery"
        )


if __name__ == "__main__":
    unittest.main()
