"""Offline safety contracts for the VisionForge managed fulfillment workflow.

The tests use only temporary SQLite databases and source inspection.  They do
not import cookies, contact Xianyu, invoke a card API, or touch a deployment.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet


UPSTREAM_ROOT = Path(__file__).resolve().parents[1] / "upstream"
DATABASE_MANAGER_PATH = UPSTREAM_ROOT / "db_manager.py"
SERVICE_PATH = UPSTREAM_ROOT / "services" / "visionforge_fulfillment.py"
AUTO_DELIVERY_PATH = UPSTREAM_ROOT / "XianyuAutoAsync.py"
REPLY_SERVER_PATH = UPSTREAM_ROOT / "reply_server.py"
FULFILLMENT_CONFIG_PATH = (
    UPSTREAM_ROOT / "infrastructure" / "visionforge_fulfillment_config.py"
)
CARD_CONTRACT_PATH = (
    UPSTREAM_ROOT / "infrastructure" / "visionforge_card_contract.py"
)
FULFILLMENT_SECURITY_PATH = (
    UPSTREAM_ROOT / "domain" / "visionforge_fulfillment_security.py"
)

SPEC_NAME = "Package"
SPEC_VALUES = ("1h", "5h", "10h", "50h", "100h")
EXPECTED_COVERAGE = {
    "expected": len(SPEC_VALUES),
    "bound": len(SPEC_VALUES),
    "missing": 0,
    "duplicate": 0,
}
BRIDGE_URL = "http://fulfillment-bridge:8080/issue"
TEST_BEARER_TOKEN = "x" * 32
TEST_AUTHORIZATION = f"Bearer {TEST_BEARER_TOKEN}"
PRODUCT_KEY_BY_SPEC_VALUE = {value: value for value in SPEC_VALUES}
TEST_REDEMPTION_CODE = "VF1-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-QQ"


class _SilentLogger:
    @staticmethod
    def debug(*_args, **_kwargs) -> None:
        return None

    info = debug
    warning = debug
    error = debug
    exception = debug


def _load_modules(bootstrap_database_path: Path):
    fake_loguru = types.ModuleType("loguru")
    fake_loguru.logger = _SilentLogger()
    previous_loguru = sys.modules.get("loguru")
    environment = {
        "DB_PATH": str(bootstrap_database_path),
        "SECRET_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
        "SQL_LOG_ENABLED": "false",
        "VISIONFORGE_MANAGED_FULFILLMENT_MODE": "live",
    }
    database_module_name = "visionforge_managed_safety_database"
    service_module_name = "visionforge_managed_safety_service"
    card_contract_module_name = "visionforge_managed_safety_card_contract"
    fulfillment_security_module_name = "visionforge_managed_safety_security"
    try:
        sys.path.insert(0, str(UPSTREAM_ROOT))
        sys.modules["loguru"] = fake_loguru
        with patch.dict(os.environ, environment):
            database_spec = importlib.util.spec_from_file_location(
                database_module_name,
                DATABASE_MANAGER_PATH,
            )
            database_module = importlib.util.module_from_spec(database_spec)
            assert database_spec and database_spec.loader
            sys.modules[database_module_name] = database_module
            database_spec.loader.exec_module(database_module)

            card_contract_spec = importlib.util.spec_from_file_location(
                card_contract_module_name,
                CARD_CONTRACT_PATH,
            )
            card_contract_module = importlib.util.module_from_spec(card_contract_spec)
            assert card_contract_spec and card_contract_spec.loader
            sys.modules[card_contract_module_name] = card_contract_module
            card_contract_spec.loader.exec_module(card_contract_module)

            fulfillment_security_spec = importlib.util.spec_from_file_location(
                fulfillment_security_module_name,
                FULFILLMENT_SECURITY_PATH,
            )
            fulfillment_security_module = importlib.util.module_from_spec(
                fulfillment_security_spec
            )
            assert fulfillment_security_spec and fulfillment_security_spec.loader
            sys.modules[fulfillment_security_module_name] = fulfillment_security_module
            fulfillment_security_spec.loader.exec_module(fulfillment_security_module)

            service_spec = importlib.util.spec_from_file_location(
                service_module_name,
                SERVICE_PATH,
            )
            service_module = importlib.util.module_from_spec(service_spec)
            assert service_spec and service_spec.loader
            sys.modules[service_module_name] = service_module
            service_spec.loader.exec_module(service_module)
        return (
            database_module,
            service_module,
            card_contract_module,
            fulfillment_security_module,
        )
    finally:
        if sys.path and sys.path[0] == str(UPSTREAM_ROOT):
            sys.path.pop(0)
        if previous_loguru is None:
            sys.modules.pop("loguru", None)
        else:
            sys.modules["loguru"] = previous_loguru


@unittest.skipUnless(
    DATABASE_MANAGER_PATH.is_file()
    and SERVICE_PATH.is_file()
    and CARD_CONTRACT_PATH.is_file()
    and FULFILLMENT_SECURITY_PATH.is_file(),
    "pinned upstream checkout is absent; run prepare.sh source checkout first",
)
class ManagedFulfillmentSafetyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bootstrap_directory = tempfile.TemporaryDirectory()
        bootstrap_path = Path(cls.bootstrap_directory.name) / "bootstrap.db"
        (
            cls.database_module,
            cls.service_module,
            cls.card_contract_module,
            cls.fulfillment_security_module,
        ) = _load_modules(bootstrap_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.database_module.db_manager.close()
        cls.bootstrap_directory.cleanup()

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_directory.name) / "managed.db"
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
        self.account_id = "managed-account"
        self.item_id = "managed-item"
        encrypted_cookie = self.manager._encrypt_secret("offline-cookie-not-used")
        self.manager.conn.execute(
            "INSERT INTO cookies (id, value, user_id) VALUES (?, ?, ?)",
            (self.account_id, encrypted_cookie, self.user_id),
        )
        self.manager.conn.execute(
            "INSERT INTO item_info "
            "(cookie_id, item_id, item_title, item_detail, is_multi_spec) "
            "VALUES (?, ?, 'VisionForge managed item', ?, 1)",
            (self.account_id, self.item_id, self._item_detail(SPEC_VALUES)),
        )
        self.manager.conn.commit()

        self.card_ids = [self._create_api_card(value) for value in SPEC_VALUES]
        config = self.service_module.CatalogConfig(
            spec_name=SPEC_NAME,
            spec_values=SPEC_VALUES,
            default_inventory=999,
            mode=self.service_module.FulfillmentMode.LIVE,
        )
        card_validator = self.card_contract_module.ManagedApiCardContractValidator(
            bridge_url=BRIDGE_URL,
            product_keys_by_spec=PRODUCT_KEY_BY_SPEC_VALUE,
            bearer_token=TEST_BEARER_TOKEN,
        )
        self.service = self.service_module.VisionForgeFulfillmentService(
            self.manager,
            config=config,
            managed_card_validator=card_validator,
        )
        self.variants = [
            {"card_id": card_id, "spec_value": spec_value}
            for card_id, spec_value in zip(self.card_ids, SPEC_VALUES)
        ]
        self.bindings = self.service.build_bindings(self.user_id, self.variants)

    def tearDown(self) -> None:
        self.manager.close()
        self.temp_directory.cleanup()

    def test_bind_existing_forces_previously_enabled_exact_rules_disabled(self) -> None:
        old_operation = self._create_operation(
            "old-enabled-binding",
            status=self.service_module.OperationStatus.VALIDATING.value,
        )
        self._bind_rules(operation=old_operation)
        old_operation = self.manager.get_visionforge_operation(
            old_operation["id"], self.user_id
        )
        old_operation = self._transition_rules(
            old_operation,
            target_status=self.service_module.OperationStatus.BOUND.value,
            enabled=True,
        )
        new_operation = self._create_operation(
            "bind-existing-disabled-contract",
            status=self.service_module.OperationStatus.VALIDATING.value,
        )

        response = self._bind_rules(operation=new_operation)

        persisted_old = self.manager.get_visionforge_operation(
            old_operation["id"], self.user_id
        )
        self.assertEqual(self._rule_enabled_values(), [0] * len(SPEC_VALUES))
        self.assertEqual(response["enabled"], False)
        self.assertEqual(response["status"], "requires_activation")
        self.assertEqual(persisted_old["status"], "deactivated")

    def test_concurrent_activate_and_deactivate_never_split_operation_and_rules(self) -> None:
        operation = self._create_bound_operation("concurrent-transition")
        start_barrier = threading.Barrier(2)
        results = []
        errors = []

        def run_transition(target) -> None:
            try:
                start_barrier.wait(timeout=5)
                results.append(target())
            except Exception as exc:  # The losing optimistic transition may fail.
                errors.append(exc)

        activate_thread = threading.Thread(
            name="activate-managed-rules",
            target=run_transition,
            args=(
                lambda: self.service.activate(
                    self.user_id,
                    operation["id"],
                    operation["version"],
                    True,
                ),
            ),
        )
        deactivate_thread = threading.Thread(
            name="deactivate-managed-rules",
            target=run_transition,
            args=(
                lambda: self.service.deactivate(
                    self.user_id,
                    operation["id"],
                    operation["version"],
                    True,
                ),
            ),
        )
        deactivate_thread.start()
        activate_thread.start()
        activate_thread.join(timeout=10)
        deactivate_thread.join(timeout=10)

        self.assertFalse(activate_thread.is_alive())
        self.assertFalse(deactivate_thread.is_alive())
        self.assertEqual(
            len(results),
            1,
            [f"{type(error).__name__}: {error}" for error in errors],
        )
        self.assertEqual(len(errors), 1, results)
        for error in errors:
            self.assertIsInstance(error, ValueError)
            self.assertRegex(
                str(error),
                "OPERATION_VERSION_CONFLICT|OPERATION_STATE_INVALID",
            )

        persisted = self.manager.get_visionforge_operation(operation["id"], self.user_id)
        enabled_values = self._rule_enabled_values()
        if persisted["status"] == self.service_module.OperationStatus.BOUND.value:
            self.assertEqual(enabled_values, [1] * len(SPEC_VALUES))
        elif persisted["status"] == self.service_module.OperationStatus.DEACTIVATED.value:
            self.assertEqual(enabled_values, [0] * len(SPEC_VALUES))
        else:
            self.fail(f"unexpected final operation status: {persisted['status']}")

    def test_generic_create_cannot_create_an_exact_managed_binding(self) -> None:
        second_item_id = "generic-create-bypass-item"
        self.manager.conn.execute(
            "INSERT INTO item_info (cookie_id, item_id, item_title, is_multi_spec) "
            "VALUES (?, ?, 'Bypass target', 1)",
            (self.account_id, second_item_id),
        )
        self.manager.conn.commit()

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.create_delivery_rule(
                "bypass",
                self.card_ids[0],
                user_id=self.user_id,
                account_id=self.account_id,
                item_id=second_item_id,
            )

        count = self.manager.conn.execute(
            "SELECT COUNT(*) FROM delivery_rules WHERE item_id = ?",
            (second_item_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_generic_create_cannot_reuse_a_card_owned_by_managed_rules(self) -> None:
        self._bind_rules()

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.create_delivery_rule(
                "VisionForge legacy bypass",
                self.card_ids[0],
                user_id=self.user_id,
            )

    def test_generic_update_cannot_switch_to_a_card_owned_by_managed_rules(self) -> None:
        text_card_id = self._create_text_card()
        generic_rule_id = self.manager.create_delivery_rule(
            "ordinary rule",
            text_card_id,
            user_id=self.user_id,
        )
        self._bind_rules()

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.update_delivery_rule(
                generic_rule_id,
                card_id=self.card_ids[0],
                user_id=self.user_id,
            )

        persisted = self.manager.get_delivery_rule_by_id(
            generic_rule_id, self.user_id
        )
        self.assertEqual(persisted["card_id"], text_card_id)

    def test_managed_bind_rejects_cards_already_used_by_generic_rules(self) -> None:
        generic_rule_id = self.manager.create_delivery_rule(
            "preexisting legacy bypass",
            self.card_ids[0],
            user_id=self.user_id,
        )
        operation = self._create_operation(
            "generic-card-conflict",
            status=self.service_module.OperationStatus.VALIDATING.value,
        )

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self._bind_rules(operation=operation)

        self.assertIsNotNone(
            self.manager.get_delivery_rule_by_id(generic_rule_id, self.user_id)
        )
        managed_count = self.manager.conn.execute(
            "SELECT COUNT(*) FROM delivery_rules WHERE is_managed = 1"
        ).fetchone()[0]
        self.assertEqual(managed_count, 0)

    def test_managed_binding_repository_requires_an_owning_operation(self) -> None:
        parameter = inspect.signature(
            self.manager.bind_managed_multi_spec_rules
        ).parameters.get("managed_operation_id")

        self.assertIsNotNone(parameter)
        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_managed_binding_repository_rejects_direct_activation(self) -> None:
        signature = inspect.signature(self.manager.bind_managed_multi_spec_rules)
        activate_parameter = signature.parameters.get("activate")
        if activate_parameter is None:
            return

        operation = self._create_operation(
            "direct-activation-bypass",
            status=self.service_module.OperationStatus.VALIDATING.value,
        )
        with self.assertRaises((TypeError, ValueError)):
            self.manager.bind_managed_multi_spec_rules(
                user_id=self.user_id,
                managed_operation_id=operation["id"],
                account_id=self.account_id,
                item_id=self.item_id,
                bindings=self.bindings,
                activate=True,
            )

    def test_bind_fails_closed_for_each_invalid_jit_card_contract(self) -> None:
        card_id = self.card_ids[0]
        for label, invalid_config in self._invalid_api_configs(SPEC_VALUES[0]):
            with self.subTest(contract_error=label):
                self._replace_api_config(card_id, invalid_config)
                try:
                    with self.assertRaisesRegex(
                        ValueError,
                        "MANAGED_CARD_CONFIG_(?:INVALID|DRIFTED)",
                    ):
                        self.service.bind_existing(
                            self.user_id,
                            self.account_id,
                            self.item_id,
                            f"invalid-jit-bind-{label}",
                            self.variants,
                        )
                finally:
                    self._replace_api_config(
                        card_id,
                        self._api_config(SPEC_VALUES[0]),
                    )
                managed_count = self.manager.conn.execute(
                    "SELECT COUNT(*) FROM delivery_rules WHERE is_managed = 1"
                ).fetchone()[0]
                self.assertEqual(managed_count, 0)

    def test_activate_fails_closed_for_each_drifted_jit_card_contract(self) -> None:
        card_id = self.card_ids[0]
        for label, invalid_config in self._invalid_api_configs(SPEC_VALUES[0]):
            with self.subTest(contract_error=label):
                mutation = self.service.bind_existing(
                    self.user_id,
                    self.account_id,
                    self.item_id,
                    f"invalid-jit-activate-{label}",
                    self.variants,
                )
                self._replace_api_config(card_id, invalid_config)
                try:
                    with self.assertRaisesRegex(
                        ValueError,
                        "MANAGED_CARD_CONFIG_(?:INVALID|DRIFTED)|"
                        "RULE_BINDING_NOT_ACTIVATABLE",
                    ):
                        self.service.activate(
                            self.user_id,
                            mutation["operation_id"],
                            mutation["operation_version"],
                            True,
                        )
                finally:
                    self._replace_api_config(
                        card_id,
                        self._api_config(SPEC_VALUES[0]),
                    )
                persisted = self.manager.get_visionforge_operation(
                    mutation["operation_id"], self.user_id
                )
                self.assertEqual(persisted["status"], "requires_activation")
                self.assertEqual(self._rule_enabled_values(), [0] * len(SPEC_VALUES))

    def test_managed_finalization_persists_no_plaintext_and_keeps_generic_reservation_meta(
        self,
    ) -> None:
        managed_meta = {
            "match_mode": "managed_exact_binding",
            "content": f"兑换码：{TEST_REDEMPTION_CODE}",
            "delivery_steps": [
                {"type": "text", "content": TEST_REDEMPTION_CODE}
            ],
            "data_line": TEST_REDEMPTION_CODE,
            "nested": {"diagnostic": TEST_REDEMPTION_CODE},
            "delivery_unit_index": 1,
        }
        sanitized = self.fulfillment_security_module.sanitize_delivery_meta(
            managed_meta
        )
        self.assertFalse(TEST_REDEMPTION_CODE in json.dumps(sanitized))
        self.assertEqual(managed_meta["content"], f"兑换码：{TEST_REDEMPTION_CODE}")
        self.manager.upsert_delivery_finalization_state(
            "managed-finalization",
            delivery_meta=sanitized,
        )
        persisted_managed_json = self.manager.conn.execute(
            "SELECT delivery_meta FROM delivery_finalization_states WHERE order_id = ?",
            ("managed-finalization",),
        ).fetchone()[0]
        self.assertFalse(TEST_REDEMPTION_CODE in persisted_managed_json)
        self.assertFalse("兑换码：" in persisted_managed_json)

        generic_meta = {
            "match_mode": "no_spec_match",
            "card_type": "data",
            "data_card_pending_consume": True,
            "data_line": "generic-reservation-record",
            "data_reservation_id": 42,
            "delivery_unit_index": 1,
        }
        sanitized_generic = self.fulfillment_security_module.sanitize_delivery_meta(
            generic_meta
        )
        self.assertIs(sanitized_generic, generic_meta)
        self.manager.upsert_delivery_finalization_state(
            "generic-finalization",
            delivery_meta=sanitized_generic,
        )
        persisted_generic = self.manager.get_delivery_finalization_state(
            "generic-finalization"
        )["delivery_meta"]
        self.assertEqual(persisted_generic, generic_meta)

    def test_generic_update_cannot_enable_a_managed_rule(self) -> None:
        rule_id = self._bind_rules()["rule_ids"][0]

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.update_delivery_rule(
                rule_id,
                enabled=True,
                user_id=self.user_id,
            )

        self.assertEqual(self._rule_enabled_values(), [0] * len(SPEC_VALUES))

    def test_generic_delete_cannot_remove_a_managed_rule(self) -> None:
        rule_ids = self._bind_rules()["rule_ids"]

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.delete_delivery_rule(rule_ids[0], self.user_id)

        persisted_ids = [
            row[0]
            for row in self.manager.conn.execute(
                "SELECT id FROM delivery_rules WHERE item_id = ? ORDER BY id",
                (self.item_id,),
            ).fetchall()
        ]
        self.assertEqual(persisted_ids, rule_ids)

    def test_generic_card_delete_cannot_cascade_managed_rules_or_operation(self) -> None:
        operation = self._create_bound_operation("card-delete-guard")
        original_rule_ids = [
            row[0]
            for row in self.manager.conn.execute(
                "SELECT id FROM delivery_rules WHERE item_id = ? ORDER BY id",
                (self.item_id,),
            ).fetchall()
        ]

        with self.assertRaisesRegex(ValueError, "MANAGED_RULE_REQUIRES_WORKFLOW"):
            self.manager.delete_card(self.card_ids[0], self.user_id)

        self.assertIsNotNone(self.manager.get_card_by_id(self.card_ids[0], self.user_id))
        persisted_rule_ids = [
            row[0]
            for row in self.manager.conn.execute(
                "SELECT id FROM delivery_rules WHERE item_id = ? ORDER BY id",
                (self.item_id,),
            ).fetchall()
        ]
        self.assertEqual(persisted_rule_ids, original_rule_ids)
        self.assertIsNotNone(
            self.manager.get_visionforge_operation(operation["id"], self.user_id)
        )

    def test_managed_card_type_mutation_never_leaves_a_non_api_rule_matched(self) -> None:
        operation = self._create_bound_operation("card-type-mutation-guard")
        self.service.activate(
            self.user_id,
            operation["id"],
            operation["version"],
            True,
        )

        try:
            self.manager.update_card(
                self.card_ids[0],
                card_type="text",
                text_content="must-never-be-delivered",
                user_id=self.user_id,
            )
        except ValueError as error:
            self.assertRegex(str(error), "MANAGED_RULE_REQUIRES_WORKFLOW")

        card = self.manager.get_card_by_id(self.card_ids[0], self.user_id)
        resolution = self.manager.resolve_exact_delivery_rule(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id=self.item_id,
            spec_name=SPEC_NAME,
            spec_value=SPEC_VALUES[0],
        )
        self.assertFalse(
            card["type"] != "api" and resolution["status"] == "matched",
            "a managed exact binding must never resolve a non-API card for delivery",
        )

    def test_repository_transition_rejects_status_and_enabled_mismatches(self) -> None:
        invalid_transitions = (
            (True, self.service_module.OperationStatus.DEACTIVATED.value),
            (False, self.service_module.OperationStatus.BOUND.value),
        )
        for index, (enabled, target_status) in enumerate(invalid_transitions):
            with self.subTest(enabled=enabled, target_status=target_status):
                operation = self._create_bound_operation(
                    f"invalid-transition-pair-{index}"
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "OPERATION_(?:STATE|TRANSITION)_INVALID",
                ):
                    self.manager.transition_managed_multi_spec_rules(
                        user_id=self.user_id,
                        managed_operation_id=operation["id"],
                        expected_version=operation["version"],
                        expected_statuses=[operation["status"]],
                        target_status=target_status,
                        enabled=enabled,
                        expected_count=len(SPEC_VALUES),
                    )

                persisted = self.manager.get_visionforge_operation(
                    operation["id"], self.user_id
                )
                self.assertEqual(
                    persisted["status"],
                    self.service_module.OperationStatus.REQUIRES_ACTIVATION.value,
                )
                self.assertEqual(self._rule_enabled_values(), [0] * len(SPEC_VALUES))

    def test_known_synced_sku_mismatch_fails_closed(self) -> None:
        mismatched_values = (*SPEC_VALUES[:-1], "unexpected")
        self.manager.conn.execute(
            "UPDATE item_info SET item_detail = ? WHERE cookie_id = ? AND item_id = ?",
            (self._item_detail(mismatched_values), self.account_id, self.item_id),
        )
        self.manager.conn.commit()

        with self.assertRaisesRegex(ValueError, "MANAGED_ITEM_SKU_MISMATCH"):
            self.service.validate_existing_binding(
                self.user_id,
                self.account_id,
                self.item_id,
                self.variants,
            )

    def test_service_option_item_is_bindable_without_standard_sku_property_list(self) -> None:
        self.manager.conn.execute(
            "UPDATE item_info SET item_detail = ?, is_multi_spec = 0 "
            "WHERE cookie_id = ? AND item_id = ?",
            (self._service_option_item_detail(), self.account_id, self.item_id),
        )
        self.manager.conn.commit()

        synced_items = self.service.list_synced_items(self.user_id, self.account_id)
        synced_item = next(
            item for item in synced_items if item["item_id"] == self.item_id
        )
        self.assertEqual(synced_item["is_multi_spec"], True)
        self.assertEqual(synced_item["is_service_option_item"], True)
        self.assertEqual(synced_item["spec_values_status"], "service_option")
        self.assertEqual(synced_item["spec_values"], list(SPEC_VALUES))

        validation = self.service.validate_existing_binding(
            self.user_id,
            self.account_id,
            self.item_id,
            self.variants,
        )
        self.assertEqual(validation["valid"], True)
        self.assertEqual(validation["coverage_verified"], False)
        self.assertEqual(validation["binding_status"], "service_option")

        mutation = self.service.bind_existing(
            self.user_id,
            self.account_id,
            self.item_id,
            "service-option-binding",
            self.variants,
        )
        self.assertEqual(mutation["requires_activation"], True)
        self.assertEqual(mutation["rules_active"], False)

    def test_partial_legacy_managed_migration_disables_the_entire_rule_set(self) -> None:
        for enabled, binding in zip((1, 0), self.bindings[:2]):
            self.manager.conn.execute(
                "INSERT INTO delivery_rules "
                "(keyword, card_id, delivery_count, enabled, description, user_id, account_id, "
                "item_id, binding_spec_name, binding_spec_value, binding_spec_name_2, "
                "binding_spec_value_2, binding_spec_key, is_managed, managed_operation_id) "
                "VALUES (?, ?, 1, ?, 'VisionForge managed exact binding', ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
                (
                    self.item_id,
                    binding["card_id"],
                    enabled,
                    self.user_id,
                    self.account_id,
                    self.item_id,
                    binding["spec_name"],
                    binding["spec_value"],
                    binding["spec_name_2"],
                    binding["spec_value_2"],
                    binding["binding_spec_key"],
                ),
            )
        self.manager.conn.commit()

        with self.manager.lock:
            cursor = self.manager.conn.cursor()
            self.manager._execute_sql(cursor, "BEGIN IMMEDIATE")
            self.manager._migrate_legacy_managed_delivery_rules(cursor)
            self.manager.conn.commit()

        migrated = self.manager.conn.execute(
            "SELECT enabled, is_managed, managed_operation_id "
            "FROM delivery_rules WHERE item_id = ? ORDER BY id",
            (self.item_id,),
        ).fetchall()
        self.assertEqual([row[0] for row in migrated], [0, 0])
        self.assertEqual([row[1] for row in migrated], [1, 1])
        operation_ids = {row[2] for row in migrated}
        self.assertEqual(len(operation_ids), 1)
        operation = self.manager.get_visionforge_operation(
            operation_ids.pop(), self.user_id
        )
        self.assertEqual(operation["status"], "requires_activation")

    def test_legacy_migration_never_leaves_a_deactivated_owner_enabled(self) -> None:
        operation = self._create_operation(
            "legacy-deactivated-owner",
            status=self.service_module.OperationStatus.DEACTIVATED.value,
        )
        for binding in self.bindings[:2]:
            self.manager.conn.execute(
                "INSERT INTO delivery_rules "
                "(keyword, card_id, delivery_count, enabled, description, user_id, account_id, "
                "item_id, binding_spec_name, binding_spec_value, binding_spec_name_2, "
                "binding_spec_value_2, binding_spec_key, is_managed, managed_operation_id) "
                "VALUES (?, ?, 1, 1, 'VisionForge managed exact binding', ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
                (
                    self.item_id,
                    binding["card_id"],
                    self.user_id,
                    self.account_id,
                    self.item_id,
                    binding["spec_name"],
                    binding["spec_value"],
                    binding["spec_name_2"],
                    binding["spec_value_2"],
                    binding["binding_spec_key"],
                ),
            )
        self.manager.conn.commit()

        with self.manager.lock:
            cursor = self.manager.conn.cursor()
            self.manager._execute_sql(cursor, "BEGIN IMMEDIATE")
            self.manager._migrate_legacy_managed_delivery_rules(cursor)
            self.manager.conn.commit()

        migrated = self.manager.conn.execute(
            "SELECT enabled, managed_operation_id FROM delivery_rules "
            "WHERE item_id = ? ORDER BY id",
            (self.item_id,),
        ).fetchall()
        self.assertEqual([row[0] for row in migrated], [0, 0])
        self.assertEqual({row[1] for row in migrated}, {operation["id"]})
        persisted = self.manager.get_visionforge_operation(
            operation["id"], self.user_id
        )
        self.assertIn(persisted["status"], {"deactivated", "requires_activation"})
        self.assertNotEqual(persisted["status"], "bound")

    def test_validation_mutation_dry_run_and_actions_share_stable_dto_shape(self) -> None:
        validation = self.service.validate_existing_binding(
            self.user_id,
            self.account_id,
            self.item_id,
            self.variants,
        )
        self.assertEqual(validation["valid"], True)
        self.assertEqual(validation["coverage"], EXPECTED_COVERAGE)

        mutation = self.service.bind_existing(
            self.user_id,
            self.account_id,
            self.item_id,
            "stable-dto-shape",
            self.variants,
        )
        self._assert_operation_shape(mutation)
        self.assertEqual(mutation["coverage"], EXPECTED_COVERAGE)
        self.assertEqual(mutation["requires_activation"], True)
        self.assertEqual(mutation["rules_active"], False)

        dry_run = self.service.dry_run_operation(
            mutation["operation_id"],
            self.user_id,
        )
        self._assert_operation_shape(dry_run)
        self.assertEqual(dry_run["valid"], True)
        self.assertEqual(dry_run["coverage"], EXPECTED_COVERAGE)

        activated = self.service.activate(
            self.user_id,
            mutation["operation_id"],
            mutation["operation_version"],
            True,
        )
        self._assert_operation_shape(activated)
        self.assertEqual(activated["requires_activation"], False)
        self.assertEqual(activated["rules_active"], True)

        deactivated = self.service.deactivate(
            self.user_id,
            activated["operation_id"],
            activated["operation_version"],
            True,
        )
        self._assert_operation_shape(deactivated)
        self.assertEqual(deactivated["requires_activation"], True)
        self.assertEqual(deactivated["rules_active"], False)

    def _create_api_card(self, spec_value: str) -> int:
        api_config = self._api_config(spec_value)
        cursor = self.manager.conn.execute(
            "INSERT INTO cards "
            "(name, type, api_config, enabled, is_multi_spec, spec_name, spec_value, user_id) "
            "VALUES (?, 'api', ?, 1, 1, ?, ?, ?)",
            (
                f"VisionForge {spec_value}",
                json.dumps(api_config, ensure_ascii=False),
                SPEC_NAME,
                spec_value,
                self.user_id,
            ),
        )
        self.manager.conn.commit()
        return int(cursor.lastrowid)

    @staticmethod
    def _api_config(spec_value: str):
        return {
            "url": BRIDGE_URL,
            "method": "GET",
            "headers": {"Authorization": TEST_AUTHORIZATION},
            "params": {
                "order_id": "{order_id}",
                "product_key": PRODUCT_KEY_BY_SPEC_VALUE[spec_value],
                "unit_index": "1",
            },
        }

    def _replace_api_config(self, card_id: int, api_config) -> None:
        self.manager.conn.execute(
            "UPDATE cards SET api_config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (json.dumps(api_config, ensure_ascii=False), card_id),
        )
        self.manager.conn.commit()

    @classmethod
    def _invalid_api_configs(cls, spec_value: str):
        cases = []

        wrong_url = cls._api_config(spec_value)
        wrong_url["url"] = "http://fulfillment-bridge:8080/not-issue"
        cases.append(("wrong_url", wrong_url))

        wrong_product = cls._api_config(spec_value)
        wrong_product["params"]["product_key"] = "wrong-product"
        cases.append(("wrong_product_key", wrong_product))

        wrong_order_placeholder = cls._api_config(spec_value)
        wrong_order_placeholder["params"]["order_id"] = "literal-order-id"
        cases.append(("wrong_order_id", wrong_order_placeholder))

        missing_bearer = cls._api_config(spec_value)
        missing_bearer["headers"] = {}
        cases.append(("missing_bearer", missing_bearer))
        return cases

    def _create_text_card(self) -> int:
        cursor = self.manager.conn.execute(
            "INSERT INTO cards (name, type, text_content, enabled, user_id) "
            "VALUES ('ordinary text card', 'text', 'offline test', 1, ?)",
            (self.user_id,),
        )
        self.manager.conn.commit()
        return int(cursor.lastrowid)

    def _bind_rules(self, *, operation=None):
        operation = operation or self._create_operation(
            "fixture-bind",
            status=self.service_module.OperationStatus.REQUIRES_ACTIVATION.value,
        )
        kwargs = {
            "managed_operation_id": operation["id"],
        }
        signature = inspect.signature(self.manager.bind_managed_multi_spec_rules)
        if "managed_operation_id" not in signature.parameters:
            kwargs = {}
        result = self.manager.bind_managed_multi_spec_rules(
            user_id=self.user_id,
            account_id=self.account_id,
            item_id=self.item_id,
            bindings=self.bindings,
            **kwargs,
        )
        if not kwargs:
            self.manager.conn.execute(
                "UPDATE delivery_rules SET is_managed = 1, managed_operation_id = ? "
                "WHERE user_id = ? AND account_id = ? AND item_id = ?",
                (operation["id"], self.user_id, self.account_id, self.item_id),
            )
            self.manager.conn.commit()
        return result

    def _transition_rules(self, operation, *, target_status: str, enabled: bool):
        result = self.manager.transition_managed_multi_spec_rules(
            user_id=self.user_id,
            managed_operation_id=operation["id"],
            expected_version=operation["version"],
            expected_statuses=[operation["status"]],
            target_status=target_status,
            enabled=enabled,
            expected_count=len(SPEC_VALUES),
        )
        return result["operation"]

    def _create_bound_operation(self, client_request_id: str):
        operation = self._create_operation(
            client_request_id,
            status=self.service_module.OperationStatus.REQUIRES_ACTIVATION.value,
        )
        self._bind_rules(operation=operation)
        return self.manager.get_visionforge_operation(operation["id"], self.user_id)

    def _create_operation(self, client_request_id: str, *, status: str, payload=None):
        return self.manager.create_or_get_visionforge_operation(
            operation_id=f"operation-{client_request_id}",
            user_id=self.user_id,
            client_request_id=client_request_id,
            operation_type="bind_existing",
            account_id=self.account_id,
            item_id=self.item_id,
            status=status,
            payload=payload or {"contract": client_request_id},
        )

    def _rule_enabled_values(self):
        return [
            int(row[0])
            for row in self.manager.conn.execute(
                "SELECT enabled FROM delivery_rules WHERE item_id = ? ORDER BY id",
                (self.item_id,),
            ).fetchall()
        ]

    @staticmethod
    def _item_detail(spec_values) -> str:
        return json.dumps(
            {
                "itemSkuList": [
                    {
                        "propertyList": [
                            {"propertyText": SPEC_NAME, "valueText": value}
                        ]
                    }
                    for value in spec_values
                ]
            },
            ensure_ascii=False,
        )

    @staticmethod
    def _service_option_item_detail() -> str:
        return json.dumps(
            {
                "detail_url": "fleamarket://awesome_detail?isSkill=true",
                "detail_params": {"isSkillProductItem": "true"},
                "card_type": 1003,
            },
            ensure_ascii=False,
        )

    def _assert_operation_shape(self, response) -> None:
        required_keys = {
            "operation_id",
            "operation_version",
            "status",
            "item_id",
            "requires_activation",
            "rules_active",
        }
        self.assertTrue(required_keys.issubset(response), response)
        self.assertIsInstance(response["operation_version"], int)
        self.assertIsInstance(response["requires_activation"], bool)
        self.assertIsInstance(response["rules_active"], bool)


@unittest.skipUnless(
    AUTO_DELIVERY_PATH.is_file()
    and REPLY_SERVER_PATH.is_file()
    and FULFILLMENT_CONFIG_PATH.is_file(),
    "pinned upstream checkout is absent; run prepare.sh source checkout first",
)
class ManagedRuntimeAndRouteSourceContracts(unittest.TestCase):
    def test_card_authorization_is_write_only_in_helpers_and_get_routes(self) -> None:
        module = self._load_card_contract_module()
        original = {
            "id": 7,
            "type": "api",
            "api_config": self._card_api_config_for_source_contract(),
        }

        safe_card = module.sanitize_api_card_for_response(original)
        safe_json = json.dumps(safe_card, ensure_ascii=False)
        self.assertFalse(TEST_BEARER_TOKEN in safe_json)
        self.assertFalse("Authorization" in safe_json)
        self.assertEqual(safe_card["authorization_configured"], True)
        self.assertEqual(
            original["api_config"]["headers"]["Authorization"],
            TEST_AUTHORIZATION,
        )

        submitted = self._card_api_config_for_source_contract()
        submitted["headers"] = {}
        preserved = module.preserve_api_card_authorization(
            submitted,
            original["api_config"],
            authorization_configured=safe_card["authorization_configured"],
        )
        self.assertEqual(
            preserved["headers"]["Authorization"],
            TEST_AUTHORIZATION,
        )

        tree = ast.parse(REPLY_SERVER_PATH.read_text(encoding="utf-8"))
        card_get_routes = {
            path: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for path in self._route_paths(node)
            if path in {"/cards", "/cards/{card_id}"}
            and self._has_http_method_decorator(node, "get")
        }
        self.assertEqual(set(card_get_routes), {"/cards", "/cards/{card_id}"})
        for path, route in card_get_routes.items():
            with self.subTest(route=path):
                self.assertTrue(
                    self._contains_call(route, "sanitize_api_card_for_response")
                )

    def test_sensitive_fulfillment_mask_removes_complete_code_and_payload(self) -> None:
        module_name = "visionforge_managed_safety_sensitive_data"
        spec = importlib.util.spec_from_file_location(
            module_name,
            FULFILLMENT_SECURITY_PATH,
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)

        masked = module.mask_sensitive_fulfillment_text(
            f"自动发货成功，兑换码：{TEST_REDEMPTION_CODE}，请妥善保存"
        )

        self.assertFalse(TEST_REDEMPTION_CODE in masked)
        self.assertNotIn("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-QQ", masked)
        self.assertIn(module.REDACTED_REDEMPTION_CODE, masked)

    def test_runtime_sanitizes_persistence_and_logs_without_masking_send_payload(
        self,
    ) -> None:
        tree = ast.parse(AUTO_DELIVERY_PATH.read_text(encoding="utf-8"))
        runtime_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "XianyuLive"
        )
        methods = {
            node.name: node
            for node in runtime_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        required_methods = {
            "_persist_delivery_finalization_state",
            "_sanitize_delivery_finalization_meta",
            "_safe_log_text",
            "_send_delivery_steps",
        }
        self.assertTrue(required_methods.issubset(methods))

        persist_method = methods["_persist_delivery_finalization_state"]
        sanitize_lines = self._call_lines(
            persist_method,
            "_sanitize_delivery_finalization_meta",
        )
        upsert_lines = self._call_lines(
            persist_method,
            "upsert_delivery_finalization_state",
        )
        self.assertTrue(sanitize_lines)
        self.assertTrue(upsert_lines)
        self.assertLess(min(sanitize_lines), min(upsert_lines))
        self.assertTrue(
            self._contains_call(
                methods["_sanitize_delivery_finalization_meta"],
                "sanitize_delivery_meta",
            )
        )
        self.assertTrue(
            self._contains_call(
                methods["_safe_log_text"],
                "mask_sensitive_fulfillment_text",
            )
        )

        self_echo_log_calls = [
            (method, node)
            for method in methods.values()
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and self._call_name(node.func) == "info"
            and self._contains_string(node, "【手动发出】")
        ]
        self.assertTrue(self_echo_log_calls)
        self.assertTrue(
            all(
                self._log_call_uses_sanitized_value(method, call)
                for method, call in self_echo_log_calls
            )
        )

        outbound_text_calls = [
            node
            for node in ast.walk(methods["_send_delivery_steps"])
            if isinstance(node, ast.Call)
            and self._call_name(node.func) == "send_msg"
        ]
        self.assertTrue(outbound_text_calls)
        self.assertTrue(
            any(
                len(call.args) >= 4
                and isinstance(call.args[3], ast.Name)
                and call.args[3].id == "step_content"
                and not self._contains_call(call, "_safe_log_text")
                for call in outbound_text_calls
            )
        )

    def test_qr_login_grace_does_not_block_websocket_initial_auth(self) -> None:
        tree = ast.parse(AUTO_DELIVERY_PATH.read_text(encoding="utf-8"))
        runtime_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "XianyuLive"
        )
        methods = {
            node.name: node
            for node in runtime_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        self.assertIn("init", methods)
        self.assertFalse(
            self._contains_call(
                methods["init"],
                "_should_defer_auth_recovery_for_qr_grace",
            )
        )
        init_source = ast.get_source_segment(
            AUTO_DELIVERY_PATH.read_text(encoding="utf-8"),
            methods["init"],
        )
        self.assertIn("allow_password_login_recovery=False", init_source)
        self.assertIn("allow_captcha_recovery=False", init_source)
        self.assertTrue(
            self._contains_call(
                methods["token_refresh_loop"],
                "_should_defer_auth_recovery_for_qr_grace",
            )
        )
        self.assertTrue(
            self._contains_call(
                methods["cookie_refresh_loop"],
                "_should_defer_auth_recovery_for_qr_grace",
            )
        )

    def test_qr_login_task_switch_requires_token_preflight(self) -> None:
        source = REPLY_SERVER_PATH.read_text(encoding="utf-8")

        preflight_marker = "source='post_qr_login_ready'"
        token_gate_marker = "if not token_prewarmed:"
        update_task_marker = "cookie_manager.manager.update_cookie(account_id, final_cookies"
        start_task_marker = "cookie_manager.manager.add_cookie(account_id, final_cookies"

        self.assertIn(preflight_marker, source)
        self.assertIn(token_gate_marker, source)
        self.assertIn(update_task_marker, source)
        self.assertIn(start_task_marker, source)
        self.assertLess(source.index(preflight_marker), source.index(token_gate_marker))
        self.assertLess(source.index(token_gate_marker), source.index(update_task_marker))
        self.assertLess(source.index(token_gate_marker), source.index(start_task_marker))
        self.assertIn("'token_prewarmed': token_prewarmed", source)
        self.assertIn("'token_preflight_status': token_preflight_status", source)

    def test_off_and_shadow_are_preserved_by_the_runtime_config_adapter(self) -> None:
        module = self._load_fulfillment_config_adapter()

        self.assertEqual(
            module.load_managed_fulfillment_mode(
                {module.MANAGED_FULFILLMENT_MODE_ENV: "off"}
            ).value,
            "off",
        )
        self.assertEqual(
            module.load_managed_fulfillment_mode(
                {module.MANAGED_FULFILLMENT_MODE_ENV: "shadow"}
            ).value,
            "shadow",
        )

    def test_inbound_code_echo_is_redacted_from_storage_events_logs_and_notifications(
        self,
    ) -> None:
        source = AUTO_DELIVERY_PATH.read_text(encoding="utf-8")

        self.assertGreaterEqual(source.count("content=stored_message"), 2)
        self.assertGreaterEqual(source.count("'content': stored_message"), 2)
        self.assertIn("self._safe_log_text(message_data)", source)
        self.assertNotIn("原始消息: {message_data}", source)
        self.assertRegex(
            source,
            r"await self\.send_notification\(\s*send_user_name,\s*send_user_id,\s*"
            r"safe_message_for_log,",
        )

    def test_generic_auto_delivery_switch_requires_an_explicit_true_string(self) -> None:
        module = self._load_fulfillment_config_adapter()
        environment_key = module.GENERIC_AUTO_DELIVERY_ENABLED_ENV

        for enabled_value in ("true", " TRUE ", "TrUe"):
            with self.subTest(enabled_value=enabled_value):
                self.assertTrue(
                    module.is_generic_auto_delivery_enabled(
                        {environment_key: enabled_value}
                    )
                )

        for disabled_value in (None, "", "false", "0", "1", "yes", True, 1):
            with self.subTest(disabled_value=repr(disabled_value)):
                environment = (
                    {} if disabled_value is None else {environment_key: disabled_value}
                )
                self.assertFalse(
                    module.is_generic_auto_delivery_enabled(environment)
                )

    def test_generic_gate_dominates_legacy_resolution_without_blocking_managed_branch(
        self,
    ) -> None:
        tree = ast.parse(AUTO_DELIVERY_PATH.read_text(encoding="utf-8"))
        auto_delivery = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_auto_delivery"
        )
        parent_by_node = {
            child: parent
            for parent in ast.walk(auto_delivery)
            for child in ast.iter_child_nodes(parent)
        }
        gate_calls = [
            node
            for node in ast.walk(auto_delivery)
            if isinstance(node, ast.Call)
            and self._call_name(node.func) == "is_generic_auto_delivery_enabled"
        ]
        self.assertEqual(len(gate_calls), 1)

        ancestors = []
        current = gate_calls[0]
        while current in parent_by_node:
            current = parent_by_node[current]
            ancestors.append(current)
        generic_branch = next(
            (
                node
                for node in ancestors
                if isinstance(node, ast.If)
                and self._is_negated_name(node.test, "managed_exact_binding")
            ),
            None,
        )
        self.assertIsNotNone(generic_branch)
        self.assertTrue(any(isinstance(node, ast.Return) for node in ast.walk(generic_branch)))

        legacy_call_names = {
            "get_delivery_rules_by_keyword",
            "get_delivery_rules_by_keyword_and_spec",
        }
        legacy_lines = [
            node.lineno
            for node in ast.walk(auto_delivery)
            if isinstance(node, ast.Call)
            and self._call_name(node.func) in legacy_call_names
        ]
        api_lines = self._call_lines(auto_delivery, "_get_api_card_content")
        self.assertTrue(legacy_lines)
        self.assertTrue(api_lines)
        self.assertLess(gate_calls[0].lineno, min(legacy_lines))
        self.assertLess(gate_calls[0].lineno, min(api_lines))

    def test_off_and_shadow_guard_dominates_rule_resolution_and_code_retrieval(self) -> None:
        tree = ast.parse(AUTO_DELIVERY_PATH.read_text(encoding="utf-8"))
        auto_delivery = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_auto_delivery"
        )
        managed_branch = next(
            node
            for node in ast.walk(auto_delivery)
            if isinstance(node, ast.If)
            and "managed_exact_binding" in {
                name.id for name in ast.walk(node.test) if isinstance(name, ast.Name)
            }
            and self._contains_call(node.body, "resolve_exact_delivery_rule")
        )
        mode_loader_names = {
            "get_managed_fulfillment_mode",
            "load_managed_fulfillment_mode",
        }
        self.assertTrue(
            any(self._contains_call(managed_branch.body, name) for name in mode_loader_names)
        )
        mode_guard = next(
            node
            for node in managed_branch.body
            if isinstance(node, ast.If)
            and any(
                isinstance(value, ast.Constant) and value.value == "live"
                for value in ast.walk(node.test)
            )
        )

        self.assertTrue(any(isinstance(node, ast.Return) for node in mode_guard.body))
        resolver_line = min(
            node.lineno
            for node in ast.walk(managed_branch)
            if isinstance(node, ast.Call)
            and self._call_name(node.func) == "resolve_exact_delivery_rule"
        )
        self.assertLess(mode_guard.lineno, resolver_line)

        api_retrieval_line = min(
            node.lineno
            for node in ast.walk(auto_delivery)
            if isinstance(node, ast.Call)
            and self._call_name(node.func) == "_get_api_card_content"
        )
        self.assertLess(mode_guard.lineno, api_retrieval_line)

    def test_managed_fulfillment_controllers_respect_service_boundary_and_dto_contract(
        self,
    ) -> None:
        tree = ast.parse(REPLY_SERVER_PATH.read_text(encoding="utf-8"))
        expected_paths = {
            "/product-publish/capabilities",
            "/product-publish/visionforge/catalog",
            "/product-publish/visionforge/synced-items",
            "/product-publish/visionforge/validate",
            "/product-publish/visionforge/bind-existing/validate",
            "/product-publish/visionforge/bind-existing",
            "/product-publish/visionforge",
            "/product-publish/visionforge/{operation_id}/binding-dry-run",
            "/product-publish/visionforge/{operation_id}/activate",
            "/product-publish/visionforge/{operation_id}/deactivate",
            "/delivery-rules/dry-run",
        }
        routes = {
            path: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for path in self._route_paths(node)
            if path == "/product-publish/capabilities"
            or path.startswith("/product-publish/visionforge")
            or path == "/delivery-rules/dry-run"
        }
        self.assertEqual(set(routes), expected_paths)

        for path, function in routes.items():
            direct_database_calls = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and self._is_module_attribute_call(node, "db_manager")
            ]
            private_service_calls = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and self._is_module_attribute_call(
                    node,
                    "visionforge_fulfillment_service",
                    private_only=True,
                )
            ]
            success_dtos = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Dict) and self._is_success_dto(node)
            ]

            with self.subTest(route=path):
                self.assertEqual(
                    direct_database_calls,
                    [],
                    "managed fulfillment controllers must use a public service instead "
                    "of db_manager directly",
                )
                self.assertEqual(
                    private_service_calls,
                    [],
                    "managed fulfillment controllers must not call private service methods",
                )
                self.assertTrue(success_dtos, "route must expose an explicit success DTO")
                for response in success_dtos:
                    response_keys = [
                        key.value
                        for key in response.keys
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                    ]
                    self.assertEqual(response_keys.count("success"), 1)
                    self.assertEqual(response_keys.count("trace_id"), 1)
                    self.assertNotIn("traceId", response_keys)

        self.assertTrue(
            self._contains_call(
                routes[
                    "/product-publish/visionforge/{operation_id}/binding-dry-run"
                ].body,
                "dry_run_operation",
            )
        )

    @staticmethod
    def _route_paths(function) -> list[str]:
        paths = []
        for decorator in function.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            route_path = decorator.args[0]
            if (
                isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "app"
                and isinstance(route_path, ast.Constant)
                and isinstance(route_path.value, str)
            ):
                paths.append(route_path.value)
        return paths

    @staticmethod
    def _is_module_attribute_call(
        call: ast.Call,
        module_name: str,
        *,
        private_only: bool = False,
    ) -> bool:
        function = call.func
        if not (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == module_name
        ):
            return False
        return not private_only or function.attr.startswith("_")

    @staticmethod
    def _is_success_dto(node: ast.Dict) -> bool:
        return any(
            isinstance(key, ast.Constant)
            and key.value == "success"
            and isinstance(value, ast.Constant)
            and value.value is True
            for key, value in zip(node.keys, node.values)
        )

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @classmethod
    def _call_lines(cls, node, expected_name: str) -> list[int]:
        return [
            child.lineno
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and cls._call_name(child.func) == expected_name
        ]

    @staticmethod
    def _contains_string(node, expected_text: str) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and expected_text in child.value
            for child in ast.walk(node)
        )

    @classmethod
    def _log_call_uses_sanitized_value(cls, method, log_call: ast.Call) -> bool:
        if cls._contains_call(log_call, "_safe_log_text"):
            return True
        logged_names = {
            child.id for child in ast.walk(log_call) if isinstance(child, ast.Name)
        }
        for node in ast.walk(method):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if node.lineno >= log_call.lineno:
                continue
            value = node.value
            if value is None or not cls._contains_call(value, "_safe_log_text"):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned_names = {
                child.id
                for target in targets
                for child in ast.walk(target)
                if isinstance(child, ast.Name)
            }
            if assigned_names & logged_names:
                return True
        return False

    @staticmethod
    def _is_negated_name(node, expected_name: str) -> bool:
        return any(
            isinstance(child, ast.UnaryOp)
            and isinstance(child.op, ast.Not)
            and isinstance(child.operand, ast.Name)
            and child.operand.id == expected_name
            for child in ast.walk(node)
        )

    @staticmethod
    def _load_fulfillment_config_adapter():
        module_name = "visionforge_managed_safety_runtime_config"
        spec = importlib.util.spec_from_file_location(
            module_name,
            FULFILLMENT_CONFIG_PATH,
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.path.insert(0, str(UPSTREAM_ROOT))
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            if sys.path and sys.path[0] == str(UPSTREAM_ROOT):
                sys.path.pop(0)
        return module

    @staticmethod
    def _load_card_contract_module():
        module_name = "visionforge_managed_safety_card_contract_source"
        spec = importlib.util.spec_from_file_location(module_name, CARD_CONTRACT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.path.insert(0, str(UPSTREAM_ROOT))
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            if sys.path and sys.path[0] == str(UPSTREAM_ROOT):
                sys.path.pop(0)
        return module

    @staticmethod
    def _card_api_config_for_source_contract():
        return {
            "url": BRIDGE_URL,
            "method": "GET",
            "headers": {
                "Authorization": TEST_AUTHORIZATION,
                "X-Test-Metadata": "preserved",
            },
            "params": {
                "order_id": "{order_id}",
                "product_key": "1h",
                "unit_index": "1",
            },
        }

    @staticmethod
    def _has_http_method_decorator(function, method_name: str) -> bool:
        return any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "app"
            and decorator.func.attr == method_name
            for decorator in function.decorator_list
        )

    @classmethod
    def _contains_call(cls, nodes, expected_name: str) -> bool:
        if not isinstance(nodes, list):
            nodes = [nodes]
        return any(
            isinstance(node, ast.Call) and cls._call_name(node.func) == expected_name
            for root in nodes
            for node in ast.walk(root)
        )


if __name__ == "__main__":
    unittest.main()
