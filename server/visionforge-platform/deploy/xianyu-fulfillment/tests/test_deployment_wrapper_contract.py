"""Offline contracts for safe Xianyu image activation and verification."""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch


DEPLOY_ROOT = Path(__file__).resolve().parents[1]
VERIFY_PATH = DEPLOY_ROOT / "verify_xianyu_state.py"
SNAPSHOT_PATH = DEPLOY_ROOT / "sqlite_snapshot.py"
PREFLIGHT_PATH = DEPLOY_ROOT / "preflight_xianyu_host.py"
ACTIVATION_PATH = DEPLOY_ROOT / "activate_hardened_image.sh"
COMPOSE_PATH = DEPLOY_ROOT / "docker-compose.yml"
DOCKERFILE_PATH = DEPLOY_ROOT / "Dockerfile.hardened"
DOCKERIGNORE_PATH = DEPLOY_ROOT / ".dockerignore"
TOKEN = "deployment-contract-token-0123456789abcdef"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


verify_module = _load_module("visionforge_deployment_verify", VERIFY_PATH)
snapshot_module = _load_module("visionforge_sqlite_snapshot", SNAPSHOT_PATH)
preflight_module = _load_module("visionforge_deployment_preflight", PREFLIGHT_PATH)


class DeploymentStateVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "xianyu.db"
        self.connection = sqlite3.connect(self.database_path)
        self.connection.executescript(
            """
            CREATE TABLE cards (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                api_config TEXT NOT NULL
            );
            CREATE TABLE delivery_rules (
                card_id INTEGER,
                enabled INTEGER NOT NULL DEFAULT 0,
                description TEXT,
                is_managed INTEGER NOT NULL DEFAULT 0,
                managed_operation_id TEXT,
                managed_card_config_fingerprint TEXT
            );
            CREATE TABLE cookies (id TEXT PRIMARY KEY);
            CREATE TABLE item_info (id INTEGER PRIMARY KEY);
            CREATE TABLE visionforge_publish_operations (id TEXT PRIMARY KEY);
            """
        )
        self.connection.commit()

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def test_runtime_allows_a_fresh_database_but_readiness_does_not(self) -> None:
        self.assertEqual(
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=False,
            ),
            0,
        )
        with self.assertRaisesRegex(RuntimeError, "readiness"):
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=True,
            )

    def test_placeholder_bridge_credentials_are_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {"BRIDGE_INTERNAL_TOKEN": "REPLACE_WITH_BRIDGE_INTERNAL_TOKEN"},
        ):
            with self.assertRaisesRegex(RuntimeError, "not safely configured"):
                verify_module._required_bridge_token()

    def test_any_existing_card_set_must_be_the_exact_complete_five(self) -> None:
        self._insert_card(1, 1)
        with self.assertRaisesRegex(RuntimeError, "exactly five"):
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=False,
            )

    def test_unrelated_upstream_cards_do_not_count_as_managed_cards(self) -> None:
        self.connection.execute(
            "INSERT INTO cards (id, name, type, enabled, api_config) "
            "VALUES (1, 'ordinary upstream card', 'text', 1, '{}')"
        )
        self.connection.commit()

        self.assertEqual(
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=False,
            ),
            0,
        )
        with self.assertRaisesRegex(RuntimeError, "readiness"):
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=True,
            )

    def test_complete_cards_must_match_the_actual_bridge_token(self) -> None:
        for card_id, hours in enumerate((1, 5, 10, 50, 100), start=1):
            self._insert_card(card_id, hours)

        self.assertEqual(
            verify_module.verify_cards(
                self.connection,
                TOKEN,
                require_configured=True,
            ),
            5,
        )
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            verify_module.verify_cards(
                self.connection,
                "different-bridge-token-0123456789abcdef",
                require_configured=True,
            )

    def test_verifier_opens_the_database_read_only_and_never_prints_token(self) -> None:
        for card_id, hours in enumerate((1, 5, 10, 50, 100), start=1):
            self._insert_card(card_id, hours)
        self.connection.close()

        with closing(verify_module._open_read_only(str(self.database_path))) as read_only:
            with self.assertRaises(sqlite3.OperationalError):
                read_only.execute("INSERT INTO cookies (id) VALUES ('forbidden')")

        environment = os.environ.copy()
        environment.update(
            {
                "DB_PATH": str(self.database_path),
                "BRIDGE_INTERNAL_TOKEN": TOKEN,
                "VISIONFORGE_MANAGED_FULFILLMENT_MODE": "shadow",
            }
        )
        result = subprocess.run(
            [sys.executable, str(VERIFY_PATH), "--mode", "readiness"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TOKEN, result.stdout)
        self.assertNotIn(TOKEN, result.stderr)

    def test_verifier_rejects_an_unmigrated_managed_rule(self) -> None:
        self.connection.execute(
            "INSERT INTO delivery_rules (description, is_managed) "
            "VALUES ('VisionForge managed exact binding', 0)"
        )
        self.connection.commit()
        environment = os.environ.copy()
        environment.update(
            {
                "DB_PATH": str(self.database_path),
                "BRIDGE_INTERNAL_TOKEN": TOKEN,
                "VISIONFORGE_MANAGED_FULFILLMENT_MODE": "shadow",
            }
        )

        result = subprocess.run(
            [sys.executable, str(VERIFY_PATH), "--mode", "runtime"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("migration is incomplete", result.stderr)

    def test_managed_rule_fingerprint_matches_current_card_configuration(self) -> None:
        self._insert_card(1, 1)
        raw_configuration = self.connection.execute(
            "SELECT api_config FROM cards WHERE id = 1"
        ).fetchone()[0]
        fingerprint = verify_module.fingerprint_managed_api_config(raw_configuration)
        self.connection.execute(
            "INSERT INTO delivery_rules "
            "(card_id, is_managed, managed_operation_id, managed_card_config_fingerprint) "
            "VALUES (1, 1, 'operation-1', ?)",
            (fingerprint,),
        )
        self.connection.commit()

        self.assertEqual(
            verify_module.verify_managed_rule_fingerprints(self.connection),
            1,
        )
        self.connection.execute(
            "UPDATE cards SET api_config = ? WHERE id = 1",
            (json.dumps({"url": "http://drifted.invalid/issue"}),),
        )
        self.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "has drifted"):
            verify_module.verify_managed_rule_fingerprints(self.connection)
        self.connection.execute(
            "UPDATE delivery_rules SET managed_card_config_fingerprint = NULL"
        )
        self.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "is missing"):
            verify_module.verify_managed_rule_fingerprints(self.connection)

    def test_fingerprint_matches_the_upstream_canonical_fixture(self) -> None:
        configuration = {
            "url": verify_module.BRIDGE_URL,
            "method": "GET",
            "headers": {
                "Authorization": f"Bearer {TOKEN}",
                "X-Test": "value",
            },
            "params": {
                "order_id": "{order_id}",
                "product_key": "1h",
                "unit_index": "1",
            },
        }

        self.assertEqual(
            verify_module.fingerprint_managed_api_config(configuration),
            "1d071cf36be6b26c2cf250de2b2dd3aeec02a891d518e98f99151010efe47dbe",
        )

    def _insert_card(self, card_id: int, hours: int) -> None:
        configuration = {
            "url": verify_module.BRIDGE_URL,
            "method": "GET",
            "headers": {"Authorization": f"Bearer {TOKEN}"},
            "params": {
                "order_id": "{order_id}",
                "product_key": f"{hours}h",
                "unit_index": "1",
            },
        }
        self.connection.execute(
            "INSERT INTO cards (id, name, type, enabled, api_config) "
            "VALUES (?, ?, 'api', 1, ?)",
            (
                card_id,
                f"VisionForge即时发码-{hours}小时",
                json.dumps(configuration),
            ),
        )
        self.connection.commit()


class SQLiteSnapshotTests(unittest.TestCase):
    def test_snapshot_and_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            database_path = root / "runtime" / "xianyu.db"
            snapshot_path = root / "backups" / "before.db"
            database_path.parent.mkdir()
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute("CREATE TABLE state (value TEXT NOT NULL)")
                connection.execute("INSERT INTO state VALUES ('before')")
                connection.commit()

            snapshot_module.create_snapshot(database_path, snapshot_path)
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute("UPDATE state SET value = 'candidate'")
                connection.commit()

            snapshot_module.restore_snapshot(snapshot_path, database_path)

            snapshot_module.verify_database(database_path)
            with closing(sqlite3.connect(database_path)) as connection:
                value = connection.execute("SELECT value FROM state").fetchone()[0]
            self.assertEqual(value, "before")


class DeploymentPreflightTests(unittest.TestCase):
    def test_managed_catalog_requires_the_exact_private_mapping(self) -> None:
        preflight_module.validate_managed_catalog(
            preflight_module.EXPECTED_MANAGED_BRIDGE_URL,
            json.dumps(preflight_module.EXPECTED_PRODUCT_KEYS, ensure_ascii=False),
        )
        with self.assertRaisesRegex(RuntimeError, "incomplete or unexpected"):
            preflight_module.validate_managed_catalog(
                preflight_module.EXPECTED_MANAGED_BRIDGE_URL,
                '{"1小时":"1h"}',
            )


class DeploymentSourceSafetyTests(unittest.TestCase):
    def test_activation_is_shadow_first_and_has_verified_rollback_contract(self) -> None:
        source = ACTIVATION_PATH.read_text(encoding="utf-8")

        self.assertIn('VISIONFORGE_MANAGED_FULFILLMENT_MODE=shadow', source)
        self.assertIn('XIANYU_AUTO_DELIVERY_ENABLED=false', source)
        self.assertIn('python - --mode runtime', source)
        self.assertIn("VISIONFORGE_GENERIC_AUTO_DELIVERY_RUNTIME_GUARD_V1", source)
        self.assertIn("is_generic_auto_delivery_enabled", source)
        self.assertIn('cp -p -- "${ENV_FILE}" "${ENV_SNAPSHOT}"', source)
        self.assertIn('cp -p -- "${ENV_SNAPSHOT}" "${ENV_FILE}"', source)
        self.assertIn('DATABASE_SNAPSHOT_READY=true', source)
        self.assertIn('activation_failed_rollback=verified', source)
        self.assertIn('activation_failed_rollback=failed', source)
        self.assertIn('PREVIOUS_APP_RUNNING', source)
        self.assertNotIn("|| true", source)

        snapshot_checkpoint = source.index('ENV_SNAPSHOT="$(mktemp')
        rollback_checkpoint = source.index("ROLLBACK_REQUIRED=true", snapshot_checkpoint)
        stop_position = source.index('stop_container "${APP_CONTAINER}"', rollback_checkpoint)
        snapshot_position = source.index('"${SNAPSHOT_TOOL}" backup', stop_position)
        candidate_position = source.index("docker compose --env-file", snapshot_position)
        self.assertLess(stop_position, snapshot_position)
        self.assertLess(snapshot_position, candidate_position)

    def test_build_context_and_runtime_are_fail_closed(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        dockerignore = DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()

        self.assertIn("AUTO_DELIVERY_ENABLED: ${XIANYU_AUTO_DELIVERY_ENABLED:-false}", compose)
        self.assertIn("VISIONFORGE_PACKAGE_PRODUCT_KEYS: ${VISIONFORGE_PACKAGE_PRODUCT_KEYS:?required}", compose)
        self.assertIn("BRIDGE_INTERNAL_TOKEN: ${BRIDGE_INTERNAL_TOKEN:?required}", compose)
        self.assertIn("ENTRYPOINT", dockerfile)
        self.assertIn("COPY bridge/bridge.py /opt/visionforge/bridge.py", dockerfile)
        self.assertIn('["python", "/opt/visionforge/bridge.py"]', compose)
        self.assertNotIn("./bridge/bridge.py:/bridge/bridge.py", compose)
        for required_entry in (".env", "runtime", "upstream", ".git", "secrets"):
            self.assertIn(required_entry, dockerignore)


if __name__ == "__main__":
    unittest.main()
