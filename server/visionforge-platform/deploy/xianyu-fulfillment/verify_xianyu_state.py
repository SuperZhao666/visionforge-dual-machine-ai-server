#!/usr/bin/env python3
"""Verify the deployed Xianyu state without exposing credentials."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sqlite3
from pathlib import Path


EXPECTED_PRODUCT_KEYS = {"1h", "5h", "10h", "50h", "100h"}
EXPECTED_CARD_NAMES = {
    f"VisionForge即时发码-{hours}小时" for hours in (1, 5, 10, 50, 100)
}
BRIDGE_URL = "http://fulfillment-bridge:8080/issue"
ALLOWED_MANAGED_MODES = {"off", "shadow", "live"}
VERIFICATION_MODES = {"runtime", "readiness"}


def verify_cards(
    connection: sqlite3.Connection,
    bridge_internal_token: str,
    *,
    require_configured: bool,
) -> int:
    rows = connection.execute(
        "SELECT name, type, enabled, api_config FROM cards "
        "WHERE name LIKE 'VisionForge%' ORDER BY id"
    ).fetchall()
    if not rows:
        if require_configured:
            raise RuntimeError("readiness verification requires five VisionForge API cards")
        return 0
    if len(rows) != len(EXPECTED_PRODUCT_KEYS):
        raise RuntimeError("expected exactly five VisionForge API cards")
    if {row[0] for row in rows} != EXPECTED_CARD_NAMES:
        raise RuntimeError("VisionForge API card names do not match the deployment contract")
    if not all(row[1] == "api" for row in rows):
        raise RuntimeError("all VisionForge cards must use the API card type")
    if not all(row[2] for row in rows):
        raise RuntimeError("all VisionForge API cards must be enabled")

    configurations = [json.loads(row[3]) for row in rows]
    product_keys = {configuration["params"]["product_key"] for configuration in configurations}
    if product_keys != EXPECTED_PRODUCT_KEYS:
        raise RuntimeError("VisionForge API card product keys are incomplete")
    if any(configuration.get("url") != BRIDGE_URL for configuration in configurations):
        raise RuntimeError("VisionForge API card bridge URL is invalid")
    if any(configuration["params"].get("order_id") != "{order_id}" for configuration in configurations):
        raise RuntimeError("VisionForge API cards must use the order id placeholder")
    if any(str(configuration["params"].get("unit_index")) != "1" for configuration in configurations):
        raise RuntimeError("VisionForge API cards must request exactly one delivery unit")
    if any(str(configuration.get("method", "")).upper() != "GET" for configuration in configurations):
        raise RuntimeError("VisionForge API cards must use GET")

    authorization_values = {
        configuration.get("headers", {}).get("Authorization", "")
        for configuration in configurations
    }
    if len(authorization_values) != 1:
        raise RuntimeError("VisionForge API card credentials are inconsistent")
    authorization_value = next(iter(authorization_values))
    if authorization_value != f"Bearer {bridge_internal_token}":
        raise RuntimeError("VisionForge API card credential does not match the bridge")
    return len(rows)


def fingerprint_managed_api_config(api_config: object) -> str:
    """Mirror the runtime fingerprint without exposing Authorization."""
    if isinstance(api_config, str):
        try:
            api_config = json.loads(api_config)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("managed API card configuration is invalid") from exc
    if not isinstance(api_config, dict):
        raise RuntimeError("managed API card configuration is invalid")
    normalized = copy.deepcopy(api_config)
    headers = normalized.get("headers")
    if isinstance(headers, dict):
        redacted_headers = {}
        for key, value in headers.items():
            if str(key).strip().lower() == "authorization":
                redacted_headers[str(key)] = {
                    "sha256": hashlib.sha256(
                        str(value or "").strip().encode("utf-8")
                    ).hexdigest()
                }
            else:
                redacted_headers[str(key)] = value
        normalized["headers"] = redacted_headers
    canonical = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_managed_rule_fingerprints(connection: sqlite3.Connection) -> int:
    rows = connection.execute(
        "SELECT dr.managed_card_config_fingerprint, c.api_config "
        "FROM delivery_rules dr "
        "LEFT JOIN cards c ON c.id = dr.card_id "
        "WHERE dr.is_managed = 1 "
        "AND dr.managed_operation_id IS NOT NULL "
        "AND TRIM(dr.managed_operation_id) <> ''"
    ).fetchall()
    for stored_fingerprint, api_config in rows:
        stored_value = str(stored_fingerprint or "").strip()
        if not stored_value:
            raise RuntimeError("managed API card fingerprint is missing")
        current_fingerprint = fingerprint_managed_api_config(api_config)
        if current_fingerprint != stored_value:
            raise RuntimeError("managed API card configuration fingerprint has drifted")
    return len(rows)


def _open_read_only(database_path: str) -> sqlite3.Connection:
    resolved_path = Path(database_path).resolve(strict=True)
    connection = sqlite3.connect(f"{resolved_path.as_uri()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection


def _required_bridge_token() -> str:
    value = os.getenv("BRIDGE_INTERNAL_TOKEN", "").strip()
    lowered = value.lower()
    placeholder_markers = (
        "replace-with",
        "replace_with",
        "placeholder",
        "change-me",
        "changeme",
    )
    if len(value) < 32 or any(marker in lowered for marker in placeholder_markers):
        raise RuntimeError("bridge credential is not safely configured")
    return value


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(VERIFICATION_MODES), default="runtime")
    return parser.parse_args()


def main() -> None:
    arguments = _parse_arguments()
    database_path = os.getenv("DB_PATH", "/app/data/xianyu_data.db")
    managed_mode = os.getenv("VISIONFORGE_MANAGED_FULFILLMENT_MODE", "shadow").strip().lower()
    if managed_mode not in ALLOWED_MANAGED_MODES:
        raise RuntimeError("managed fulfillment mode is invalid")
    bridge_internal_token = _required_bridge_token()
    connection = _open_read_only(database_path)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Xianyu database integrity check failed")
        card_count = verify_cards(
            connection,
            bridge_internal_token,
            require_configured=arguments.mode == "readiness",
        )
        delivery_rule_count = connection.execute("SELECT COUNT(*) FROM delivery_rules").fetchone()[0]
        managed_rule_count = connection.execute(
            "SELECT COUNT(*) FROM delivery_rules "
            "WHERE is_managed = 1 "
            "AND managed_operation_id IS NOT NULL "
            "AND TRIM(managed_operation_id) <> ''"
        ).fetchone()[0]
        active_managed_rule_count = connection.execute(
            "SELECT COUNT(*) FROM delivery_rules "
            "WHERE is_managed = 1 "
            "AND managed_operation_id IS NOT NULL "
            "AND TRIM(managed_operation_id) <> '' "
            "AND enabled = 1"
        ).fetchone()[0]
        orphan_managed_rule_count = connection.execute(
            "SELECT COUNT(*) FROM delivery_rules "
            "WHERE (is_managed = 1 AND (managed_operation_id IS NULL "
            "OR TRIM(managed_operation_id) = '')) "
            "OR (is_managed = 0 AND description = 'VisionForge managed exact binding')"
        ).fetchone()[0]
        operation_table_count = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'table' AND name = 'visionforge_publish_operations'"
        ).fetchone()[0]
        if operation_table_count != 1:
            raise RuntimeError("managed operation schema is missing")
        if orphan_managed_rule_count:
            raise RuntimeError("managed delivery rule migration is incomplete")
        verified_fingerprint_count = verify_managed_rule_fingerprints(connection)
        if managed_mode != "live" and active_managed_rule_count:
            raise RuntimeError("non-live mode must not retain active managed rules")
        account_count = connection.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
        item_count = connection.execute("SELECT COUNT(*) FROM item_info").fetchone()[0]
    finally:
        connection.close()

    print("xianyu_integrity=ok")
    print(f"visionforge_api_cards={card_count}_enabled")
    print(
        "api_card_credentials=consistent"
        if card_count
        else "api_card_credentials=not_configured"
    )
    print(f"verification_mode={arguments.mode}")
    print(f"managed_fulfillment_mode={managed_mode}")
    print(f"managed_operation_schema={'ok' if operation_table_count == 1 else 'missing'}")
    print(f"delivery_rules={delivery_rule_count}")
    print(f"managed_delivery_rules={managed_rule_count}")
    print(f"active_managed_delivery_rules={active_managed_rule_count}")
    print(f"orphan_managed_delivery_rules={orphan_managed_rule_count}")
    print(f"managed_rule_fingerprints={verified_fingerprint_count}_verified")
    print(f"account_records={account_count}")
    print(f"item_records={item_count}")


if __name__ == "__main__":
    main()
