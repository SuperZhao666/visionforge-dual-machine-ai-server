from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest
from dual_machine_service.admin_service import DualMachineAdminService
from dual_machine_service.card_service import CardIssuanceService
from dual_machine_service.database import connect_database, initialize_database
from dual_machine_service.errors import DualMachineServiceError
from dual_machine_service.settings import DualMachineSettings


@pytest.fixture()
def admin_settings(tmp_path: Path) -> DualMachineSettings:
    settings = _settings(tmp_path / "dual.db")
    initialize_database(settings)
    return settings


def _settings(database_path: Path) -> DualMachineSettings:
    return DualMachineSettings(
        database_path=database_path,
        license_code_secret=b"admin-license-code-secret-at-least-32-bytes",
        token_secret=b"admin-token-secret-at-least-32-bytes-long",
        minimum_host_client_version="17.8.81",
        minimum_android_client_version="1.0.0",
    )


def _insert_issued_challenge(
    settings: DualMachineSettings,
    code_id: int,
    seed: str,
) -> str:
    challenge_id = seed * 32
    connection = connect_database(settings)
    try:
        connection.execute(
            "INSERT INTO dm_activation_challenges "
            "(challenge_id, request_id, request_payload_hash, token_digest, "
            "license_code_id, pair_id, protocol_version, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "expires_at_epoch) VALUES (?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?)",
            (
                challenge_id,
                (seed.upper() if seed.isalpha() else seed) * 32,
                seed * 64,
                f"hmac-sha256:{seed * 64}",
                int(code_id),
                seed * 32,
                "HOST-1",
                "17.8.81",
                "host-public-key",
                seed * 64,
                "ANDROID-1",
                "1.0.0",
                "android-public-key",
                ("f" if seed != "f" else "e") * 64,
                int(time.time()) + 120,
            ),
        )
    finally:
        connection.close()
    return challenge_id


def _database_text(settings: DualMachineSettings) -> str:
    connection = connect_database(settings)
    try:
        values: list[str] = []
        for table_row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name LIKE 'dm_%'",
        ).fetchall():
            table_name = str(table_row[0])
            columns = [
                str(row["name"])
                for row in connection.execute(
                    f'PRAGMA table_info("{table_name}")',
                ).fetchall()
                if "TEXT" in str(row["type"]).upper()
            ]
            if not columns:
                continue
            selection = ", ".join(f'"{column}"' for column in columns)
            for row in connection.execute(
                f'SELECT {selection} FROM "{table_name}"',
            ).fetchall():
                values.extend(
                    str(row[column])
                    for column in columns
                    if row[column] is not None
                )
        return "\n".join(values)
    finally:
        connection.close()


def _insert_activated_entitlement(
    settings: DualMachineSettings,
    code_id: int,
) -> tuple[str, str]:
    entitlement_id = "2" * 32
    binding_id = "5" * 32
    pair_id = "e" * 32
    now = int(time.time())
    connection = connect_database(settings)
    try:
        connection.execute(
            "UPDATE dm_license_codes SET status = 'activated', "
            "activated_at_epoch = ? WHERE id = ?",
            (now, int(code_id)),
        )
        connection.execute(
            "INSERT INTO dm_activation_challenges "
            "(challenge_id, request_id, request_payload_hash, token_digest, "
            "license_code_id, pair_id, protocol_version, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, status, "
            "expires_at_epoch, consumed_at_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, "
            "'consumed', ?, ?)",
            (
                "a" * 32,
                "b" * 32,
                "c" * 64,
                "hmac-sha256:" + "d" * 64,
                int(code_id),
                pair_id,
                "HOST-ORIGINAL",
                "17.8.81",
                "host-public-original",
                "f" * 64,
                "ANDROID-ORIGINAL",
                "1.0.0",
                "android-public-original",
                "1" * 64,
                now + 120,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO dm_entitlements "
            "(entitlement_id, pair_id, protocol_version, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "remaining_seconds, total_credited_seconds, authorization_kind, "
            "product_key, source_license_code_id) "
            "VALUES (?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, 86400, 86400, "
            "'day', 'day', ?)",
            (
                entitlement_id,
                pair_id,
                "HOST-ORIGINAL",
                "17.8.81",
                "host-public-original",
                "3" * 64,
                "ANDROID-ORIGINAL",
                "1.0.0",
                "android-public-original",
                "4" * 64,
                int(code_id),
            ),
        )
        connection.execute(
            "INSERT INTO dm_entitlement_device_bindings "
            "(binding_id, entitlement_id, pair_id, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "android_device_profile_json, is_current) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (
                binding_id,
                entitlement_id,
                pair_id,
                "HOST-ORIGINAL",
                "17.8.81",
                "host-public-original",
                "f" * 64,
                "ANDROID-ORIGINAL",
                "1.0.0",
                "android-public-original",
                "1" * 64,
                '{"model":"Admin Test"}',
            ),
        )
        connection.execute(
            "INSERT INTO dm_license_activations "
            "(activation_id, license_code_id, entitlement_id, challenge_id, "
            "credited_seconds) VALUES (?, ?, ?, ?, 86400)",
            ("6" * 32, int(code_id), entitlement_id, "a" * 32),
        )
        connection.execute(
            "INSERT INTO dm_pair_security_state "
            "(pair_id, entitlement_id, binding_id, binding_revision, "
            "revocation_version, host_key_sha256, android_key_sha256, "
            "assurance_state, generation_high_water, predecessor_pair_id, "
            "created_at_epoch, updated_at_epoch) "
            "VALUES (?, ?, ?, 1, 1, ?, ?, 'active', 0, NULL, ?, ?)",
            (
                pair_id,
                entitlement_id,
                binding_id,
                "f" * 64,
                "1" * 64,
                now,
                now,
            ),
        )
    finally:
        connection.close()
    return entitlement_id, binding_id


def _insert_active_usage_state(
    settings: DualMachineSettings,
    entitlement_id: str,
    pair_id: str,
) -> None:
    now = int(time.time())
    connection = connect_database(settings)
    try:
        connection.execute(
            "INSERT INTO dm_usage_start_challenges "
            "(challenge_id, request_id, request_payload_hash, token_digest, "
            "entitlement_id, pair_id, channel_binding_sha256, "
            "expires_at_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "7" * 32,
                "8" * 32,
                "9" * 64,
                "hmac-sha256:" + "a" * 64,
                entitlement_id,
                pair_id,
                "b" * 64,
                now + 120,
            ),
        )
        connection.execute(
            "INSERT INTO dm_usage_sessions "
            "(session_id, entitlement_id, pair_id, channel_binding_sha256, "
            "start_request_id, start_request_hash, started_at_epoch, "
            "last_heartbeat_at_epoch, last_host_frames_total, "
            "last_android_frames_total, current_lease_sha256, "
            "previous_lease_sha256, lease_issued_at_epoch, "
            "lease_not_before_epoch, lease_expires_at_epoch, "
            "lease_remaining_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, "
            "1, ?, ?, ?, ?, ?, 86395)",
            (
                "c" * 32,
                entitlement_id,
                pair_id,
                "b" * 64,
                "d" * 32,
                "e" * 64,
                now,
                now,
                "f" * 64,
                "0" * 64,
                now,
                now,
                now + 5,
            ),
        )
    finally:
        connection.close()


def test_admin_crud_is_atomic_searchable_and_never_persists_exported_codes(
    admin_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(admin_settings).issue_batch(
        request_id="1" * 32,
        product_key="day",
        quantity=3,
        channel="xianyu",
        note="first batch",
    )
    admin = DualMachineAdminService(admin_settings)
    products = admin.list_products(enabled=True)
    assert [item["product_key"] for item in products["products"]] == [
        "day",
        "week",
        "month",
        "permanent",
    ]
    assert [item["display_name"] for item in products["products"]] == [
        "天卡",
        "周卡",
        "月卡",
        "永久卡",
    ]
    assert not {
        item["product_key"] for item in products["products"]
    } & {"1h", "5h", "10h", "50h", "100h"}

    listed = admin.list_batches(query="first")
    assert listed["total"] == 1
    assert listed["batches"][0]["issued_count"] == 3
    codes = admin.list_codes(
        batch_id=issued.batch_id,
        query=issued.codes[0][-4:],
    )
    assert codes["total"] == 1
    code_ids = [
        item["id"]
        for item in admin.list_codes(batch_id=issued.batch_id)["codes"]
    ]

    challenge_id = _insert_issued_challenge(admin_settings, code_ids[0], "2")
    expiry = int(time.time()) + 86_400
    updated = admin.update_code(
        code_ids[0],
        admin_note="buyer reserved",
        expires_at_epoch=expiry,
        reason="support correction",
        trace_id="trace-update-code",
    )
    assert updated["admin_note"] == "buyer reserved"
    assert updated["invalidated_challenges"] == 1
    connection = connect_database(admin_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_activation_challenges "
            "WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()[0] == "expired"
    finally:
        connection.close()

    _insert_issued_challenge(admin_settings, code_ids[0], "3")
    revoked = admin.revoke_code(
        code_ids[0],
        reason="manual investigation",
        trace_id="trace-revoke-code",
    )
    assert revoked["status"] == "revoked"
    assert revoked["invalidated_challenges"] == 1
    assert admin.restore_code(
        code_ids[0],
        reason="investigation cleared",
    )["status"] == "issued"

    admin.revoke_code(code_ids[1], reason="individual hold")
    batch_revoked = admin.revoke_batch(
        issued.batch_id,
        reason="batch hold",
    )
    assert batch_revoked["revoked_issued_codes"] == 2
    restored = admin.restore_batch(
        issued.batch_id,
        reason="batch cleared",
    )
    assert restored["restored_unused_codes"] == 2
    status_by_id = {
        item["id"]: item["status"]
        for item in admin.list_codes(batch_id=issued.batch_id)["codes"]
    }
    assert status_by_id[code_ids[1]] == "revoked"
    assert status_by_id[code_ids[0]] == "issued"
    assert status_by_id[code_ids[2]] == "issued"

    archived = admin.delete_code(
        code_ids[0],
        reason="duplicate sale record",
        trace_id="trace-delete-code",
    )
    assert archived["deleted"] is True
    assert admin.list_codes(batch_id=issued.batch_id)["total"] == 2
    deleted_codes = admin.list_codes(
        batch_id=issued.batch_id,
        deleted=True,
    )
    assert [item["id"] for item in deleted_codes["codes"]] == [code_ids[0]]

    exported = admin.export_batch_codes(
        issued.batch_id,
        trace_id="trace-export",
    )
    assert exported["total"] == 2
    assert [item["code"] for item in exported["codes"]] == list(
        issued.codes[1:],
    )
    database_text = _database_text(admin_settings)
    assert all(code not in database_text for code in issued.codes)
    export_events = admin.list_audit(
        event_type="license_batch_codes_exported",
    )
    assert export_events["total"] == 1
    assert export_events["events"][0]["detail"] == {
        "exported_count": 2,
        "key_versions": [1],
    }
    assert all(
        code not in json.dumps(export_events, ensure_ascii=False)
        for code in issued.codes
    )

    archived_batch = admin.delete_batch(
        issued.batch_id,
        reason="batch archived",
    )
    assert archived_batch["deleted"] is True
    assert admin.list_batches()["total"] == 0
    assert admin.list_batches(deleted=True)["total"] == 1
    unarchived_batch = admin.unarchive_batch(
        issued.batch_id,
        reason="archive reversed",
        trace_id="trace-unarchive-batch",
    )
    assert unarchived_batch["status"] == "revoked"
    assert unarchived_batch["requires_restore"] is True
    assert unarchived_batch["unarchived_codes"] == 2
    assert admin.list_batches()["total"] == 1
    assert admin.list_codes(batch_id=issued.batch_id)["total"] == 2
    unarchived_code = admin.unarchive_code(
        code_ids[0],
        reason="record restored",
        trace_id="trace-unarchive-code",
    )
    assert unarchived_code["status"] == "revoked"
    assert unarchived_code["requires_restore"] is True
    assert admin.list_codes(batch_id=issued.batch_id)["total"] == 3
    restored_batch = admin.restore_batch(
        issued.batch_id,
        reason="batch safely re-enabled",
    )
    assert restored_batch["restored_unused_codes"] == 1
    assert admin.restore_code(
        code_ids[0],
        reason="single card safely re-enabled",
    )["status"] == "issued"
    assert admin.list_audit(
        event_type="license_batch_unarchived",
    )["events"][0]["trace_id"] == "trace-unarchive-batch"
    assert admin.list_audit(
        event_type="license_code_unarchived",
    )["events"][0]["trace_id"] == "trace-unarchive-code"


def test_admin_queries_normalize_naturally_expired_issued_codes(
    admin_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(admin_settings).issue_batch(
        request_id="7" * 32,
        product_key="day",
        quantity=2,
        channel="test",
    )
    admin = DualMachineAdminService(admin_settings)
    code_id = admin.list_codes(batch_id=issued.batch_id)["codes"][0]["id"]
    challenge_id = _insert_issued_challenge(admin_settings, code_id, "8")
    connection = connect_database(admin_settings)
    try:
        connection.execute(
            "UPDATE dm_license_codes SET expires_at_epoch = ? WHERE id = ?",
            (int(time.time()) - 1, code_id),
        )
    finally:
        connection.close()

    batches = admin.list_batches()
    assert batches["batches"][0]["issued_count"] == 1
    assert batches["batches"][0]["expired_count"] == 1
    expired = admin.list_codes(
        batch_id=issued.batch_id,
        status="expired",
    )
    assert [item["id"] for item in expired["codes"]] == [code_id]
    connection = connect_database(admin_settings)
    try:
        assert connection.execute(
            "SELECT status FROM dm_activation_challenges "
            "WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()[0] == "expired"
    finally:
        connection.close()
    audit = admin.list_audit(event_type="license_codes_expired")
    assert audit["total"] == 1
    assert audit["events"][0]["detail"]["expired_codes"] == 1
    admin.update_batch(
        issued.batch_id,
        note="extended redemption window",
        expires_at_epoch=int(time.time()) + 86_400,
        reason="sales window extended",
    )
    refreshed = admin.list_batches()["batches"][0]
    assert refreshed["issued_count"] == 2
    assert refreshed["expired_count"] == 0


def test_global_code_search_uses_only_safe_cross_batch_fields(
    admin_settings: DualMachineSettings,
) -> None:
    first = CardIssuanceService(admin_settings).issue_batch(
        request_id="9" * 32,
        product_key="day",
        quantity=1,
        channel="test",
        note="first global batch",
    )
    second = CardIssuanceService(admin_settings).issue_batch(
        request_id="a" * 32,
        product_key="week",
        quantity=1,
        channel="test",
        note="second global batch",
    )
    admin = DualMachineAdminService(admin_settings)
    first_code = admin.list_codes(batch_id=first.batch_id)["codes"][0]
    second_code = admin.list_codes(batch_id=second.batch_id)["codes"][0]
    admin.update_code(
        second_code["id"],
        admin_note="buyer reservation 42",
        expires_at_epoch=None,
        reason="add searchable note",
    )
    _insert_activated_entitlement(admin_settings, first_code["id"])

    by_note = admin.list_all_codes(query="reservation 42")
    assert by_note["total"] == 1
    assert by_note["codes"][0]["batch_id"] == second.batch_id
    by_fingerprint = admin.list_all_codes(query="f" * 16)
    assert by_fingerprint["total"] == 1
    assert by_fingerprint["codes"][0]["id"] == first_code["id"]
    by_batch = admin.list_all_codes(query=str(second.batch_id))
    assert any(item["batch_id"] == second.batch_id for item in by_batch["codes"])

    serialized = json.dumps(
        admin.list_all_codes(deleted=None),
        ensure_ascii=False,
    )
    assert all(code not in serialized for code in (*first.codes, *second.codes))
    assert "code_digest" not in serialized
    assert "derivation_ref" not in serialized


def test_entitlement_restore_and_device_unbind_preserve_credit_and_audit(
    admin_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(admin_settings).issue_batch(
        request_id="d" * 32,
        product_key="day",
        quantity=1,
        channel="test",
    )
    admin = DualMachineAdminService(admin_settings)
    code_id = admin.list_codes(batch_id=issued.batch_id)["codes"][0]["id"]
    entitlement_id, binding_id = _insert_activated_entitlement(
        admin_settings,
        code_id,
    )

    revoked = admin.revoke_entitlement(
        entitlement_id,
        reason="support hold",
        trace_id="trace-entitlement-revoke",
    )
    assert revoked["revocation_version"] == 2
    assert revoked["pair_assurance_state"] == "revoked"
    restored = admin.restore_entitlement(
        entitlement_id,
        reason="support hold cleared",
        trace_id="trace-entitlement-restore",
    )
    assert restored["status"] == "active"
    assert restored["revocation_version"] == 3
    assert restored["remaining_seconds"] == 86_400
    assert restored["total_credited_seconds"] == 86_400
    assert restored["time_credited_seconds"] == 0
    assert restored["requires_card_rebind"] is True

    summary = admin.entitlement_summary(entitlement_id)
    original_pair_id = summary["pair_id"]
    _insert_active_usage_state(admin_settings, entitlement_id, original_pair_id)
    binding_challenge = _insert_issued_challenge(admin_settings, code_id, "e")
    connection = connect_database(admin_settings)
    try:
        connection.execute(
            "UPDATE dm_activation_challenges SET activation_mode = "
            "'bind_device', target_entitlement_id = ? WHERE challenge_id = ?",
            (entitlement_id, binding_challenge),
        )
    finally:
        connection.close()

    unbound = admin.unbind_entitlement_device(
        entitlement_id,
        binding_id,
        reason="customer device replacement",
        trace_id="trace-device-unbind",
    )
    assert unbound["status"] == "active"
    assert unbound["revocation_version"] == 4
    assert unbound["ended_sessions"] == 1
    assert unbound["expired_start_challenges"] == 1
    assert unbound["expired_binding_challenges"] == 1
    assert unbound["requires_card_rebind"] is True
    assert unbound["pair_assurance_state"] == "revoked"

    after = admin.entitlement_summary(entitlement_id)
    assert after["remaining_seconds"] == 86_400
    assert after["total_credited_seconds"] == 86_400
    assert after["pair_id"] != original_pair_id
    assert all(not item["is_current"] for item in after["device_bindings"])
    connection = connect_database(admin_settings)
    try:
        session = connection.execute(
            "SELECT status, ended_reason FROM dm_usage_sessions "
            "WHERE entitlement_id = ?",
            (entitlement_id,),
        ).fetchone()
        assert tuple(session) == ("ended", "admin_device_unbound")
        tombstone = connection.execute(
            "SELECT host_identity_public_key_b64, "
            "android_identity_public_key_b64 FROM dm_entitlements "
            "WHERE entitlement_id = ?",
            (entitlement_id,),
        ).fetchone()
        assert tuple(tombstone) == ("", "")
        assert connection.execute(
            "SELECT assurance_state FROM dm_pair_security_state",
        ).fetchone()[0] == "revoked"
    finally:
        connection.close()
    assert admin.list_audit(event_type="entitlement_restored")["total"] == 1
    assert admin.list_audit(
        event_type="entitlement_device_unbound",
    )["events"][0]["trace_id"] == "trace-device-unbind"
    with pytest.raises(
        DualMachineServiceError,
        match="dual_machine_device_binding_not_current",
    ):
        admin.unbind_entitlement_device(
            entitlement_id,
            binding_id,
            reason="repeat unbind",
        )


def test_restoring_consumed_entitlement_keeps_it_exhausted(
    admin_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(admin_settings).issue_batch(
        request_id="f" * 32,
        product_key="day",
        quantity=1,
        channel="test",
    )
    admin = DualMachineAdminService(admin_settings)
    code_id = admin.list_codes(batch_id=issued.batch_id)["codes"][0]["id"]
    entitlement_id, _ = _insert_activated_entitlement(admin_settings, code_id)
    connection = connect_database(admin_settings)
    try:
        connection.execute(
            "UPDATE dm_entitlements SET remaining_seconds = 0, "
            "total_consumed_seconds = total_credited_seconds, "
            "status = 'revoked', revoked_at = datetime('now'), "
            "revoke_reason = 'consumed test' WHERE entitlement_id = ?",
            (entitlement_id,),
        )
    finally:
        connection.close()

    restored = admin.restore_entitlement(
        entitlement_id,
        reason="clear administrative revocation",
    )
    assert restored["status"] == "exhausted"
    assert restored["remaining_seconds"] == 0
    assert restored["time_credited_seconds"] == 0


def test_batch_update_synchronizes_only_unactivated_code_expiry(
    admin_settings: DualMachineSettings,
) -> None:
    issued = CardIssuanceService(admin_settings).issue_batch(
        request_id="4" * 32,
        product_key="week",
        quantity=2,
        channel="test",
    )
    expiry = int(time.time()) + 172_800
    updated = DualMachineAdminService(admin_settings).update_batch(
        issued.batch_id,
        note="new sales window",
        expires_at_epoch=expiry,
        reason="campaign extended",
    )
    assert updated["updated_unused_codes"] == 2
    connection = connect_database(admin_settings)
    try:
        rows = connection.execute(
            "SELECT expires_at_epoch FROM dm_license_codes ORDER BY ordinal",
        ).fetchall()
        assert [row[0] for row in rows] == [expiry, expiry]
    finally:
        connection.close()


def test_v3_database_migrates_in_place_and_preserves_legacy_rows(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy-v3.db"
    connection = sqlite3.connect(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE dm_products (
                product_key TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE dm_license_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                product_key TEXT NOT NULL REFERENCES dm_products(product_key),
                quantity INTEGER NOT NULL,
                channel TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                expires_at_epoch INTEGER,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                revoked_at TEXT,
                revoke_reason TEXT NOT NULL DEFAULT '',
                deleted_at TEXT,
                delete_reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE dm_license_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL REFERENCES dm_license_batches(id),
                ordinal INTEGER NOT NULL,
                code_digest TEXT UNIQUE NOT NULL,
                code_suffix TEXT NOT NULL,
                key_version INTEGER NOT NULL,
                derivation_ref TEXT UNIQUE NOT NULL,
                product_key TEXT NOT NULL REFERENCES dm_products(product_key),
                duration_seconds INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'issued'
                    CHECK(status IN ('issued', 'consumed', 'revoked', 'expired')),
                expires_at_epoch INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                activated_at_epoch INTEGER,
                revoked_at TEXT,
                revoke_reason TEXT NOT NULL DEFAULT '',
                revoked_by_batch INTEGER NOT NULL DEFAULT 0,
                deleted_at TEXT,
                delete_reason TEXT NOT NULL DEFAULT '',
                UNIQUE(batch_id, ordinal)
            );
            CREATE TABLE dm_activation_challenges (
                challenge_id TEXT PRIMARY KEY,
                request_id TEXT UNIQUE NOT NULL,
                request_payload_hash TEXT NOT NULL,
                token_digest TEXT UNIQUE NOT NULL,
                license_code_id INTEGER NOT NULL REFERENCES dm_license_codes(id),
                pair_id TEXT NOT NULL,
                protocol_version INTEGER NOT NULL,
                host_device_code TEXT NOT NULL,
                host_client_version TEXT NOT NULL,
                host_identity_public_key_b64 TEXT NOT NULL,
                host_key_sha256 TEXT NOT NULL,
                android_device_code TEXT NOT NULL,
                android_client_version TEXT NOT NULL,
                android_identity_public_key_b64 TEXT NOT NULL,
                android_key_sha256 TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'issued',
                expires_at_epoch INTEGER NOT NULL,
                issued_ip TEXT NOT NULL DEFAULT '',
                consumed_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                consumed_at_epoch INTEGER,
                revoke_reason TEXT NOT NULL DEFAULT '',
                activation_mode TEXT NOT NULL DEFAULT 'activate'
                    CHECK(activation_mode IN ('activate', 'bind_device')),
                target_entitlement_id TEXT NOT NULL DEFAULT '',
                android_device_profile_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE dm_entitlements (
                entitlement_id TEXT PRIMARY KEY,
                pair_id TEXT UNIQUE NOT NULL,
                protocol_version INTEGER NOT NULL,
                host_device_code TEXT NOT NULL,
                host_client_version TEXT NOT NULL,
                host_identity_public_key_b64 TEXT NOT NULL,
                host_key_sha256 TEXT NOT NULL,
                android_device_code TEXT NOT NULL,
                android_client_version TEXT NOT NULL,
                android_identity_public_key_b64 TEXT NOT NULL,
                android_key_sha256 TEXT NOT NULL,
                remaining_seconds INTEGER NOT NULL,
                total_credited_seconds INTEGER NOT NULL,
                total_consumed_seconds INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                revocation_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                revoked_at TEXT,
                revoke_reason TEXT NOT NULL DEFAULT '',
                UNIQUE(host_key_sha256, android_key_sha256)
            );
            CREATE TABLE dm_license_activations (
                activation_id TEXT PRIMARY KEY,
                license_code_id INTEGER UNIQUE NOT NULL
                    REFERENCES dm_license_codes(id),
                entitlement_id TEXT NOT NULL
                    REFERENCES dm_entitlements(entitlement_id),
                challenge_id TEXT UNIQUE NOT NULL
                    REFERENCES dm_activation_challenges(challenge_id),
                credited_seconds INTEGER NOT NULL CHECK(credited_seconds > 0),
                activated_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO dm_products
                (product_key, display_name, duration_seconds, sort_order)
                VALUES ('1h', 'legacy hour', 3600, 10);
            INSERT INTO dm_license_batches
                (request_id, product_key, quantity, channel)
                VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '1h', 1, 'old');
            INSERT INTO dm_license_codes
                (batch_id, ordinal, code_digest, code_suffix, key_version,
                 derivation_ref, product_key, duration_seconds)
                VALUES (1, 1, 'legacy-digest', 'ABCD', 1,
                        'legacy-ref', '1h', 3600);
            INSERT INTO dm_activation_challenges
                (challenge_id, request_id, request_payload_hash, token_digest,
                 license_code_id, pair_id, protocol_version,
                 host_device_code, host_client_version,
                 host_identity_public_key_b64, host_key_sha256,
                 android_device_code, android_client_version,
                 android_identity_public_key_b64, android_key_sha256,
                 status, expires_at_epoch, activation_mode,
                 target_entitlement_id)
                VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                        'cccccccccccccccccccccccccccccccc', 'payload', 'token',
                        1, 'dddddddddddddddddddddddddddddddd', 2,
                        'HOST-OLD', '17.8.81', 'host-public',
                        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                        'ANDROID-OLD', '1.0.0', 'android-public',
                        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                        'consumed', 1700000100, 'activate',
                        '11111111111111111111111111111111');
            INSERT INTO dm_entitlements
                (entitlement_id, pair_id, protocol_version,
                 host_device_code, host_client_version,
                 host_identity_public_key_b64, host_key_sha256,
                 android_device_code, android_client_version,
                 android_identity_public_key_b64, android_key_sha256,
                 remaining_seconds, total_credited_seconds)
                VALUES ('11111111111111111111111111111111',
                        'dddddddddddddddddddddddddddddddd', 2,
                        'HOST-OLD', '17.8.81', 'host-public',
                        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                        'ANDROID-OLD', '1.0.0', 'android-public',
                        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                        3600, 3600);
            INSERT INTO dm_license_activations
                (activation_id, license_code_id, entitlement_id,
                 challenge_id, credited_seconds)
                VALUES ('22222222222222222222222222222222', 1,
                        '11111111111111111111111111111111',
                        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 3600);
            """
        )
        connection.commit()
    finally:
        connection.close()

    settings = _settings(database_path)
    initialize_database(settings)
    migrated = connect_database(settings)
    try:
        product = migrated.execute(
            "SELECT enabled, authorization_kind FROM dm_products "
            "WHERE product_key = '1h'",
        ).fetchone()
        assert tuple(product) == (0, "legacy_balance")
        assert migrated.execute(
            "SELECT COUNT(*) FROM dm_license_codes "
            "WHERE derivation_ref = 'legacy-ref'",
        ).fetchone()[0] == 1
        code_columns = {
            row["name"]
            for row in migrated.execute(
                "PRAGMA table_info(dm_license_codes)",
            ).fetchall()
        }
        assert {"authorization_kind", "admin_note"} <= code_columns
        binding = migrated.execute(
            "SELECT host_key_sha256, android_key_sha256, is_current "
            "FROM dm_entitlement_device_bindings",
        ).fetchone()
        assert tuple(binding) == ("e" * 64, "f" * 64, 1)
        activation_sql = migrated.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'dm_license_activations'",
        ).fetchone()[0]
        assert "credited_seconds >= 0" in activation_sql
        assert migrated.execute(
            "SELECT credited_seconds FROM dm_license_activations",
        ).fetchone()[0] == 3_600
        migrated_challenge = migrated.execute(
            "SELECT activation_mode, target_entitlement_id "
            "FROM dm_activation_challenges",
        ).fetchone()
        assert tuple(migrated_challenge) == (
            "reactivate",
            "1" * 32,
        )
        challenge_sql = migrated.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'dm_activation_challenges'",
        ).fetchone()[0]
        assert "'reactivate'" in challenge_sql
        assert migrated.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            migrated.execute(
                "UPDATE dm_activation_challenges SET activation_mode = "
                "'activate' WHERE challenge_id = ?",
                ("b" * 32,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            migrated.execute(
                "UPDATE dm_activation_challenges SET "
                "target_entitlement_id = ? WHERE challenge_id = ?",
                ("0" * 32, "b" * 32),
            )
        assert {
            row[0]
            for row in migrated.execute(
                "SELECT product_key FROM dm_products WHERE enabled = 1",
            ).fetchall()
        } == {"day", "week", "month", "permanent"}
    finally:
        migrated.close()
