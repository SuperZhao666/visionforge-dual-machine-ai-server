"""Independent SQLite boundary for the dual-machine sidecar."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .settings import DualMachineSettings


PAIR_GENERATION_FOUNDATION_SCHEMA_VERSION = (
    "20260804_dual_machine_pair_generation_foundation_v8"
)
REACTIVATION_SCHEMA_VERSION = "20260804_dual_machine_reactivation_mode_v9"
PAIR_GENERATION_CREDENTIAL_JOURNAL_SCHEMA_VERSION = (
    "20260804_dual_machine_generation_credential_journal_v10"
)
VERIFIED_PAIR_BOOTSTRAP_SCHEMA_VERSION = (
    "20260804_dual_machine_verified_pair_bootstrap_v11"
)
PAIR_SECURITY_SCHEMA_ATTESTATION_VERSION = (
    "20260804_dual_machine_pair_security_schema_attestation_v12"
)
# Keep the active version as an exact top-level literal. The release verifier
# reads this assignment without importing database code, while the equality
# assertion prevents the named migration constant from drifting independently.
SCHEMA_VERSION = "20260804_dual_machine_pair_security_schema_attestation_v12"
assert SCHEMA_VERSION == PAIR_SECURITY_SCHEMA_ATTESTATION_VERSION
SCHEMA_MIGRATIONS = (
    PAIR_GENERATION_FOUNDATION_SCHEMA_VERSION,
    REACTIVATION_SCHEMA_VERSION,
    PAIR_GENERATION_CREDENTIAL_JOURNAL_SCHEMA_VERSION,
    VERIFIED_PAIR_BOOTSTRAP_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
PAIR_SECURITY_TRIGGER_NAMES = (
    "dm_pair_allocations_validate_insert",
    "dm_pair_allocations_reject_update",
    "dm_pair_allocations_reject_delete",
    "dm_pair_credentials_validate_insert",
    "dm_pair_credentials_reject_update",
    "dm_pair_credentials_reject_delete",
    "dm_pair_state_reject_delete",
    "dm_pair_state_reject_identity_update",
    "dm_pair_state_reject_rollback",
    "dm_pair_state_validate_transition",
    "dm_pair_challenge_reject_delete",
    "dm_pair_challenge_reject_content_update",
    "dm_pair_challenge_reject_terminal_update",
)
PAIR_SECURITY_INDEX_NAMES = (
    "idx_dm_pair_one_issued_challenge",
)
DEFAULT_PRODUCTS = (
    ("1h", "1 小时", 3_600, 10),
    ("5h", "5 小时", 5 * 3_600, 20),
    ("10h", "10 小时", 10 * 3_600, 30),
    ("50h", "50 小时", 50 * 3_600, 40),
    ("100h", "100 小时", 100 * 3_600, 50),
)
TERM_PRODUCTS = (
    ("day", "天卡", 24 * 60 * 60, "day", 10),
    ("week", "周卡", 7 * 24 * 60 * 60, "week", 20),
    ("month", "月卡", 30 * 24 * 60 * 60, "month", 30),
    # duration_seconds is legacy-only. Permanent authorization never debits
    # or interprets this compatibility sentinel as a usable balance.
    ("permanent", "永久卡", 1, "permanent", 40),
)
LEGACY_PRODUCT_KEYS = tuple(row[0] for row in DEFAULT_PRODUCTS)


def connect_database(
    settings: DualMachineSettings,
) -> sqlite3.Connection:
    database_path = Path(settings.database_path).resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        str(database_path),
        timeout=15,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    _require_isolated_database(connection)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=8000")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def _require_isolated_database(
    connection: sqlite3.Connection,
) -> None:
    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'",
        ).fetchall()
    }
    unexpected = sorted(
        table_name
        for table_name in table_names
        if not table_name.startswith(("dm_", "sqlite_"))
    )
    if unexpected:
        connection.close()
        raise ValueError(
            "dual-machine database contains non-sidecar tables",
        )


def initialize_database(settings: DualMachineSettings) -> None:
    connection = connect_database(settings)
    try:
        initialize_schema(connection)
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def initialize_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        BEGIN IMMEDIATE;

        CREATE TABLE IF NOT EXISTS dm_schema_migrations (
            migration_key TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS dm_products (
            product_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL CHECK(duration_seconds > 0),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            authorization_kind TEXT NOT NULL DEFAULT 'legacy_balance'
                CHECK(authorization_kind IN (
                    'legacy_balance', 'day', 'week', 'month', 'permanent'
                )),
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS dm_license_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            product_key TEXT NOT NULL REFERENCES dm_products(product_key),
            quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 500),
            channel TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            expires_at_epoch INTEGER,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active', 'revoked')),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            revoked_at TEXT,
            revoke_reason TEXT NOT NULL DEFAULT '',
            deleted_at TEXT,
            delete_reason TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS dm_license_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL REFERENCES dm_license_batches(id),
            ordinal INTEGER NOT NULL,
            code_digest TEXT UNIQUE NOT NULL,
            code_suffix TEXT NOT NULL CHECK(length(code_suffix) = 4),
            key_version INTEGER NOT NULL CHECK(key_version > 0),
            derivation_ref TEXT UNIQUE NOT NULL,
            product_key TEXT NOT NULL REFERENCES dm_products(product_key),
            duration_seconds INTEGER NOT NULL CHECK(duration_seconds > 0),
            authorization_kind TEXT NOT NULL DEFAULT 'legacy_balance'
                CHECK(authorization_kind IN (
                    'legacy_balance', 'day', 'week', 'month', 'permanent'
                )),
            status TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued', 'activated', 'revoked', 'expired')),
            expires_at_epoch INTEGER,
            admin_note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            activated_at_epoch INTEGER,
            revoked_at TEXT,
            revoke_reason TEXT NOT NULL DEFAULT '',
            revoked_by_batch INTEGER NOT NULL DEFAULT 0
                CHECK(revoked_by_batch IN (0, 1)),
            deleted_at TEXT,
            delete_reason TEXT NOT NULL DEFAULT '',
            deleted_by_batch INTEGER NOT NULL DEFAULT 0
                CHECK(deleted_by_batch IN (0, 1)),
            UNIQUE(batch_id, ordinal),
            CHECK(
                (status = 'activated' AND activated_at_epoch IS NOT NULL)
                OR
                (status != 'activated' AND activated_at_epoch IS NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS dm_activation_challenges (
            challenge_id TEXT PRIMARY KEY,
            request_id TEXT UNIQUE NOT NULL,
            request_payload_hash TEXT NOT NULL,
            token_digest TEXT UNIQUE NOT NULL,
            license_code_id INTEGER NOT NULL REFERENCES dm_license_codes(id),
            pair_id TEXT NOT NULL,
            protocol_version INTEGER NOT NULL CHECK(protocol_version = 2),
            host_device_code TEXT NOT NULL,
            host_client_version TEXT NOT NULL,
            host_identity_public_key_b64 TEXT NOT NULL,
            host_key_sha256 TEXT NOT NULL,
            android_device_code TEXT NOT NULL,
            android_client_version TEXT NOT NULL,
            android_identity_public_key_b64 TEXT NOT NULL,
            android_key_sha256 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued', 'consumed', 'revoked', 'expired')),
            expires_at_epoch INTEGER NOT NULL,
            issued_ip TEXT NOT NULL DEFAULT '',
            consumed_ip TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            consumed_at_epoch INTEGER,
            revoke_reason TEXT NOT NULL DEFAULT '',
            activation_mode TEXT NOT NULL DEFAULT 'activate',
            target_entitlement_id TEXT NOT NULL DEFAULT '',
            android_device_profile_json TEXT NOT NULL DEFAULT '{}',
            CHECK(
                (activation_mode = 'activate'
                    AND target_entitlement_id = '')
                OR
                (activation_mode IN ('reactivate', 'bind_device')
                    AND length(target_entitlement_id) = 32
                    AND target_entitlement_id
                        NOT GLOB '*[^0-9a-f]*'
                    AND target_entitlement_id GLOB '*[1-9a-f]*')
            )
        );

        CREATE TABLE IF NOT EXISTS dm_entitlements (
            entitlement_id TEXT PRIMARY KEY,
            pair_id TEXT UNIQUE NOT NULL,
            protocol_version INTEGER NOT NULL CHECK(protocol_version = 2),
            host_device_code TEXT NOT NULL,
            host_client_version TEXT NOT NULL,
            host_identity_public_key_b64 TEXT NOT NULL,
            host_key_sha256 TEXT NOT NULL,
            android_device_code TEXT NOT NULL,
            android_client_version TEXT NOT NULL,
            android_identity_public_key_b64 TEXT NOT NULL,
            android_key_sha256 TEXT NOT NULL,
            remaining_seconds INTEGER NOT NULL CHECK(remaining_seconds >= 0),
            total_credited_seconds INTEGER NOT NULL
                CHECK(total_credited_seconds >= 0),
            total_consumed_seconds INTEGER NOT NULL DEFAULT 0
                CHECK(total_consumed_seconds >= 0),
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active', 'exhausted', 'revoked')),
            revocation_version INTEGER NOT NULL DEFAULT 1
                CHECK(revocation_version > 0),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            revoked_at TEXT,
            revoke_reason TEXT NOT NULL DEFAULT '',
            authorization_kind TEXT NOT NULL DEFAULT 'legacy_balance'
                CHECK(authorization_kind IN (
                    'legacy_balance', 'day', 'week', 'month', 'permanent'
                )),
            product_key TEXT NOT NULL DEFAULT '',
            source_license_code_id INTEGER,
            UNIQUE(host_key_sha256, android_key_sha256),
            CHECK(
                total_credited_seconds
                = remaining_seconds + total_consumed_seconds
            ),
            CHECK(
                (status = 'exhausted' AND remaining_seconds = 0)
                OR status != 'exhausted'
            )
        );

        CREATE TABLE IF NOT EXISTS dm_license_activations (
            activation_id TEXT PRIMARY KEY,
            license_code_id INTEGER UNIQUE NOT NULL
                REFERENCES dm_license_codes(id),
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            challenge_id TEXT UNIQUE NOT NULL
                REFERENCES dm_activation_challenges(challenge_id),
            credited_seconds INTEGER NOT NULL CHECK(credited_seconds >= 0),
            activated_ip TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS dm_entitlement_device_bindings (
            binding_id TEXT PRIMARY KEY,
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            pair_id TEXT NOT NULL,
            host_device_code TEXT NOT NULL,
            host_client_version TEXT NOT NULL,
            host_identity_public_key_b64 TEXT NOT NULL,
            host_key_sha256 TEXT NOT NULL,
            android_device_code TEXT NOT NULL,
            android_client_version TEXT NOT NULL,
            android_identity_public_key_b64 TEXT NOT NULL,
            android_key_sha256 TEXT NOT NULL,
            android_device_profile_json TEXT NOT NULL DEFAULT '{}',
            is_current INTEGER NOT NULL DEFAULT 1
                CHECK(is_current IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(
                entitlement_id,
                pair_id,
                host_key_sha256,
                android_key_sha256
            )
        );

        CREATE TABLE IF NOT EXISTS dm_pair_security_state (
            pair_id TEXT PRIMARY KEY CHECK(length(pair_id) BETWEEN 1 AND 128),
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            binding_id TEXT NOT NULL
                REFERENCES dm_entitlement_device_bindings(binding_id),
            binding_revision INTEGER NOT NULL
                CHECK(binding_revision BETWEEN 1 AND 9223372036854775807),
            revocation_version INTEGER NOT NULL
                CHECK(revocation_version BETWEEN 1 AND 9223372036854775807),
            host_key_sha256 TEXT NOT NULL
                CHECK(
                    length(host_key_sha256) = 64
                    AND host_key_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            android_key_sha256 TEXT NOT NULL
                CHECK(
                    length(android_key_sha256) = 64
                    AND android_key_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            assurance_state TEXT NOT NULL DEFAULT 'pending'
                CHECK(assurance_state IN (
                    'legacy_blocked', 'pending', 'active', 'rotated',
                    'revoked', 'recovery_pending'
                )),
            generation_high_water INTEGER NOT NULL DEFAULT 0
                CHECK(
                    generation_high_water
                    BETWEEN 0 AND 9223372036854775807
                ),
            predecessor_pair_id TEXT
                REFERENCES dm_pair_security_state(pair_id),
            created_at_epoch INTEGER NOT NULL
                CHECK(created_at_epoch BETWEEN 0 AND 9223372036854775807),
            updated_at_epoch INTEGER NOT NULL
                CHECK(updated_at_epoch BETWEEN 0 AND 9223372036854775807),
            UNIQUE(entitlement_id, binding_revision),
            CHECK(host_key_sha256 <> android_key_sha256),
            CHECK(predecessor_pair_id IS NULL OR predecessor_pair_id <> pair_id)
        );

        CREATE TABLE IF NOT EXISTS dm_pair_generation_challenges (
            challenge_id TEXT PRIMARY KEY,
            request_id TEXT UNIQUE NOT NULL,
            request_payload_sha256 TEXT NOT NULL
                CHECK(
                    length(request_payload_sha256) = 64
                    AND request_payload_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            pair_id TEXT NOT NULL REFERENCES dm_pair_security_state(pair_id),
            binding_revision INTEGER NOT NULL
                CHECK(binding_revision BETWEEN 1 AND 9223372036854775807),
            server_nonce_sha256 TEXT UNIQUE NOT NULL
                CHECK(
                    length(server_nonce_sha256) = 64
                    AND server_nonce_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            status TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued', 'consumed', 'expired', 'revoked')),
            expires_at_epoch INTEGER NOT NULL
                CHECK(expires_at_epoch BETWEEN 0 AND 9223372036854775807),
            consumed_at_epoch INTEGER
                CHECK(
                    consumed_at_epoch IS NULL
                    OR consumed_at_epoch BETWEEN 0 AND 9223372036854775807
                ),
            created_at_epoch INTEGER NOT NULL
                CHECK(created_at_epoch BETWEEN 0 AND 9223372036854775807),
            CHECK(
                (status = 'consumed' AND consumed_at_epoch IS NOT NULL)
                OR
                (status <> 'consumed' AND consumed_at_epoch IS NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS dm_pair_generation_allocations (
            allocation_request_id TEXT PRIMARY KEY,
            request_payload_sha256 TEXT NOT NULL
                CHECK(
                    length(request_payload_sha256) = 64
                    AND request_payload_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            challenge_id TEXT UNIQUE NOT NULL
                REFERENCES dm_pair_generation_challenges(challenge_id),
            pair_id TEXT NOT NULL REFERENCES dm_pair_security_state(pair_id),
            binding_revision INTEGER NOT NULL
                CHECK(binding_revision BETWEEN 1 AND 9223372036854775807),
            generation INTEGER NOT NULL
                CHECK(generation BETWEEN 1 AND 9223372036854775807),
            connection_id INTEGER NOT NULL
                CHECK(connection_id BETWEEN 1 AND 9223372036854775807),
            transcript_proposal_sha256 TEXT NOT NULL
                CHECK(
                    length(transcript_proposal_sha256) = 64
                    AND transcript_proposal_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            allocated_at_epoch INTEGER NOT NULL
                CHECK(allocated_at_epoch BETWEEN 0 AND 9223372036854775807),
            UNIQUE(pair_id, generation),
            UNIQUE(pair_id, connection_id)
        );

        CREATE TABLE IF NOT EXISTS dm_usage_start_challenges (
            challenge_id TEXT PRIMARY KEY,
            request_id TEXT UNIQUE NOT NULL,
            request_payload_hash TEXT NOT NULL,
            token_digest TEXT UNIQUE NOT NULL,
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            pair_id TEXT NOT NULL,
            channel_binding_sha256 TEXT NOT NULL
                CHECK(length(channel_binding_sha256) = 64),
            status TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued', 'consumed', 'expired')),
            expires_at_epoch INTEGER NOT NULL,
            issued_ip TEXT NOT NULL DEFAULT '',
            consumed_at_epoch INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS dm_usage_sessions (
            session_id TEXT PRIMARY KEY,
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            pair_id TEXT NOT NULL,
            channel_binding_sha256 TEXT NOT NULL
                CHECK(length(channel_binding_sha256) = 64),
            start_request_id TEXT NOT NULL,
            start_request_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active', 'ended', 'exhausted', 'revoked')),
            started_at_epoch INTEGER NOT NULL,
            last_heartbeat_at_epoch INTEGER NOT NULL,
            last_heartbeat_sequence INTEGER NOT NULL DEFAULT 0
                CHECK(last_heartbeat_sequence >= 0),
            last_request_id TEXT NOT NULL DEFAULT '',
            last_request_hash TEXT NOT NULL DEFAULT '',
            last_host_frames_total INTEGER NOT NULL CHECK(last_host_frames_total >= 0),
            last_android_frames_total INTEGER NOT NULL
                CHECK(last_android_frames_total >= 0),
            current_lease_sha256 TEXT NOT NULL,
            previous_lease_sha256 TEXT NOT NULL
                CHECK(length(previous_lease_sha256) = 64),
            lease_issued_at_epoch INTEGER NOT NULL,
            lease_not_before_epoch INTEGER NOT NULL,
            lease_expires_at_epoch INTEGER NOT NULL,
            lease_phase TEXT NOT NULL DEFAULT 'active'
                CHECK(lease_phase = 'active'),
            lease_remaining_seconds INTEGER NOT NULL
                CHECK(lease_remaining_seconds >= 0),
            seconds_consumed INTEGER NOT NULL DEFAULT 0
                CHECK(seconds_consumed >= 0),
            ended_at_epoch INTEGER,
            ended_reason TEXT NOT NULL DEFAULT '',
            UNIQUE(entitlement_id, start_request_id),
            CHECK(lease_not_before_epoch >= lease_issued_at_epoch),
            CHECK(lease_expires_at_epoch > lease_not_before_epoch)
        );

        CREATE TABLE IF NOT EXISTS dm_usage_start_cancellations (
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            start_request_id TEXT NOT NULL
                CHECK(length(start_request_id) = 32),
            cancel_request_id TEXT NOT NULL
                CHECK(length(cancel_request_id) = 32),
            cancel_request_hash TEXT NOT NULL
                CHECK(length(cancel_request_hash) = 64),
            authenticated_request_hash TEXT NOT NULL DEFAULT ''
                CHECK(
                    authenticated_request_hash = ''
                    OR length(authenticated_request_hash) = 64
                ),
            response_json TEXT NOT NULL DEFAULT '',
            channel_binding_sha256 TEXT NOT NULL
                CHECK(length(channel_binding_sha256) = 64),
            created_at_epoch INTEGER NOT NULL,
            PRIMARY KEY(entitlement_id, start_request_id),
            UNIQUE(entitlement_id, cancel_request_id)
        );

        CREATE TABLE IF NOT EXISTS dm_usage_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            charge_id TEXT UNIQUE NOT NULL,
            entitlement_id TEXT NOT NULL
                REFERENCES dm_entitlements(entitlement_id),
            session_id TEXT NOT NULL REFERENCES dm_usage_sessions(session_id),
            sequence INTEGER NOT NULL CHECK(sequence >= 0),
            interval_started_at_epoch INTEGER NOT NULL,
            interval_ended_at_epoch INTEGER NOT NULL,
            charged_seconds INTEGER NOT NULL CHECK(charged_seconds > 0),
            balance_before_seconds INTEGER NOT NULL
                CHECK(balance_before_seconds >= 0),
            balance_after_seconds INTEGER NOT NULL
                CHECK(balance_after_seconds >= 0),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(session_id, sequence),
            CHECK(interval_ended_at_epoch > interval_started_at_epoch),
            CHECK(
                balance_before_seconds
                = balance_after_seconds + charged_seconds
            )
        );

        CREATE TABLE IF NOT EXISTS dm_auth_nonces (
            scope TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            nonce_digest TEXT NOT NULL,
            expires_at_epoch INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(scope, subject_id, nonce_digest)
        );

        CREATE TABLE IF NOT EXISTS dm_audit_events (
            event_id TEXT PRIMARY KEY,
            trace_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL,
            error_code TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE UNIQUE INDEX IF NOT EXISTS
            idx_dm_challenge_one_issued_per_code
            ON dm_activation_challenges(license_code_id)
            WHERE status = 'issued';
        CREATE INDEX IF NOT EXISTS idx_dm_codes_status
            ON dm_license_codes(status, expires_at_epoch);
        CREATE INDEX IF NOT EXISTS idx_dm_challenges_expiry
            ON dm_activation_challenges(status, expires_at_epoch);
        CREATE INDEX IF NOT EXISTS idx_dm_entitlements_status
            ON dm_entitlements(status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_dm_usage_start_challenge_expiry
            ON dm_usage_start_challenges(status, expires_at_epoch);
        CREATE UNIQUE INDEX IF NOT EXISTS
            idx_dm_usage_one_issued_start_challenge
            ON dm_usage_start_challenges(entitlement_id)
            WHERE status = 'issued';
        CREATE UNIQUE INDEX IF NOT EXISTS
            idx_dm_usage_one_active_entitlement
            ON dm_usage_sessions(entitlement_id)
            WHERE status = 'active';
        CREATE INDEX IF NOT EXISTS idx_dm_usage_lease_expiry
            ON dm_usage_sessions(status, lease_expires_at_epoch);
        CREATE INDEX IF NOT EXISTS idx_dm_nonces_expiry
            ON dm_auth_nonces(expires_at_epoch);
        CREATE INDEX IF NOT EXISTS idx_dm_audit_created
            ON dm_audit_events(created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dm_pair_one_issued_challenge
            ON dm_pair_generation_challenges(pair_id)
            WHERE status = 'issued';
        CREATE INDEX IF NOT EXISTS idx_dm_pair_challenge_expiry
            ON dm_pair_generation_challenges(status, expires_at_epoch);
        CREATE INDEX IF NOT EXISTS idx_dm_pair_allocation_created
            ON dm_pair_generation_allocations(pair_id, allocated_at_epoch);

        COMMIT;
        """
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        _migrate_card_admin_schema(connection)
        _migrate_usage_start_cancellation_schema(connection)
        _migrate_pair_security_schema(connection)
        _reinstall_pair_security_indexes(connection)
        _reinstall_pair_security_triggers(connection)
        connection.executemany(
            "INSERT OR IGNORE INTO dm_products "
            "(product_key, display_name, duration_seconds, sort_order) "
            "VALUES (?, ?, ?, ?)",
            DEFAULT_PRODUCTS,
        )
        connection.executemany(
            "INSERT INTO dm_products "
            "(product_key, display_name, duration_seconds, "
            "authorization_kind, sort_order, enabled) "
            "VALUES (?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(product_key) DO UPDATE SET "
            "display_name = excluded.display_name, "
            "duration_seconds = excluded.duration_seconds, "
            "authorization_kind = excluded.authorization_kind, "
            "sort_order = excluded.sort_order, enabled = 1, "
            "updated_at = datetime('now')",
            TERM_PRODUCTS,
        )
        connection.execute(
            "UPDATE dm_products SET enabled = 0, "
            "updated_at = datetime('now') "
            "WHERE product_key IN (?, ?, ?, ?, ?)",
            LEGACY_PRODUCT_KEYS,
        )
        connection.executemany(
            "INSERT OR IGNORE INTO dm_schema_migrations(migration_key) "
            "VALUES (?)",
            ((migration_key,) for migration_key in SCHEMA_MIGRATIONS),
        )
        connection.commit()
        _migrate_activation_challenge_modes(connection)
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def _migrate_usage_start_cancellation_schema(
    connection: sqlite3.Connection,
) -> None:
    """Add authenticated exact-replay data without discarding tombstones."""
    _ensure_column(
        connection,
        "dm_usage_start_cancellations",
        "authenticated_request_hash",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_usage_start_cancellations",
        "response_json",
        "TEXT NOT NULL DEFAULT ''",
    )


def _migrate_pair_security_schema(
    connection: sqlite3.Connection,
) -> None:
    """Quarantine pre-foundation bindings instead of trusting them."""
    _migrate_pair_generation_allocation_schema(connection)
    _require_exact_pair_security_core_schemas(connection)
    _migrate_pair_generation_credential_schema(connection)
    connection.execute(
        "INSERT OR IGNORE INTO dm_pair_security_state "
        "(pair_id, entitlement_id, binding_id, binding_revision, "
        "revocation_version, host_key_sha256, android_key_sha256, "
        "assurance_state, generation_high_water, predecessor_pair_id, "
        "created_at_epoch, updated_at_epoch) "
        "SELECT b.pair_id, b.entitlement_id, b.binding_id, 1, "
        "e.revocation_version, b.host_key_sha256, b.android_key_sha256, "
        "'legacy_blocked', 0, NULL, 0, 0 "
        "FROM dm_entitlement_device_bindings b "
        "JOIN dm_entitlements e ON e.entitlement_id = b.entitlement_id "
        "WHERE b.is_current = 1 AND length(b.pair_id) BETWEEN 1 AND 128 "
        "AND e.revocation_version BETWEEN 1 AND 9223372036854775807 "
        "AND length(b.host_key_sha256) = 64 "
        "AND b.host_key_sha256 NOT GLOB '*[^0-9a-f]*' "
        "AND length(b.android_key_sha256) = 64 "
        "AND b.android_key_sha256 NOT GLOB '*[^0-9a-f]*' "
        "AND b.host_key_sha256 <> b.android_key_sha256 "
        "AND NOT EXISTS ("
        "SELECT 1 FROM dm_pair_security_state s "
        "WHERE s.pair_id = b.pair_id OR s.entitlement_id = b.entitlement_id"
        ")",
    )


def _migrate_pair_generation_allocation_schema(
    connection: sqlite3.Connection,
) -> None:
    """Remove the pre-signer credential placeholder columns atomically."""
    legacy_table = "dm_pair_generation_allocations_with_credential_v7"
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (legacy_table,),
    ).fetchone() is not None:
        raise RuntimeError(
            "pair generation allocation migration requires operator recovery",
        )
    columns = {
        str(row["name"])
        for row in connection.execute(
            'PRAGMA table_info("dm_pair_generation_allocations")',
        ).fetchall()
    }
    removed_columns = {"credential_token", "credential_sha256"}
    if not columns.intersection(removed_columns):
        return
    credential_journal_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("dm_pair_generation_credentials",),
    ).fetchone()
    if credential_journal_exists is not None:
        raise RuntimeError(
            "pair generation allocation downgrade requires operator recovery",
        )
    _drop_pair_security_triggers(connection)
    connection.execute(
        "DROP INDEX IF EXISTS idx_dm_pair_allocation_created",
    )
    connection.execute(
        "ALTER TABLE dm_pair_generation_allocations RENAME TO "
        f'"{legacy_table}"',
    )
    _create_pair_generation_allocations_table(connection)
    connection.execute(
        "INSERT INTO dm_pair_generation_allocations "
        "(allocation_request_id, request_payload_sha256, challenge_id, "
        "pair_id, binding_revision, generation, connection_id, "
        "transcript_proposal_sha256, allocated_at_epoch) "
        "SELECT allocation_request_id, request_payload_sha256, "
        "challenge_id, pair_id, binding_revision, generation, "
        "connection_id, transcript_proposal_sha256, allocated_at_epoch "
        f'FROM "{legacy_table}"',
    )
    connection.execute(f'DROP TABLE "{legacy_table}"')
    connection.execute(
        "CREATE INDEX idx_dm_pair_allocation_created "
        "ON dm_pair_generation_allocations(pair_id, allocated_at_epoch)",
    )


_PAIR_SECURITY_STATE_TABLE_SQL = (
    "CREATE TABLE dm_pair_security_state ("
    "pair_id TEXT PRIMARY KEY CHECK(length(pair_id) BETWEEN 1 AND 128), "
    "entitlement_id TEXT NOT NULL REFERENCES dm_entitlements(entitlement_id), "
    "binding_id TEXT NOT NULL REFERENCES "
    "dm_entitlement_device_bindings(binding_id), "
    "binding_revision INTEGER NOT NULL CHECK("
    "binding_revision BETWEEN 1 AND 9223372036854775807), "
    "revocation_version INTEGER NOT NULL CHECK("
    "revocation_version BETWEEN 1 AND 9223372036854775807), "
    "host_key_sha256 TEXT NOT NULL CHECK("
    "length(host_key_sha256) = 64 AND "
    "host_key_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "android_key_sha256 TEXT NOT NULL CHECK("
    "length(android_key_sha256) = 64 AND "
    "android_key_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "assurance_state TEXT NOT NULL DEFAULT 'pending' CHECK("
    "assurance_state IN ('legacy_blocked', 'pending', 'active', 'rotated', "
    "'revoked', 'recovery_pending')), "
    "generation_high_water INTEGER NOT NULL DEFAULT 0 CHECK("
    "generation_high_water BETWEEN 0 AND 9223372036854775807), "
    "predecessor_pair_id TEXT REFERENCES dm_pair_security_state(pair_id), "
    "created_at_epoch INTEGER NOT NULL CHECK("
    "created_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "updated_at_epoch INTEGER NOT NULL CHECK("
    "updated_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "UNIQUE(entitlement_id, binding_revision), "
    "CHECK(host_key_sha256 <> android_key_sha256), "
    "CHECK(predecessor_pair_id IS NULL OR predecessor_pair_id <> pair_id))"
)

_PAIR_GENERATION_CHALLENGE_TABLE_SQL = (
    "CREATE TABLE dm_pair_generation_challenges ("
    "challenge_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, "
    "request_payload_sha256 TEXT NOT NULL CHECK("
    "length(request_payload_sha256) = 64 AND "
    "request_payload_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "pair_id TEXT NOT NULL REFERENCES dm_pair_security_state(pair_id), "
    "binding_revision INTEGER NOT NULL CHECK("
    "binding_revision BETWEEN 1 AND 9223372036854775807), "
    "server_nonce_sha256 TEXT UNIQUE NOT NULL CHECK("
    "length(server_nonce_sha256) = 64 AND "
    "server_nonce_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "status TEXT NOT NULL DEFAULT 'issued' CHECK("
    "status IN ('issued', 'consumed', 'expired', 'revoked')), "
    "expires_at_epoch INTEGER NOT NULL CHECK("
    "expires_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "consumed_at_epoch INTEGER CHECK(consumed_at_epoch IS NULL OR "
    "consumed_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "created_at_epoch INTEGER NOT NULL CHECK("
    "created_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "CHECK((status = 'consumed' AND consumed_at_epoch IS NOT NULL) OR "
    "(status <> 'consumed' AND consumed_at_epoch IS NULL)))"
)

_PAIR_GENERATION_ALLOCATION_TABLE_SQL = (
    "CREATE TABLE dm_pair_generation_allocations ("
    "allocation_request_id TEXT PRIMARY KEY, "
    "request_payload_sha256 TEXT NOT NULL CHECK("
    "length(request_payload_sha256) = 64 AND "
    "request_payload_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "challenge_id TEXT UNIQUE NOT NULL REFERENCES "
    "dm_pair_generation_challenges(challenge_id), "
    "pair_id TEXT NOT NULL REFERENCES dm_pair_security_state(pair_id), "
    "binding_revision INTEGER NOT NULL CHECK("
    "binding_revision BETWEEN 1 AND 9223372036854775807), "
    "generation INTEGER NOT NULL CHECK("
    "generation BETWEEN 1 AND 9223372036854775807), "
    "connection_id INTEGER NOT NULL CHECK("
    "connection_id BETWEEN 1 AND 9223372036854775807), "
    "transcript_proposal_sha256 TEXT NOT NULL CHECK("
    "length(transcript_proposal_sha256) = 64 AND "
    "transcript_proposal_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "allocated_at_epoch INTEGER NOT NULL CHECK("
    "allocated_at_epoch BETWEEN 0 AND 9223372036854775807), "
    "UNIQUE(pair_id, generation), UNIQUE(pair_id, connection_id))"
)


def _create_pair_generation_allocations_table(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(_PAIR_GENERATION_ALLOCATION_TABLE_SQL)


def _require_exact_pair_security_core_schemas(
    connection: sqlite3.Connection,
) -> None:
    """Reject same-name weak tables before any pair state is trusted.

    SQLite's ``CREATE TABLE IF NOT EXISTS`` accepts an attacker-precreated
    table solely by name.  Column-name checks therefore cannot attest primary
    keys, uniqueness, foreign keys, or CHECK constraints.  A non-exact core
    table is never adopted automatically, even when empty: startup fails closed
    so an operator can inspect the database provenance before replacement.
    """
    expected_schemas = {
        "dm_pair_security_state": _PAIR_SECURITY_STATE_TABLE_SQL,
        "dm_pair_generation_challenges": _PAIR_GENERATION_CHALLENGE_TABLE_SQL,
        "dm_pair_generation_allocations": _PAIR_GENERATION_ALLOCATION_TABLE_SQL,
    }
    for table_name, expected_schema in expected_schemas.items():
        schema_row = connection.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?",
            (table_name,),
        ).fetchone()
        if (
            schema_row is None
            or str(schema_row["type"]) != "table"
            or _normalized_schema_sql(str(schema_row["sql"] or ""))
            != _normalized_schema_sql(expected_schema)
        ):
            raise RuntimeError(
                "pair security core schema requires operator recovery",
            )


def _migrate_pair_generation_credential_schema(
    connection: sqlite3.Connection,
) -> None:
    """Create the separate append-only credential journal.

    The v7 allocation-table token placeholders were deliberately discarded by
    the v8 migration because they predated the strict signer.  They must never
    be imported into this journal as if they were authoritative credentials.
    """
    schema_row = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = ?",
        ("dm_pair_generation_credentials",),
    ).fetchone()
    if schema_row is None:
        _create_pair_generation_credentials_table(connection)
        return
    if str(schema_row["type"]) != "table":
        raise RuntimeError(
            "pair generation credential journal requires operator recovery",
        )
    actual_schema = str(schema_row["sql"] or "")
    schema_is_exact = (
        _normalized_schema_sql(actual_schema)
        == _normalized_schema_sql(_PAIR_GENERATION_CREDENTIAL_TABLE_SQL)
    )
    if schema_is_exact:
        return
    row_count = connection.execute(
        "SELECT COUNT(*) FROM dm_pair_generation_credentials",
    ).fetchone()
    if row_count is None or int(row_count[0]) != 0:
        raise RuntimeError(
            "pair generation credential journal requires operator recovery",
        )
    connection.execute("DROP TABLE dm_pair_generation_credentials")
    _create_pair_generation_credentials_table(connection)


_PAIR_GENERATION_CREDENTIAL_TABLE_SQL = (
    "CREATE TABLE dm_pair_generation_credentials ("
    "allocation_request_id TEXT PRIMARY KEY REFERENCES "
    "dm_pair_generation_allocations(allocation_request_id), "
    "credential_token BLOB UNIQUE NOT NULL CHECK("
    "typeof(credential_token) = 'blob' AND "
    "length(credential_token) BETWEEN 1 AND 8192), "
    "credential_sha256 TEXT UNIQUE NOT NULL CHECK("
    "length(credential_sha256) = 64 AND "
    "credential_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "key_id TEXT NOT NULL CHECK("
    "length(key_id) = 16 AND key_id NOT GLOB '*[^0-9a-f]*'), "
    "credential_nonce_sha256 TEXT UNIQUE NOT NULL CHECK("
    "length(credential_nonce_sha256) = 64 AND "
    "credential_nonce_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "issued_at_epoch INTEGER NOT NULL CHECK("
    "issued_at_epoch BETWEEN 1 AND 9223372036854775807), "
    "not_before_epoch INTEGER NOT NULL CHECK("
    "not_before_epoch = issued_at_epoch), "
    "expires_at_epoch INTEGER NOT NULL CHECK("
    "expires_at_epoch > issued_at_epoch AND "
    "expires_at_epoch - issued_at_epoch BETWEEN 1 AND 30))"
)


def _create_pair_generation_credentials_table(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(_PAIR_GENERATION_CREDENTIAL_TABLE_SQL)


def _normalized_schema_sql(value: str) -> tuple[str, ...]:
    """Return a quote-aware SQLite token fingerprint.

    Layout and comments are ignored, unquoted SQL words are folded to their
    case-insensitive form, and quoted literals/identifiers remain byte-exact.
    This makes harmless formatting changes equivalent without allowing a
    literal-sensitive CHECK constraint to be weakened by case folding.
    """
    tokens: list[str] = []
    index = 0
    length = len(value)
    two_character_operators = {
        "!=", "%=", "&&", "&=", "*=", "+=", "-=", "->", "/=", "<<",
        "<=", "<>", "==", ">=", ">>", "|=", "||",
    }
    while index < length:
        character = value[index]
        if character.isspace():
            index += 1
            continue
        if value.startswith("--", index):
            newline = value.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if value.startswith("/*", index):
            closing = value.find("*/", index + 2)
            if closing < 0:
                tokens.append(value[index:])
                break
            index = closing + 2
            continue
        if character == "'":
            end = index + 1
            while end < length:
                if value[end] != "'":
                    end += 1
                    continue
                if end + 1 < length and value[end + 1] == "'":
                    end += 2
                    continue
                end += 1
                break
            tokens.append(value[index:end])
            index = end
            continue
        if character in {'"', "`", "["}:
            closing_character = "]" if character == "[" else character
            end = index + 1
            while end < length:
                if value[end] != closing_character:
                    end += 1
                    continue
                if (
                    character != "["
                    and end + 1 < length
                    and value[end + 1] == closing_character
                ):
                    end += 2
                    continue
                end += 1
                break
            tokens.append(value[index:end])
            index = end
            continue
        if character.isalpha() or character == "_":
            end = index + 1
            while end < length and (
                value[end].isalnum() or value[end] in {"_", "$"}
            ):
                end += 1
            tokens.append(value[index:end].lower())
            index = end
            continue
        if character.isdigit():
            end = index + 1
            while end < length and (
                value[end].isalnum() or value[end] in {"_", "."}
            ):
                end += 1
            tokens.append(value[index:end].lower())
            index = end
            continue
        if index + 2 <= length:
            candidate = value[index : index + 2]
            if candidate in two_character_operators:
                if (
                    candidate == "->"
                    and index + 3 <= length
                    and value[index + 2] == ">"
                ):
                    tokens.append("->>")
                    index += 3
                else:
                    tokens.append(candidate)
                    index += 2
                continue
        tokens.append(character)
        index += 1
    return tuple(tokens)


def _drop_pair_security_triggers(connection: sqlite3.Connection) -> None:
    for trigger_name in PAIR_SECURITY_TRIGGER_NAMES:
        connection.execute(f'DROP TRIGGER IF EXISTS "{trigger_name}"')


def _reinstall_pair_security_indexes(
    connection: sqlite3.Connection,
) -> None:
    """Replace security-critical indexes instead of trusting their names."""
    for index_name in PAIR_SECURITY_INDEX_NAMES:
        connection.execute(f'DROP INDEX IF EXISTS "{index_name}"')
    connection.execute(
        "CREATE UNIQUE INDEX idx_dm_pair_one_issued_challenge "
        "ON dm_pair_generation_challenges(pair_id) "
        "WHERE status = 'issued'",
    )


def _reinstall_pair_security_triggers(
    connection: sqlite3.Connection,
) -> None:
    """Replace known triggers so a weak prior definition cannot survive."""
    _drop_pair_security_triggers(connection)
    for statement in _pair_security_trigger_definitions():
        connection.execute(statement)


def _pair_security_trigger_definitions() -> tuple[str, ...]:
    return (
        "CREATE TRIGGER dm_pair_allocations_validate_insert "
        "BEFORE INSERT ON dm_pair_generation_allocations WHEN NOT EXISTS ("
        "SELECT 1 FROM dm_pair_generation_challenges challenge "
        "JOIN dm_pair_security_state state "
        "ON state.pair_id = challenge.pair_id "
        "WHERE challenge.challenge_id = NEW.challenge_id "
        "AND challenge.request_payload_sha256 = NEW.request_payload_sha256 "
        "AND challenge.pair_id = NEW.pair_id "
        "AND challenge.binding_revision = NEW.binding_revision "
        "AND challenge.status = 'consumed' "
        "AND challenge.consumed_at_epoch = NEW.allocated_at_epoch "
        "AND state.assurance_state = 'active' "
        "AND state.binding_revision = NEW.binding_revision "
        "AND state.generation_high_water = NEW.generation) BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_allocation_authority_invalid'); "
        "END",
        "CREATE TRIGGER dm_pair_allocations_reject_update "
        "BEFORE UPDATE ON dm_pair_generation_allocations BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_allocations_immutable'); END",
        "CREATE TRIGGER dm_pair_allocations_reject_delete "
        "BEFORE DELETE ON dm_pair_generation_allocations BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_allocations_immutable'); END",
        "CREATE TRIGGER dm_pair_credentials_validate_insert "
        "BEFORE INSERT ON dm_pair_generation_credentials WHEN NOT EXISTS ("
        "SELECT 1 FROM dm_pair_generation_allocations allocation "
        "WHERE allocation.allocation_request_id = NEW.allocation_request_id "
        "AND NEW.issued_at_epoch >= allocation.allocated_at_epoch "
        "AND NEW.issued_at_epoch - allocation.allocated_at_epoch <= 5) BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_credential_allocation_invalid'); "
        "END",
        "CREATE TRIGGER dm_pair_credentials_reject_update "
        "BEFORE UPDATE ON dm_pair_generation_credentials BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_credentials_immutable'); END",
        "CREATE TRIGGER dm_pair_credentials_reject_delete "
        "BEFORE DELETE ON dm_pair_generation_credentials BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_credentials_immutable'); END",
        "CREATE TRIGGER dm_pair_state_reject_delete "
        "BEFORE DELETE ON dm_pair_security_state BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_security_state_immutable'); END",
        "CREATE TRIGGER dm_pair_state_reject_identity_update "
        "BEFORE UPDATE ON dm_pair_security_state WHEN "
        "NEW.pair_id <> OLD.pair_id "
        "OR NEW.entitlement_id <> OLD.entitlement_id "
        "OR NEW.binding_id <> OLD.binding_id "
        "OR NEW.binding_revision <> OLD.binding_revision "
        "OR (NEW.revocation_version <> OLD.revocation_version AND NOT ("
        "OLD.assurance_state = 'recovery_pending' "
        "AND NEW.assurance_state = 'active' "
        "AND OLD.revocation_version < 9223372036854775807 "
        "AND NEW.revocation_version = OLD.revocation_version + 1)) "
        "OR NEW.host_key_sha256 <> OLD.host_key_sha256 "
        "OR NEW.android_key_sha256 <> OLD.android_key_sha256 "
        "OR NEW.predecessor_pair_id IS NOT OLD.predecessor_pair_id "
        "OR NEW.created_at_epoch <> OLD.created_at_epoch BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_security_identity_immutable'); END",
        "CREATE TRIGGER dm_pair_state_reject_rollback "
        "BEFORE UPDATE ON dm_pair_security_state WHEN "
        "NEW.generation_high_water < OLD.generation_high_water "
        "OR NEW.updated_at_epoch < OLD.updated_at_epoch OR ("
        "NEW.generation_high_water > OLD.generation_high_water AND ("
        "OLD.assurance_state <> 'active' "
        "OR NEW.assurance_state <> 'active')) BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_security_state_rollback'); END",
        "CREATE TRIGGER dm_pair_state_validate_transition "
        "BEFORE UPDATE ON dm_pair_security_state WHEN NOT ("
        "NEW.assurance_state = OLD.assurance_state OR ("
        "OLD.assurance_state = 'legacy_blocked' AND "
        "NEW.assurance_state IN ('recovery_pending', 'revoked')) OR ("
        "OLD.assurance_state = 'pending' AND "
        "NEW.assurance_state IN ('active', 'rotated', 'revoked')) OR ("
        "OLD.assurance_state = 'active' AND NEW.assurance_state IN ("
        "'rotated', 'revoked', 'recovery_pending')) OR ("
        "OLD.assurance_state = 'recovery_pending' AND "
        "NEW.assurance_state IN ('active', 'rotated', 'revoked'))) BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_security_transition_invalid'); END",
        "CREATE TRIGGER dm_pair_challenge_reject_delete "
        "BEFORE DELETE ON dm_pair_generation_challenges BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_challenge_immutable'); END",
        "CREATE TRIGGER dm_pair_challenge_reject_content_update "
        "BEFORE UPDATE ON dm_pair_generation_challenges WHEN "
        "NEW.challenge_id <> OLD.challenge_id "
        "OR NEW.request_id <> OLD.request_id "
        "OR NEW.request_payload_sha256 <> OLD.request_payload_sha256 "
        "OR NEW.pair_id <> OLD.pair_id "
        "OR NEW.binding_revision <> OLD.binding_revision "
        "OR NEW.server_nonce_sha256 <> OLD.server_nonce_sha256 "
        "OR NEW.expires_at_epoch <> OLD.expires_at_epoch "
        "OR NEW.created_at_epoch <> OLD.created_at_epoch BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_challenge_immutable'); END",
        "CREATE TRIGGER dm_pair_challenge_reject_terminal_update "
        "BEFORE UPDATE ON dm_pair_generation_challenges WHEN ("
        "OLD.status IN ('consumed', 'expired', 'revoked') AND ("
        "NEW.status <> OLD.status OR "
        "NEW.consumed_at_epoch IS NOT OLD.consumed_at_epoch)) OR ("
        "OLD.status = 'issued' AND NEW.status NOT IN ("
        "'issued', 'consumed', 'expired', 'revoked')) BEGIN "
        "SELECT RAISE(ABORT, 'dm_pair_generation_challenge_terminal'); END",
    )


def _migrate_activation_challenge_modes(
    connection: sqlite3.Connection,
) -> None:
    """Add the explicit reactivation mode without losing signed history."""
    if _activation_challenge_modes_are_current(connection):
        return
    if connection.in_transaction:
        raise RuntimeError("activation_mode_migration_requires_autocommit")

    foreign_keys_enabled = bool(
        connection.execute("PRAGMA foreign_keys").fetchone()[0],
    )
    if foreign_keys_enabled:
        connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        _replace_activation_challenge_table(connection)
        if connection.execute("PRAGMA foreign_key_check").fetchone():
            raise RuntimeError("activation_mode_migration_foreign_key_invalid")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        if foreign_keys_enabled:
            connection.execute("PRAGMA foreign_keys=ON")
        restored = bool(
            connection.execute("PRAGMA foreign_keys").fetchone()[0],
        )
        if restored != foreign_keys_enabled:
            raise RuntimeError("activation_mode_migration_foreign_key_state")


def _activation_challenge_modes_are_current(
    connection: sqlite3.Connection,
) -> bool:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'dm_activation_challenges'",
    ).fetchone()
    table_sql = str(row["sql"] or "") if row is not None else ""
    return "'reactivate'" in table_sql.lower()


def _replace_activation_challenge_table(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        "CREATE TABLE dm_activation_challenges_reactivation_v1 ("
        "challenge_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, "
        "request_payload_hash TEXT NOT NULL, "
        "token_digest TEXT UNIQUE NOT NULL, license_code_id INTEGER NOT NULL "
        "REFERENCES dm_license_codes(id), pair_id TEXT NOT NULL, "
        "protocol_version INTEGER NOT NULL CHECK(protocol_version = 2), "
        "host_device_code TEXT NOT NULL, host_client_version TEXT NOT NULL, "
        "host_identity_public_key_b64 TEXT NOT NULL, "
        "host_key_sha256 TEXT NOT NULL, android_device_code TEXT NOT NULL, "
        "android_client_version TEXT NOT NULL, "
        "android_identity_public_key_b64 TEXT NOT NULL, "
        "android_key_sha256 TEXT NOT NULL, status TEXT NOT NULL "
        "DEFAULT 'issued' CHECK(status IN "
        "('issued', 'consumed', 'revoked', 'expired')), "
        "expires_at_epoch INTEGER NOT NULL, issued_ip TEXT NOT NULL "
        "DEFAULT '', consumed_ip TEXT NOT NULL DEFAULT '', "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')), "
        "consumed_at_epoch INTEGER, revoke_reason TEXT NOT NULL DEFAULT '', "
        "activation_mode TEXT NOT NULL DEFAULT 'activate', "
        "target_entitlement_id TEXT NOT NULL DEFAULT '', "
        "android_device_profile_json TEXT NOT NULL DEFAULT '{}', "
        "CHECK((activation_mode = 'activate' AND target_entitlement_id = '') "
        "OR (activation_mode IN ('reactivate', 'bind_device') "
        "AND length(target_entitlement_id) = 32 "
        "AND target_entitlement_id NOT GLOB '*[^0-9a-f]*' "
        "AND target_entitlement_id GLOB '*[1-9a-f]*')))"
    )
    _copy_activation_challenge_rows(connection)
    connection.execute("DROP TABLE dm_activation_challenges")
    connection.execute(
        "ALTER TABLE dm_activation_challenges_reactivation_v1 "
        "RENAME TO dm_activation_challenges",
    )
    _restore_activation_challenge_indexes(connection)


def _copy_activation_challenge_rows(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        "INSERT INTO dm_activation_challenges_reactivation_v1 "
        "(challenge_id, request_id, request_payload_hash, token_digest, "
        "license_code_id, pair_id, protocol_version, host_device_code, "
        "host_client_version, host_identity_public_key_b64, host_key_sha256, "
        "android_device_code, android_client_version, "
        "android_identity_public_key_b64, android_key_sha256, status, "
        "expires_at_epoch, issued_ip, consumed_ip, created_at, "
        "consumed_at_epoch, revoke_reason, activation_mode, "
        "target_entitlement_id, android_device_profile_json) "
        "SELECT challenge_id, request_id, request_payload_hash, token_digest, "
        "license_code_id, pair_id, protocol_version, host_device_code, "
        "host_client_version, host_identity_public_key_b64, host_key_sha256, "
        "android_device_code, android_client_version, "
        "android_identity_public_key_b64, android_key_sha256, status, "
        "expires_at_epoch, issued_ip, consumed_ip, created_at, "
        "consumed_at_epoch, revoke_reason, CASE WHEN activation_mode = "
        "'activate' AND target_entitlement_id <> '' THEN 'reactivate' "
        "ELSE activation_mode END, target_entitlement_id, "
        "android_device_profile_json FROM dm_activation_challenges"
    )


def _restore_activation_challenge_indexes(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        "CREATE UNIQUE INDEX idx_dm_challenge_one_issued_per_code "
        "ON dm_activation_challenges(license_code_id) "
        "WHERE status = 'issued'",
    )
    connection.execute(
        "CREATE INDEX idx_dm_challenges_expiry "
        "ON dm_activation_challenges(status, expires_at_epoch)",
    )


def _migrate_card_admin_schema(
    connection: sqlite3.Connection,
) -> None:
    """Add term authorization and admin metadata while preserving data."""
    _ensure_column(
        connection,
        "dm_products",
        "authorization_kind",
        "TEXT NOT NULL DEFAULT 'legacy_balance'",
    )
    _ensure_column(
        connection,
        "dm_license_batches",
        "deleted_at",
        "TEXT",
    )
    _ensure_column(
        connection,
        "dm_license_batches",
        "delete_reason",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "revoked_by_batch",
        "INTEGER NOT NULL DEFAULT 0 CHECK(revoked_by_batch IN (0, 1))",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "deleted_at",
        "TEXT",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "delete_reason",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "deleted_by_batch",
        "INTEGER NOT NULL DEFAULT 0 CHECK(deleted_by_batch IN (0, 1))",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "authorization_kind",
        "TEXT NOT NULL DEFAULT 'legacy_balance'",
    )
    _ensure_column(
        connection,
        "dm_license_codes",
        "admin_note",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_activation_challenges",
        "activation_mode",
        "TEXT NOT NULL DEFAULT 'activate'",
    )
    _ensure_column(
        connection,
        "dm_activation_challenges",
        "target_entitlement_id",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_activation_challenges",
        "android_device_profile_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        connection,
        "dm_entitlements",
        "authorization_kind",
        "TEXT NOT NULL DEFAULT 'legacy_balance'",
    )
    _ensure_column(
        connection,
        "dm_entitlements",
        "product_key",
        "TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        connection,
        "dm_entitlements",
        "source_license_code_id",
        "INTEGER",
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS dm_entitlement_device_bindings ("
        "binding_id TEXT PRIMARY KEY, "
        "entitlement_id TEXT NOT NULL REFERENCES "
        "dm_entitlements(entitlement_id), "
        "pair_id TEXT NOT NULL, host_device_code TEXT NOT NULL, "
        "host_client_version TEXT NOT NULL, "
        "host_identity_public_key_b64 TEXT NOT NULL, "
        "host_key_sha256 TEXT NOT NULL, "
        "android_device_code TEXT NOT NULL, "
        "android_client_version TEXT NOT NULL, "
        "android_identity_public_key_b64 TEXT NOT NULL, "
        "android_key_sha256 TEXT NOT NULL, "
        "android_device_profile_json TEXT NOT NULL DEFAULT '{}', "
        "is_current INTEGER NOT NULL DEFAULT 1 "
        "CHECK(is_current IN (0, 1)), "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')), "
        "last_seen_at TEXT NOT NULL DEFAULT (datetime('now')), "
        "UNIQUE(entitlement_id, pair_id, host_key_sha256, "
        "android_key_sha256))",
    )
    _migrate_license_activations(connection)
    connection.execute(
        "INSERT INTO dm_entitlement_device_bindings "
        "(binding_id, entitlement_id, pair_id, host_device_code, "
        "host_client_version, host_identity_public_key_b64, "
        "host_key_sha256, android_device_code, android_client_version, "
        "android_identity_public_key_b64, android_key_sha256, "
        "android_device_profile_json, is_current) "
        "SELECT lower(hex(randomblob(16))), e.entitlement_id, e.pair_id, "
        "e.host_device_code, e.host_client_version, "
        "e.host_identity_public_key_b64, e.host_key_sha256, "
        "e.android_device_code, e.android_client_version, "
        "e.android_identity_public_key_b64, e.android_key_sha256, '{}', 1 "
        "FROM dm_entitlements e WHERE NOT EXISTS ("
        "SELECT 1 FROM dm_entitlement_device_bindings b "
        "WHERE b.entitlement_id = e.entitlement_id AND b.is_current = 1)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dm_batches_deleted "
        "ON dm_license_batches(deleted_at, status, id)",
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dm_codes_admin_lookup "
        "ON dm_license_codes(deleted_at, status, code_suffix, batch_id)",
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_dm_term_entitlement_source_code "
        "ON dm_entitlements(source_license_code_id) "
        "WHERE source_license_code_id IS NOT NULL",
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dm_binding_one_current "
        "ON dm_entitlement_device_bindings(entitlement_id) "
        "WHERE is_current = 1",
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dm_bindings_entitlement "
        "ON dm_entitlement_device_bindings(entitlement_id, created_at)",
    )


def _migrate_license_activations(connection: sqlite3.Connection) -> None:
    """Allow permanent-card activations to record a real zero credit."""
    row = connection.execute(
        "SELECT sql FROM sqlite_master "
        "WHERE type = 'table' AND name = 'dm_license_activations'",
    ).fetchone()
    table_sql = str(row["sql"] or "") if row is not None else ""
    normalized_sql = "".join(table_sql.lower().split())
    if "check(credited_seconds>0)" not in normalized_sql:
        return
    connection.execute(
        "CREATE TABLE dm_license_activations_v4 ("
        "activation_id TEXT PRIMARY KEY, "
        "license_code_id INTEGER UNIQUE NOT NULL "
        "REFERENCES dm_license_codes(id), "
        "entitlement_id TEXT NOT NULL "
        "REFERENCES dm_entitlements(entitlement_id), "
        "challenge_id TEXT UNIQUE NOT NULL "
        "REFERENCES dm_activation_challenges(challenge_id), "
        "credited_seconds INTEGER NOT NULL CHECK(credited_seconds >= 0), "
        "activated_ip TEXT NOT NULL DEFAULT '', "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    connection.execute(
        "INSERT INTO dm_license_activations_v4 "
        "(activation_id, license_code_id, entitlement_id, challenge_id, "
        "credited_seconds, activated_ip, created_at) "
        "SELECT activation_id, license_code_id, entitlement_id, "
        "challenge_id, credited_seconds, activated_ip, created_at "
        "FROM dm_license_activations"
    )
    connection.execute("DROP TABLE dm_license_activations")
    connection.execute(
        "ALTER TABLE dm_license_activations_v4 "
        "RENAME TO dm_license_activations"
    )


def _ensure_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    declaration: str,
) -> None:
    columns = {
        str(row["name"])
        for row in connection.execute(
            f'PRAGMA table_info("{table_name}")',
        ).fetchall()
    }
    if column_name in columns:
        return
    connection.execute(
        f'ALTER TABLE "{table_name}" ADD COLUMN '
        f'"{column_name}" {declaration}',
    )
