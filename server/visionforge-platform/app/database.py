"""Database connection and initialization."""
import logging
import sqlite3
import threading
import time
from pathlib import Path
from app.config import config

logger = logging.getLogger("database")
_journal_mode_paths: set[str] = set()
_journal_mode_lock = threading.Lock()
SINGLE_LOGIN_MIGRATION = "20260715_single_login_runtime_instance_v2"
RUNTIME_EVENT_SCHEMA_MIGRATION = "20260719_runtime_event_dimensions_v1"


def get_db_path() -> str:
    db_path = config.DATABASE_PATH
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return db_path


def get_connection() -> sqlite3.Connection:
    """Get SQLite connection with WAL mode and busy timeout. Retries on lock."""
    for attempt in range(3):
        conn: sqlite3.Connection | None = None
        try:
            db_path = str(Path(get_db_path()).resolve())
            conn = sqlite3.connect(db_path, timeout=15)
            conn.row_factory = sqlite3.Row
            if db_path not in _journal_mode_paths:
                with _journal_mode_lock:
                    if db_path not in _journal_mode_paths:
                        conn.execute("PRAGMA journal_mode=WAL")
                        _journal_mode_paths.add(db_path)
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=8000")
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        except sqlite3.OperationalError:
            if conn is not None:
                conn.close()
            if attempt < 2:
                logger.warning("DB locked, retry %d/3", attempt + 1)
                time.sleep(0.5)
    raise sqlite3.OperationalError("Database locked after 3 retries")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _drop_empty_legacy_tables(conn: sqlite3.Connection) -> None:
    """Remove retired Platform-owned Xianyu tables without discarding historical data."""
    for table in ("channel_product_mappings", "fulfillment_deliveries"):
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if exists and int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) == 0:
            conn.execute(f"DROP TABLE {table}")


def _dedupe_user_emails(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE users SET email = lower(trim(email)) WHERE trim(email) != ''")
    duplicates = conn.execute(
        "SELECT lower(trim(email)) AS normalized_email, MIN(id) AS keep_id, COUNT(*) AS c "
        "FROM users WHERE trim(email) != '' "
        "GROUP BY lower(trim(email)) HAVING c > 1"
    ).fetchall()
    for row in duplicates:
        normalized = str(row["normalized_email"] or "")
        keep_id = int(row["keep_id"])
        conn.execute(
            "UPDATE users SET email = '', updated_at = datetime('now') "
            "WHERE lower(trim(email)) = ? AND id != ?",
            (normalized, keep_id),
        )
        logger.warning("Cleared duplicate email binding, kept user id %d", keep_id)


def _dedupe_active_sessions(conn: sqlite3.Connection) -> None:
    duplicate_rows = conn.execute(
        "SELECT user_id, MAX(id) AS keep_id, COUNT(*) AS c "
        "FROM time_sessions WHERE status = 'active' "
        "GROUP BY user_id HAVING c > 1"
    ).fetchall()
    for row in duplicate_rows:
        conn.execute(
            "UPDATE users SET runtime_blocked_until_epoch = MAX(runtime_blocked_until_epoch, "
            "COALESCE((SELECT MAX(CAST(strftime('%s', lease_expires_at) AS INTEGER)) "
            "FROM time_sessions WHERE user_id = ? AND status = 'active'), 0)) WHERE id = ?",
            (row["user_id"], row["user_id"]),
        )
        conn.execute(
            "UPDATE time_sessions SET status = 'ended', "
            "ended_at = COALESCE(ended_at, datetime('now')), "
            "ended_reason = 'duplicate_active_session', "
            "revoked_at = COALESCE(revoked_at, datetime('now')) "
            "WHERE user_id = ? AND status = 'active' AND id != ?",
            (row["user_id"], row["keep_id"]),
        )
        logger.warning("Closed duplicate active sessions for user id %s, kept session id %s", row["user_id"], row["keep_id"])


def _dedupe_order_links(conn: sqlite3.Connection) -> None:
    duplicate_recharges = conn.execute(
        "SELECT order_id, MIN(id) AS keep_id, COUNT(*) AS c "
        "FROM time_recharges WHERE order_id IS NOT NULL "
        "GROUP BY order_id HAVING c > 1"
    ).fetchall()
    for row in duplicate_recharges:
        conn.execute(
            "UPDATE time_recharges SET order_id = NULL WHERE order_id = ? AND id != ?",
            (row["order_id"], row["keep_id"]),
        )
        logger.warning("Detached duplicate recharge rows for order id %s, kept recharge id %s", row["order_id"], row["keep_id"])

    duplicate_sessions = conn.execute(
        "SELECT order_id, MIN(token) AS keep_token, COUNT(*) AS c "
        "FROM purchase_sessions WHERE order_id IS NOT NULL "
        "GROUP BY order_id HAVING c > 1"
    ).fetchall()
    for row in duplicate_sessions:
        conn.execute(
            "UPDATE purchase_sessions SET order_id = NULL, "
            "status = CASE WHEN status = 'delivered' THEN status ELSE 'cancelled' END "
            "WHERE order_id = ? AND token != ?",
            (row["order_id"], row["keep_token"]),
        )
        logger.warning("Detached duplicate purchase sessions for order id %s, kept token %s", row["order_id"], row["keep_token"])


def _dedupe_active_purchase_sessions(conn: sqlite3.Connection) -> None:
    """Keep one active checkout per user before adding the partial unique index."""
    rows = conn.execute(
        "SELECT ps.user_id, ps.token, ps.created_at, COALESCE(o.status, '') AS order_status "
        "FROM purchase_sessions ps LEFT JOIN orders o ON o.id = ps.order_id "
        "WHERE ps.status IN ('open', 'pending') "
        "ORDER BY ps.user_id, "
        "CASE WHEN o.status = 'pending' THEN 0 ELSE 1 END, "
        "ps.created_at DESC, ps.token DESC"
    ).fetchall()
    kept_by_user: dict[int, str] = {}
    for row in rows:
        user_id = int(row["user_id"])
        token = str(row["token"])
        if user_id not in kept_by_user:
            kept_by_user[user_id] = token
            continue
        conn.execute(
            "UPDATE purchase_sessions SET status = 'cancelled' WHERE token = ?",
            (token,),
        )
        logger.warning(
            "Cancelled duplicate active purchase session for user id %s, kept token %s",
            user_id,
            kept_by_user[user_id],
        )


def _backfill_order_numbers(conn: sqlite3.Connection) -> None:
    if "merchant_order_no" not in _table_columns(conn, "orders"):
        return
    rows = conn.execute(
        "SELECT id FROM orders WHERE trim(COALESCE(merchant_order_no, '')) = ''"
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE orders SET merchant_order_no = ? WHERE id = ?",
            (f"VFLEGACY{int(row['id']):010d}", row["id"]),
        )


def _backfill_payment_event_ids(conn: sqlite3.Connection) -> None:
    columns = _table_columns(conn, "payment_events")
    if "event_id" not in columns:
        return
    source_expr = "event_key" if "event_key" in columns else "''"
    rows = conn.execute(
        f"SELECT id, COALESCE({source_expr}, '') AS legacy_key "
        "FROM payment_events WHERE trim(COALESCE(event_id, '')) = ''"
    ).fetchall()
    for row in rows:
        legacy_key = str(row["legacy_key"] or "").strip()
        event_id = legacy_key if legacy_key else f"legacy:{int(row['id'])}"
        conn.execute("UPDATE payment_events SET event_id = ? WHERE id = ?", (event_id[:255], row["id"]))


def _dedupe_log_sessions(conn: sqlite3.Connection) -> None:
    duplicates = conn.execute(
        "SELECT COALESCE(user_id, 0) AS owner_id, session_id, MIN(id) AS keep_id, COUNT(*) AS c "
        "FROM log_sessions GROUP BY COALESCE(user_id, 0), session_id HAVING c > 1"
    ).fetchall()
    for row in duplicates:
        owner_id = int(row["owner_id"] or 0)
        session_id = str(row["session_id"] or "")
        keep_id = int(row["keep_id"])
        extra_rows = conn.execute(
            "SELECT id FROM log_sessions WHERE COALESCE(user_id, 0) = ? AND session_id = ? AND id != ?",
            (owner_id, session_id, keep_id),
        ).fetchall()
        extra_ids = [int(item["id"]) for item in extra_rows]
        if not extra_ids:
            continue
        placeholders = ",".join("?" for _ in extra_ids)
        conn.execute(
            f"UPDATE log_files SET session_id = ? WHERE session_id IN ({placeholders})",
            (keep_id, *extra_ids),
        )
        conn.execute(
            "UPDATE log_sessions SET upload_count = (SELECT COUNT(*) FROM log_files WHERE session_id = ?), "
            "latest_upload_at = (SELECT MAX(uploaded_at) FROM log_files WHERE session_id = ?) WHERE id = ?",
            (keep_id, keep_id, keep_id),
        )
        conn.execute(f"DELETE FROM log_sessions WHERE id IN ({placeholders})", extra_ids)
        logger.warning("Merged duplicate log sessions for owner %s session %s", owner_id, session_id)


def _dedupe_releases(conn: sqlite3.Connection) -> None:
    """Make legacy release rows safe for the uniqueness constraints."""
    release_rows = conn.execute(
        "SELECT id, channel, version, published FROM releases "
        "ORDER BY channel, version, published DESC, id DESC"
    ).fetchall()
    kept_versions: dict[tuple[str, str], int] = {}
    for row in release_rows:
        identity = (str(row["channel"]), str(row["version"]))
        if identity not in kept_versions:
            kept_versions[identity] = int(row["id"])
            continue
        conn.execute(
            "DELETE FROM releases WHERE id = ?",
            (row["id"],),
        )
        logger.warning(
            "Removed duplicate release rows for channel %s version %s, kept id %s",
            row["channel"],
            row["version"],
            kept_versions[identity],
        )
    active_channels = conn.execute(
        "SELECT channel, MAX(id) AS keep_id, COUNT(*) AS c FROM releases "
        "WHERE published = 1 GROUP BY channel HAVING c > 1"
    ).fetchall()
    for row in active_channels:
        conn.execute(
            "UPDATE releases SET published = 0, updated_at = datetime('now') "
            "WHERE channel = ? AND published = 1 AND id != ?",
            (row["channel"], row["keep_id"]),
        )
        logger.warning(
            "Unpublished duplicate active releases for channel %s, kept id %s",
            row["channel"],
            row["keep_id"],
        )


def init_db() -> None:
    conn = get_connection()
    try:
        _init_db_impl(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db_impl(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_key TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            auth_version INTEGER NOT NULL DEFAULT 0,
            login_device_code TEXT NOT NULL DEFAULT '',
            login_instance_id TEXT NOT NULL DEFAULT '',
            login_started_at TEXT,
            runtime_blocked_until_epoch INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            ban_reason TEXT NOT NULL DEFAULT '',
            log_upload_enabled INTEGER NOT NULL DEFAULT -1,
            log_upload_interval_seconds INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            plan TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            merchant_order_no TEXT NOT NULL DEFAULT '',
            yungouos_trade_no TEXT NOT NULL DEFAULT '',
            payment_method TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS payment_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            amount REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'received',
            order_id INTEGER REFERENCES orders(id),
            merchant_order_no TEXT NOT NULL DEFAULT '',
            provider_trade_no TEXT NOT NULL DEFAULT '',
            payment_method TEXT NOT NULL DEFAULT '',
            raw_payload TEXT NOT NULL DEFAULT '{}',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            processed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS license_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER REFERENCES orders(id),
            key_text TEXT NOT NULL,
            license_id TEXT UNIQUE NOT NULL,
            plan TEXT NOT NULL,
            features TEXT NOT NULL DEFAULT '["aim"]',
            hwid_hash TEXT,
            status TEXT NOT NULL DEFAULT 'unused',
            issued_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            bound_at TEXT
        );

        CREATE TABLE IF NOT EXISTS activation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL,
            hwid TEXT NOT NULL,
            client_version TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS log_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            session_id TEXT NOT NULL,
            machine_info TEXT NOT NULL DEFAULT '{}',
            device_code TEXT NOT NULL DEFAULT '',
            client_version TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            upload_count INTEGER NOT NULL DEFAULT 0,
            latest_upload_at TEXT,
            latest_bundle_reason TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            ended_at TEXT
        );

        CREATE TABLE IF NOT EXISTS log_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER REFERENCES log_sessions(id),
            file_type TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0,
            storage_path TEXT NOT NULL,
            sha256 TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_license_keys_status ON license_keys(status);
        CREATE INDEX IF NOT EXISTS idx_license_keys_license_id ON license_keys(license_id);
        CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
        CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
        CREATE INDEX IF NOT EXISTS idx_payment_events_order ON payment_events(order_id);
        CREATE INDEX IF NOT EXISTS idx_log_sessions_user_id ON log_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_log_files_session_id ON log_files(session_id);

        -- Time-based billing tables
        CREATE TABLE IF NOT EXISTS time_balance (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            balance_seconds INTEGER NOT NULL DEFAULT 0,
            total_consumed_seconds INTEGER NOT NULL DEFAULT 0,
            total_recharged_seconds INTEGER NOT NULL DEFAULT 0,
            last_heartbeat_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS time_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            login_auth_version INTEGER NOT NULL DEFAULT -1,
            login_instance_id TEXT NOT NULL DEFAULT '',
            runtime_instance_id TEXT NOT NULL DEFAULT '',
            machine_code TEXT NOT NULL DEFAULT '',
            client_version TEXT NOT NULL DEFAULT '',
            device_profile TEXT NOT NULL DEFAULT '{}',
            integrity_manifest_hash TEXT NOT NULL DEFAULT '',
            integrity_status TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_heartbeat_at TEXT,
            last_heartbeat_sequence INTEGER NOT NULL DEFAULT 0,
            last_heartbeat_id TEXT NOT NULL DEFAULT '',
            last_heartbeat_response TEXT NOT NULL DEFAULT '',
            lease_expires_at TEXT,
            lease_token_hash TEXT NOT NULL DEFAULT '',
            last_request_lease_hash TEXT NOT NULL DEFAULT '',
            ended_at TEXT,
            ended_reason TEXT NOT NULL DEFAULT '',
            revoked_at TEXT,
            seconds_consumed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS time_recharges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            order_id INTEGER REFERENCES orders(id),
            hours REAL NOT NULL,
            seconds INTEGER NOT NULL,
            amount REAL NOT NULL,
            source_type TEXT NOT NULL DEFAULT '',
            source_ref TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS duration_products (
            product_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL CHECK(duration_seconds > 0),
            enabled INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS growth_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            redemption_enabled INTEGER NOT NULL DEFAULT 1,
            referral_enabled INTEGER NOT NULL DEFAULT 1,
            referral_reward_seconds INTEGER NOT NULL DEFAULT 3600,
            code_expiry_days INTEGER NOT NULL DEFAULT 365,
            download_url TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS code_issuance_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_key TEXT UNIQUE NOT NULL,
            channel TEXT NOT NULL,
            issuer_type TEXT NOT NULL,
            issuer_id INTEGER NOT NULL DEFAULT 0,
            product_key TEXT NOT NULL REFERENCES duration_products(product_key),
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS redemption_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL REFERENCES code_issuance_batches(id),
            ordinal INTEGER NOT NULL,
            code_digest TEXT UNIQUE NOT NULL,
            code_suffix TEXT NOT NULL,
            key_version INTEGER NOT NULL,
            derivation_ref TEXT UNIQUE NOT NULL,
            product_key TEXT NOT NULL REFERENCES duration_products(product_key),
            duration_seconds INTEGER NOT NULL CHECK(duration_seconds > 0),
            status TEXT NOT NULL DEFAULT 'issued' CHECK(status IN ('issued', 'redeemed', 'revoked', 'expired')),
            redeemed_by_user_id INTEGER REFERENCES users(id),
            redeemed_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(batch_id, ordinal),
            CHECK(
                (status = 'redeemed' AND redeemed_by_user_id IS NOT NULL AND redeemed_at IS NOT NULL)
                OR
                (status != 'redeemed' AND redeemed_by_user_id IS NULL AND redeemed_at IS NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS invite_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
            code TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invite_code_id INTEGER NOT NULL REFERENCES invite_codes(id),
            inviter_user_id INTEGER NOT NULL REFERENCES users(id),
            invitee_user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
            registration_event_id TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered', 'rewarded')),
            reward_seconds INTEGER NOT NULL CHECK(reward_seconds > 0),
            reward_recharge_id INTEGER UNIQUE REFERENCES time_recharges(id),
            device_fingerprint TEXT NOT NULL DEFAULT '',
            ip_fingerprint TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            rewarded_at TEXT,
            CHECK(inviter_user_id != invitee_user_id)
        );

        CREATE TABLE IF NOT EXISTS external_code_issuances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            product_key TEXT NOT NULL REFERENCES duration_products(product_key),
            issuance_batch_id INTEGER NOT NULL REFERENCES code_issuance_batches(id),
            redemption_code_id INTEGER NOT NULL REFERENCES redemption_codes(id),
            trace_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS integration_nonces (
            service_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(service_id, nonce)
        );

        CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            device_code TEXT NOT NULL,
            device_profile TEXT NOT NULL DEFAULT '{}',
            client_version TEXT NOT NULL DEFAULT '',
            first_ip TEXT NOT NULL DEFAULT '',
            last_ip TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at TEXT,
            last_session_at TEXT,
            heartbeat_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE(user_id, device_code)
        );

        CREATE TABLE IF NOT EXISTS purchase_sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            order_id INTEGER REFERENCES orders(id),
            status TEXT NOT NULL DEFAULT 'open',
            ip_address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_time_sessions_user ON time_sessions(user_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_time_recharges_user ON time_recharges(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices(user_id, last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_user_devices_code ON user_devices(device_code);
        CREATE INDEX IF NOT EXISTS idx_purchase_sessions_user ON purchase_sessions(user_id, created_at);

        CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'reset_password',
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_email_codes_email_purpose ON email_codes(email, purpose, created_at);

        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            level TEXT NOT NULL DEFAULT 'info',
            enabled INTEGER NOT NULL DEFAULT 1,
            starts_at TEXT NOT NULL DEFAULT '',
            ends_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS help_faqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL DEFAULT '',
            sort_order INTEGER NOT NULL DEFAULT 100,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'stable',
            notes TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL DEFAULT '',
            installer_url TEXT NOT NULL DEFAULT '',
            installer_sha256 TEXT NOT NULL DEFAULT '',
            min_supported_version TEXT NOT NULL DEFAULT '',
            manifest_published_at TEXT NOT NULL DEFAULT '',
            mandatory INTEGER NOT NULL DEFAULT 0,
            published INTEGER NOT NULL DEFAULT 1,
            target_size INTEGER NOT NULL DEFAULT 0,
            deltas_json TEXT NOT NULL DEFAULT '[]',
            algorithm TEXT NOT NULL DEFAULT '',
            key_id TEXT NOT NULL DEFAULT '',
            payload_b64 TEXT NOT NULL DEFAULT '',
            signature_b64 TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            ip TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_announcements_enabled ON announcements(enabled, starts_at, ends_at);
        CREATE INDEX IF NOT EXISTS idx_help_faqs_enabled ON help_faqs(enabled, sort_order, id);
        CREATE INDEX IF NOT EXISTS idx_releases_channel ON releases(channel, published, created_at);
        CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);

        CREATE TABLE IF NOT EXISTS log_upload_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL DEFAULT 3600,
            max_bundle_mb INTEGER NOT NULL DEFAULT 50,
            retention_days INTEGER NOT NULL DEFAULT 30,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS runtime_security_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            enforce_integrity INTEGER NOT NULL DEFAULT 0,
            lease_ttl_seconds INTEGER NOT NULL DEFAULT 15,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS client_integrity_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_version TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            file_hashes_json TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(client_version, manifest_hash)
        );

        CREATE TABLE IF NOT EXISTS ip_locations (
            ip TEXT PRIMARY KEY,
            country TEXT NOT NULL DEFAULT '',
            region TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            isp TEXT NOT NULL DEFAULT '',
            latitude REAL,
            longitude REAL,
            source TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- Application-private CUDA/cuDNN/TensorRT delivery.  These tables are
        -- deliberately independent from billing and payment state.
        CREATE TABLE IF NOT EXISTS runtime_components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id TEXT NOT NULL,
            version TEXT NOT NULL,
            object_key TEXT NOT NULL,
            archive_sha256 TEXT NOT NULL,
            archive_size INTEGER NOT NULL,
            metadata_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(component_id, version)
        );

        CREATE TABLE IF NOT EXISTS runtime_catalog_releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            catalog_version TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'pilot',
            algorithm TEXT NOT NULL DEFAULT 'Ed25519',
            key_id TEXT NOT NULL,
            payload_b64 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(catalog_version, channel)
        );

        CREATE TABLE IF NOT EXISTS runtime_rollout_allowlist (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            channel TEXT NOT NULL DEFAULT 'pilot',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS runtime_install_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id),
            attempt_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT '',
            error_code TEXT NOT NULL DEFAULT '',
            failure_stage TEXT NOT NULL DEFAULT '',
            http_status INTEGER NOT NULL DEFAULT 0,
            app_version TEXT NOT NULL DEFAULT '',
            os_name TEXT NOT NULL DEFAULT '',
            architecture TEXT NOT NULL DEFAULT '',
            cpu_model TEXT NOT NULL DEFAULT '',
            cpu_cores_physical INTEGER NOT NULL DEFAULT 0,
            cpu_cores_logical INTEGER NOT NULL DEFAULT 0,
            gpu_model TEXT NOT NULL DEFAULT '',
            driver_version TEXT NOT NULL DEFAULT '',
            compute_capability TEXT NOT NULL DEFAULT '',
            component_id TEXT NOT NULL DEFAULT '',
            component_version TEXT NOT NULL DEFAULT '',
            duration_ms INTEGER NOT NULL DEFAULT 0,
            bytes_count INTEGER NOT NULL DEFAULT 0,
            final_provider TEXT NOT NULL DEFAULT '',
            anonymized INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_runtime_components_enabled
            ON runtime_components(component_id, version, enabled);
        CREATE INDEX IF NOT EXISTS idx_runtime_catalog_channel
            ON runtime_catalog_releases(channel, enabled, id);
        CREATE INDEX IF NOT EXISTS idx_runtime_events_user_created
            ON runtime_install_events(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_runtime_events_aggregate_created
            ON runtime_install_events(anonymized, created_at);
    """)
    # Column upgrades use check-then-ALTER operations. Take the cross-process
    # SQLite write lock before those checks so concurrent workers cannot attempt
    # the same ALTER or claim the one-time login migration twice.
    conn.execute("BEGIN IMMEDIATE")
    _ensure_column(conn, "users", "status", "TEXT NOT NULL DEFAULT 'active'")
    _ensure_column(conn, "users", "ban_reason", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "auth_version", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "login_device_code", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "login_instance_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "login_started_at", "TEXT")
    _ensure_column(conn, "users", "runtime_blocked_until_epoch", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "updated_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "deleted_at", "TEXT")
    _ensure_column(conn, "users", "log_upload_enabled", "INTEGER NOT NULL DEFAULT -1")
    _ensure_column(conn, "users", "log_upload_interval_seconds", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "orders", "status", "TEXT NOT NULL DEFAULT 'pending'")
    _ensure_column(conn, "orders", "merchant_order_no", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "orders", "yungouos_trade_no", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "orders", "payment_method", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "orders", "ip_address", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "payment_events", "event_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "payment_events", "status", "TEXT NOT NULL DEFAULT 'received'")
    _ensure_column(conn, "payment_events", "merchant_order_no", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "payment_events", "provider_trade_no", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "payment_events", "payment_method", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "payment_events", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "payment_events", "processed_at", "TEXT")
    _ensure_column(conn, "log_sessions", "device_code", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "log_sessions", "client_version", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "log_sessions", "ip_address", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "log_sessions", "upload_count", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "log_sessions", "latest_upload_at", "TEXT")
    _ensure_column(conn, "log_sessions", "latest_bundle_reason", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "log_files", "sha256", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "log_files", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "time_sessions", "machine_code", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "login_auth_version", "INTEGER NOT NULL DEFAULT -1")
    _ensure_column(conn, "time_sessions", "login_instance_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "runtime_instance_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "client_version", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "device_profile", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "time_sessions", "integrity_manifest_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "integrity_status", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "last_heartbeat_at", "TEXT")
    _ensure_column(conn, "time_sessions", "last_heartbeat_sequence", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "time_sessions", "last_heartbeat_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "last_heartbeat_response", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "lease_expires_at", "TEXT")
    _ensure_column(conn, "time_sessions", "lease_token_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "last_request_lease_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "ended_reason", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_sessions", "revoked_at", "TEXT")
    _ensure_column(conn, "time_recharges", "source_type", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "time_recharges", "source_ref", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "min_supported_version", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "manifest_published_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "target_size", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "releases", "deltas_json", "TEXT NOT NULL DEFAULT '[]'")
    _ensure_column(conn, "releases", "algorithm", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "key_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "payload_b64", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "releases", "signature_b64", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "failure_stage", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "http_status", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "runtime_install_events", "os_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "architecture", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "cpu_model", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "cpu_cores_physical", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "runtime_install_events", "cpu_cores_logical", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "runtime_install_events", "compute_capability", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "runtime_install_events", "final_provider", "TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (migration_key) VALUES (?)",
        (RUNTIME_EVENT_SCHEMA_MIGRATION,),
    )
    single_login_migrated = conn.execute(
        "SELECT 1 FROM schema_migrations WHERE migration_key = ?",
        (SINGLE_LOGIN_MIGRATION,),
    ).fetchone()
    if not single_login_migrated:
        conn.execute(
            "UPDATE users SET runtime_blocked_until_epoch = MAX(runtime_blocked_until_epoch, "
            "COALESCE((SELECT MAX(CAST(strftime('%s', time_sessions.lease_expires_at) AS INTEGER)) "
            "FROM time_sessions WHERE time_sessions.user_id = users.id "
            "AND time_sessions.status = 'active'), 0))"
        )
        rotated_users = conn.execute(
            "UPDATE users SET auth_version = auth_version + 1, login_device_code = '', "
            "login_instance_id = '', login_started_at = NULL, updated_at = datetime('now')"
        ).rowcount
        revoked_sessions = conn.execute(
            "UPDATE time_sessions SET status = 'ended', ended_at = COALESCE(ended_at, datetime('now')), "
            "ended_reason = 'login_policy_migration', revoked_at = COALESCE(revoked_at, datetime('now')) "
            "WHERE status = 'active'"
        ).rowcount
        conn.execute(
            "UPDATE runtime_security_settings SET lease_ttl_seconds = 15, updated_at = datetime('now') "
            "WHERE id = 1 AND lease_ttl_seconds > 15"
        )
        conn.execute(
            "INSERT INTO schema_migrations (migration_key) VALUES (?)",
            (SINGLE_LOGIN_MIGRATION,),
        )
        if rotated_users or revoked_sessions:
            logger.warning(
                "Activated single-login policy: rotated %d users and revoked %d runtime sessions",
                int(rotated_users or 0),
                int(revoked_sessions or 0),
            )
    _dedupe_user_emails(conn)
    conn.execute(
        "UPDATE users SET deleted_at = COALESCE(NULLIF(updated_at, ''), datetime('now')) "
        "WHERE deleted_at IS NULL AND status = 'disabled' AND username GLOB 'deleted_[0-9]*_[0-9a-f]*'"
    )
    _dedupe_active_sessions(conn)
    _dedupe_order_links(conn)
    _dedupe_active_purchase_sessions(conn)
    _backfill_order_numbers(conn)
    _backfill_payment_event_ids(conn)
    _dedupe_log_sessions(conn)
    _dedupe_releases(conn)
    conn.execute(
        "INSERT OR IGNORE INTO log_upload_settings "
        "(id, enabled, interval_seconds, max_bundle_mb, retention_days) "
        "VALUES (1, 1, 3600, 50, 30)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO runtime_security_settings "
        "(id, enforce_integrity, lease_ttl_seconds) VALUES (1, 0, 15)"
    )
    conn.executemany(
        "INSERT OR IGNORE INTO duration_products "
        "(product_key, display_name, duration_seconds, enabled, sort_order) VALUES (?, ?, ?, 1, ?)",
        (
            ("1h", "1 小时", 3600, 10),
            ("5h", "5 小时", 5 * 3600, 20),
            ("10h", "10 小时", 10 * 3600, 30),
            ("50h", "50 小时", 50 * 3600, 40),
            ("100h", "100 小时", 100 * 3600, 50),
        ),
    )
    conn.execute(
        "INSERT OR IGNORE INTO growth_settings "
        "(id, redemption_enabled, referral_enabled, referral_reward_seconds, code_expiry_days, download_url) "
        "VALUES (1, 1, 1, 3600, 365, ?)",
        ("https://www.visionforge.cloud/download",),
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time ON login_attempts(username, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(email)) WHERE trim(email) != ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_merchant_order_unique ON orders(merchant_order_no) WHERE trim(merchant_order_no) != ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_trade_unique ON orders(yungouos_trade_no) WHERE trim(yungouos_trade_no) != ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_events_event_id_unique ON payment_events(event_id) WHERE trim(event_id) != ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_events_status ON payment_events(status, created_at)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_time_recharges_order_unique ON time_recharges(order_id) WHERE order_id IS NOT NULL")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_time_recharges_source_unique "
        "ON time_recharges(source_type, source_ref) WHERE trim(source_ref) != ''"
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_purchase_sessions_order_unique ON purchase_sessions(order_id) WHERE order_id IS NOT NULL")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_purchase_sessions_active_user_unique "
        "ON purchase_sessions(user_id) WHERE status IN ('open', 'pending')"
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_time_sessions_active_user_unique ON time_sessions(user_id) WHERE status = 'active'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_time_sessions_integrity ON time_sessions(integrity_manifest_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_client_integrity_allowlist_enabled ON client_integrity_allowlist(client_version, manifest_hash, enabled)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_releases_channel_version_unique ON releases(channel, version)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_releases_one_published_channel "
        "ON releases(channel) WHERE published = 1"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_log_sessions_latest_upload ON log_sessions(latest_upload_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_log_sessions_device ON log_sessions(device_code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_log_files_uploaded_at ON log_files(uploaded_at)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_log_sessions_owner_session_unique "
        "ON log_sessions(COALESCE(user_id, 0), session_id)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_locations_updated ON ip_locations(updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_redemption_codes_status ON redemption_codes(status, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_referrals_inviter ON referrals(inviter_user_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_integration_nonces_created ON integration_nonces(created_at)")
    _drop_empty_legacy_tables(conn)
