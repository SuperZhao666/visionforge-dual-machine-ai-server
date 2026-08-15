from __future__ import annotations
import re as _re
import os
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.config import config
from app.database import get_connection


def get_log_dir() -> Path:
    d = Path(config.LOG_STORAGE_PATH)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sanitize_filename_part(s: str, max_len: int = 64) -> str:
    """Strip path separators and dangerous characters from a filename component."""
    return _re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:max_len]


def _json_obj(value: str | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _machine_field(machine_info: dict[str, Any], key: str) -> str:
    value = machine_info.get(key)
    if value:
        return str(value).strip()
    profile = machine_info.get("device_profile")
    if isinstance(profile, dict):
        value = profile.get(key)
        if value:
            return str(value).strip()
    return ""


def _safe_int(value: Any, default: int = 0, *, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        out = int(value)
    except Exception:
        out = default
    out = max(minimum, out)
    if maximum is not None:
        out = min(maximum, out)
    return out


def log_upload_policy(conn, user_id: int | None = None) -> dict[str, Any]:
    row = conn.execute(
        "SELECT enabled, interval_seconds, max_bundle_mb, retention_days FROM log_upload_settings WHERE id = 1"
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT OR IGNORE INTO log_upload_settings "
            "(id, enabled, interval_seconds, max_bundle_mb, retention_days) VALUES (1, 1, 3600, 50, 30)"
        )
        row = conn.execute(
            "SELECT enabled, interval_seconds, max_bundle_mb, retention_days FROM log_upload_settings WHERE id = 1"
        ).fetchone()
    enabled = bool(row["enabled"])
    interval = _safe_int(row["interval_seconds"], 3600, minimum=300, maximum=86400)
    max_bundle_mb = _safe_int(row["max_bundle_mb"], 50, minimum=5, maximum=512)
    retention_days = _safe_int(row["retention_days"], 30, minimum=1, maximum=365)
    if user_id:
        user_row = conn.execute(
            "SELECT log_upload_enabled, log_upload_interval_seconds FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if user_row:
            override_enabled = int(user_row["log_upload_enabled"] or -1)
            if override_enabled in {0, 1}:
                enabled = bool(override_enabled)
            override_interval = int(user_row["log_upload_interval_seconds"] or 0)
            if override_interval > 0:
                interval = _safe_int(override_interval, interval, minimum=300, maximum=86400)
    return {
        "enabled": enabled,
        "interval_s": interval,
        "interval_seconds": interval,
        "max_bundle_mb": max_bundle_mb,
        "max_bundle_bytes": max_bundle_mb * 1024 * 1024,
        "retention_days": retention_days,
        "bundle_mode": True,
        "upload_on_start": False,
        "upload_on_stop": False,
    }


def update_global_log_upload_policy(
    conn,
    *,
    enabled: bool,
    interval_seconds: int,
    max_bundle_mb: int,
    retention_days: int,
) -> None:
    conn.execute(
        "INSERT INTO log_upload_settings "
        "(id, enabled, interval_seconds, max_bundle_mb, retention_days, updated_at) "
        "VALUES (1, ?, ?, ?, ?, datetime('now')) "
        "ON CONFLICT(id) DO UPDATE SET "
        "enabled = excluded.enabled, interval_seconds = excluded.interval_seconds, "
        "max_bundle_mb = excluded.max_bundle_mb, retention_days = excluded.retention_days, "
        "updated_at = datetime('now')",
        (
            1 if enabled else 0,
            _safe_int(interval_seconds, 3600, minimum=300, maximum=86400),
            _safe_int(max_bundle_mb, 50, minimum=5, maximum=512),
            _safe_int(retention_days, 30, minimum=1, maximum=365),
        ),
    )


def update_user_log_upload_policy(conn, user_id: int, enabled: int, interval_seconds: int) -> None:
    safe_enabled = int(enabled)
    if safe_enabled not in {-1, 0, 1}:
        safe_enabled = -1
    safe_interval = _safe_int(interval_seconds, 0, minimum=0, maximum=86400)
    if 0 < safe_interval < 300:
        safe_interval = 300
    conn.execute(
        "UPDATE users SET log_upload_enabled = ?, log_upload_interval_seconds = ?, updated_at = datetime('now') WHERE id = ?",
        (safe_enabled, safe_interval, user_id),
    )


def store_log_file(
    session_id: str,
    file_type: str,
    original_name: str,
    content: bytes,
    user_id: int | None = None,
    machine_info: str | dict[str, Any] = "{}",
    *,
    ip_address: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict:
    """Store an uploaded log file. Returns metadata dict.

    All user-supplied filename components are sanitized to prevent path traversal.
    """
    log_dir = get_log_dir()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    safe_session = _sanitize_filename_part(session_id) or "session"
    safe_name = _sanitize_filename_part(original_name, max_len=128) or "log.bin"
    safe_type = _sanitize_filename_part(file_type, max_len=32) or "log"
    safe_filename = f"{safe_session}_{timestamp}_{secrets.token_hex(4)}_{safe_name}"
    storage_path = log_dir / safe_filename
    staging_path = log_dir / f".{safe_filename}.uploading"

    log_root = log_dir.resolve()
    if os.path.commonpath((str(log_root), str(storage_path.resolve()))) != str(log_root):
        raise ValueError("Path traversal detected")

    file_size = len(content)
    digest = hashlib.sha256(content).hexdigest()
    machine_obj = _json_obj(machine_info)
    machine_text = json.dumps(machine_obj, ensure_ascii=False, separators=(",", ":"))
    device_code = _machine_field(machine_obj, "device_code")
    client_version = _machine_field(machine_obj, "client_version")
    metadata_obj = dict(metadata or {})
    reason = str(metadata_obj.get("reason") or machine_obj.get("reason") or "")

    try:
        staging_path.write_bytes(content)
    except Exception:
        staging_path.unlink(missing_ok=True)
        raise
    conn = get_connection()
    moved_to_final = False
    try:
        conn.execute("BEGIN IMMEDIATE")
        session = conn.execute(
            "SELECT id FROM log_sessions WHERE session_id = ? "
            "AND ((user_id = ?) OR (user_id IS NULL AND ? IS NULL))",
            (session_id, user_id, user_id),
        ).fetchone()
        if not session:
            cursor = conn.execute(
                "INSERT INTO log_sessions "
                "(user_id, session_id, machine_info, device_code, client_version, ip_address, upload_count, latest_upload_at, latest_bundle_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, NULL, '')",
                (user_id, session_id, machine_text or "{}", device_code, client_version, ip_address),
            )
            session_id_int = int(cursor.lastrowid)
        else:
            session_id_int = int(session["id"])

        duplicate = conn.execute(
            "SELECT id, file_type, original_name, file_size, sha256 FROM log_files "
            "WHERE session_id = ? AND file_type = ? AND sha256 = ? LIMIT 1",
            (session_id_int, safe_type, digest),
        ).fetchone()
        if duplicate:
            conn.commit()
            return {
                "file_id": int(duplicate["id"]),
                "session_db_id": session_id_int,
                "file_type": duplicate["file_type"],
                "original_name": duplicate["original_name"],
                "file_size": int(duplicate["file_size"]),
                "sha256": duplicate["sha256"],
                "duplicate": True,
            }

        conn.execute(
            "UPDATE log_sessions SET "
            "machine_info = CASE WHEN ? != '{}' THEN ? ELSE machine_info END, "
            "device_code = CASE WHEN ? != '' THEN ? ELSE device_code END, "
            "client_version = CASE WHEN ? != '' THEN ? ELSE client_version END, "
            "ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END, "
            "upload_count = upload_count + 1, latest_upload_at = datetime('now'), latest_bundle_reason = ? "
            "WHERE id = ?",
            (
                machine_text,
                machine_text,
                device_code,
                device_code,
                client_version,
                client_version,
                ip_address,
                ip_address,
                reason,
                session_id_int,
            ),
        )
        cursor = conn.execute(
            "INSERT INTO log_files (session_id, file_type, original_name, file_size, storage_path, sha256, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session_id_int,
                safe_type,
                str(original_name),
                file_size,
                str(storage_path),
                digest,
                json.dumps(metadata_obj, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        os.replace(staging_path, storage_path)
        moved_to_final = True
        conn.commit()
        return {
            "file_id": int(cursor.lastrowid),
            "session_db_id": session_id_int,
            "file_type": safe_type,
            "original_name": str(original_name),
            "file_size": file_size,
            "sha256": digest,
            "duplicate": False,
        }
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        if moved_to_final:
            storage_path.unlink(missing_ok=True)
        raise
    finally:
        conn.close()
        staging_path.unlink(missing_ok=True)


def get_sessions(user_id: int | None = None, limit: int = 50) -> list[dict]:
    """Retrieve log sessions, optionally filtered by user."""
    conn = get_connection()
    if user_id:
        rows = conn.execute(
            "SELECT id, user_id, session_id, machine_info, device_code, client_version, ip_address, "
            "upload_count, latest_upload_at, latest_bundle_reason, started_at, ended_at "
            "FROM log_sessions WHERE user_id = ? ORDER BY started_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT ls.id, ls.user_id, ls.session_id, ls.machine_info, ls.device_code, ls.client_version, ls.ip_address, "
            "ls.upload_count, ls.latest_upload_at, ls.latest_bundle_reason, ls.started_at, ls.ended_at, u.username "
            "FROM log_sessions ls LEFT JOIN users u ON u.id = ls.user_id "
            "ORDER BY COALESCE(ls.latest_upload_at, ls.started_at) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session_files(session_db_id: int) -> list[dict]:
    """Get all log files for a session."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, file_type, original_name, file_size, storage_path, sha256, metadata_json, uploaded_at "
        "FROM log_files WHERE session_id = ? ORDER BY uploaded_at",
        (session_db_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session_stats() -> dict:
    """Get aggregate stats for admin dashboard."""
    conn = get_connection()
    total_sessions = conn.execute("SELECT COUNT(*) as c FROM log_sessions").fetchone()["c"]
    total_files = conn.execute("SELECT COUNT(*) as c FROM log_files").fetchone()["c"]
    total_bytes = conn.execute(
        "SELECT COALESCE(SUM(file_size), 0) as s FROM log_files"
    ).fetchone()["s"]
    conn.close()
    return {
        "total_sessions": total_sessions,
        "total_files": total_files,
        "total_bytes": total_bytes,
    }
