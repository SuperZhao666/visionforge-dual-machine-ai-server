from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Iterable

from app.config import config
from app.services.auth_session_service import revoke_user_runtime_sessions_locked


MAX_AUDIT_DETAIL_JSON_LENGTH = 100_000
MAX_ADMIN_REASON_LENGTH = 500


def _admin_reason(value: str) -> str:
    return str(value or "")[:MAX_ADMIN_REASON_LENGTH]


def _audit_detail_json(detail: dict[str, Any] | None) -> str:
    try:
        serialized = json.dumps(detail or {}, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError):
        safe_detail = {
            str(key): repr(value)[:1000]
            for key, value in (detail or {}).items()
        }
        serialized = json.dumps(safe_detail, ensure_ascii=False, separators=(",", ":"))
    if len(serialized) <= MAX_AUDIT_DETAIL_JSON_LENGTH:
        return serialized
    summary = {
        "truncated": True,
        "original_length": len(serialized),
        "key_count": len(detail or {}),
        "keys": [str(key)[:120] for key in list((detail or {}).keys())[:200]],
    }
    summarized = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    return summarized[:MAX_AUDIT_DETAIL_JSON_LENGTH]


def write_admin_audit(
    conn,
    *,
    admin_user_id: int,
    ip_address: str,
    action: str,
    target_type: str = "",
    target_id: Any = "",
    reason: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        "INSERT INTO admin_audit (admin_user_id, action, target_type, target_id, reason, detail_json, ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            int(admin_user_id),
            str(action)[:120],
            str(target_type)[:80],
            str(target_id or "")[:120],
            _admin_reason(reason),
            _audit_detail_json(detail),
            str(ip_address or "")[:96],
        ),
    )


def revoke_user_sessions_locked(conn, user_id: int, reason: str) -> None:
    revoke_user_runtime_sessions_locked(conn, user_id, reason or "account_disabled")


def soft_delete_user_locked(conn, user_id: int, reason: str) -> tuple[dict[str, Any], list[str]]:
    user = conn.execute(
        "SELECT id, username, email, is_admin, status, deleted_at FROM users WHERE id = ?",
        (int(user_id),),
    ).fetchone()
    if not user or user["deleted_at"] is not None:
        raise LookupError("user not found")
    if bool(user["is_admin"]):
        raise PermissionError("admin accounts cannot be deleted")

    paths = [
        str(row["storage_path"] or "")
        for row in conn.execute(
            "SELECT lf.storage_path FROM log_files lf "
            "JOIN log_sessions ls ON ls.id = lf.session_id WHERE ls.user_id = ?",
            (int(user_id),),
        ).fetchall()
    ]
    conn.execute(
        "DELETE FROM log_files WHERE session_id IN (SELECT id FROM log_sessions WHERE user_id = ?)",
        (int(user_id),),
    )
    conn.execute("DELETE FROM log_sessions WHERE user_id = ?", (int(user_id),))
    conn.execute("DELETE FROM user_devices WHERE user_id = ?", (int(user_id),))
    revoke_user_sessions_locked(conn, int(user_id), "account_deleted")
    conn.execute(
        "UPDATE time_sessions SET machine_code = '', device_profile = '{}', ip_address = '' WHERE user_id = ?",
        (int(user_id),),
    )
    conn.execute("UPDATE orders SET ip_address = '' WHERE user_id = ?", (int(user_id),))
    conn.execute("UPDATE purchase_sessions SET ip_address = '' WHERE user_id = ?", (int(user_id),))
    tombstone = f"deleted_{int(user_id)}_{secrets.token_hex(4)}"
    safe_reason = _admin_reason(reason or "admin delete")
    conn.execute(
        "UPDATE users SET username = ?, email = '', status = 'disabled', ban_reason = ?, "
        "auth_version = auth_version + 1, log_upload_enabled = 0, "
        "deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ?",
        (tombstone, safe_reason, int(user_id)),
    )
    return dict(user), paths


def detach_log_session_locked(conn, session_db_id: int) -> tuple[dict[str, Any], list[str]]:
    session = conn.execute("SELECT * FROM log_sessions WHERE id = ?", (int(session_db_id),)).fetchone()
    if not session:
        raise LookupError("log session not found")
    paths = [
        str(row["storage_path"] or "")
        for row in conn.execute(
            "SELECT storage_path FROM log_files WHERE session_id = ?",
            (int(session_db_id),),
        ).fetchall()
    ]
    conn.execute("DELETE FROM log_files WHERE session_id = ?", (int(session_db_id),))
    conn.execute("DELETE FROM log_sessions WHERE id = ?", (int(session_db_id),))
    return dict(session), paths


def delete_storage_paths(paths: Iterable[str]) -> None:
    root = Path(config.LOG_STORAGE_PATH).resolve()
    for raw_path in paths:
        if not raw_path:
            continue
        path = Path(raw_path)
        try:
            resolved = path.resolve()
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                continue
            resolved.unlink(missing_ok=True)
        except (OSError, ValueError):
            continue
