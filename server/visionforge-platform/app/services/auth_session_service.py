from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any


LOGIN_SUPERSEDED = "login_superseded"
LOGIN_DEVICE_MISMATCH = "login_device_mismatch"
MAX_LOGIN_DEVICE_CODE_LENGTH = 128


@dataclass(frozen=True)
class LoginInstance:
    auth_version: int
    login_instance_id: str
    revoked_session_count: int = 0


@dataclass(frozen=True)
class LoginContext:
    user_id: int
    auth_version: int
    device_code: str
    login_instance_id: str


def new_login_instance_id() -> str:
    return secrets.token_urlsafe(24)


def _normalized_device_code(value: str) -> str:
    return str(value or "").strip().upper()


def _is_valid_device_code(value: str) -> bool:
    return len(_normalized_device_code(value)) <= MAX_LOGIN_DEVICE_CODE_LENGTH


def extend_runtime_block_from_active_sessions_locked(conn, user_id: int) -> int:
    """Preserve offline lease validity so a replacement cannot overlap it."""
    row = conn.execute(
        "SELECT COALESCE(MAX(CAST(strftime('%s', lease_expires_at) AS INTEGER)), 0) AS max_exp "
        "FROM time_sessions WHERE user_id = ? AND status = 'active'",
        (int(user_id),),
    ).fetchone()
    max_expiry = int(row["max_exp"] or 0) if row else 0
    if max_expiry > 0:
        conn.execute(
            "UPDATE users SET runtime_blocked_until_epoch = "
            "MAX(runtime_blocked_until_epoch, ?) WHERE id = ?",
            (max_expiry, int(user_id)),
        )
    return max_expiry


def revoke_user_runtime_sessions_locked(conn, user_id: int, reason: str) -> int:
    extend_runtime_block_from_active_sessions_locked(conn, user_id)
    cursor = conn.execute(
        "UPDATE time_sessions SET status = 'ended', "
        "ended_at = COALESCE(ended_at, datetime('now')), ended_reason = ?, "
        "revoked_at = COALESCE(revoked_at, datetime('now')) "
        "WHERE user_id = ? AND status = 'active'",
        (str(reason or LOGIN_SUPERSEDED), int(user_id)),
    )
    return max(0, int(cursor.rowcount or 0))


def establish_login_locked(conn, user_id: int, device_code: str) -> LoginInstance:
    normalized_device_code = _normalized_device_code(device_code)
    if not _is_valid_device_code(normalized_device_code):
        raise ValueError("device_code exceeds maximum length")
    row = conn.execute(
        "SELECT auth_version, status, deleted_at FROM users WHERE id = ?",
        (int(user_id),),
    ).fetchone()
    if not row or row["deleted_at"] is not None or str(row["status"] or "active") != "active":
        raise LookupError("user not found")
    auth_version = int(row["auth_version"] or 0) + 1
    login_instance_id = new_login_instance_id()
    conn.execute(
        "UPDATE users SET auth_version = ?, login_device_code = ?, login_instance_id = ?, "
        "login_started_at = datetime('now'), updated_at = datetime('now') WHERE id = ?",
        (auth_version, normalized_device_code, login_instance_id, int(user_id)),
    )
    revoked = revoke_user_runtime_sessions_locked(conn, user_id, LOGIN_SUPERSEDED)
    return LoginInstance(auth_version, login_instance_id, revoked)


def invalidate_login_locked(conn, user_id: int, reason: str) -> int:
    conn.execute(
        "UPDATE users SET auth_version = auth_version + 1, login_device_code = '', "
        "login_instance_id = '', login_started_at = NULL, updated_at = datetime('now') "
        "WHERE id = ?",
        (int(user_id),),
    )
    return revoke_user_runtime_sessions_locked(conn, user_id, reason)


def validate_login_context_locked(
    conn,
    payload: dict[str, Any],
    *,
    request_device_code: str = "",
    require_device: bool = False,
) -> tuple[LoginContext | None, str]:
    try:
        user_id = int(payload.get("sub") or 0)
        token_auth_version = int(payload.get("av") or 0)
    except (TypeError, ValueError):
        return None, "invalid_token"
    token_device_code = _normalized_device_code(payload.get("did") or "")
    token_login_instance_id = str(payload.get("lid") or "").strip()
    row = conn.execute(
        "SELECT auth_version, status, deleted_at, login_device_code, login_instance_id FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return None, "invalid_token"
    if row["deleted_at"] is not None or str(row["status"] or "active") != "active":
        return None, "account_disabled"

    db_auth_version = int(row["auth_version"] or 0)
    db_device_code = _normalized_device_code(row["login_device_code"] or "")
    db_login_instance_id = str(row["login_instance_id"] or "").strip()
    if not (
        _is_valid_device_code(token_device_code)
        and _is_valid_device_code(db_device_code)
        and _is_valid_device_code(request_device_code)
    ):
        return None, LOGIN_DEVICE_MISMATCH
    if db_auth_version != token_auth_version:
        return None, LOGIN_SUPERSEDED
    if db_login_instance_id and token_login_instance_id != db_login_instance_id:
        return None, LOGIN_SUPERSEDED
    if db_device_code and token_device_code != db_device_code:
        return None, LOGIN_SUPERSEDED

    request_device = _normalized_device_code(request_device_code)
    if require_device and not request_device:
        return None, "missing_device_code"
    if require_device and (
        not token_device_code
        or request_device != token_device_code
        or (db_device_code and request_device != db_device_code)
    ):
        return None, LOGIN_DEVICE_MISMATCH
    return LoginContext(
        user_id=user_id,
        auth_version=token_auth_version,
        device_code=token_device_code,
        login_instance_id=token_login_instance_id,
    ), ""
