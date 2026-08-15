from __future__ import annotations

import re
import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from app.database import get_connection
from app.security import ACCOUNT_PASSWORD_MAX_LENGTH, hash_password, require_admin
from app.services.admin_service import (
    delete_storage_paths,
    detach_log_session_locked,
    revoke_user_sessions_locked,
    soft_delete_user_locked,
    write_admin_audit,
)
from app.services.email_service import normalize_email
from app.services.release_service import (
    ReleaseConflictError,
    ReleaseNotFoundError,
    ReleaseService,
    ReleaseValidationError,
)


router = APIRouter(prefix="/api/admin", dependencies=[Depends(require_admin)])
release_service = ReleaseService()
USER_STATUSES = {"active", "disabled", "banned"}
ANNOUNCEMENT_LEVELS = {"info", "success", "warning", "error"}
MAX_BALANCE_SECONDS = 10 * 365 * 24 * 3600
ADMIN_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PositivePathId = Annotated[int, Path(ge=1)]


class AdminRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserCreate(AdminRequestModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=ACCOUNT_PASSWORD_MAX_LENGTH)
    email: str = Field(default="", max_length=254)
    balance_seconds: int = Field(default=0, ge=0, le=MAX_BALANCE_SECONDS)


class UserUpdate(AdminRequestModel):
    username: str | None = Field(default=None, min_length=3, max_length=64)
    email: str | None = Field(default=None, max_length=254)
    balance_seconds: int | None = Field(default=None, ge=0, le=MAX_BALANCE_SECONDS)
    status: str | None = None


class UserPasswordReset(AdminRequestModel):
    new_password: str = Field(min_length=8, max_length=ACCOUNT_PASSWORD_MAX_LENGTH)
    reason: str = Field(default="admin password reset", max_length=500)


class TimeAdjustment(AdminRequestModel):
    delta_seconds: int = Field(ge=-MAX_BALANCE_SECONDS, le=MAX_BALANCE_SECONDS)
    reason: str = Field(min_length=2, max_length=500)


class ActionReason(AdminRequestModel):
    reason: str = Field(default="admin action", max_length=500)


class AnnouncementCreate(AdminRequestModel):
    title: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=20000)
    level: str = Field(default="info", max_length=20)
    starts_at: str = Field(default="", max_length=40)
    ends_at: str = Field(default="", max_length=40)


class AnnouncementUpdate(AdminRequestModel):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    body: str | None = Field(default=None, min_length=1, max_length=20000)
    level: str | None = Field(default=None, max_length=20)
    starts_at: str | None = Field(default=None, max_length=40)
    ends_at: str | None = Field(default=None, max_length=40)
    enabled: bool | None = None


class ReleaseCreate(AdminRequestModel):
    version: str = Field(min_length=1, max_length=80)
    channel: str = Field(default="stable", max_length=32)
    url: str = Field(default="", max_length=2000)
    sha256: str = Field(default="", max_length=64)
    installer_url: str = Field(default="", max_length=2000)
    installer_sha256: str = Field(default="", max_length=64)
    min_supported_version: str = Field(default="", max_length=80)
    notes: str = Field(default="", max_length=20000)
    mandatory: bool = False


class SignedReleaseV2(AdminRequestModel):
    channel: str = Field(default="stable", min_length=1, max_length=32)
    algorithm: str = Field(default="Ed25519", min_length=1, max_length=32)
    key_id: str = Field(min_length=1, max_length=128)
    payload_b64: str = Field(min_length=1, max_length=3_000_000)
    signature_b64: str = Field(min_length=1, max_length=1024)
    legacy_bridge_url: str = Field(default="", max_length=2000)
    legacy_bridge_sha256: str = Field(default="", max_length=64)


class RollbackRequest(AdminRequestModel):
    channel: str = Field(default="stable", max_length=32)


def _admin_id(payload: dict[str, Any]) -> int:
    return int(payload.get("sub") or 0)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _limit(value: int, maximum: int = 500) -> int:
    return max(1, min(int(value or 50), maximum))


def _valid_admin_username(value: str) -> bool:
    text = str(value or "").strip()
    return bool(3 <= len(text) <= 64 and ADMIN_USERNAME_RE.fullmatch(text))


def _raise_release_error(exc: Exception) -> None:
    if isinstance(exc, ReleaseNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, ReleaseConflictError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail=str(exc)) from exc


def _audit(conn, request: Request, payload: dict[str, Any], action: str, target_type: str, target_id: Any, *, reason: str = "", detail: dict[str, Any] | None = None) -> None:
    write_admin_audit(
        conn,
        admin_user_id=_admin_id(payload),
        ip_address=_client_ip(request),
        action=action,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        detail=detail,
    )


def _user_row(conn, user_id: int):
    return conn.execute(
        "SELECT u.id, u.username, u.email, u.is_admin, u.status, u.ban_reason, u.auth_version, u.deleted_at, "
        "u.created_at, u.updated_at, COALESCE(tb.balance_seconds, 0) AS balance_seconds, "
        "COALESCE(tb.total_consumed_seconds, 0) AS total_consumed_seconds, "
        "COALESCE(tb.total_recharged_seconds, 0) AS total_recharged_seconds "
        "FROM users u LEFT JOIN time_balance tb ON tb.user_id = u.id WHERE u.id = ?",
        (int(user_id),),
    ).fetchone()


@router.get("/users")
async def list_users(limit: int = 50):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT u.id, u.username, u.email, u.is_admin, u.status, u.ban_reason, u.created_at, "
            "COALESCE(tb.balance_seconds, 0) AS balance_seconds "
            "FROM users u LEFT JOIN time_balance tb ON tb.user_id = u.id "
            "WHERE u.deleted_at IS NULL "
            "ORDER BY u.created_at DESC, u.id DESC LIMIT ?",
            (_limit(limit),),
        ).fetchall()
        return {"ok": True, "users": [dict(row) for row in rows]}
    finally:
        conn.close()


@router.get("/users/{user_id}")
async def get_user(user_id: PositivePathId):
    conn = get_connection()
    try:
        row = _user_row(conn, user_id)
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        return {"ok": True, "user": dict(row)}
    finally:
        conn.close()


@router.post("/users")
async def create_user(request: Request, body: UserCreate, admin: dict = Depends(require_admin)):
    username = body.username.strip()
    if not _valid_admin_username(username):
        raise HTTPException(
            status_code=422,
            detail="username must be 3-64 characters using letters, numbers, underscore, or hyphen",
        )
    email = normalize_email(body.email)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if email and conn.execute("SELECT 1 FROM users WHERE lower(email) = lower(?)", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="email already bound")
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hash_password(body.password)),
        )
        user_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO time_balance (user_id, balance_seconds, total_recharged_seconds) VALUES (?, ?, ?)",
            (user_id, body.balance_seconds, body.balance_seconds),
        )
        if body.balance_seconds:
            conn.execute(
                "INSERT INTO time_recharges (user_id, hours, seconds, amount) VALUES (?, ?, ?, 0)",
                (user_id, body.balance_seconds / 3600.0, body.balance_seconds),
            )
        _audit(conn, request, admin, "user.create", "user", user_id, detail={"username": username, "balance_seconds": body.balance_seconds})
        conn.commit()
        return {"ok": True, "user": dict(_user_row(conn, user_id))}
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="username or email already exists") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.patch("/users/{user_id}")
async def update_user(user_id: PositivePathId, request: Request, body: UserUpdate, admin: dict = Depends(require_admin)):
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="no fields to update")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = _user_row(conn, user_id)
        if not current or current["deleted_at"] is not None:
            raise HTTPException(status_code=404, detail="user not found")
        username = body.username.strip() if body.username is not None else str(current["username"])
        if not _valid_admin_username(username):
            raise HTTPException(
                status_code=422,
                detail="username must be 3-64 characters using letters, numbers, underscore, or hyphen",
            )
        email = normalize_email(body.email) if body.email is not None else str(current["email"] or "")
        status = str(body.status) if body.status is not None else str(current["status"])
        if status not in USER_STATUSES:
            raise HTTPException(status_code=422, detail="invalid user status")
        if bool(current["is_admin"]) and user_id == _admin_id(admin) and status != "active":
            raise HTTPException(status_code=409, detail="cannot disable the current administrator")
        if email and conn.execute(
            "SELECT 1 FROM users WHERE lower(email) = lower(?) AND id != ?",
            (email, user_id),
        ).fetchone():
            raise HTTPException(status_code=409, detail="email already bound")
        status_changed = status != str(current["status"])
        conn.execute(
            "UPDATE users SET username = ?, email = ?, status = ?, "
            "ban_reason = CASE WHEN ? = 'banned' THEN ban_reason ELSE '' END, "
            "auth_version = auth_version + ?, updated_at = datetime('now') WHERE id = ?",
            (username, email, status, status, 1 if status_changed else 0, user_id),
        )
        if body.balance_seconds is not None:
            conn.execute("INSERT OR IGNORE INTO time_balance (user_id) VALUES (?)", (user_id,))
            conn.execute(
                "UPDATE time_balance SET balance_seconds = ?, updated_at = datetime('now') WHERE user_id = ?",
                (body.balance_seconds, user_id),
            )
        if status != "active":
            revoke_user_sessions_locked(conn, user_id, "account_disabled")
        _audit(conn, request, admin, "user.update", "user", user_id, detail=changes)
        conn.commit()
        return {"ok": True, "user": dict(_user_row(conn, user_id))}
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="username or email already exists") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: PositivePathId,
    request: Request,
    body: UserPasswordReset,
    admin: dict = Depends(require_admin),
):
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        user = _user_row(conn, user_id)
        if not user or user["deleted_at"] is not None:
            raise HTTPException(status_code=404, detail="user not found")
        conn.execute(
            "UPDATE users SET password_hash = ?, auth_version = auth_version + 1, updated_at = datetime('now') WHERE id = ?",
            (hash_password(body.new_password), user_id),
        )
        revoke_user_sessions_locked(conn, user_id, "password_reset")
        _audit(conn, request, admin, "user.reset_password", "user", user_id, reason=body.reason)
        conn.commit()
        return {"ok": True, "user": dict(_user_row(conn, user_id))}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.post("/users/{user_id}/adjust-time")
async def adjust_user_time(
    user_id: PositivePathId,
    request: Request,
    body: TimeAdjustment,
    admin: dict = Depends(require_admin),
):
    if body.delta_seconds == 0:
        raise HTTPException(status_code=422, detail="delta_seconds must not be zero")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not conn.execute(
            "SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="user not found")
        conn.execute("INSERT OR IGNORE INTO time_balance (user_id) VALUES (?)", (user_id,))
        current_balance = conn.execute(
            "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        next_balance = int(current_balance["balance_seconds"] if current_balance else 0) + int(body.delta_seconds)
        if not 0 <= next_balance <= MAX_BALANCE_SECONDS:
            raise HTTPException(status_code=422, detail="balance would be out of range")
        conn.execute(
            "UPDATE time_balance SET balance_seconds = balance_seconds + ?, "
            "total_recharged_seconds = total_recharged_seconds + CASE WHEN ? > 0 THEN ? ELSE 0 END, "
            "updated_at = datetime('now') WHERE user_id = ?",
            (body.delta_seconds, body.delta_seconds, body.delta_seconds, user_id),
        )
        conn.execute(
            "INSERT INTO time_recharges (user_id, hours, seconds, amount) VALUES (?, ?, ?, 0)",
            (user_id, body.delta_seconds / 3600.0, body.delta_seconds),
        )
        _audit(conn, request, admin, "user.adjust_time", "user", user_id, reason=body.reason, detail={"delta_seconds": body.delta_seconds})
        conn.commit()
        return {"ok": True, "user": dict(_user_row(conn, user_id))}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _set_user_status(user_id: int, request: Request, admin: dict, status: str, reason: str) -> dict[str, Any]:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        user = _user_row(conn, user_id)
        if not user or user["deleted_at"] is not None:
            raise HTTPException(status_code=404, detail="user not found")
        if bool(user["is_admin"]):
            raise HTTPException(status_code=409, detail="admin status cannot be changed through this endpoint")
        conn.execute(
            "UPDATE users SET status = ?, ban_reason = ?, auth_version = auth_version + 1, "
            "updated_at = datetime('now') WHERE id = ?",
            (status, reason[:500] if status == "banned" else "", user_id),
        )
        if status != "active":
            revoke_user_sessions_locked(conn, user_id, "account_disabled")
        _audit(conn, request, admin, f"user.{status}", "user", user_id, reason=reason)
        conn.commit()
        return {"ok": True, "user": dict(_user_row(conn, user_id))}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.post("/users/{user_id}/ban")
async def ban_user(user_id: PositivePathId, request: Request, body: ActionReason, admin: dict = Depends(require_admin)):
    return _set_user_status(user_id, request, admin, "banned", body.reason)


@router.post("/users/{user_id}/unban")
async def unban_user(user_id: PositivePathId, request: Request, body: ActionReason, admin: dict = Depends(require_admin)):
    return _set_user_status(user_id, request, admin, "active", body.reason)


@router.delete("/users/{user_id}")
async def delete_user(user_id: PositivePathId, request: Request, body: ActionReason, admin: dict = Depends(require_admin)):
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        previous, paths = soft_delete_user_locked(conn, user_id, body.reason)
        _audit(conn, request, admin, "user.soft_delete", "user", user_id, reason=body.reason, detail={"previous_username": previous["username"]})
        conn.commit()
    except LookupError as exc:
        conn.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return {"ok": True, "soft_deleted": True, "user_id": user_id}


@router.get("/announcements")
async def list_announcements(limit: int = 50):
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM announcements ORDER BY created_at DESC, id DESC LIMIT ?", (_limit(limit),)).fetchall()
        return {"ok": True, "announcements": [dict(row) for row in rows]}
    finally:
        conn.close()


@router.post("/announcements")
async def create_announcement(request: Request, body: AnnouncementCreate, admin: dict = Depends(require_admin)):
    level = body.level.strip().lower()
    if level not in ANNOUNCEMENT_LEVELS:
        raise HTTPException(status_code=422, detail="invalid announcement level")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "INSERT INTO announcements (title, body, level, starts_at, ends_at, enabled) VALUES (?, ?, ?, ?, ?, 1)",
            (body.title.strip(), body.body.strip(), level, body.starts_at.strip(), body.ends_at.strip()),
        )
        announcement_id = int(cursor.lastrowid)
        _audit(conn, request, admin, "announcement.create", "announcement", announcement_id, detail={"title": body.title})
        conn.commit()
        row = conn.execute("SELECT * FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
        return {"ok": True, "announcement": dict(row)}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.patch("/announcements/{announcement_id}")
async def update_announcement(
    announcement_id: PositivePathId,
    request: Request,
    body: AnnouncementUpdate,
    admin: dict = Depends(require_admin),
):
    changes = body.model_dump(exclude_none=True)
    if "level" in changes and str(changes["level"]).strip().lower() not in ANNOUNCEMENT_LEVELS:
        raise HTTPException(status_code=422, detail="invalid announcement level")
    allowed = {"title", "body", "level", "starts_at", "ends_at", "enabled"}
    assignments = []
    values: list[Any] = []
    for key, value in changes.items():
        if key not in allowed:
            continue
        assignments.append(f"{key} = ?")
        if key == "enabled":
            values.append(1 if value else 0)
        elif key == "level":
            values.append(str(value).strip().lower())
        else:
            values.append(str(value).strip())
    if not assignments:
        raise HTTPException(status_code=422, detail="no fields to update")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not conn.execute("SELECT 1 FROM announcements WHERE id = ?", (announcement_id,)).fetchone():
            raise HTTPException(status_code=404, detail="announcement not found")
        conn.execute(
            f"UPDATE announcements SET {', '.join(assignments)}, updated_at = datetime('now') WHERE id = ?",
            (*values, announcement_id),
        )
        _audit(conn, request, admin, "announcement.update", "announcement", announcement_id, detail=changes)
        conn.commit()
        row = conn.execute("SELECT * FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
        return {"ok": True, "announcement": dict(row)}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.delete("/announcements/{announcement_id}")
async def delete_announcement(announcement_id: PositivePathId, request: Request, admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        deleted = conn.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,)).rowcount
        if not deleted:
            raise HTTPException(status_code=404, detail="announcement not found")
        _audit(conn, request, admin, "announcement.delete", "announcement", announcement_id)
        conn.commit()
        return {"ok": True, "announcement_id": announcement_id}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.get("/releases")
async def list_releases(channel: str = "stable"):
    try:
        return {"ok": True, "releases": release_service.list_releases(channel)}
    except ReleaseValidationError as exc:
        _raise_release_error(exc)


@router.post("/releases")
async def publish_release(request: Request, body: ReleaseCreate, admin: dict = Depends(require_admin)):
    try:
        release = await run_in_threadpool(
            release_service.save_legacy,
            body.model_dump(),
            published=True,
            audit=lambda conn, release_id: _audit(
                conn,
                request,
                admin,
                "release.publish",
                "release",
                release_id,
                detail={"version": body.version, "channel": body.channel, "signed": False},
            ),
        )
        return {"ok": True, "release": release, "deprecated_unsigned_release": True}
    except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError) as exc:
        _raise_release_error(exc)


@router.post("/releases/v2")
async def publish_signed_release_v2(
    request: Request,
    body: SignedReleaseV2,
    admin: dict = Depends(require_admin),
):
    try:
        release = await run_in_threadpool(
            release_service.publish_signed,
            body.model_dump(),
            channel=body.channel,
            audit=lambda conn, release_id: _audit(
                conn,
                request,
                admin,
                "release.publish_signed_v2",
                "release",
                release_id,
                detail={"channel": body.channel, "key_id": body.key_id},
            ),
        )
        return {"ok": True, "release": release}
    except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError) as exc:
        _raise_release_error(exc)


@router.post("/releases/{version}/rollback")
async def rollback_release(version: str, request: Request, body: RollbackRequest, admin: dict = Depends(require_admin)):
    try:
        release = release_service.rollback(
            version,
            body.channel,
            audit=lambda conn, release_id: _audit(
                conn,
                request,
                admin,
                "release.rollback",
                "release",
                release_id,
                detail={"version": version, "channel": body.channel},
            ),
        )
        return {"ok": True, "version": release["version"], "channel": release["channel"]}
    except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError) as exc:
        _raise_release_error(exc)


@router.get("/logs")
async def list_logs(limit: int = 50, user_id: int | None = None):
    conn = get_connection()
    try:
        where = "WHERE ls.user_id = ?" if user_id is not None else ""
        params: tuple[Any, ...] = (user_id, _limit(limit)) if user_id is not None else (_limit(limit),)
        rows = conn.execute(
            "SELECT ls.id, ls.user_id, u.username, ls.session_id, ls.device_code, ls.client_version, "
            "ls.ip_address, ls.upload_count, ls.latest_upload_at, ls.latest_bundle_reason, ls.started_at, "
            "COUNT(lf.id) AS file_count, COALESCE(SUM(lf.file_size), 0) AS total_bytes "
            "FROM log_sessions ls LEFT JOIN users u ON u.id = ls.user_id "
            "LEFT JOIN log_files lf ON lf.session_id = ls.id "
            f"{where} GROUP BY ls.id ORDER BY COALESCE(ls.latest_upload_at, ls.started_at) DESC LIMIT ?",
            params,
        ).fetchall()
        return {"ok": True, "logs": [dict(row) for row in rows]}
    finally:
        conn.close()


@router.get("/logs/{log_id}")
async def get_log(log_id: PositivePathId):
    conn = get_connection()
    try:
        session = conn.execute(
            "SELECT ls.*, u.username FROM log_sessions ls LEFT JOIN users u ON u.id = ls.user_id WHERE ls.id = ?",
            (log_id,),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="log session not found")
        files = conn.execute(
            "SELECT id, file_type, original_name, file_size, sha256, metadata_json, uploaded_at "
            "FROM log_files WHERE session_id = ? ORDER BY uploaded_at",
            (log_id,),
        ).fetchall()
        return {"ok": True, "log": dict(session), "files": [dict(row) for row in files]}
    finally:
        conn.close()


@router.delete("/logs/{log_id}")
async def delete_log(log_id: PositivePathId, request: Request, body: ActionReason, admin: dict = Depends(require_admin)):
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        session, paths = detach_log_session_locked(conn, log_id)
        _audit(conn, request, admin, "log_session.delete", "log_session", log_id, reason=body.reason, detail={"session_id": session["session_id"]})
        conn.commit()
    except LookupError as exc:
        conn.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return {"ok": True, "log_id": log_id}


@router.get("/audit")
async def list_audit(limit: int = 100):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT aa.*, u.username AS admin_username FROM admin_audit aa "
            "LEFT JOIN users u ON u.id = aa.admin_user_id ORDER BY aa.created_at DESC, aa.id DESC LIMIT ?",
            (_limit(limit),),
        ).fetchall()
        return {"ok": True, "audit": [dict(row) for row in rows]}
    finally:
        conn.close()
