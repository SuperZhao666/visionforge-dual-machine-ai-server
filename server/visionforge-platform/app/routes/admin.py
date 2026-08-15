"""Admin dashboard and commercial operations."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.background import BackgroundTask

from app.config import config
from app.database import get_connection
from app.routes.auth import get_user_from_cookie
from app.security import ACCOUNT_PASSWORD_MAX_LENGTH, hash_password, require_form_csrf
from app.services.email_service import normalize_email
from app.services.auth_session_service import extend_runtime_block_from_active_sessions_locked
from app.services.admin_service import (
    delete_storage_paths,
    detach_log_session_locked,
    revoke_user_sessions_locked,
    soft_delete_user_locked,
    write_admin_audit,
)
from app.services.log_service import log_upload_policy, update_global_log_upload_policy, update_user_log_upload_policy
from app.services.payment_service import deliver_order
from app.services.release_service import (
    ReleaseConflictError,
    ReleaseNotFoundError,
    ReleaseService,
    ReleaseValidationError,
)
from app.templating import templates

logger = logging.getLogger("admin")
router = APIRouter(dependencies=[Depends(require_form_csrf)])
release_service = ReleaseService()
ADMIN_USERNAME_MAX_LENGTH = 64
ADMIN_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
OPTIONAL_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
MAX_BALANCE_SECONDS = 10 * 365 * 24 * 3600
ANNOUNCEMENT_LEVELS = {"info", "success", "warning", "error"}


def _admin_guard(request: Request, user: dict | None):
    if not user or not user.get("is_admin"):
        return RedirectResponse(url="/login", status_code=303)
    return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _email_taken(conn, email: str, exclude_user_id: int = 0) -> bool:
    normalized = normalize_email(email)
    if not normalized:
        return False
    return bool(conn.execute(
        "SELECT id FROM users WHERE lower(email) = lower(?) AND id != ? LIMIT 1",
        (normalized, int(exclude_user_id or 0)),
    ).fetchone())


def _valid_admin_username(value: str) -> bool:
    text = str(value or "").strip()
    return bool(3 <= len(text) <= ADMIN_USERNAME_MAX_LENGTH and ADMIN_USERNAME_RE.fullmatch(text))


def _valid_optional_email(value: str) -> bool:
    normalized = normalize_email(value)
    return not normalized or bool(OPTIONAL_EMAIL_RE.fullmatch(normalized))


HELP_FAQ_SORT_ORDER_RANGE = (0, 100000)


def _safe_help_faq_fields(question: str, answer: str) -> tuple[str, str] | None:
    safe_question = str(question or "").strip()
    safe_answer = str(answer or "").strip()
    if not safe_question or len(safe_question) > 500 or len(safe_answer) > 8000:
        return None
    return safe_question, safe_answer


def _safe_help_faq_sort_order(value: Any) -> int | None:
    try:
        parsed = int(value)
    except Exception:
        return None
    if not _in_int_range(parsed, HELP_FAQ_SORT_ORDER_RANGE):
        return None
    return parsed


def _announcement_level(value: str) -> str | None:
    level = str(value or "").strip().lower() or "info"
    return level if level in ANNOUNCEMENT_LEVELS else None


def _audit(
    conn,
    request: Request,
    admin: dict,
    action: str,
    target_type: str = "",
    target_id: Any = "",
    reason: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    write_admin_audit(
        conn,
        admin_user_id=int(admin.get("id") or 0),
        ip_address=_client_ip(request),
        action=action,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        detail=detail,
    )


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


def _safe_limit(value: int, default: int = 100, maximum: int = 500) -> int:
    try:
        return max(1, min(int(value), maximum))
    except Exception:
        return default


def _safe_lease_ttl(value: int) -> int:
    return 15


def _safe_form_int(value: Any, default: int = 0, *, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(parsed, maximum)
    return parsed


LOG_UPLOAD_INTERVAL_RANGE = (300, 86400)
LOG_UPLOAD_MAX_BUNDLE_MB_RANGE = (5, 512)
LOG_UPLOAD_RETENTION_DAYS_RANGE = (1, 365)
MAX_ALLOWLIST_NOTE_LENGTH = 500


def _in_int_range(value: int, bounds: tuple[int, int]) -> bool:
    return bounds[0] <= int(value) <= bounds[1]


def _form_int_list(form: Any, key: str, *, maximum_items: int = 500) -> list[int]:
    try:
        raw_values = form.getlist(key)
    except Exception:
        raw = form.get(key) if hasattr(form, "get") else None
        raw_values = [raw] if raw is not None else []
    values: list[int] = []
    for raw in raw_values:
        try:
            value = int(raw)
        except Exception:
            continue
        if value > 0:
            values.append(value)
        if len(values) >= maximum_items:
            break
    return sorted(set(values))


def _normalize_manifest_hash(value: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        return ""
    return text


def _normalize_client_version(value: str) -> str:
    text = str(value or "").strip()
    if len(text) > 80:
        raise ValueError("client_version is too long")
    return text or "*"


def _production_wildcard_allowlist_error(
    client_version: str,
    *,
    enabled: bool,
) -> str:
    if config.REQUIRE_RUNTIME_INTEGRITY and enabled and client_version == "*":
        return "production integrity allowlists require an exact client_version"
    return ""


def _normalize_file_hashes_json(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "[]"
    parsed = json.loads(text)
    if isinstance(parsed, dict) and isinstance(parsed.get("files"), list):
        parsed = parsed["files"]
    if not isinstance(parsed, list):
        raise ValueError("file_hashes_json must be a list or contain a files list")
    normalized = json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(normalized) > 100000:
        raise ValueError("file_hashes_json is too large")
    return normalized


def _normalize_allowlist_note(value: str) -> str:
    text = str(value or "").strip()
    if len(text) > MAX_ALLOWLIST_NOTE_LENGTH:
        raise ValueError("allowlist note is too long")
    return text


def _cleanup_temp_file(path_text: str) -> None:
    try:
        Path(path_text).unlink(missing_ok=True)
    except Exception:
        logger.warning("Failed to cleanup temp file: %s", path_text, exc_info=True)


def _safe_zip_part(value: Any, fallback: str = "item") -> str:
    text = str(value or "").strip()[:120] or fallback
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in text)
    return safe.strip("._") or fallback


def _resolve_log_storage_file(value: Any) -> Path | None:
    try:
        root = Path(config.LOG_STORAGE_PATH).resolve()
        path = Path(str(value or "")).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    if not path.is_file():
        return None
    return path


def _write_log_zip(rows: list[dict[str, Any]], filename_prefix: str) -> tuple[str, int]:
    tmp = tempfile.NamedTemporaryFile(prefix="visionforge_logs_", suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()
    written = 0
    seen: set[str] = set()
    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for row in rows:
            path = _resolve_log_storage_file(row.get("storage_path"))
            if path is None:
                continue
            session_part = _safe_zip_part(row.get("session_id"), "session")
            original_name = _safe_zip_part(row.get("original_name") or path.name, path.name)
            arcname = f"{session_part}/{original_name}"
            if arcname in seen:
                arcname = f"{session_part}/{int(row.get('id') or written)}_{original_name}"
            seen.add(arcname)
            zf.write(path, arcname)
            written += 1
        if written == 0:
            zf.writestr("README.txt", "没有找到可下载的日志文件，可能已经被删除或迁移。\n")
    return tmp_path, written


def _log_zip_response(rows: list[dict[str, Any]], filename_prefix: str) -> FileResponse:
    tmp_path, _ = _write_log_zip(rows, filename_prefix)
    filename = f"{_safe_zip_part(filename_prefix, 'visionforge_logs')}.zip"
    return FileResponse(
        tmp_path,
        filename=filename,
        media_type="application/zip",
        background=BackgroundTask(_cleanup_temp_file, tmp_path),
    )


def _format_memory_gb(value: Any) -> str:
    try:
        bytes_value = int(value or 0)
    except Exception:
        return ""
    if bytes_value <= 0:
        return ""
    return f"{bytes_value / 1024 / 1024 / 1024:.1f} GB"


def _dependency_summary(profile: dict[str, Any]) -> str:
    deps = profile.get("dependencies") if isinstance(profile.get("dependencies"), dict) else {}
    if not deps:
        return "-"
    parts = []
    for key in ("python", "onnxruntime", "numpy", "opencv_python"):
        value = str(deps.get(key) or "").strip()
        if value:
            label = {"opencv_python": "opencv"}.get(key, key)
            parts.append(f"{label}:{value}")
    return " / ".join(parts[:5]) or "-"


def _device_profile_summary(profile_text: str) -> dict[str, str]:
    try:
        profile = json.loads(profile_text or "{}")
    except Exception:
        profile = {}
    if not isinstance(profile, dict):
        profile = {}
    os_info = profile.get("os") if isinstance(profile.get("os"), dict) else {}
    cpu_info = profile.get("cpu") if isinstance(profile.get("cpu"), dict) else {}
    memory_info = profile.get("memory") if isinstance(profile.get("memory"), dict) else {}
    gpus = profile.get("gpus") if isinstance(profile.get("gpus"), list) else []
    gpu_names = []
    for gpu in gpus[:3]:
        if isinstance(gpu, dict) and gpu.get("name"):
            gpu_names.append(str(gpu.get("name"))[:120])
    os_text = " ".join(
        str(os_info.get(key) or "").strip()
        for key in ("system", "release", "machine")
        if str(os_info.get(key) or "").strip()
    )
    return {
        "os_summary": os_text or "-",
        "cpu_summary": str(cpu_info.get("name") or "-")[:160],
        "memory_summary": _format_memory_gb(memory_info.get("total_bytes")) or "-",
        "gpu_summary": ", ".join(gpu_names) if gpu_names else "-",
        "dependency_summary": _dependency_summary(profile),
    }


def _ip_location_text(country: str, region: str, city: str, isp: str = "") -> str:
    parts = [part for part in [country, region, city] if part]
    text = " ".join(parts)
    if isp:
        text = f"{text} / {isp}" if text else isp
    return text or "未知"


def _lookup_ip_location(ip_text: str) -> dict[str, Any] | None:
    template = str(getattr(config, "IP_GEOLOOKUP_URL_TEMPLATE", "") or "").strip()
    if not template:
        return None
    url = template.format(ip=urllib.parse.quote(ip_text, safe=""))
    timeout = float(getattr(config, "IP_GEOLOOKUP_TIMEOUT_SECONDS", 1.5) or 1.5)
    with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310 - admin-configured endpoint.
        payload = json.loads(response.read(4096).decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        return None
    status = str(payload.get("status") or payload.get("code") or "").lower()
    if status and status not in {"success", "ok", "200"}:
        return None
    return {
        "country": str(payload.get("country") or payload.get("countryName") or "")[:80],
        "region": str(payload.get("regionName") or payload.get("province") or payload.get("region") or "")[:80],
        "city": str(payload.get("city") or "")[:80],
        "isp": str(payload.get("isp") or payload.get("org") or "")[:120],
        "latitude": payload.get("lat") or payload.get("latitude"),
        "longitude": payload.get("lon") or payload.get("longitude"),
        "source": "ip_lookup",
    }


def _ip_location_summary(conn, ip_text: str) -> str:
    ip = str(ip_text or "").strip()[:64]
    if not ip:
        return "-"
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return "内网/本机"
    except Exception:
        return "未知"
    row = conn.execute("SELECT * FROM ip_locations WHERE ip = ?", (ip,)).fetchone()
    if row:
        return _ip_location_text(str(row["country"] or ""), str(row["region"] or ""), str(row["city"] or ""), str(row["isp"] or ""))
    try:
        data = _lookup_ip_location(ip)
    except Exception:
        logger.info("IP lookup failed for %s", ip, exc_info=True)
        data = None
    if not data:
        return "未知"
    conn.execute(
        "INSERT OR REPLACE INTO ip_locations "
        "(ip, country, region, city, isp, latitude, longitude, source, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        (
            ip,
            data.get("country") or "",
            data.get("region") or "",
            data.get("city") or "",
            data.get("isp") or "",
            data.get("latitude"),
            data.get("longitude"),
            data.get("source") or "",
        ),
    )
    conn.commit()
    return _ip_location_text(str(data.get("country") or ""), str(data.get("region") or ""), str(data.get("city") or ""), str(data.get("isp") or ""))


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    total_users = conn.execute("SELECT COUNT(*) as c FROM users WHERE deleted_at IS NULL").fetchone()["c"]
    banned_users = conn.execute(
        "SELECT COUNT(*) as c FROM users WHERE status = 'banned' AND deleted_at IS NULL"
    ).fetchone()["c"]
    total_orders = conn.execute("SELECT COUNT(*) as c FROM orders").fetchone()["c"]
    total_hours = conn.execute("SELECT COALESCE(SUM(hours), 0) as s FROM time_recharges").fetchone()["s"]
    active_sessions = conn.execute("SELECT COUNT(*) as c FROM time_sessions WHERE status = 'active'").fetchone()["c"]
    total_sessions = conn.execute("SELECT COUNT(*) as c FROM time_sessions").fetchone()["c"]
    revenue = conn.execute("SELECT COALESCE(SUM(amount), 0) as s FROM orders WHERE status = 'delivered'").fetchone()["s"]
    announcements = conn.execute("SELECT COUNT(*) as c FROM announcements WHERE enabled = 1").fetchone()["c"]
    published_releases = conn.execute("SELECT COUNT(*) as c FROM releases WHERE published = 1").fetchone()["c"]
    # ── 驾驶舱图表数据（近 30 天，与 created_at 同为 UTC 按天聚合）──
    trend_rows = conn.execute(
        """
        SELECT substr(created_at, 1, 10) AS d,
               COUNT(*) AS cnt,
               COALESCE(SUM(CASE WHEN status = 'delivered' THEN amount END), 0) AS rev
        FROM orders
        WHERE created_at >= date('now', '-29 days')
        GROUP BY d
        """
    ).fetchall()
    user_rows = conn.execute(
        """
        SELECT substr(created_at, 1, 10) AS d, COUNT(*) AS cnt
        FROM users
        WHERE deleted_at IS NULL AND created_at >= date('now', '-29 days')
        GROUP BY d
        """
    ).fetchall()
    hour_rows = conn.execute(
        """
        SELECT substr(started_at, 1, 10) AS d, COALESCE(SUM(seconds_consumed), 0) AS secs
        FROM time_sessions
        WHERE started_at >= date('now', '-29 days')
        GROUP BY d
        """
    ).fetchall()
    status_rows = conn.execute("SELECT status, COUNT(*) AS cnt FROM orders GROUP BY status").fetchall()
    plan_rows = conn.execute(
        """
        SELECT plan, COUNT(*) AS cnt,
               COALESCE(SUM(CASE WHEN status = 'delivered' THEN amount END), 0) AS rev
        FROM orders GROUP BY plan ORDER BY rev DESC, cnt DESC LIMIT 6
        """
    ).fetchall()
    recent_orders = conn.execute(
        """
        SELECT o.id, o.plan, o.amount, o.status, o.created_at, u.username
        FROM orders o LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.id DESC LIMIT 8
        """
    ).fetchall()
    conn.close()
    utc_today = datetime.now(timezone.utc).date()
    day_labels = [(utc_today - timedelta(days=offset)).isoformat() for offset in range(29, -1, -1)]
    trend_map = {r["d"]: r for r in trend_rows}
    user_map = {r["d"]: r["cnt"] for r in user_rows}
    hour_map = {r["d"]: r["secs"] for r in hour_rows}
    charts = {
        "trend": {
            "labels": day_labels,
            "revenue": [round(float(trend_map[d]["rev"]), 2) if d in trend_map else 0 for d in day_labels],
            "orders": [int(trend_map[d]["cnt"]) if d in trend_map else 0 for d in day_labels],
        },
        "users": {"labels": day_labels, "values": [int(user_map.get(d, 0)) for d in day_labels]},
        "hours": {"labels": day_labels, "values": [round(float(hour_map.get(d, 0)) / 3600.0, 1) for d in day_labels]},
        "status": [{"status": r["status"], "value": int(r["cnt"])} for r in status_rows],
        "plans": [
            {"label": r["plan"], "value": round(float(r["rev"]), 2), "count": int(r["cnt"])}
            for r in plan_rows
        ],
    }
    return templates.TemplateResponse(request, "admin/dashboard.html", {
        "user": user, "active_page": "dashboard",
        "total_users": total_users, "banned_users": banned_users,
        "total_orders": total_orders, "total_hours": total_hours,
        "active_sessions": active_sessions, "total_sessions": total_sessions,
        "revenue": revenue, "announcements": announcements, "published_releases": published_releases,
        "charts": charts, "recent_orders": [dict(r) for r in recent_orders],
    })


@router.get("/admin/orders", response_class=HTMLResponse)
async def admin_orders(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    orders = conn.execute("""
        SELECT o.id, o.plan, o.amount, o.status, o.merchant_order_no, o.yungouos_trade_no,
               o.payment_method, o.created_at, u.username, u.email
        FROM orders o LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC LIMIT 100
    """).fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin/orders.html", {
        "user": user, "active_page": "orders", "orders": [dict(o) for o in orders],
    })


@router.post("/admin/orders/confirm")
async def admin_confirm_payment(request: Request, order_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    result = deliver_order(order_id, "admin")
    conn = get_connection()
    try:
        if result:
            _audit(conn, request, user, "order.confirm", "order", order_id, detail={"delivered": True})
        conn.commit()
    finally:
        conn.close()
    return _redirect("/admin/orders")


@router.post("/admin/orders/cancel")
async def admin_cancel_order(request: Request, order_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute("UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'", (order_id,)).rowcount
        if updated:
            conn.execute(
                "UPDATE purchase_sessions SET status = 'cancelled' "
                "WHERE order_id = ? AND status NOT IN ('delivered', 'cancelled')",
                (order_id,),
            )
            _audit(conn, request, user, "order.cancel", "order", order_id, detail={"cancelled": True})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/orders")


@router.post("/admin/orders/refund")
async def admin_refund_order(request: Request, order_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        order = conn.execute("SELECT id, status FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order and order["status"] in {"delivered", "refund_required"}:
            conn.execute("UPDATE orders SET status = 'refunding' WHERE id = ?", (order_id,))
            _audit(conn, request, user, "order.refund.request", "order", order_id)
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/orders")


@router.post("/admin/orders/refund-done")
async def admin_refund_done(request: Request, order_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute("UPDATE orders SET status = 'refunded' WHERE id = ? AND status = 'refunding'", (order_id,)).rowcount
        if updated:
            _audit(conn, request, user, "order.refund.done", "order", order_id, detail={"refunded": True})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/orders")


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    users = conn.execute("""
        SELECT u.id, u.username, u.email, u.is_admin, u.status, u.ban_reason, u.created_at,
               COALESCE(tb.balance_seconds, 0) AS balance_seconds
        FROM users u
        LEFT JOIN time_balance tb ON tb.user_id = u.id
        WHERE u.deleted_at IS NULL
        ORDER BY u.created_at DESC LIMIT 200
    """).fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin/users.html", {
        "user": user, "active_page": "users", "users": [dict(u) for u in users],
    })


@router.get("/admin/usage-records", response_class=HTMLResponse)
async def admin_usage_records(request: Request, limit: int = 200):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    safe_limit = _safe_limit(limit, default=200, maximum=500)
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT ts.id, ts.user_id, u.username, u.email, ts.machine_code, ts.client_version,
                   ts.device_profile, ts.ip_address, ts.started_at, ts.last_heartbeat_at,
                   ts.ended_at, ts.ended_reason, ts.revoked_at, ts.lease_expires_at,
                   ts.integrity_manifest_hash, ts.integrity_status, ts.seconds_consumed, ts.status,
                   CAST((julianday(COALESCE(ts.ended_at, ts.last_heartbeat_at, ts.started_at)) - julianday(ts.started_at)) * 86400 AS INTEGER) AS duration_seconds
            FROM time_sessions ts
            LEFT JOIN users u ON u.id = ts.user_id
            ORDER BY ts.started_at DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
        records = []
        for row in rows:
            item = dict(row)
            item.update(_device_profile_summary(str(item.get("device_profile") or "{}")))
            item["ip_location"] = _ip_location_summary(conn, str(item.get("ip_address") or ""))
            records.append(item)
    finally:
        conn.close()
    return templates.TemplateResponse(request, "admin/usage_records.html", {
        "user": user,
        "active_page": "usage_records",
        "records": records,
        "limit": safe_limit,
    })


@router.post("/admin/users/create")
async def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(""),
    balance_hours: int = Form(0),
    balance_seconds: int = Form(0),
    is_admin: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    clean_username = username.strip()
    if not _valid_admin_username(clean_username):
        return HTMLResponse("username must be 3-64 characters using letters, numbers, underscore, or hyphen", status_code=422)
    if not 8 <= len(str(password or "")) <= ACCOUNT_PASSWORD_MAX_LENGTH:
        return HTMLResponse("password length must be 8 to 128", status_code=422)
    normalized_email = normalize_email(email)
    if not _valid_optional_email(normalized_email):
        return HTMLResponse("email is invalid", status_code=422)
    max_balance_hours = MAX_BALANCE_SECONDS // 3600
    if not 0 <= int(balance_hours) <= max_balance_hours or not 0 <= int(balance_seconds) <= MAX_BALANCE_SECONDS:
        return HTMLResponse("initial balance is out of range", status_code=422)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if _email_taken(conn, normalized_email):
            conn.execute("ROLLBACK")
            return HTMLResponse("邮箱已绑定其他账号", status_code=409)
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (clean_username, normalized_email, hash_password(password), 1 if is_admin else 0),
        )
        uid = cursor.lastrowid
        hours = int(balance_hours)
        seconds = hours * 3600
        if seconds == 0 and balance_seconds:
            seconds = int(balance_seconds)
        conn.execute(
            "INSERT INTO time_balance (user_id, balance_seconds, total_recharged_seconds) VALUES (?, ?, ?)",
            (uid, seconds, seconds),
        )
        if seconds:
            conn.execute(
                "INSERT INTO time_recharges (user_id, hours, seconds, amount) VALUES (?, ?, ?, 0)",
                (uid, seconds / 3600, seconds),
            )
        _audit(conn, request, user, "user.create", "user", uid, detail={"username": clean_username, "balance_hours": seconds // 3600})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/users")


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
async def admin_user_detail(request: Request, user_id: int):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    target = conn.execute(
        "SELECT id, username, email, is_admin, status, ban_reason, log_upload_enabled, "
        "log_upload_interval_seconds, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not target:
        conn.close()
        return _redirect("/admin/users")

    orders = conn.execute(
        "SELECT o.id, o.plan, o.amount, o.status, o.merchant_order_no, o.yungouos_trade_no, "
        "o.payment_method, o.ip_address, o.created_at FROM orders o "
        "WHERE o.user_id = ? ORDER BY o.created_at DESC LIMIT 50",
        (user_id,),
    ).fetchall()
    sessions = conn.execute(
        "SELECT id, machine_code, client_version, device_profile, ip_address, started_at, "
        "last_heartbeat_at, lease_expires_at, ended_at, ended_reason, revoked_at, "
        "integrity_manifest_hash, integrity_status, seconds_consumed, status, "
        "CAST((julianday(COALESCE(ended_at, last_heartbeat_at, started_at)) - julianday(started_at)) * 86400 AS INTEGER) AS duration_seconds "
        "FROM time_sessions WHERE user_id = ? ORDER BY started_at DESC LIMIT 20",
        (user_id,),
    ).fetchall()
    log_sessions = conn.execute(
        "SELECT id, session_id, device_code, client_version, ip_address, upload_count, "
        "latest_upload_at, latest_bundle_reason, started_at "
        "FROM log_sessions WHERE user_id = ? ORDER BY COALESCE(latest_upload_at, started_at) DESC LIMIT 20",
        (user_id,),
    ).fetchall()
    recharges = conn.execute(
        "SELECT id, hours, seconds, amount, created_at FROM time_recharges WHERE user_id = ? "
        "ORDER BY created_at DESC LIMIT 20",
        (user_id,),
    ).fetchall()
    balance = conn.execute(
        "SELECT balance_seconds, total_consumed_seconds, total_recharged_seconds, last_heartbeat_at "
        "FROM time_balance WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    device_rows = conn.execute(
        "SELECT id, device_code, device_profile, client_version, first_ip, last_ip, "
        "first_seen_at, last_seen_at, last_login_at, last_session_at, heartbeat_count "
        "FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC LIMIT 20",
        (user_id,),
    ).fetchall()
    effective_log_policy = log_upload_policy(conn, user_id)
    try:
        session_items = []
        for row in sessions:
            item = dict(row)
            item.update(_device_profile_summary(str(item.get("device_profile") or "{}")))
            item["ip_location"] = _ip_location_summary(conn, str(item.get("ip_address") or ""))
            session_items.append(item)
        devices = []
        for row in device_rows:
            item = dict(row)
            item.update(_device_profile_summary(str(item.get("device_profile") or "{}")))
            item["last_ip_location"] = _ip_location_summary(conn, str(item.get("last_ip") or ""))
            devices.append(item)
        log_session_items = []
        for row in log_sessions:
            item = dict(row)
            item["ip_location"] = _ip_location_summary(conn, str(item.get("ip_address") or ""))
            log_session_items.append(item)
        order_items = []
        for row in orders:
            item = dict(row)
            item["ip_location"] = _ip_location_summary(conn, str(item.get("ip_address") or ""))
            order_items.append(item)
    finally:
        conn.close()

    return templates.TemplateResponse(request, "admin/user_detail.html", {
        "user": user, "active_page": "users", "target": dict(target),
        "orders": order_items, "sessions": session_items,
        "recharges": [dict(r) for r in recharges], "balance": dict(balance) if balance else None,
        "devices": devices, "log_sessions": log_session_items,
        "global_log_policy": effective_log_policy,
    })


@router.post("/admin/users/update")
async def admin_update_user(
    request: Request,
    user_id: int = Form(...),
    username: str = Form(...),
    email: str = Form(""),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    clean_username = username.strip()
    if not _valid_admin_username(clean_username):
        return HTMLResponse("username must be 3-64 characters using letters, numbers, underscore, or hyphen", status_code=422)
    normalized_email = normalize_email(email)
    if not _valid_optional_email(normalized_email):
        return HTMLResponse("email is invalid", status_code=422)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["deleted_at"] is not None:
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        if _email_taken(conn, normalized_email, user_id):
            conn.execute("ROLLBACK")
            return HTMLResponse("邮箱已绑定其他账号", status_code=409)
        conn.execute(
            "UPDATE users SET username = ?, email = ?, updated_at = datetime('now') WHERE id = ?",
            (clean_username, normalized_email, user_id),
        )
        _audit(conn, request, user, "user.update", "user", user_id, detail={"username": clean_username, "email": normalized_email})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/reset-password")
async def admin_reset_user_password(
    request: Request,
    user_id: int = Form(...),
    new_password: str = Form(...),
    reason: str = Form("admin password reset"),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if not 8 <= len(str(new_password or "")) <= ACCOUNT_PASSWORD_MAX_LENGTH:
        return HTMLResponse("new password length must be 8 to 128", status_code=422)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["deleted_at"] is not None:
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        conn.execute(
            "UPDATE users SET password_hash = ?, auth_version = auth_version + 1, updated_at = datetime('now') WHERE id = ?",
            (hash_password(new_password), user_id),
        )
        revoke_user_sessions_locked(conn, user_id, "password_reset")
        _audit(conn, request, user, "user.reset_password", "user", user_id, reason=reason)
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/adjust-time")
async def admin_adjust_time(
    request: Request,
    user_id: int = Form(...),
    delta_hours: int = Form(0),
    delta_seconds: int = Form(0),
    reason: str = Form(...),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    delta = int(delta_hours or 0) * 3600
    if delta == 0 and delta_seconds:
        delta = int(delta_seconds)
    if delta == 0:
        return _redirect(f"/admin/users/{user_id}")
    if user_id <= 0 or abs(delta) > MAX_BALANCE_SECONDS:
        return _redirect("/admin/users")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not conn.execute(
            "SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)
        ).fetchone():
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        conn.execute("INSERT OR IGNORE INTO time_balance (user_id) VALUES (?)", (user_id,))
        current_balance = conn.execute(
            "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        next_balance = int(current_balance["balance_seconds"] if current_balance else 0) + delta
        if not 0 <= next_balance <= MAX_BALANCE_SECONDS:
            conn.execute("ROLLBACK")
            return _redirect(f"/admin/users/{user_id}")
        conn.execute(
            "UPDATE time_balance SET balance_seconds = balance_seconds + ?, "
            "total_recharged_seconds = total_recharged_seconds + CASE WHEN ? > 0 THEN ? ELSE 0 END, "
            "updated_at = datetime('now') WHERE user_id = ?",
            (delta, delta, delta, user_id),
        )
        conn.execute(
            "INSERT INTO time_recharges (user_id, hours, seconds, amount) VALUES (?, ?, ?, 0)",
            (user_id, delta / 3600, delta),
        )
        _audit(conn, request, user, "user.adjust_time", "user", user_id, reason=reason, detail={"delta_hours": delta // 3600, "delta_seconds": delta})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/set-status")
async def admin_set_status(
    request: Request,
    user_id: int = Form(...),
    status: str = Form(...),
    ban_reason: str = Form(""),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if status not in {"active", "disabled", "banned"}:
        return _redirect(f"/admin/users/{user_id}")
    safe_status = status
    reason = ban_reason.strip() if safe_status == "banned" else ""
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["deleted_at"] is not None:
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        conn.execute(
            "UPDATE users SET status = ?, ban_reason = ?, auth_version = auth_version + 1, "
            "updated_at = datetime('now') WHERE id = ?",
            (safe_status, reason, user_id),
        )
        if safe_status in {"disabled", "banned"}:
            revoke_user_sessions_locked(conn, user_id, "account_disabled")
        _audit(conn, request, user, "user.set_status", "user", user_id, reason=reason, detail={"status": safe_status})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/kick-session")
async def admin_kick_user_session(
    request: Request,
    user_id: int = Form(...),
    session_id: int = Form(0),
    reason: str = Form("admin_kick"),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    safe_reason = (reason or "admin_kick").strip() or "admin_kick"
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["deleted_at"] is not None:
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        if session_id:
            extend_runtime_block_from_active_sessions_locked(conn, user_id)
            conn.execute(
                "UPDATE time_sessions SET status = 'ended', ended_at = datetime('now'), "
                "ended_reason = ?, revoked_at = datetime('now') "
                "WHERE user_id = ? AND id = ? AND status = 'active'",
                (safe_reason, user_id, session_id),
            )
        else:
            revoke_user_sessions_locked(conn, user_id, safe_reason)
        _audit(conn, request, user, "user.kick_session", "user", user_id, reason=safe_reason, detail={"session_id": session_id})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/log-policy")
async def admin_user_log_policy(
    request: Request,
    user_id: int = Form(...),
    log_upload_enabled: int = Form(-1),
    log_upload_interval_seconds: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if log_upload_enabled not in {-1, 0, 1} or not (
        log_upload_interval_seconds == 0 or _in_int_range(log_upload_interval_seconds, LOG_UPLOAD_INTERVAL_RANGE)
    ):
        return _redirect(f"/admin/users/{user_id}?error=invalid_log_policy")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["deleted_at"] is not None:
            conn.execute("ROLLBACK")
            return _redirect("/admin/users")
        update_user_log_upload_policy(conn, user_id, log_upload_enabled, log_upload_interval_seconds)
        _audit(
            conn,
            request,
            user,
            "user.log_policy",
            "user",
            user_id,
            detail={"enabled": log_upload_enabled, "interval_seconds": log_upload_interval_seconds},
        )
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect(f"/admin/users/{user_id}")


@router.post("/admin/users/delete")
async def admin_delete_user(request: Request, user_id: int = Form(...), reason: str = Form("admin delete")):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        previous, paths = soft_delete_user_locked(conn, user_id, reason)
        _audit(
            conn,
            request,
            user,
            "user.soft_delete",
            "user",
            user_id,
            reason=reason,
            detail={"previous_username": previous["username"]},
        )
        conn.commit()
    except (LookupError, PermissionError):
        conn.rollback()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return _redirect("/admin/users")


@router.post("/admin/users/toggle-admin")
async def admin_toggle_admin(request: Request, user_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT id, is_admin, deleted_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if target and target["deleted_at"] is None and target["id"] != user["id"]:
            new_value = 0 if target["is_admin"] else 1
            conn.execute(
                "UPDATE users SET is_admin = ?, auth_version = auth_version + 1, "
                "updated_at = datetime('now') WHERE id = ?",
                (new_value, user_id),
            )
            revoke_user_sessions_locked(conn, user_id, "admin_role_changed")
            _audit(conn, request, user, "user.toggle_admin", "user", user_id, detail={"is_admin": new_value})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/users")


@router.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    from app.services.log_service import get_sessions, get_session_stats
    conn = get_connection()
    try:
        policy = log_upload_policy(conn)
    finally:
        conn.close()
    return templates.TemplateResponse(request, "admin/logs.html", {
        "user": user, "active_page": "logs", "sessions": get_sessions(), "stats": get_session_stats(),
        "policy": policy,
    })


@router.post("/admin/logs/settings")
async def admin_update_log_settings(
    request: Request,
    enabled: int = Form(0),
    interval_seconds: int = Form(3600),
    max_bundle_mb: int = Form(50),
    retention_days: int = Form(30),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if (
        enabled not in {0, 1}
        or not _in_int_range(interval_seconds, LOG_UPLOAD_INTERVAL_RANGE)
        or not _in_int_range(max_bundle_mb, LOG_UPLOAD_MAX_BUNDLE_MB_RANGE)
        or not _in_int_range(retention_days, LOG_UPLOAD_RETENTION_DAYS_RANGE)
    ):
        return _redirect("/admin/logs?error=invalid_log_policy")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        update_global_log_upload_policy(
            conn,
            enabled=bool(enabled),
            interval_seconds=interval_seconds,
            max_bundle_mb=max_bundle_mb,
            retention_days=retention_days,
        )
        _audit(
            conn,
            request,
            user,
            "log_policy.update",
            "system",
            "log_upload",
            detail={
                "enabled": bool(enabled),
                "interval_seconds": interval_seconds,
                "max_bundle_mb": max_bundle_mb,
                "retention_days": retention_days,
            },
        )
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/logs")


@router.get("/admin/logs/{session_db_id}", response_class=HTMLResponse)
async def admin_logs_detail(request: Request, session_db_id: int):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    from app.services.log_service import get_session_files
    conn = get_connection()
    session = conn.execute("SELECT * FROM log_sessions WHERE id = ?", (session_db_id,)).fetchone()
    conn.close()
    if not session:
        return _redirect("/admin/logs")
    return templates.TemplateResponse(request, "admin/logs.html", {
        "user": user, "active_page": "logs", "current_session": dict(session),
        "files": get_session_files(session_db_id), "sessions": [], "stats": {},
    })


@router.get("/admin/logs/{session_db_id}/download-zip")
async def admin_download_log_session_zip(request: Request, session_db_id: int):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        session = conn.execute("SELECT id, session_id FROM log_sessions WHERE id = ?", (session_db_id,)).fetchone()
        if not session:
            return _redirect("/admin/logs")
        rows = conn.execute(
            """
            SELECT lf.id, lf.original_name, lf.storage_path, ls.session_id
            FROM log_files lf
            JOIN log_sessions ls ON ls.id = lf.session_id
            WHERE lf.session_id = ?
            ORDER BY lf.uploaded_at
            """,
            (session_db_id,),
        ).fetchall()
        _audit(conn, request, user, "log_session.download_zip", "log_session", session_db_id, detail={"file_count": len(rows)})
        conn.commit()
        return _log_zip_response([dict(r) for r in rows], f"visionforge_logs_{session['session_id']}")
    finally:
        conn.close()


@router.get("/admin/logs/files/{file_id}/download")
async def admin_download_log_file(request: Request, file_id: int):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    row = conn.execute("SELECT original_name, storage_path FROM log_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    path = _resolve_log_storage_file(row["storage_path"] if row else "")
    if not row or path is None:
        return _redirect("/admin/logs")
    return FileResponse(path, filename=row["original_name"], media_type="application/octet-stream")


@router.post("/admin/logs/files/download-bulk")
async def admin_download_log_files_bulk(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    form = await request.form()
    session_db_id = _safe_form_int(form.get("session_db_id"), 0, minimum=1)
    file_ids = _form_int_list(form, "file_ids")
    if not session_db_id or not file_ids:
        return _redirect(f"/admin/logs/{session_db_id}" if session_db_id else "/admin/logs")
    placeholders = ",".join("?" for _ in file_ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""
            SELECT lf.id, lf.original_name, lf.storage_path, ls.session_id
            FROM log_files lf
            JOIN log_sessions ls ON ls.id = lf.session_id
            WHERE lf.session_id = ? AND lf.id IN ({placeholders})
            ORDER BY lf.uploaded_at
            """,
            (session_db_id, *file_ids),
        ).fetchall()
        _audit(conn, request, user, "log_file.bulk_download_zip", "log_file", "bulk", detail={"session_id": session_db_id, "file_ids": file_ids, "count": len(rows)})
        conn.commit()
        return _log_zip_response([dict(r) for r in rows], f"visionforge_selected_logs_{session_db_id}")
    finally:
        conn.close()


@router.post("/admin/logs/download-sessions")
async def admin_download_log_sessions_bulk(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    form = await request.form()
    session_ids = _form_int_list(form, "session_ids")
    if not session_ids:
        return _redirect("/admin/logs")
    placeholders = ",".join("?" for _ in session_ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""
            SELECT lf.id, lf.original_name, lf.storage_path, ls.session_id
            FROM log_files lf
            JOIN log_sessions ls ON ls.id = lf.session_id
            WHERE ls.id IN ({placeholders})
            ORDER BY ls.started_at DESC, lf.uploaded_at
            """,
            tuple(session_ids),
        ).fetchall()
        _audit(conn, request, user, "log_session.bulk_download_zip", "log_session", "bulk", detail={"session_ids": session_ids, "count": len(rows)})
        conn.commit()
        return _log_zip_response([dict(r) for r in rows], "visionforge_selected_log_sessions")
    finally:
        conn.close()


@router.post("/admin/logs/files/delete")
async def admin_delete_log_file(request: Request, file_id: int = Form(...), session_db_id: int = Form(...), reason: str = Form("admin delete")):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT storage_path FROM log_files WHERE id = ?", (file_id,)).fetchone()
        if row:
            paths.append(str(row["storage_path"] or ""))
            conn.execute("DELETE FROM log_files WHERE id = ?", (file_id,))
            _audit(conn, request, user, "log_file.delete", "log_file", file_id, reason=reason)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return _redirect(f"/admin/logs/{session_db_id}")


@router.post("/admin/logs/files/delete-bulk")
async def admin_delete_log_files_bulk(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    form = await request.form()
    session_db_id = _safe_form_int(form.get("session_db_id"), 0, minimum=1)
    file_ids = _form_int_list(form, "file_ids")
    reason = str(form.get("reason") or "admin bulk delete")
    if not session_db_id or not file_ids:
        return _redirect(f"/admin/logs/{session_db_id}" if session_db_id else "/admin/logs")
    placeholders = ",".join("?" for _ in file_ids)
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            f"SELECT id, storage_path FROM log_files WHERE session_id = ? AND id IN ({placeholders})",
            (session_db_id, *file_ids),
        ).fetchall()
        paths = [str(row["storage_path"] or "") for row in rows]
        if rows:
            ids = [int(row["id"]) for row in rows]
            delete_placeholders = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM log_files WHERE id IN ({delete_placeholders})", tuple(ids))
            _audit(
                conn,
                request,
                user,
                "log_file.bulk_delete",
                "log_file",
                "bulk",
                reason=reason,
                detail={"session_id": session_db_id, "file_ids": ids, "count": len(ids)},
            )
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return _redirect(f"/admin/logs/{session_db_id}")


@router.post("/admin/logs/delete-session")
async def admin_delete_log_session(request: Request, session_db_id: int = Form(...), reason: str = Form("admin delete")):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        _, paths = detach_log_session_locked(conn, session_db_id)
        _audit(conn, request, user, "log_session.delete", "log_session", session_db_id, reason=reason)
        conn.commit()
    except LookupError:
        conn.rollback()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return _redirect("/admin/logs")


@router.post("/admin/logs/delete-sessions")
async def admin_delete_log_sessions_bulk(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    form = await request.form()
    session_ids = _form_int_list(form, "session_ids")
    reason = str(form.get("reason") or "admin bulk delete")
    if not session_ids:
        return _redirect("/admin/logs")
    conn = get_connection()
    paths: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        for session_id in session_ids:
            try:
                _, session_paths = detach_log_session_locked(conn, session_id)
                paths.extend(session_paths)
            except LookupError:
                continue
        _audit(
            conn,
            request,
            user,
            "log_session.bulk_delete",
            "log_session",
            "bulk",
            reason=reason,
            detail={"session_ids": session_ids, "count": len(session_ids)},
        )
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    delete_storage_paths(paths)
    return _redirect("/admin/logs")


@router.get("/admin/help-faqs", response_class=HTMLResponse)
async def admin_help_faqs(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    rows = conn.execute("SELECT * FROM help_faqs ORDER BY sort_order ASC, id ASC LIMIT 200").fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin/help_faqs.html", {
        "user": user, "active_page": "help_faqs", "faqs": [dict(r) for r in rows],
    })


@router.post("/admin/help-faqs/create")
async def admin_create_help_faq(
    request: Request,
    question: str = Form(...),
    answer: str = Form(""),
    sort_order: int = Form(100),
    enabled: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return _redirect("/admin/help-faqs")
    safe_fields = _safe_help_faq_fields(question, answer)
    safe_sort_order = _safe_help_faq_sort_order(sort_order)
    if safe_fields is None or safe_sort_order is None:
        return _redirect("/admin/help-faqs")
    safe_question, safe_answer = safe_fields
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "INSERT INTO help_faqs (question, answer, sort_order, enabled) VALUES (?, ?, ?, ?)",
            (safe_question, safe_answer, safe_sort_order, 1 if enabled else 0),
        )
        _audit(conn, request, user, "help_faq.create", "help_faq", cursor.lastrowid, detail={"question": safe_question[:120]})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/help-faqs")


@router.post("/admin/help-faqs/update")
async def admin_update_help_faq(
    request: Request,
    faq_id: int = Form(...),
    question: str = Form(...),
    answer: str = Form(""),
    sort_order: int = Form(100),
    enabled: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return _redirect("/admin/help-faqs")
    safe_fields = _safe_help_faq_fields(question, answer)
    safe_sort_order = _safe_help_faq_sort_order(sort_order)
    if safe_fields is None or safe_sort_order is None:
        return _redirect("/admin/help-faqs")
    safe_question, safe_answer = safe_fields
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute(
            "UPDATE help_faqs SET question = ?, answer = ?, sort_order = ?, enabled = ?, updated_at = datetime('now') WHERE id = ?",
            (safe_question, safe_answer, safe_sort_order, 1 if enabled else 0, faq_id),
        ).rowcount
        if updated:
            _audit(conn, request, user, "help_faq.update", "help_faq", faq_id, detail={"question": safe_question[:120]})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/help-faqs")


@router.post("/admin/help-faqs/delete")
async def admin_delete_help_faq(request: Request, faq_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        deleted = conn.execute("DELETE FROM help_faqs WHERE id = ?", (faq_id,)).rowcount
        if deleted:
            _audit(conn, request, user, "help_faq.delete", "help_faq", faq_id)
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/help-faqs")


@router.get("/admin/announcements", response_class=HTMLResponse)
async def admin_announcements(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    rows = conn.execute("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin/announcements.html", {
        "user": user, "active_page": "announcements", "announcements": [dict(r) for r in rows],
    })


@router.post("/admin/announcements/create")
async def admin_create_announcement(
    request: Request,
    title: str = Form(...),
    body: str = Form(""),
    level: str = Form("info"),
    starts_at: str = Form(""),
    ends_at: str = Form(""),
    enabled: int = Form(1),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return HTMLResponse("invalid announcement enabled flag", status_code=422)
    safe_level = _announcement_level(level)
    if safe_level is None:
        return HTMLResponse("invalid announcement level", status_code=422)
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO announcements (title, body, level, starts_at, ends_at, enabled) VALUES (?, ?, ?, ?, ?, ?)",
        (title.strip(), body.strip(), safe_level, starts_at.strip(), ends_at.strip(), 1 if enabled else 0),
    )
    _audit(conn, request, user, "announcement.create", "announcement", cursor.lastrowid, detail={"title": title})
    conn.commit()
    conn.close()
    return _redirect("/admin/announcements")


@router.post("/admin/announcements/update")
async def admin_update_announcement(
    request: Request,
    announcement_id: int = Form(...),
    title: str = Form(...),
    body: str = Form(""),
    level: str = Form("info"),
    starts_at: str = Form(""),
    ends_at: str = Form(""),
    enabled: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return HTMLResponse("invalid announcement enabled flag", status_code=422)
    safe_level = _announcement_level(level)
    if safe_level is None:
        return HTMLResponse("invalid announcement level", status_code=422)
    conn = get_connection()
    updated = conn.execute(
        "UPDATE announcements SET title = ?, body = ?, level = ?, starts_at = ?, ends_at = ?, enabled = ?, "
        "updated_at = datetime('now') WHERE id = ?",
        (title.strip(), body.strip(), safe_level, starts_at.strip(), ends_at.strip(), 1 if enabled else 0, announcement_id),
    ).rowcount
    if updated:
        _audit(conn, request, user, "announcement.update", "announcement", announcement_id, detail={"title": title})
    conn.commit()
    conn.close()
    return _redirect("/admin/announcements")


@router.post("/admin/announcements/delete")
async def admin_delete_announcement(request: Request, announcement_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    deleted = conn.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,)).rowcount
    if deleted:
        _audit(conn, request, user, "announcement.delete", "announcement", announcement_id)
    conn.commit()
    conn.close()
    return _redirect("/admin/announcements")


@router.get("/admin/releases", response_class=HTMLResponse)
async def admin_releases(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    return templates.TemplateResponse(request, "admin/releases.html", {
        "user": user, "active_page": "releases", "releases": release_service.list_releases(limit=100),
    })


@router.post("/admin/releases/create")
async def admin_create_release(
    request: Request,
    version: str = Form(...),
    channel: str = Form("stable"),
    notes: str = Form(""),
    url: str = Form(""),
    sha256: str = Form(""),
    installer_url: str = Form(""),
    installer_sha256: str = Form(""),
    min_supported_version: str = Form(""),
    mandatory: int = Form(0),
    published: int = Form(1),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if mandatory not in {0, 1} or published not in {0, 1}:
        return HTMLResponse("invalid release boolean flag", status_code=422)
    try:
        await run_in_threadpool(
            release_service.save_legacy,
            {
                "version": version,
                "channel": channel,
                "notes": notes,
                "url": url,
                "sha256": sha256,
                "installer_url": installer_url,
                "installer_sha256": installer_sha256,
                "min_supported_version": min_supported_version,
                "mandatory": bool(mandatory),
            },
            published=bool(published),
            audit=lambda conn, release_id: _audit(
                conn,
                request,
                user,
                "release.create",
                "release",
                release_id,
                detail={"version": version, "channel": channel, "signed": False},
            ),
        )
    except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError) as exc:
        status = 404 if isinstance(exc, ReleaseNotFoundError) else 409 if isinstance(exc, ReleaseConflictError) else 422
        return HTMLResponse(str(exc), status_code=status)
    return _redirect("/admin/releases")


@router.post("/admin/releases/update")
async def admin_update_release(
    request: Request,
    release_id: int = Form(...),
    version: str = Form(...),
    channel: str = Form("stable"),
    notes: str = Form(""),
    url: str = Form(""),
    sha256: str = Form(""),
    installer_url: str = Form(""),
    installer_sha256: str = Form(""),
    min_supported_version: str = Form(""),
    mandatory: int = Form(0),
    published: int = Form(0),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if mandatory not in {0, 1} or published not in {0, 1}:
        return HTMLResponse("invalid release boolean flag", status_code=422)
    try:
        await run_in_threadpool(
            release_service.save_legacy,
            {
                "version": version,
                "channel": channel,
                "notes": notes,
                "url": url,
                "sha256": sha256,
                "installer_url": installer_url,
                "installer_sha256": installer_sha256,
                "min_supported_version": min_supported_version,
                "mandatory": bool(mandatory),
            },
            published=bool(published),
            release_id=release_id,
            audit=lambda conn, saved_id: _audit(
                conn,
                request,
                user,
                "release.update",
                "release",
                saved_id,
                detail={"version": version, "channel": channel, "signed": False},
            ),
        )
    except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError) as exc:
        status = 404 if isinstance(exc, ReleaseNotFoundError) else 409 if isinstance(exc, ReleaseConflictError) else 422
        return HTMLResponse(str(exc), status_code=status)
    return _redirect("/admin/releases")


@router.post("/admin/releases/delete")
async def admin_delete_release(request: Request, release_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    try:
        release_service.delete(
            release_id,
            audit=lambda conn, deleted_id: _audit(
                conn, request, user, "release.delete", "release", deleted_id
            ),
        )
    except (ReleaseNotFoundError, ReleaseConflictError) as exc:
        return HTMLResponse(
            str(exc),
            status_code=404 if isinstance(exc, ReleaseNotFoundError) else 409,
        )
    return _redirect("/admin/releases")


@router.get("/admin/security", response_class=HTMLResponse)
async def admin_security(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        security = conn.execute(
            "SELECT enforce_integrity, lease_ttl_seconds, updated_at FROM runtime_security_settings WHERE id = 1"
        ).fetchone()
        if not security:
            conn.execute(
                "INSERT OR IGNORE INTO runtime_security_settings "
                "(id, enforce_integrity, lease_ttl_seconds) VALUES (1, 0, 15)"
            )
            conn.commit()
            security = conn.execute(
                "SELECT enforce_integrity, lease_ttl_seconds, updated_at FROM runtime_security_settings WHERE id = 1"
            ).fetchone()
        allowlist = conn.execute(
            "SELECT id, client_version, manifest_hash, file_hashes_json, enabled, note, created_at, updated_at "
            "FROM client_integrity_allowlist ORDER BY enabled DESC, updated_at DESC, id DESC LIMIT 200"
        ).fetchall()
    finally:
        conn.close()
    return templates.TemplateResponse(request, "admin/security.html", {
        "user": user,
        "active_page": "security",
        "security": dict(security) if security else {"enforce_integrity": 0, "lease_ttl_seconds": 15},
        "allowlist": [dict(r) for r in allowlist],
    })


@router.post("/admin/security/settings")
async def admin_security_settings(
    request: Request,
    enforce_integrity: int = Form(0),
    lease_ttl_seconds: int = Form(15),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enforce_integrity not in {0, 1}:
        return _redirect("/admin/security")
    ttl = _safe_lease_ttl(lease_ttl_seconds)
    enforce = 1 if enforce_integrity else 0
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO runtime_security_settings (id, enforce_integrity, lease_ttl_seconds, updated_at) "
            "VALUES (1, ?, ?, datetime('now')) "
            "ON CONFLICT(id) DO UPDATE SET enforce_integrity = excluded.enforce_integrity, "
            "lease_ttl_seconds = excluded.lease_ttl_seconds, updated_at = datetime('now')",
            (enforce, ttl),
        )
        _audit(conn, request, user, "security.settings", "runtime_security", "1", detail={"enforce_integrity": bool(enforce), "lease_ttl_seconds": ttl})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/security")


@router.post("/admin/security/allowlist/create")
async def admin_security_allowlist_create(
    request: Request,
    client_version: str = Form("*"),
    manifest_hash: str = Form(...),
    file_hashes_json: str = Form(""),
    enabled: int = Form(1),
    note: str = Form(""),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return HTMLResponse("invalid allowlist enabled flag", status_code=400)
    safe_hash = _normalize_manifest_hash(manifest_hash)
    if not safe_hash:
        return HTMLResponse("manifest_hash 必须是 64 位十六进制 SHA256。", status_code=400)
    try:
        files_json = _normalize_file_hashes_json(file_hashes_json)
    except Exception:
        return HTMLResponse("file_hashes_json 不是合法 JSON。", status_code=400)
    try:
        safe_note = _normalize_allowlist_note(note)
    except ValueError:
        return HTMLResponse("note must be 500 characters or fewer", status_code=400)
    try:
        safe_version = _normalize_client_version(client_version)
    except ValueError:
        return HTMLResponse("client_version must be 80 characters or fewer", status_code=400)
    wildcard_error = _production_wildcard_allowlist_error(
        safe_version,
        enabled=bool(enabled),
    )
    if wildcard_error:
        return HTMLResponse(wildcard_error, status_code=400)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "INSERT INTO client_integrity_allowlist "
            "(client_version, manifest_hash, file_hashes_json, enabled, note) VALUES (?, ?, ?, ?, ?)",
            (safe_version, safe_hash, files_json, 1 if enabled else 0, safe_note),
        )
        _audit(conn, request, user, "security.allowlist.create", "client_integrity_allowlist", cursor.lastrowid, detail={"client_version": safe_version, "manifest_hash": safe_hash})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/security")


@router.post("/admin/security/allowlist/update")
async def admin_security_allowlist_update(
    request: Request,
    allowlist_id: int = Form(...),
    client_version: str = Form("*"),
    manifest_hash: str = Form(...),
    file_hashes_json: str = Form(""),
    enabled: int = Form(0),
    note: str = Form(""),
):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    if enabled not in {0, 1}:
        return HTMLResponse("invalid allowlist enabled flag", status_code=400)
    safe_hash = _normalize_manifest_hash(manifest_hash)
    if not safe_hash:
        return HTMLResponse("manifest_hash 必须是 64 位十六进制 SHA256。", status_code=400)
    try:
        files_json = _normalize_file_hashes_json(file_hashes_json)
    except Exception:
        return HTMLResponse("file_hashes_json 不是合法 JSON。", status_code=400)
    try:
        safe_note = _normalize_allowlist_note(note)
    except ValueError:
        return HTMLResponse("note must be 500 characters or fewer", status_code=400)
    try:
        safe_version = _normalize_client_version(client_version)
    except ValueError:
        return HTMLResponse("client_version must be 80 characters or fewer", status_code=400)
    wildcard_error = _production_wildcard_allowlist_error(
        safe_version,
        enabled=bool(enabled),
    )
    if wildcard_error:
        return HTMLResponse(wildcard_error, status_code=400)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute(
            "UPDATE client_integrity_allowlist SET client_version = ?, manifest_hash = ?, "
            "file_hashes_json = ?, enabled = ?, note = ?, updated_at = datetime('now') WHERE id = ?",
            (safe_version, safe_hash, files_json, 1 if enabled else 0, safe_note, allowlist_id),
        ).rowcount
        if updated:
            _audit(conn, request, user, "security.allowlist.update", "client_integrity_allowlist", allowlist_id, detail={"client_version": safe_version, "manifest_hash": safe_hash})
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/security")


@router.post("/admin/security/allowlist/delete")
async def admin_security_allowlist_delete(request: Request, allowlist_id: int = Form(...)):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        deleted = conn.execute("DELETE FROM client_integrity_allowlist WHERE id = ?", (allowlist_id,)).rowcount
        if deleted:
            _audit(conn, request, user, "security.allowlist.delete", "client_integrity_allowlist", allowlist_id)
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return _redirect("/admin/security")


@router.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit(request: Request):
    user = await get_user_from_cookie(request)
    guard = _admin_guard(request, user)
    if guard:
        return guard
    conn = get_connection()
    rows = conn.execute("""
        SELECT a.*, u.username AS admin_username
        FROM admin_audit a LEFT JOIN users u ON u.id = a.admin_user_id
        ORDER BY a.created_at DESC LIMIT 200
    """).fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin/audit.html", {
        "user": user, "active_page": "audit", "records": [dict(r) for r in rows],
    })
