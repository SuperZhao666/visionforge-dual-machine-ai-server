"""Administrator UI for duration products, redemption codes, and referrals."""
from __future__ import annotations

import csv
import io
import uuid
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import config
from app.database import get_connection
from app.routes.auth import get_user_from_cookie
from app.security import require_form_csrf
from app.services.admin_service import write_admin_audit
from app.services.redemption_constants import MAX_ISSUANCE_NOTE_LENGTH
from app.services.redemption_service import issue_codes_locked
from app.templating import templates


router = APIRouter(dependencies=[Depends(require_form_csrf)])

MAX_PRODUCT_DISPLAY_NAME_LENGTH = 80
REFERRAL_REWARD_HOURS_RANGE = (1, 1000)
CODE_EXPIRY_DAYS_RANGE = (1, 3650)
PRODUCT_DURATION_HOURS_RANGE = (1, 10000)


def _in_range(value: int, bounds: tuple[int, int]) -> bool:
    return bounds[0] <= int(value) <= bounds[1]


async def _admin_user(request: Request) -> dict | None:
    user = await get_user_from_cookie(request)
    return user if user and user.get("is_admin") else None


def _redirect(kind: str = "", message: str = "") -> RedirectResponse:
    query = urlencode({kind: message}) if kind and message else ""
    return RedirectResponse(f"/admin/growth?{query}" if query else "/admin/growth", status_code=303)


def _audit(conn, request: Request, user: dict, action: str, target_type: str, target_id, detail=None) -> None:
    safe_detail = dict(detail or {})
    safe_detail["trace_id"] = str(getattr(request.state, "trace_id", "") or "")
    write_admin_audit(
        conn,
        admin_user_id=int(user["id"]),
        ip_address=request.client.host if request.client else "",
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=safe_detail,
    )


@router.get("/admin/growth", response_class=HTMLResponse)
async def admin_growth(request: Request):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    conn = get_connection()
    try:
        settings = conn.execute("SELECT * FROM growth_settings WHERE id = 1").fetchone()
        products = conn.execute(
            "SELECT * FROM duration_products ORDER BY sort_order, product_key"
        ).fetchall()
        batches = conn.execute(
            "SELECT b.id, b.channel, b.issuer_type, b.product_key, b.quantity, b.status, b.note, b.created_at, "
            "dp.display_name, SUM(CASE WHEN rc.status = 'redeemed' THEN 1 ELSE 0 END) AS redeemed_count, "
            "SUM(CASE WHEN rc.status = 'issued' THEN 1 ELSE 0 END) AS issued_count, "
            "SUM(CASE WHEN rc.status IN ('revoked', 'expired') THEN 1 ELSE 0 END) AS unavailable_count "
            "FROM code_issuance_batches b JOIN duration_products dp ON dp.product_key = b.product_key "
            "LEFT JOIN redemption_codes rc ON rc.batch_id = b.id GROUP BY b.id ORDER BY b.id DESC LIMIT 100"
        ).fetchall()
        referrals = conn.execute(
            "SELECT r.id, inviter.username AS inviter_username, invitee.username AS invitee_username, "
            "r.reward_seconds, r.status, r.created_at, r.rewarded_at "
            "FROM referrals r JOIN users inviter ON inviter.id = r.inviter_user_id "
            "JOIN users invitee ON invitee.id = r.invitee_user_id ORDER BY r.id DESC LIMIT 100"
        ).fetchall()
    finally:
        conn.close()
    return templates.TemplateResponse(request, "admin/growth.html", {
        "active_page": "growth",
        "user": user,
        "settings": dict(settings) if settings else {},
        "products": [dict(row) for row in products],
        "batches": [dict(row) for row in batches],
        "referrals": [dict(row) for row in referrals],
        "redemption_secret_configured": bool(str(config.REDEMPTION_CODE_SECRET or "")),
        "success": str(request.query_params.get("success") or ""),
        "error": str(request.query_params.get("error") or ""),
    })


@router.post("/admin/growth/settings")
async def admin_growth_settings(
    request: Request,
    redemption_enabled: str = Form(""),
    referral_enabled: str = Form(""),
    referral_reward_hours: int = Form(1),
    code_expiry_days: int = Form(365),
    download_url: str = Form(""),
):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    reward_hours = int(referral_reward_hours)
    expiry_days = int(code_expiry_days)
    if not _in_range(reward_hours, REFERRAL_REWARD_HOURS_RANGE) or not _in_range(expiry_days, CODE_EXPIRY_DAYS_RANGE):
        return _redirect("error", "兑换码与邀请配置参数无效")
    safe_download_url = str(download_url or "").strip()
    if len(safe_download_url) > 500:
        return _redirect("error", "下载地址不能超过 500 个字符")
    if not safe_download_url.startswith("https://"):
        return _redirect("error", "下载地址必须使用 HTTPS")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE growth_settings SET redemption_enabled = ?, referral_enabled = ?, "
            "referral_reward_seconds = ?, code_expiry_days = ?, download_url = ?, "
            "updated_at = datetime('now') WHERE id = 1",
            (
                1 if redemption_enabled else 0,
                1 if referral_enabled else 0,
                reward_hours * 3600,
                expiry_days,
                safe_download_url,
            ),
        )
        _audit(
            conn,
            request,
            user,
            "growth.settings.update",
            "growth_settings",
            1,
            {
                "redemption_enabled": bool(redemption_enabled),
                "referral_enabled": bool(referral_enabled),
                "referral_reward_hours": reward_hours,
                "code_expiry_days": expiry_days,
                "download_url": safe_download_url,
            },
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _redirect("success", "兑换码与邀请配置已更新")


@router.post("/admin/growth/products/update")
async def admin_growth_product_update(
    request: Request,
    product_key: str = Form(""),
    display_name: str = Form(""),
    duration_hours: int = Form(1),
    enabled: str = Form(""),
):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    key = str(product_key or "").strip().lower()
    name = str(display_name or "").strip()
    hours = int(duration_hours)
    if (
        not key
        or len(key) > 32
        or not name
        or len(name) > MAX_PRODUCT_DISPLAY_NAME_LENGTH
        or not _in_range(hours, PRODUCT_DURATION_HOURS_RANGE)
    ):
        return _redirect("error", "时长产品参数无效")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE duration_products SET display_name = ?, duration_seconds = ?, enabled = ?, "
            "updated_at = datetime('now') WHERE product_key = ?",
            (name, hours * 3600, 1 if enabled else 0, key),
        ).rowcount
        if changed != 1:
            conn.rollback()
            return _redirect("error", "时长产品不存在")
        _audit(conn, request, user, "growth.product.update", "duration_product", key, {
            "display_name": name,
            "duration_hours": hours,
            "enabled": bool(enabled),
        })
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _redirect("success", f"时长产品 {key} 已更新；已生成兑换码的时长快照不受影响")


@router.post("/admin/growth/codes/generate")
async def admin_growth_codes_generate(
    request: Request,
    product_key: str = Form(""),
    quantity: int = Form(1),
    note: str = Form(""),
):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    safe_note = str(note or "").strip()
    if len(safe_note) > MAX_ISSUANCE_NOTE_LENGTH:
        return _redirect("error", f"用途备注不能超过 {MAX_ISSUANCE_NOTE_LENGTH} 个字符")
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        settings = conn.execute("SELECT code_expiry_days FROM growth_settings WHERE id = 1").fetchone()
        result = issue_codes_locked(
            conn,
            product_key=product_key,
            quantity=int(quantity),
            channel="admin",
            issuer_type="admin",
            issuer_id=int(user["id"]),
            request_key=f"admin:{uuid.uuid4().hex}",
            note=safe_note,
            expires_days=int(settings["code_expiry_days"] if settings else 365),
        )
        _audit(conn, request, user, "growth.codes.generate", "code_batch", result.batch_id, {
            "product_key": result.product_key,
            "quantity": len(result.codes),
            "note": safe_note,
        })
        conn.commit()
    except (LookupError, ValueError) as exc:
        conn.rollback()
        return _redirect("error", str(exc))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(("batch_id", "product_key", "duration_seconds", "redemption_code"))
    for code in result.codes:
        writer.writerow((result.batch_id, result.product_key, result.duration_seconds, code))
    content = "\ufeff" + stream.getvalue()
    response = Response(content, media_type="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="visionforge_codes_{result.batch_id}.csv"'
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@router.post("/admin/growth/codes/revoke")
async def admin_growth_codes_revoke(request: Request, batch_id: int = Form(0)):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE redemption_codes SET status = 'revoked' WHERE batch_id = ? AND status = 'issued'",
            (int(batch_id),),
        ).rowcount
        batch_changed = conn.execute(
            "UPDATE code_issuance_batches SET status = 'revoked' WHERE id = ?",
            (int(batch_id),),
        ).rowcount
        if batch_changed != 1:
            conn.rollback()
            return _redirect("error", "发码批次不存在")
        _audit(conn, request, user, "growth.codes.revoke", "code_batch", batch_id, {
            "revoked_unused_count": int(changed),
        })
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _redirect("success", f"已废止 {changed} 张尚未兑换的兑换码")
