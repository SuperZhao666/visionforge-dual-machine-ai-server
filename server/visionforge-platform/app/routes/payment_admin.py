"""Administrator UI for fixed-amount payment QR assets."""
from __future__ import annotations

import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import config
from app.database import get_connection
from app.repositories.purchase_checkout_repository import SqlitePurchaseCheckoutRepository
from app.routes.auth import get_user_from_cookie
from app.security import require_form_csrf
from app.services.admin_service import write_admin_audit
from app.services.payment_channels import PAYMENT_CHANNELS, normalize_payment_method, payment_method_label
from app.services.payment_qr_service import MAX_PAYMENT_QR_BYTES, payment_qr_path, save_payment_qr_png
from app.services.payment_service import PLAN_BY_KEY, PLANS
from app.services.purchase_checkout_service import PurchaseCheckoutService
from app.templating import templates


logger = logging.getLogger("admin.payment_qr")
router = APIRouter(dependencies=[Depends(require_form_csrf)])
purchase_checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())
PAYMENT_QR_MULTIPART_OVERHEAD_BYTES = 64 * 1024


async def _admin_user(request: Request) -> dict | None:
    user = await get_user_from_cookie(request)
    if not user or not user.get("is_admin"):
        return None
    return user


def _redirect(message_type: str = "", message: str = "") -> RedirectResponse:
    query = urlencode({message_type: message}) if message_type and message else ""
    target = f"/admin/payment-qr?{query}" if query else "/admin/payment-qr"
    return RedirectResponse(target, status_code=303)


def _upload_length_error(request: Request) -> RedirectResponse | None:
    declared = str(request.headers.get("content-length") or "").strip()
    if not declared:
        return None
    try:
        value = int(declared)
    except ValueError:
        return _redirect("error", "invalid content-length")
    if value < 0:
        return _redirect("error", "invalid content-length")
    if value > MAX_PAYMENT_QR_BYTES + PAYMENT_QR_MULTIPART_OVERHEAD_BYTES:
        return _redirect("error", "payload too large")
    return None


def _payment_qr_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for plan in PLANS:
        for channel in PAYMENT_CHANNELS:
            path = payment_qr_path(plan.key, channel.key)
            try:
                ready = path.is_file()
                version = int(path.stat().st_mtime) if ready else 0
            except OSError:
                ready = False
                version = 0
            rows.append({
                "plan_key": plan.key,
                "plan_name": plan.name,
                "price": plan.price,
                "payment_method": channel.key,
                "payment_label": channel.label,
                "ready": ready,
                "filename": path.name,
                "version": version,
            })
    return rows


@router.get("/admin/payment-qr", response_class=HTMLResponse)
async def admin_payment_qr(request: Request):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "admin/payment_qr.html", {
        "active_page": "payment_qr",
        "user": user,
        "rows": _payment_qr_rows(),
        "payment_exceptions": purchase_checkout_service.list_payment_exceptions(30),
        "success": str(request.query_params.get("success") or ""),
        "error": str(request.query_params.get("error") or ""),
        "monitor_config_ready": bool(config.VMQ_MONITOR_HOST and config.VMQ_WEBHOOK_SECRET),
    })


@router.post("/admin/payment-qr/monitor-config", response_class=HTMLResponse)
async def admin_payment_monitor_config(request: Request):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    monitor_host = str(config.VMQ_MONITOR_HOST or "").strip()
    monitor_secret = str(config.VMQ_WEBHOOK_SECRET or "")
    if not monitor_host or not monitor_secret:
        return _redirect("error", "监听端配置尚未完成")

    conn = get_connection()
    try:
        write_admin_audit(
            conn,
            admin_user_id=int(user["id"]),
            ip_address=request.client.host if request.client else "",
            action="payment_monitor.reveal_config",
            target_type="payment_monitor",
            target_id="vmq",
            detail={"monitor_host": monitor_host},
        )
        conn.commit()
    finally:
        conn.close()
    logger.info("payment monitor config viewed admin_user_id=%s", user["id"])
    response = templates.TemplateResponse(request, "admin/payment_monitor_config.html", {
        "active_page": "payment_qr",
        "user": user,
        "monitor_host": monitor_host,
        "monitor_secret": monitor_secret,
    })
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@router.post("/admin/payment-qr/upload")
async def admin_payment_qr_upload(
    request: Request,
    plan: str = Form(""),
    payment_method: str = Form(""),
    qr_file: UploadFile = File(...),
):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    plan_key = str(plan or "").strip()
    method = normalize_payment_method(payment_method)
    if plan_key not in PLAN_BY_KEY:
        return _redirect("error", "无效套餐")
    if not method:
        return _redirect("error", "无效支付方式")

    length_error = _upload_length_error(request)
    if length_error is not None:
        return length_error

    content = await qr_file.read(MAX_PAYMENT_QR_BYTES + 1)
    try:
        saved = save_payment_qr_png(plan_key, method, content)
    except (OSError, ValueError) as exc:
        logger.warning("payment QR upload rejected plan=%s method=%s error=%s", plan_key, method, exc)
        return _redirect("error", str(exc))
    finally:
        await qr_file.close()

    conn = get_connection()
    try:
        write_admin_audit(
            conn,
            admin_user_id=int(user["id"]),
            ip_address=request.client.host if request.client else "",
            action="payment_qr.upload",
            target_type="payment_qr",
            target_id=f"{method}:{plan_key}",
            detail={
                "filename": saved["filename"],
                "width": saved["width"],
                "height": saved["height"],
                "size": saved["size"],
            },
        )
        conn.commit()
    finally:
        conn.close()
    logger.info("payment QR updated plan=%s method=%s size=%s", plan_key, method, saved["size"])
    return _redirect("success", f"{PLAN_BY_KEY[plan_key].name} {payment_method_label(method)}二维码已更新")
