"""Shop routes: browse plans, create order, show fixed-price QR code.

V免签 flow: user selects plan → sees pre-set-amount QR code →
scans → pays exact amount → vmq-itchat detects → platform delivers.
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

# JSONResponse IS used by order_status

from app.routes.auth import get_user_from_cookie
from app.templating import templates
from app.database import get_connection
from app.security import limiter
from app.services.payment_service import PLANS, PLAN_BY_KEY, create_order_record

logger = logging.getLogger("shop")
router = APIRouter()


def _render(request: Request, user: dict | None, **extra):
    plans_data = [
        {"key": p.key, "name": p.name, "price": p.price, "desc": p.desc, "qr_file": p.qr_file}
        for p in PLANS
    ]
    return templates.TemplateResponse(request, "shop.html", {"user": user, "plans": plans_data, **extra})


@router.get("/shop", response_class=HTMLResponse)
async def shop_page(request: Request):
    user = await get_user_from_cookie(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return _render(request, user)


@router.post("/shop/create-order")
@limiter.limit("5/minute")
async def create_order(request: Request):
    user = await get_user_from_cookie(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    form = await request.form()
    plan_key = str(form.get("plan", ""))
    plan = PLAN_BY_KEY.get(plan_key)
    if not plan:
        return _render(request, user, error="无效的套餐")

    client_ip = request.client.host if request.client else ""
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        order_id, merchant_order_no = create_order_record(conn, int(user["id"]), plan_key, plan.price, client_ip, "vmq")
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    logger.info("Order #%d (%s): plan=%s price=%.2f user=%s", order_id, merchant_order_no, plan_key, plan.price, user["username"])
    return _render(request, user, pay_plan=plan, order_id=order_id, merchant_order_no=merchant_order_no)


@router.get("/shop/order-status/{order_id}")
async def order_status(request: Request, order_id: int):
    """AJAX polling endpoint: check if an order has been delivered."""
    user = await get_user_from_cookie(request)
    if not user:
        return JSONResponse({"status": "unauthorized"}, status_code=401)

    conn = get_connection()
    try:
        order = conn.execute(
            "SELECT status FROM orders WHERE id = ? AND user_id = ?",
            (order_id, user["id"]),
        ).fetchone()
        if not order:
            return JSONResponse({"status": "not_found"}, status_code=404)
        return JSONResponse({"status": order["status"]})
    finally:
        conn.close()
