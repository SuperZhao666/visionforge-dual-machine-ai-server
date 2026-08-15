"""Payment callback handlers — V免签 protocol + JSON webhook.

All delivery operations use BEGIN IMMEDIATE transactions to prevent
race conditions (two payments matching the same order simultaneously).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from decimal import Decimal, InvalidOperation
from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app.config import config
from app.security import limiter
from app.services.payment_channels import payment_method_from_vmq_type
from app.services.payment_service import build_payment_event_id, deliver_order, process_payment_event

logger = logging.getLogger("payment")
router = APIRouter()


def _payload_amount(payload: dict) -> str:
    for key in ("amount", "price", "money", "total_amount", "total_fee"):
        value = payload.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


MAX_PAYMENT_BODY_BYTES = 64 * 1024
MAX_PAYMENT_AMOUNT = Decimal("1000000.00")
MONEY_QUANTUM = Decimal("0.01")
RETRYABLE_PAYMENT_STATUSES = {"received", "unmatched", "ambiguous", "order_not_found"}
VMQ_SUCCESS_RESPONSE = {"code": 1, "msg": "成功"}
VMQ_CALLBACK_MAX_AGE_SECONDS = 15 * 60
VMQ_CALLBACK_MAX_FUTURE_SKEW_SECONDS = 60


def _parse_positive_amount(value: str) -> Decimal | None:
    try:
        amount = Decimal(str(value).strip())
        quantized = amount.quantize(MONEY_QUANTUM)
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not amount.is_finite() or amount != quantized or amount <= 0 or amount > MAX_PAYMENT_AMOUNT:
        return None
    return quantized


def _valid_json_webhook_signature(body: bytes, signature: str) -> bool:
    secret = str(config.VMQ_WEBHOOK_SECRET or "")
    if not secret:
        return False
    supplied = str(signature or "").strip()
    if supplied.lower().startswith("sha256="):
        supplied = supplied[7:]
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return bool(supplied) and hmac.compare_digest(supplied.lower(), expected)


def _valid_vmq_timestamp(value: str, *, now_seconds: float | None = None) -> bool:
    """Accept upstream millisecond timestamps and legacy second timestamps."""
    timestamp_text = str(value or "").strip()
    if not timestamp_text.isascii() or not timestamp_text.isdigit():
        return False
    if len(timestamp_text) == 13:
        callback_milliseconds = int(timestamp_text)
    elif len(timestamp_text) == 10:
        callback_milliseconds = int(timestamp_text) * 1000
    else:
        return False

    current_milliseconds = int((time.time() if now_seconds is None else now_seconds) * 1000)
    earliest_milliseconds = current_milliseconds - VMQ_CALLBACK_MAX_AGE_SECONDS * 1000
    latest_milliseconds = current_milliseconds + VMQ_CALLBACK_MAX_FUTURE_SKEW_SECONDS * 1000
    return earliest_milliseconds <= callback_milliseconds <= latest_milliseconds


def _valid_vmq_signature(
    signed_values: tuple[str, ...],
    supplied_signature: str,
) -> bool:
    secret = str(config.VMQ_WEBHOOK_SECRET or "")
    if not secret:
        return False
    expected = hashlib.md5("".join((*signed_values, secret)).encode()).hexdigest()
    return hmac.compare_digest(str(supplied_signature or "").strip().lower(), expected)


# ── Atomic order delivery ────────────────────────────────────────
# This is the CRITICAL SECTION — it must be atomic to prevent double-delivery.
# Uses BEGIN IMMEDIATE to lock the database for the duration of the transaction.

def _deliver_order(order_id: int, plan: str) -> dict | None:
    """Backward-compatible admin hook; the business logic lives in payment_service."""
    return deliver_order(order_id, plan)


# ── V免签 protocol (vmq-itchat) ──────────────────────────────────

@router.get("/appHeart")
async def vmq_heartbeat(t: str = "", sign: str = ""):
    if not config.VMQ_WEBHOOK_SECRET:
        logger.error("VMQ heartbeat rejected because VMQ_WEBHOOK_SECRET is not configured")
        return {"code": -1, "msg": "webhook disabled"}
    if not _valid_vmq_signature((t,), sign):
        return {"code": -1, "msg": "bad signature"}
    if not _valid_vmq_timestamp(t):
        return {"code": -1, "msg": "bad timestamp"}
    return VMQ_SUCCESS_RESPONSE


@router.get("/appPush")
@limiter.limit("240/minute")
async def vmq_push(request: Request, t: str = "", type: str = "", price: str = "", sign: str = ""):
    """vmq-itchat payment notification via V免签 protocol."""
    secret = str(config.VMQ_WEBHOOK_SECRET or "")
    if not secret:
        logger.error("VMQ callback rejected because VMQ_WEBHOOK_SECRET is not configured")
        return {"code": -1, "msg": "webhook disabled"}
    vmq_type = str(type or "").strip() or "1"
    payment_method = payment_method_from_vmq_type(vmq_type)
    if not payment_method:
        return {"code": -1, "msg": "unsupported payment type"}
    # V免签 protocol: type=1 WeChat, type=2 Alipay.
    if not _valid_vmq_signature((vmq_type, price, t), sign):
        return {"code": -1, "msg": "bad signature"}
    if not _valid_vmq_timestamp(t):
        return {"code": -1, "msg": "bad timestamp"}

    amount = _parse_positive_amount(price)
    if amount is None:
        return {"code": -1, "msg": "bad price"}

    # Only signed protocol fields may influence matching or event identity.
    payload = {
        "t": str(t).strip(),
        "type": vmq_type,
        "price": str(price).strip(),
        "payment_method": payment_method,
    }
    event_id = build_payment_event_id("vmq", payload)
    result = await run_in_threadpool(process_payment_event, "vmq", event_id, amount, payload)
    logger.info(
        "payment callback processed trace_id=%s source=vmq status=%s order_id=%s method=%s late_settlement=%s",
        str(getattr(request.state, "trace_id", "") or ""),
        result.get("status"),
        result.get("order_id", 0),
        payment_method,
        bool(result.get("late_settlement")),
    )
    if result.get("status") == "delivered":
        response = dict(VMQ_SUCCESS_RESPONSE)
        response["duplicate"] = bool(result.get("duplicate"))
        return response
    if result.get("status") != "delivered":
        logger.warning("VMQ payment event not delivered: status=%s amount=%s event=%s", result.get("status"), amount, event_id)
        return {"code": -1, "msg": "no match"}
    return {"code": -1, "msg": "delivery failed"}


# ── JSON webhook (alternative callback format) ────────────────────

@router.post("/api/payment/webhook")
@limiter.limit("120/minute")
async def payment_webhook(request: Request):
    """JSON webhook for manual/external payment callbacks."""
    if not config.VMQ_WEBHOOK_SECRET:
        logger.error("JSON payment webhook rejected because VMQ_WEBHOOK_SECRET is not configured")
        return JSONResponse({"ok": False, "error": "webhook disabled"}, status_code=503)
    content_length = request.headers.get("content-length", "")
    if content_length:
        try:
            declared_length = int(content_length)
            if declared_length < 0:
                return JSONResponse({"ok": False, "error": "invalid content-length"}, status_code=400)
            if declared_length > MAX_PAYMENT_BODY_BYTES:
                return JSONResponse({"ok": False, "error": "payload too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"ok": False, "error": "invalid content-length"}, status_code=400)
    body_bytes = await request.body()
    if len(body_bytes) > MAX_PAYMENT_BODY_BYTES:
        return JSONResponse({"ok": False, "error": "payload too large"}, status_code=413)
    if not _valid_json_webhook_signature(body_bytes, request.headers.get("X-VisionForge-Signature", "")):
        return JSONResponse({"ok": False, "error": "bad signature"}, status_code=401)
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "invalid payload"}, status_code=400)
    amount_str = _payload_amount(payload)
    if not amount_str:
        return JSONResponse({"ok": False, "error": "missing amount"}, status_code=400)

    amount = _parse_positive_amount(amount_str)
    if amount is None:
        return JSONResponse({"ok": False, "error": "bad amount"}, status_code=400)

    event_id = build_payment_event_id("json", payload, body_bytes)
    result = await run_in_threadpool(process_payment_event, "json", event_id, amount, payload)
    logger.info(
        "payment callback processed trace_id=%s source=json status=%s order_id=%s method=%s late_settlement=%s",
        str(getattr(request.state, "trace_id", "") or ""),
        result.get("status"),
        result.get("order_id", 0),
        result.get("payment_method", ""),
        bool(result.get("late_settlement")),
    )
    status = str(result.get("status") or "")
    status_code = 409 if status in RETRYABLE_PAYMENT_STATUSES or status == "idempotency_conflict" else 200
    return JSONResponse(result, status_code=status_code)
