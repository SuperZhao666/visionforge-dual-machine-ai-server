"""Business orchestration for a reusable, single-active purchase checkout."""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from app.services.payment_channels import PAYMENT_CHANNELS, normalize_payment_method
from app.services.payment_qr_service import payment_qr_ready
from app.services.payment_service import (
    OPEN_PURCHASE_SESSION_MINUTES,
    PAYMENT_AMOUNT_REUSE_MINUTES,
    PENDING_ORDER_MATCH_MINUTES,
    PLAN_BY_KEY,
    PLAN_SECONDS,
    PLANS,
    create_order_record,
    expire_stale_pending_orders,
)


logger = logging.getLogger("purchase.checkout")
MAX_PURCHASE_TOKEN_LENGTH = 128


class PurchaseCheckoutRepository(Protocol):
    def transaction(self): ...

    def read_authenticated_status(self, token: str, user_id: int) -> dict | None: ...


class PurchaseCheckoutError(RuntimeError):
    error_code = "PURCHASE_CHECKOUT_ERROR"

    def __init__(self, message: str, *, status_code: int = 400):
        self.status_code = int(status_code)
        super().__init__(message)


class PurchaseCheckoutNotFound(PurchaseCheckoutError):
    error_code = "PURCHASE_CHECKOUT_NOT_FOUND"

    def __init__(self):
        super().__init__("购买会话不存在，请回到客户端重新打开购买页面。", status_code=404)


class PurchaseCheckoutClosed(PurchaseCheckoutError):
    error_code = "PURCHASE_CHECKOUT_CLOSED"


class PurchaseAccountUnavailable(PurchaseCheckoutError):
    error_code = "PURCHASE_ACCOUNT_UNAVAILABLE"

    def __init__(self, account_state: str, message: str):
        self.account_state = str(account_state or "missing")
        super().__init__(message or "账号不可用", status_code=403)


@dataclass(frozen=True)
class CheckoutLink:
    token: str
    status: str
    order_id: int
    expires_at: str
    reused: bool


@dataclass(frozen=True)
class CheckoutPage:
    session: dict | None
    order: dict | None
    payment_options: dict[tuple[str, str], dict[str, object]]


class PurchaseCheckoutService:
    def __init__(self, repository: PurchaseCheckoutRepository):
        self._repository = repository

    def acquire_checkout(self, user_id: int, ip_address: str, trace_id: str = "") -> CheckoutLink:
        with self._repository.transaction() as conn:
            expire_stale_pending_orders(conn)
            account_state, reason = self._repository.account_state(conn, user_id)
            if account_state != "active":
                raise PurchaseAccountUnavailable(account_state, reason)

            pending = self._repository.find_recent_pending(conn, user_id, PENDING_ORDER_MATCH_MINUTES)
            if pending:
                token = str(pending["token"])
                self._repository.cancel_other_active(conn, user_id, token)
                checkout = self._repository.revive_pending(
                    conn,
                    token,
                    str(pending.get("order_created_at") or ""),
                    ip_address,
                )
                result = self._link_from_checkout(checkout, reused=True)
                self._log_event("reused_pending", result, user_id, trace_id)
                return result

            opened = self._repository.find_recent_open(conn, user_id, OPEN_PURCHASE_SESSION_MINUTES)
            if opened:
                token = str(opened["token"])
                self._repository.cancel_other_active(conn, user_id, token)
                checkout = self._repository.reuse_open(
                    conn,
                    token,
                    str(opened.get("created_at") or ""),
                    ip_address,
                )
                result = self._link_from_checkout(checkout, reused=True)
                self._log_event("reused_open", result, user_id, trace_id)
                return result

            token = secrets.token_urlsafe(24)
            expires_at = _utc_text(datetime.utcnow() + timedelta(minutes=OPEN_PURCHASE_SESSION_MINUTES))
            checkout = self._repository.create_open(conn, token, user_id, ip_address, expires_at)
            result = self._link_from_checkout(checkout, reused=False)
            self._log_event("created", result, user_id, trace_id)
            return result

    def get_page(self, token: str) -> CheckoutPage:
        safe_token = _safe_token(token)
        if not safe_token:
            return CheckoutPage(None, None, {})
        with self._repository.transaction() as conn:
            expire_stale_pending_orders(conn)
            checkout = self._repository.get_checkout(conn, safe_token)
            occupied = self._repository.list_occupied_slots(conn, PAYMENT_AMOUNT_REUSE_MINUTES)
        if not checkout:
            return CheckoutPage(None, None, self._payment_options(occupied))
        session, order = _split_checkout(checkout)
        return CheckoutPage(session, order, self._payment_options(occupied))

    def create_order(
        self,
        token: str,
        plan_key: str,
        payment_method: str,
        ip_address: str,
        trace_id: str = "",
    ) -> CheckoutPage:
        safe_token = _safe_token(token)
        plan = PLAN_BY_KEY.get(str(plan_key or "").strip())
        method = normalize_payment_method(payment_method, default="wechat")
        if not plan:
            raise PurchaseCheckoutError("无效套餐。")
        if not method:
            raise PurchaseCheckoutError("无效支付方式。")
        if not payment_qr_ready(plan.key, method):
            raise PurchaseCheckoutError("该支付方式的二维码尚未配置。", status_code=503)

        with self._repository.transaction() as conn:
            expire_stale_pending_orders(conn)
            checkout = self._repository.get_checkout(conn, safe_token)
            if not checkout:
                raise PurchaseCheckoutNotFound()
            account_state, reason = self._repository.account_state(conn, int(checkout["user_id"]))
            if account_state != "active":
                raise PurchaseAccountUnavailable(account_state, reason)
            if checkout.get("order_id"):
                session, order = _split_checkout(checkout)
                return CheckoutPage(session, order, {})
            if str(checkout.get("status") or "") != "open":
                raise PurchaseCheckoutClosed("当前购买会话已结束，请回到客户端重新打开购买页面。")
            if _remaining_seconds(str(checkout.get("expires_at") or "")) <= 0:
                raise PurchaseCheckoutClosed("购买会话已过期，请回到客户端重新打开购买页面。")

            order_id, merchant_order_no = create_order_record(
                conn,
                int(checkout["user_id"]),
                plan.key,
                plan.price,
                ip_address,
                method,
            )
            expires_at = _utc_text(datetime.utcnow() + timedelta(minutes=PENDING_ORDER_MATCH_MINUTES))
            if not self._repository.attach_order(conn, safe_token, order_id, expires_at):
                raise PurchaseCheckoutError("当前购买会话已有订单。", status_code=409)
            checkout = self._repository.get_checkout(conn, safe_token)
            logger.info(
                "purchase checkout order_created trace_id=%s user_id=%s order_id=%s plan=%s method=%s merchant_order_no=%s",
                trace_id,
                checkout.get("user_id") if checkout else 0,
                order_id,
                plan.key,
                method,
                merchant_order_no,
            )
        session, order = _split_checkout(checkout or {})
        return CheckoutPage(session, order, {})

    def cancel_checkout(self, token: str, trace_id: str = "") -> CheckoutPage:
        safe_token = _safe_token(token)
        with self._repository.transaction() as conn:
            expire_stale_pending_orders(conn)
            checkout = self._repository.cancel_checkout(conn, safe_token)
            if not checkout:
                raise PurchaseCheckoutNotFound()
            logger.info(
                "purchase checkout cancelled trace_id=%s user_id=%s order_id=%s",
                trace_id,
                checkout.get("user_id", 0),
                checkout.get("order_id", 0),
            )
        session, order = _split_checkout(checkout)
        return CheckoutPage(session, order, {})

    def acknowledge_abandon(self, token: str, trace_id: str = "") -> None:
        safe_token = _safe_token(token)
        logger.info(
            "purchase checkout abandon_ignored trace_id=%s token_ref=%s",
            trace_id,
            safe_token[:8],
        )

    def get_authenticated_status(self, user_id: int, token: str) -> dict[str, object]:
        safe_token = _safe_token(token)
        checkout = self._repository.read_authenticated_status(safe_token, user_id)
        if not checkout:
            return {"ok": True, "status": "not_found", "message": "purchase session not found"}

        session_status = str(checkout.get("status") or "")
        order_status = str(checkout.get("order_status") or "")
        if order_status in {"delivered", "refund_required"}:
            status = order_status
        elif session_status in {"cancelled", "expired", "abandoned"}:
            status = session_status
        else:
            status = order_status or session_status
        remaining_seconds = _remaining_seconds(str(checkout.get("expires_at") or ""))
        if session_status == "pending" and not int(checkout.get("order_id") or 0):
            status = "expired"
        elif status in {"open", "pending"} and remaining_seconds <= 0:
            status = "expired"
        plan = str(checkout.get("plan") or "")
        message = {
            "open": "waiting for plan selection",
            "pending": "waiting for payment",
            "delivered": "delivered",
            "refund_required": "payment received; refund required",
            "cancelled": "purchase cancelled",
            "expired": "purchase expired",
            "abandoned": "purchase page closed",
        }.get(status, status)
        return {
            "ok": True,
            "status": status,
            "message": message,
            "balance_seconds": int(checkout.get("balance_seconds") or 0),
            "order_id": int(checkout.get("order_id") or 0),
            "plan": plan,
            "amount": float(checkout.get("amount") or 0),
            "seconds": int(checkout.get("seconds") or PLAN_SECONDS.get(plan, 0)),
            "payment_method": normalize_payment_method(checkout.get("payment_method")),
            "expires_at": str(checkout.get("expires_at") or ""),
            "remaining_seconds": remaining_seconds,
        }

    def list_payment_exceptions(self, limit: int = 30) -> list[dict]:
        return self._repository.list_payment_exceptions(limit)

    @staticmethod
    def supported_payment_methods() -> list[str]:
        return [
            channel.key
            for channel in PAYMENT_CHANNELS
            if any(payment_qr_ready(plan.key, channel.key) for plan in PLANS)
        ]

    @staticmethod
    def _link_from_checkout(checkout: dict, *, reused: bool) -> CheckoutLink:
        return CheckoutLink(
            token=str(checkout.get("token") or ""),
            status=str(checkout.get("status") or "open"),
            order_id=int(checkout.get("order_id") or 0),
            expires_at=str(checkout.get("expires_at") or ""),
            reused=bool(reused),
        )

    @staticmethod
    def _payment_options(occupied_rows: list[dict]) -> dict[tuple[str, str], dict[str, object]]:
        options: dict[tuple[str, str], dict[str, object]] = {}
        for plan in PLANS:
            for channel in PAYMENT_CHANNELS:
                if payment_qr_ready(plan.key, channel.key):
                    options[(plan.key, channel.key)] = {
                        "available": True,
                        "available_at": "",
                        "remaining_seconds": 0,
                    }
        for row in occupied_rows:
            key = (str(row.get("plan") or ""), normalize_payment_method(row.get("payment_method")))
            if key not in options or not key[1]:
                continue
            if not bool(options[key].get("available", True)):
                continue
            deadline = _parse_utc(str(row.get("created_at") or "")) + timedelta(minutes=PAYMENT_AMOUNT_REUSE_MINUTES)
            remaining = max(0, int((deadline - datetime.utcnow()).total_seconds()))
            if remaining > 0:
                options[key] = {
                    "available": False,
                    "available_at": _utc_text(deadline),
                    "remaining_seconds": remaining,
                }
        return options

    @staticmethod
    def _log_event(event: str, result: CheckoutLink, user_id: int, trace_id: str) -> None:
        logger.info(
            "purchase checkout %s trace_id=%s user_id=%s order_id=%s status=%s token_ref=%s",
            event,
            trace_id,
            int(user_id),
            result.order_id,
            result.status,
            result.token[:8],
        )


def _split_checkout(checkout: dict) -> tuple[dict, dict | None]:
    session = {
        "token": str(checkout.get("token") or ""),
        "user_id": int(checkout.get("user_id") or 0),
        "order_id": int(checkout.get("order_id") or 0) or None,
        "status": str(checkout.get("status") or "invalid"),
        "ip_address": str(checkout.get("ip_address") or ""),
        "created_at": str(checkout.get("created_at") or ""),
        "expires_at": str(checkout.get("expires_at") or ""),
    }
    if not session["order_id"]:
        return session, None
    order = {
        "id": int(session["order_id"]),
        "plan": str(checkout.get("plan") or ""),
        "amount": float(checkout.get("amount") or 0),
        "status": str(checkout.get("order_status") or ""),
        "merchant_order_no": str(checkout.get("merchant_order_no") or ""),
        "payment_method": str(checkout.get("payment_method") or ""),
        "created_at": str(checkout.get("order_created_at") or ""),
    }
    return session, order


def _safe_token(token: str) -> str:
    safe_token = str(token or "").strip()
    if len(safe_token) > MAX_PURCHASE_TOKEN_LENGTH:
        return ""
    return safe_token


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.strptime(str(value or ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.utcnow()


def _utc_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _remaining_seconds(expires_at: str) -> int:
    return max(0, int((_parse_utc(expires_at) - datetime.utcnow()).total_seconds()))
