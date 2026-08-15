"""V免签 payment integration — fixed-price QR codes and idempotent delivery.

Each plan has a fixed price with a pre-set-amount WeChat QR code.
When a payment comes in, record a unique payment event before matching.
"""
from __future__ import annotations

import logging
import hashlib
import json
import secrets
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import datetime, timedelta
from typing import Any, Optional

from app.database import get_connection
from app.services.payment_channels import (
    DEFAULT_PAYMENT_METHOD,
    normalize_payment_method,
    payment_method_storage_aliases,
)
from app.services.payment_qr_service import payment_qr_ready
from app.services.time_credit_service import MAX_CREDIT_SECONDS

logger = logging.getLogger("payment.vmq")


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    price: float
    desc: str
    qr_file: str  # e.g. "wechat_qr_week.png"

PLANS = [
    Plan("1h",    "1小时",    0.75,   "试用尝鲜",           "wechat_qr_1h.png"),
    Plan("5h",    "5小时",    3.00,   "轻度用户首选",        "wechat_qr_5h.png"),
    Plan("10h",   "10小时",   5.00,   "中度使用推荐",        "wechat_qr_10h.png"),
    Plan("50h",   "50小时",   20.00,  "重度玩家必备",        "wechat_qr_50h.png"),
    Plan("100h",  "100小时",  35.00,  "最超值包",           "wechat_qr_100h.png"),
]

PLAN_HOURS = {
    "1h": 1, "5h": 5, "10h": 10, "50h": 50, "100h": 100,
}

PLAN_SECONDS = {k: v * 3600 for k, v in PLAN_HOURS.items()}

PLAN_BY_KEY: dict[str, Plan] = {p.key: p for p in PLANS}
OPEN_PURCHASE_SESSION_MINUTES = 5
PENDING_ORDER_MATCH_MINUTES = 15
PAYMENT_AMOUNT_SLOT_COUNT = 1
PAYMENT_AMOUNT_REUSE_MINUTES = PENDING_ORDER_MATCH_MINUTES
LEGACY_VMQ_REPLAY_GUARD_MINUTES = PENDING_ORDER_MATCH_MINUTES
SETTLEABLE_ORDER_STATUSES = {"pending", "cancelled", "expired"}
RETRYABLE_PAYMENT_EVENT_STATUSES = {"received", "unmatched", "ambiguous", "order_not_found"}
PROVIDER_TRADE_KEYS = (
    "trade_no",
    "transaction_id",
    "provider_trade_no",
    "payment_trade_no",
    "pay_id",
    "bill_id",
    "payment_id",
    "transaction_no",
)
MERCHANT_ORDER_KEYS = (
    "merchant_order_no",
    "out_trade_no",
    "mch_order_no",
    "order_no",
    "order_sn",
    "order_id",
)
PAYMENT_METHOD_KEYS = (
    "payment_method",
    "pay_method",
    "pay_type",
    "channel",
    "method",
    "type",
)
MAX_PAYMENT_FIELD_LENGTH = 255
MAX_PAYMENT_EVENT_ID_LENGTH = 255


class PaymentSlotOccupiedError(RuntimeError):
    """Raised when a fixed channel/amount slot is still reserved."""

    error_code = "PAYMENT_SLOT_OCCUPIED"

    def __init__(self, plan_key: str, payment_method: str, created_at: str):
        self.plan_key = str(plan_key or "")
        self.payment_method = str(payment_method or "")
        self.available_at = _slot_available_at(created_at)
        self.remaining_seconds = max(0, int((self.available_at - datetime.utcnow()).total_seconds()))
        super().__init__(
            f"fixed payment amount for plan {self.plan_key!r} and method "
            f"{self.payment_method!r} is occupied for {self.remaining_seconds} seconds"
        )

    @property
    def available_at_text(self) -> str:
        return self.available_at.strftime("%Y-%m-%d %H:%M:%S")


def plan_qr_ready(plan: Plan, payment_method: str = DEFAULT_PAYMENT_METHOD) -> bool:
    return payment_qr_ready(plan.key, payment_method)


def expire_stale_pending_orders(conn=None) -> None:
    own_conn = conn is None
    if conn is None:
        conn = get_connection()
    try:
        conn.execute(
            "UPDATE purchase_sessions SET status = 'expired' "
            "WHERE order_id IS NULL AND status = 'open' "
            "AND created_at <= datetime('now', ?)",
            (f"-{OPEN_PURCHASE_SESSION_MINUTES} minutes",),
        )
        conn.execute(
            "UPDATE purchase_sessions SET status = 'expired' "
            "WHERE order_id IS NULL AND status = 'pending'"
        )
        _cancel_stale_pending_orders(conn)
        if own_conn:
            conn.commit()
    finally:
        if own_conn:
            conn.close()


def _cancel_stale_pending_orders(conn) -> None:
    stale_rows = conn.execute(
        "SELECT id FROM orders WHERE status = 'pending' "
        "AND created_at <= datetime('now', ?)",
        (f"-{PENDING_ORDER_MATCH_MINUTES} minutes",),
    ).fetchall()
    stale_ids = [int(row["id"]) for row in stale_rows]
    if not stale_ids:
        return
    placeholders = ",".join("?" for _ in stale_ids)
    conn.execute(
        f"UPDATE purchase_sessions SET status = 'expired' "
        f"WHERE order_id IN ({placeholders}) AND status NOT IN ('delivered', 'cancelled')",
        stale_ids,
    )
    conn.execute(
        f"UPDATE orders SET status = 'expired' WHERE id IN ({placeholders}) AND status = 'pending'",
        stale_ids,
    )


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return json.dumps(str(value), ensure_ascii=False)


def _payload_value(
    payload: dict[str, Any],
    keys: tuple[str, ...],
    *,
    max_length: int | None = MAX_PAYMENT_FIELD_LENGTH,
) -> str:
    lowered = {str(k).lower(): str(v).strip() for k, v in payload.items() if v is not None}
    for key in keys:
        value = lowered.get(key)
        if value:
            return value[:max_length] if max_length is not None else value
    return ""


def extract_payment_fields(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "merchant_order_no": _payload_value(payload, MERCHANT_ORDER_KEYS),
        "provider_trade_no": _payload_value(payload, PROVIDER_TRADE_KEYS),
        "payment_method": _payload_value(payload, PAYMENT_METHOD_KEYS),
    }


def _has_explicit_payment_method(payload: dict[str, Any]) -> bool:
    lowered = {str(key).lower(): value for key, value in payload.items()}
    return any(str(lowered.get(key) or "").strip() for key in PAYMENT_METHOD_KEYS)


def build_payment_event_id(source: str, payload: dict[str, Any], raw_body: bytes | None = None) -> str:
    """Build a stable idempotency key from provider fields, falling back to body hash."""
    provider_trade_no = _payload_value(payload, PROVIDER_TRADE_KEYS, max_length=None)
    merchant_order_no = _payload_value(payload, MERCHANT_ORDER_KEYS, max_length=None)
    if provider_trade_no:
        return _payment_reference_event_id(source, "trade", provider_trade_no)
    if merchant_order_no:
        return _payment_reference_event_id(source, "order", merchant_order_no)
    body = _canonical_json(payload).encode("utf-8") if payload else (raw_body or b"")
    digest = hashlib.sha256(body).hexdigest()
    return f"{source}:sha256:{digest}"


def _payment_reference_event_id(source: str, kind: str, value: str) -> str:
    event_id = f"{source}:{kind}:{value}"
    if len(event_id) <= MAX_PAYMENT_EVENT_ID_LENGTH:
        return event_id
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{source}:{kind}:sha256:{digest}"


def generate_merchant_order_no(order_id: int) -> str:
    return f"VF{datetime.utcnow():%Y%m%d}{int(order_id):08d}{secrets.token_hex(2).upper()}"


def _money_to_fen(value: Any) -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("invalid payment amount") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("invalid payment amount")
    return int(amount * 100)


def _fen_to_amount(value: int) -> float:
    return float(Decimal(int(value)) / Decimal(100))


def _ensure_fixed_amount_slot_available_locked(conn, plan: Plan, payment_method: str) -> None:
    aliases = payment_method_storage_aliases(payment_method)
    placeholders = ",".join("?" for _ in aliases)
    existing = conn.execute(
        "SELECT orders.id, "
        "CASE WHEN orders.status = 'delivered' THEN time_recharges.created_at "
        "ELSE orders.created_at END AS created_at "
        "FROM orders "
        "LEFT JOIN time_recharges ON time_recharges.order_id = orders.id "
        "WHERE orders.plan = ? "
        f"AND orders.payment_method IN ({placeholders}) "
        "AND ("
        "  (orders.status IN ('pending', 'cancelled', 'expired') "
        "   AND orders.created_at > datetime('now', ?)) "
        "  OR "
        "  (orders.status = 'delivered' "
        "   AND time_recharges.created_at > datetime('now', ?))"
        ") "
        "ORDER BY created_at DESC, orders.id DESC LIMIT 1",
        (
            plan.key,
            *aliases,
            f"-{PAYMENT_AMOUNT_REUSE_MINUTES} minutes",
            f"-{PAYMENT_AMOUNT_REUSE_MINUTES} minutes",
        ),
    ).fetchone()
    if existing:
        raise PaymentSlotOccupiedError(plan.key, payment_method, str(existing["created_at"] or ""))


def _slot_available_at(created_at: str) -> datetime:
    try:
        started_at = datetime.strptime(str(created_at or ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        started_at = datetime.utcnow()
    return started_at + timedelta(minutes=PAYMENT_AMOUNT_REUSE_MINUTES)


def create_order_record(conn, user_id: int, plan_key: str, amount: float, ip_address: str = "", payment_method: str = "vmq") -> tuple[int, str]:
    plan = PLAN_BY_KEY.get(plan_key)
    if not plan:
        raise ValueError("unsupported payment plan")
    if not conn.execute(
        "SELECT id FROM users WHERE id = ? AND status = 'active' AND deleted_at IS NULL",
        (int(user_id),),
    ).fetchone():
        raise LookupError("user not found")
    normalized_payment_method = normalize_payment_method(payment_method, default=DEFAULT_PAYMENT_METHOD)
    if not normalized_payment_method:
        raise ValueError("unsupported payment method")
    _ensure_fixed_amount_slot_available_locked(conn, plan, normalized_payment_method)
    allocated_amount = _fen_to_amount(_money_to_fen(plan.price))
    cursor = conn.execute(
        "INSERT INTO orders (user_id, plan, amount, ip_address, payment_method) VALUES (?, ?, ?, ?, ?)",
        (user_id, plan_key, allocated_amount, ip_address, normalized_payment_method),
    )
    order_id = int(cursor.lastrowid)
    merchant_order_no = generate_merchant_order_no(order_id)
    conn.execute(
        "UPDATE orders SET merchant_order_no = ? WHERE id = ?",
        (merchant_order_no, order_id),
    )
    return order_id, merchant_order_no


def _plan_for_amount(price: float) -> Plan | None:
    try:
        received_fen = _money_to_fen(price)
    except ValueError:
        return None
    for plan in PLANS:
        base_fen = _money_to_fen(plan.price)
        if base_fen <= received_fen < base_fen + PAYMENT_AMOUNT_SLOT_COUNT:
            return plan
    return None


def _orders_for_amount_locked(conn, amount: float, payment_method: str = ""):
    amount_fen = _money_to_fen(amount)
    aliases = payment_method_storage_aliases(payment_method)
    channel_filter = ""
    params: list[Any] = [amount_fen]
    if aliases:
        placeholders = ",".join("?" for _ in aliases)
        channel_filter = f"AND payment_method IN ({placeholders}) "
        params.extend(aliases)
    params.append(f"-{PAYMENT_AMOUNT_REUSE_MINUTES} minutes")
    return conn.execute(
        "SELECT id, status FROM orders "
        "WHERE CAST(ROUND(amount * 100.0) AS INTEGER) = ? "
        + channel_filter +
        "AND status IN ('pending', 'cancelled', 'expired') "
        "AND created_at > datetime('now', ?) "
        "ORDER BY created_at DESC, id DESC LIMIT 2",
        params,
    ).fetchall()


def _has_recent_vmq_amount_delivery_locked(
    conn,
    amount_fen: int,
    payment_method: str,
) -> bool:
    aliases = payment_method_storage_aliases(payment_method)
    if not aliases:
        return False
    placeholders = ",".join("?" for _ in aliases)
    return bool(conn.execute(
        "SELECT 1 FROM payment_events "
        "WHERE source = 'vmq' AND status = 'delivered' "
        "AND CAST(ROUND(amount * 100.0) AS INTEGER) = ? "
        f"AND payment_method IN ({placeholders}) "
        "AND processed_at > datetime('now', ?) "
        "LIMIT 1",
        (
            amount_fen,
            *aliases,
            f"-{LEGACY_VMQ_REPLAY_GUARD_MINUTES} minutes",
        ),
    ).fetchone())


def _find_order_by_reference_locked(conn, reference: str):
    reference = str(reference or "").strip()
    if not reference:
        return None
    order = conn.execute(
        "SELECT id, plan, status, user_id, amount, merchant_order_no, payment_method FROM orders WHERE merchant_order_no = ?",
        (reference,),
    ).fetchone()
    if order:
        return order
    if reference.isdigit():
        return conn.execute(
            "SELECT id, plan, status, user_id, amount, merchant_order_no, payment_method FROM orders WHERE id = ?",
            (int(reference),),
        ).fetchone()
    return None


def deliver_order_locked(
    conn,
    order_id: int,
    delivered_by: str = "payment",
    trade_no: str = "",
    payment_method: str = "",
) -> dict | None:
    """Deliver an order inside an existing BEGIN IMMEDIATE transaction."""
    order = conn.execute(
        "SELECT id, plan, status, user_id, amount, merchant_order_no FROM orders WHERE id = ?",
        (order_id,),
    ).fetchone()
    if not order or order["status"] not in SETTLEABLE_ORDER_STATUSES:
        logger.info("Order #%d already %s; delivery skipped", order_id, order["status"] if order else "not_found")
        return None

    recipient = conn.execute(
        "SELECT status, deleted_at FROM users WHERE id = ?",
        (int(order["user_id"]),),
    ).fetchone()
    if not recipient or recipient["deleted_at"] is not None or str(recipient["status"]) != "active":
        conn.execute(
            "UPDATE orders SET status = 'refund_required' "
            "WHERE id = ? AND status IN ('pending', 'cancelled', 'expired')",
            (order_id,),
        )
        conn.execute(
            "UPDATE purchase_sessions SET status = 'cancelled' "
            "WHERE order_id = ? AND status != 'delivered'",
            (order_id,),
        )
        logger.warning("Order #%d requires refund because its account is unavailable", order_id)
        return None

    late_settlement = str(order["status"] or "") in {"cancelled", "expired"}

    seconds = PLAN_SECONDS.get(order["plan"], 3600)
    balance = conn.execute(
        "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
        (int(order["user_id"]),),
    ).fetchone()
    current_balance = int(balance["balance_seconds"] if balance else 0)
    if current_balance + seconds > MAX_CREDIT_SECONDS:
        conn.execute(
            "UPDATE orders SET status = 'refund_required' "
            "WHERE id = ? AND status IN ('pending', 'cancelled', 'expired')",
            (order_id,),
        )
        conn.execute(
            "UPDATE purchase_sessions SET status = 'cancelled' "
            "WHERE order_id = ? AND status != 'delivered'",
            (order_id,),
        )
        logger.warning("Order #%d requires refund because credit would exceed maximum balance", order_id)
        return None

    recharge = conn.execute(
        "INSERT OR IGNORE INTO time_recharges (user_id, order_id, hours, seconds, amount) "
        "VALUES (?, ?, ?, ?, ?)",
        (order["user_id"], order_id, seconds / 3600.0, seconds, order["amount"]),
    )
    if recharge.rowcount != 1:
        existing_recharge = conn.execute(
            "SELECT seconds FROM time_recharges WHERE order_id = ? LIMIT 1",
            (order_id,),
        ).fetchone()
        if not existing_recharge:
            raise RuntimeError(f"duplicate recharge row for order #{order_id}")
        conn.execute(
            "UPDATE orders SET status = 'delivered', "
            "yungouos_trade_no = CASE WHEN ? != '' THEN ? ELSE yungouos_trade_no END, "
            "payment_method = CASE WHEN ? != '' THEN ? ELSE payment_method END "
            "WHERE id = ? AND status IN ('pending', 'cancelled', 'expired')",
            (trade_no, trade_no, payment_method or delivered_by, payment_method or delivered_by, order_id),
        )
        conn.execute(
            "UPDATE purchase_sessions SET status = 'delivered' "
            "WHERE order_id = ? AND status != 'delivered'",
            (order_id,),
        )
        logger.warning("Order #%d had an existing recharge row; marked delivered without adding balance again", order_id)
        return {
            "user_id": order["user_id"],
            "plan": order["plan"],
            "seconds": int(existing_recharge["seconds"] or seconds),
            "order_id": order_id,
            "merchant_order_no": order["merchant_order_no"],
            "provider_trade_no": trade_no,
            "payment_method": payment_method or delivered_by,
            "late_settlement": late_settlement,
        }

    conn.execute(
        "INSERT INTO time_balance (user_id, balance_seconds, total_recharged_seconds) "
        "VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET "
        "balance_seconds = balance_seconds + ?, "
        "total_recharged_seconds = total_recharged_seconds + ?, "
        "updated_at = datetime('now')",
        (order["user_id"], seconds, seconds, seconds, seconds),
    )
    conn.execute(
        "UPDATE orders SET status = 'delivered', "
        "yungouos_trade_no = CASE WHEN ? != '' THEN ? ELSE yungouos_trade_no END, "
        "payment_method = CASE WHEN ? != '' THEN ? ELSE payment_method END "
        "WHERE id = ? AND status IN ('pending', 'cancelled', 'expired')",
        (trade_no, trade_no, payment_method or delivered_by, payment_method or delivered_by, order_id),
    )
    conn.execute(
        "UPDATE purchase_sessions SET status = 'delivered' "
        "WHERE order_id = ? AND status != 'delivered'",
        (order_id,),
    )

    logger.info("Order #%d delivered by %s: user=%d seconds=%d", order_id, delivered_by, order["user_id"], seconds)
    return {
        "user_id": order["user_id"],
        "plan": order["plan"],
        "seconds": seconds,
        "order_id": order_id,
        "merchant_order_no": order["merchant_order_no"],
        "provider_trade_no": trade_no,
        "payment_method": payment_method or delivered_by,
        "late_settlement": late_settlement,
    }


def deliver_order(order_id: int, delivered_by: str = "payment", trade_no: str = "", payment_method: str = "") -> dict | None:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        result = deliver_order_locked(conn, order_id, delivered_by, trade_no, payment_method)
        conn.commit()
        return result
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _undeliverable_order_event_status(conn, order_id: int) -> str:
    row = conn.execute("SELECT status FROM orders WHERE id = ?", (order_id,)).fetchone()
    return "refund_required" if row and row["status"] == "refund_required" else "order_not_pending"


def _finish_payment_event(
    conn,
    event_id: str,
    status: str,
    order_id: int | None = None,
    merchant_order_no: str = "",
    provider_trade_no: str = "",
    payment_method: str = "",
) -> None:
    conn.execute(
        "UPDATE payment_events SET status = ?, order_id = ?, merchant_order_no = ?, "
        "provider_trade_no = ?, payment_method = ?, processed_at = datetime('now') "
        "WHERE event_id = ?",
        (status, order_id, merchant_order_no, provider_trade_no, payment_method, event_id),
    )


def _insert_payment_event(
    conn,
    event_id: str,
    source: str,
    amount: float,
    merchant_order_no: str,
    provider_trade_no: str,
    payment_method: str,
    raw_payload: dict[str, Any],
) -> None:
    serialized_payload = _canonical_json(raw_payload)
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(payment_events)")}
    if "event_key" in columns:
        conn.execute(
            "INSERT INTO payment_events "
            "(event_id, event_key, source, amount, merchant_order_no, provider_trade_no, payment_method, raw_payload, attempt_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (event_id, event_id, source, amount, merchant_order_no, provider_trade_no, payment_method, serialized_payload),
        )
        return
    conn.execute(
        "INSERT INTO payment_events "
        "(event_id, source, amount, merchant_order_no, provider_trade_no, payment_method, raw_payload, attempt_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (event_id, source, amount, merchant_order_no, provider_trade_no, payment_method, serialized_payload),
    )


def process_payment_event(source: str, event_id: str, amount: Any, raw_payload: dict[str, Any]) -> dict[str, Any]:
    amount_fen = _money_to_fen(amount)
    amount = _fen_to_amount(amount_fen)
    fields = extract_payment_fields(raw_payload)
    merchant_order_no = fields["merchant_order_no"]
    provider_trade_no = fields["provider_trade_no"]
    supplied_payment_method = fields["payment_method"] or source
    matching_payment_method = normalize_payment_method(supplied_payment_method)
    payment_method = matching_payment_method or str(supplied_payment_method or "")
    has_invalid_explicit_payment_method = _has_explicit_payment_method(raw_payload) and not matching_payment_method
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT event_id, source, amount, status, order_id, merchant_order_no, provider_trade_no, payment_method "
            "FROM payment_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        is_retry = False
        if existing:
            status = str(existing["status"] or "")
            if status not in RETRYABLE_PAYMENT_EVENT_STATUSES:
                conn.commit()
                return {
                    "ok": True,
                    "duplicate": True,
                    "matched": bool(existing["order_id"]),
                    "status": status,
                    "order_id": existing["order_id"],
                    "merchant_order_no": existing["merchant_order_no"],
                    "provider_trade_no": existing["provider_trade_no"],
                    "payment_method": existing["payment_method"],
                    "event_id": event_id,
                }
            try:
                existing_amount_fen = _money_to_fen(existing["amount"])
            except ValueError:
                existing_amount_fen = -1
            if str(existing["source"] or "") != source or existing_amount_fen != amount_fen:
                conn.commit()
                return {
                    "ok": False,
                    "duplicate": True,
                    "matched": False,
                    "status": "idempotency_conflict",
                    "event_id": event_id,
                }
            is_retry = True
            conn.execute(
                "UPDATE payment_events SET status = 'received', order_id = NULL, amount = ?, "
                "merchant_order_no = ?, provider_trade_no = ?, payment_method = ?, raw_payload = ?, "
                "attempt_count = attempt_count + 1, processed_at = NULL WHERE event_id = ?",
                (amount, merchant_order_no, provider_trade_no, payment_method, _canonical_json(raw_payload), event_id),
            )
        else:
            _insert_payment_event(
                conn,
                event_id,
                source,
                amount,
                merchant_order_no,
                provider_trade_no,
                payment_method,
                raw_payload,
            )
        if has_invalid_explicit_payment_method:
            _finish_payment_event(conn, event_id, "payment_method_mismatch", None, merchant_order_no, provider_trade_no, payment_method)
            conn.commit()
            return {
                "ok": True,
                "duplicate": is_retry,
                "matched": False,
                "status": "payment_method_mismatch",
                "event_id": event_id,
                "merchant_order_no": merchant_order_no,
                "provider_trade_no": provider_trade_no,
                "payment_method": payment_method,
            }
        expire_stale_pending_orders(conn)

        if merchant_order_no:
            order = _find_order_by_reference_locked(conn, merchant_order_no)
            if not order:
                _finish_payment_event(conn, event_id, "order_not_found", None, merchant_order_no, provider_trade_no, payment_method)
                conn.commit()
                return {
                    "ok": True,
                    "duplicate": is_retry,
                    "matched": False,
                    "status": "order_not_found",
                    "event_id": event_id,
                    "merchant_order_no": merchant_order_no,
                    "provider_trade_no": provider_trade_no,
                    "payment_method": payment_method,
                }
            try:
                order_amount_fen = _money_to_fen(order["amount"])
            except ValueError:
                order_amount_fen = -1
            if order_amount_fen != amount_fen:
                _finish_payment_event(conn, event_id, "amount_mismatch", int(order["id"]), order["merchant_order_no"], provider_trade_no, payment_method)
                conn.commit()
                return {
                    "ok": True,
                    "duplicate": is_retry,
                    "matched": True,
                    "status": "amount_mismatch",
                    "order_id": int(order["id"]),
                    "merchant_order_no": order["merchant_order_no"],
                    "provider_trade_no": provider_trade_no,
                    "payment_method": payment_method,
                }
            order_payment_method = normalize_payment_method(order["payment_method"])
            if matching_payment_method and order_payment_method and matching_payment_method != order_payment_method:
                _finish_payment_event(conn, event_id, "payment_method_mismatch", int(order["id"]), order["merchant_order_no"], provider_trade_no, payment_method)
                conn.commit()
                return {
                    "ok": True,
                    "duplicate": is_retry,
                    "matched": True,
                    "status": "payment_method_mismatch",
                    "order_id": int(order["id"]),
                    "merchant_order_no": order["merchant_order_no"],
                    "provider_trade_no": provider_trade_no,
                    "payment_method": payment_method,
                }
            delivery = deliver_order_locked(conn, int(order["id"]), source, provider_trade_no, payment_method)
            if delivery is None:
                event_status = _undeliverable_order_event_status(conn, int(order["id"]))
                _finish_payment_event(conn, event_id, event_status, int(order["id"]), order["merchant_order_no"], provider_trade_no, payment_method)
                conn.commit()
                return {
                    "ok": True,
                    "duplicate": is_retry,
                    "matched": True,
                    "already_processed": True,
                    "status": event_status,
                    "order_id": int(order["id"]),
                    "merchant_order_no": order["merchant_order_no"],
                    "provider_trade_no": provider_trade_no,
                    "payment_method": payment_method,
                    "event_id": event_id,
                }
            _finish_payment_event(conn, event_id, "delivered", int(order["id"]), delivery["merchant_order_no"], provider_trade_no, payment_method)
            conn.commit()
            return {
                "ok": True,
                "duplicate": is_retry,
                "matched": True,
                "status": "delivered",
                "event_id": event_id,
                **delivery,
            }

        plan = _plan_for_amount(amount)
        if not plan:
            _finish_payment_event(conn, event_id, "no_plan", None, merchant_order_no, provider_trade_no, payment_method)
            conn.commit()
            return {
                "ok": True,
                "duplicate": is_retry,
                "matched": False,
                "status": "no_plan",
                "event_id": event_id,
                "provider_trade_no": provider_trade_no,
                "payment_method": payment_method,
            }

        if source == "vmq" and _has_recent_vmq_amount_delivery_locked(
            conn,
            amount_fen,
            matching_payment_method,
        ):
            _finish_payment_event(
                conn,
                event_id,
                "possible_duplicate",
                None,
                merchant_order_no,
                provider_trade_no,
                payment_method,
            )
            conn.commit()
            logger.warning(
                "VMQ payment %.2f on %s was held as a possible replay",
                amount,
                payment_method,
            )
            return {
                "ok": True,
                "duplicate": is_retry,
                "matched": False,
                "status": "possible_duplicate",
                "event_id": event_id,
                "provider_trade_no": provider_trade_no,
                "payment_method": payment_method,
            }

        candidates = _orders_for_amount_locked(conn, amount, matching_payment_method)
        if not candidates:
            _finish_payment_event(conn, event_id, "unmatched", None, merchant_order_no, provider_trade_no, payment_method)
            conn.commit()
            logger.info("Payment %.2f = %s but no recent pending order", amount, plan.key)
            return {"ok": True, "duplicate": is_retry, "matched": False, "status": "unmatched", "event_id": event_id, "provider_trade_no": provider_trade_no, "payment_method": payment_method}
        if len(candidates) > 1:
            _finish_payment_event(conn, event_id, "ambiguous", None, merchant_order_no, provider_trade_no, payment_method)
            conn.commit()
            logger.warning("Payment %.2f = %s matched multiple pending orders; manual review required", amount, plan.key)
            return {"ok": True, "duplicate": is_retry, "matched": False, "status": "ambiguous", "event_id": event_id, "provider_trade_no": provider_trade_no, "payment_method": payment_method}

        order_id = int(candidates[0]["id"])
        delivery = deliver_order_locked(conn, order_id, source, provider_trade_no, payment_method)
        if delivery is None:
            order_row = conn.execute("SELECT merchant_order_no FROM orders WHERE id = ?", (order_id,)).fetchone()
            event_status = _undeliverable_order_event_status(conn, order_id)
            _finish_payment_event(
                conn,
                event_id,
                event_status,
                order_id,
                str(order_row["merchant_order_no"] or "") if order_row else "",
                provider_trade_no,
                payment_method,
            )
            conn.commit()
            return {
                "ok": True,
                "duplicate": is_retry,
                "matched": True,
                "already_processed": True,
                "status": event_status,
                "order_id": order_id,
                "event_id": event_id,
                "provider_trade_no": provider_trade_no,
                "payment_method": payment_method,
            }

        _finish_payment_event(conn, event_id, "delivered", order_id, delivery["merchant_order_no"], provider_trade_no, payment_method)
        conn.commit()
        return {
            "ok": True,
            "duplicate": is_retry,
            "matched": True,
            "status": "delivered",
            "order_id": order_id,
            "event_id": event_id,
            **delivery,
        }
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def find_pending_order_by_price(price: float, payment_method: str = "") -> Optional[int]:
    """Legacy helper: return a pending order only when the amount maps to one order."""
    plan = _plan_for_amount(price)
    if not plan:
        logger.info("No plan matches amount %.2f", price)
        return None
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        expire_stale_pending_orders(conn)
        candidates = [row for row in _orders_for_amount_locked(conn, price, payment_method) if row["status"] == "pending"]
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    if len(candidates) == 1:
        logger.info("Matched %.2f -> %s order #%d", price, plan.key, candidates[0]["id"])
        return int(candidates[0]["id"])
    if len(candidates) > 1:
        logger.warning("Payment %.2f = %s matched multiple pending orders; refusing automatic match", price, plan.key)
    else:
        logger.info("Payment %.2f = %s but no recent pending order", price, plan.key)
    return None
