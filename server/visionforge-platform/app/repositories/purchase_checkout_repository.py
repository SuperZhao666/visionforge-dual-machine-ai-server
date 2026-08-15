"""SQLite persistence for the purchase checkout aggregate."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from app.database import get_connection


MAX_PURCHASE_TOKEN_LENGTH = 128


class SqlitePurchaseCheckoutRepository:
    """Keep purchase-session and order SQL behind one narrow repository."""

    @contextmanager
    def transaction(self) -> Iterator[object]:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    @staticmethod
    def account_state(conn, user_id: int) -> tuple[str, str]:
        row = conn.execute(
            "SELECT status, ban_reason, deleted_at FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if not row:
            return "missing", "账号不存在"
        if row["deleted_at"]:
            return "deleted", "\u8d26\u53f7\u5df2\u5220\u9664"
        state = str(row["status"] or "active")
        reason = str(row["ban_reason"] or "")
        return state, reason

    @staticmethod
    def find_recent_pending(conn, user_id: int, match_minutes: int) -> dict | None:
        row = conn.execute(
            "SELECT ps.*, o.created_at AS order_created_at "
            "FROM purchase_sessions ps JOIN orders o ON o.id = ps.order_id "
            "WHERE ps.user_id = ? AND o.status = 'pending' "
            "AND o.created_at > datetime('now', ?) "
            "ORDER BY o.created_at DESC, o.id DESC LIMIT 1",
            (int(user_id), f"-{int(match_minutes)} minutes"),
        ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def find_recent_open(conn, user_id: int, open_minutes: int) -> dict | None:
        row = conn.execute(
            "SELECT * FROM purchase_sessions "
            "WHERE user_id = ? AND status = 'open' AND order_id IS NULL "
            "AND created_at > datetime('now', ?) "
            "ORDER BY created_at DESC, token DESC LIMIT 1",
            (int(user_id), f"-{int(open_minutes)} minutes"),
        ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def cancel_other_active(conn, user_id: int, keep_token: str = "") -> None:
        conn.execute(
            "UPDATE purchase_sessions SET status = 'cancelled' "
            "WHERE user_id = ? AND status IN ('open', 'pending') AND token != ?",
            (int(user_id), str(keep_token or "")),
        )

    @staticmethod
    def revive_pending(conn, token: str, order_created_at: str, ip_address: str) -> dict:
        conn.execute(
            "UPDATE purchase_sessions SET status = 'pending', ip_address = ?, "
            "expires_at = datetime(?, '+15 minutes') WHERE token = ?",
            (str(ip_address or ""), str(order_created_at or ""), str(token or "")),
        )
        return SqlitePurchaseCheckoutRepository.get_checkout(conn, token) or {}

    @staticmethod
    def reuse_open(conn, token: str, created_at: str, ip_address: str) -> dict:
        conn.execute(
            "UPDATE purchase_sessions SET ip_address = ?, "
            "expires_at = datetime(?, '+5 minutes') WHERE token = ?",
            (str(ip_address or ""), str(created_at or ""), str(token or "")),
        )
        return SqlitePurchaseCheckoutRepository.get_checkout(conn, token) or {}

    @staticmethod
    def create_open(conn, token: str, user_id: int, ip_address: str, expires_at: str) -> dict:
        conn.execute(
            "INSERT INTO purchase_sessions "
            "(token, user_id, status, ip_address, expires_at) VALUES (?, ?, 'open', ?, ?)",
            (str(token), int(user_id), str(ip_address or ""), str(expires_at)),
        )
        return SqlitePurchaseCheckoutRepository.get_checkout(conn, token) or {}

    @staticmethod
    def get_checkout(conn, token: str, user_id: int | None = None) -> dict | None:
        user_filter = " AND ps.user_id = ?" if user_id is not None else ""
        params = (str(token or ""), int(user_id)) if user_id is not None else (str(token or ""),)
        row = conn.execute(
            "SELECT ps.token, ps.user_id, ps.order_id, ps.status, ps.ip_address, "
            "ps.created_at, ps.expires_at, "
            "o.plan, o.amount, o.status AS order_status, o.merchant_order_no, "
            "o.payment_method, o.created_at AS order_created_at "
            "FROM purchase_sessions ps LEFT JOIN orders o ON o.id = ps.order_id "
            "WHERE ps.token = ?" + user_filter,
            params,
        ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def attach_order(conn, token: str, order_id: int, expires_at: str) -> bool:
        updated = conn.execute(
            "UPDATE purchase_sessions SET order_id = ?, status = 'pending', expires_at = ? "
            "WHERE token = ? AND order_id IS NULL AND status = 'open'",
            (int(order_id), str(expires_at), str(token or "")),
        )
        return updated.rowcount == 1

    @staticmethod
    def cancel_checkout(conn, token: str) -> dict | None:
        checkout = SqlitePurchaseCheckoutRepository.get_checkout(conn, token)
        if not checkout:
            return None
        order_id = int(checkout.get("order_id") or 0)
        if str(checkout.get("order_status") or "") == "delivered":
            conn.execute(
                "UPDATE purchase_sessions SET status = 'delivered' WHERE token = ?",
                (str(token or ""),),
            )
            return SqlitePurchaseCheckoutRepository.get_checkout(conn, token)
        if order_id:
            conn.execute(
                "UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'",
                (order_id,),
            )
        conn.execute(
            "UPDATE purchase_sessions SET status = 'cancelled' "
            "WHERE token = ? AND status != 'delivered'",
            (str(token or ""),),
        )
        return SqlitePurchaseCheckoutRepository.get_checkout(conn, token)

    @staticmethod
    def transition_checkout_status(
        conn,
        token: str,
        order_id: int | None = None,
        *,
        cancel_order: bool = True,
        session_status: str = "cancelled",
    ) -> None:
        """Compatibility transition used by legacy callers during rollout."""
        safe_token = str(token or "").strip()
        if not safe_token or len(safe_token) > MAX_PURCHASE_TOKEN_LENGTH:
            return
        if order_id and cancel_order:
            conn.execute(
                "UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'",
                (int(order_id),),
            )
        if order_id:
            conn.execute(
                "UPDATE purchase_sessions SET status = ? "
                "WHERE token = ? AND status NOT IN ('delivered', 'cancelled') "
                "AND NOT EXISTS (SELECT 1 FROM orders WHERE id = ? AND status = 'delivered')",
                (str(session_status), safe_token, int(order_id)),
            )
        else:
            conn.execute(
                "UPDATE purchase_sessions SET status = ? "
                "WHERE token = ? AND status NOT IN ('delivered', 'cancelled')",
                (str(session_status), safe_token),
            )

    @staticmethod
    def load_authenticated_status(conn, token: str, user_id: int) -> dict | None:
        checkout = SqlitePurchaseCheckoutRepository.get_checkout(conn, token, user_id)
        if not checkout:
            return None
        order_id = int(checkout.get("order_id") or 0)
        checkout["seconds"] = 0
        if order_id:
            recharge = conn.execute(
                "SELECT seconds FROM time_recharges WHERE order_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (order_id,),
            ).fetchone()
            checkout["seconds"] = int(recharge["seconds"] or 0) if recharge else 0
        balance = conn.execute(
            "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
            (int(user_id),),
        ).fetchone()
        checkout["balance_seconds"] = int(balance["balance_seconds"] or 0) if balance else 0
        return checkout

    @staticmethod
    def read_authenticated_status(token: str, user_id: int) -> dict | None:
        """Read polling state without contending with the payment write transaction."""
        conn = get_connection()
        try:
            return SqlitePurchaseCheckoutRepository.load_authenticated_status(conn, token, user_id)
        finally:
            conn.close()

    @staticmethod
    def list_occupied_slots(conn, reuse_minutes: int) -> list[dict]:
        rows = conn.execute(
            "SELECT orders.plan, orders.payment_method, "
            "CASE WHEN orders.status = 'delivered' THEN time_recharges.created_at "
            "ELSE orders.created_at END AS created_at "
            "FROM orders "
            "LEFT JOIN time_recharges ON time_recharges.order_id = orders.id "
            "WHERE ("
            "  (orders.status IN ('pending', 'cancelled', 'expired') "
            "   AND orders.created_at > datetime('now', ?)) "
            "  OR "
            "  (orders.status = 'delivered' "
            "   AND time_recharges.created_at > datetime('now', ?))"
            ") "
            "ORDER BY created_at DESC, orders.id DESC",
            (
                f"-{int(reuse_minutes)} minutes",
                f"-{int(reuse_minutes)} minutes",
            ),
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def list_payment_exceptions(limit: int = 30) -> list[dict]:
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT id, source, amount, status, order_id, merchant_order_no, "
                "provider_trade_no, payment_method, attempt_count, created_at, processed_at "
                "FROM payment_events "
                "WHERE status IN ("
                "'unmatched', 'ambiguous', 'order_not_found', "
                "'payment_method_mismatch', 'possible_duplicate'"
                ") "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]
