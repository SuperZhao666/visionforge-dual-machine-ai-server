"""SQLite data access for public purchase-page status."""
from __future__ import annotations

from app.database import get_connection
from app.domain.purchase import PurchaseStatusRecord


class SqlitePurchaseStatusRepository:
    """Read the smallest possible purchase status projection from SQLite."""

    def find_by_token(self, token: str) -> PurchaseStatusRecord | None:
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT ps.status AS session_status, ps.order_id, ps.expires_at, "
                "COALESCE(o.status, '') AS order_status "
                "FROM purchase_sessions ps "
                "LEFT JOIN orders o ON o.id = ps.order_id "
                "WHERE ps.token = ?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        return PurchaseStatusRecord(
            session_status=str(row["session_status"] or ""),
            order_status=str(row["order_status"] or ""),
            order_id=int(row["order_id"] or 0),
            expires_at=str(row["expires_at"] or ""),
        )
