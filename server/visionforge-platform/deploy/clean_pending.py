from app.database import get_connection
from app.services.payment_service import PENDING_ORDER_MATCH_MINUTES

conn = get_connection()
try:
    conn.execute("BEGIN IMMEDIATE")
    n = conn.execute(
        "UPDATE orders SET status = 'cancelled' "
        "WHERE status = 'pending' AND created_at <= datetime('now', ?)",
        (f"-{PENDING_ORDER_MATCH_MINUTES} minutes",),
    ).rowcount
    conn.execute(
        "UPDATE purchase_sessions SET status = 'cancelled' "
        "WHERE status IN ('open', 'pending', 'abandoned') "
        "AND expires_at <= datetime('now')"
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
print(f"Cancelled {n} stale pending orders")
