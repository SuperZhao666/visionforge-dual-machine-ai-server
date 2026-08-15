"""Single, idempotent entry point for adding account time."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TimeCreditResult:
    credited: bool
    recharge_id: int
    balance_seconds: int


MAX_CREDIT_SECONDS = 10 * 365 * 24 * 3600


def credit_time_locked(
    conn,
    *,
    user_id: int,
    seconds: int,
    source_type: str,
    source_ref: str,
    amount: float = 0.0,
) -> TimeCreditResult:
    """Add time using the caller's transaction and an idempotency source."""
    safe_user_id = int(user_id)
    safe_seconds = int(seconds)
    safe_source_type = str(source_type or "").strip().lower()
    safe_source_ref = str(source_ref or "").strip()
    if safe_user_id <= 0 or safe_seconds <= 0:
        raise ValueError("user_id and seconds must be positive")
    if safe_seconds > MAX_CREDIT_SECONDS:
        raise ValueError("seconds exceeds maximum credit amount")
    if not safe_source_type or not safe_source_ref:
        raise ValueError("source_type and source_ref are required")
    if not conn.execute(
        "SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL", (safe_user_id,)
    ).fetchone():
        raise LookupError("user not found")

    existing = conn.execute(
        "SELECT id, user_id, seconds FROM time_recharges WHERE source_type = ? AND source_ref = ?",
        (safe_source_type, safe_source_ref),
    ).fetchone()
    if existing:
        if int(existing["user_id"]) != safe_user_id or int(existing["seconds"]) != safe_seconds:
            raise RuntimeError("time credit idempotency conflict")
        return TimeCreditResult(
            credited=False,
            recharge_id=int(existing["id"]),
            balance_seconds=_balance_seconds(conn, safe_user_id),
        )

    current_balance = _balance_seconds(conn, safe_user_id)
    if current_balance + safe_seconds > MAX_CREDIT_SECONDS:
        raise ValueError("credit would exceed maximum balance")

    cursor = conn.execute(
        "INSERT INTO time_recharges "
        "(user_id, hours, seconds, amount, source_type, source_ref) VALUES (?, ?, ?, ?, ?, ?)",
        (
            safe_user_id,
            safe_seconds / 3600.0,
            safe_seconds,
            float(amount),
            safe_source_type,
            safe_source_ref,
        ),
    )
    conn.execute("INSERT OR IGNORE INTO time_balance (user_id) VALUES (?)", (safe_user_id,))
    conn.execute(
        "UPDATE time_balance SET balance_seconds = balance_seconds + ?, "
        "total_recharged_seconds = total_recharged_seconds + ?, updated_at = datetime('now') "
        "WHERE user_id = ?",
        (safe_seconds, safe_seconds, safe_user_id),
    )
    return TimeCreditResult(
        credited=True,
        recharge_id=int(cursor.lastrowid),
        balance_seconds=_balance_seconds(conn, safe_user_id),
    )


def _balance_seconds(conn, user_id: int) -> int:
    row = conn.execute(
        "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
        (int(user_id),),
    ).fetchone()
    return int(row["balance_seconds"] if row else 0)
