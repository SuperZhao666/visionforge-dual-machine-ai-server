"""Read-only application queries for growth-facing routes."""
from __future__ import annotations

from dataclasses import dataclass

from app.config import config
from app.database import get_connection


@dataclass(frozen=True)
class InviteLandingInfo:
    invite_code: str
    download_url: str


def is_redemption_enabled() -> bool:
    conn = get_connection()
    try:
        row = conn.execute("SELECT redemption_enabled FROM growth_settings WHERE id = 1").fetchone()
        return bool(row and row["redemption_enabled"])
    finally:
        conn.close()


def list_time_entries(user_id: int, limit: int) -> list[dict]:
    safe_limit = max(1, min(int(limit), 100))
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, seconds, amount, source_type, created_at FROM time_recharges "
            "WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (int(user_id), safe_limit),
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "id": int(row["id"]),
            "seconds": int(row["seconds"]),
            "amount": float(row["amount"]),
            "source_type": str(row["source_type"] or "purchase"),
            "created_at": str(row["created_at"]),
        }
        for row in rows
    ]


def invite_landing_info(invite_code: str) -> InviteLandingInfo | None:
    normalized = str(invite_code or "").strip().upper()
    if not 1 <= len(normalized) <= 32:
        return None
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT ic.code FROM invite_codes ic "
            "JOIN users u ON u.id = ic.user_id "
            "WHERE upper(ic.code) = ? AND ic.status = 'active' "
            "AND u.status = 'active' AND u.deleted_at IS NULL",
            (normalized,),
        ).fetchone()
        settings = conn.execute("SELECT download_url FROM growth_settings WHERE id = 1").fetchone()
    finally:
        conn.close()
    if not row:
        return None
    download_url = str(settings["download_url"] or "") if settings else ""
    return InviteLandingInfo(
        invite_code=str(row["code"]),
        download_url=download_url or f"{str(config.SITE_URL).rstrip('/')}/download",
    )


def latest_download_target() -> str:
    conn = get_connection()
    try:
        release = conn.execute(
            "SELECT installer_url, url FROM releases WHERE channel = 'stable' AND published = 1 "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if release:
        target = str(release["installer_url"] or release["url"] or "").strip()
        if target:
            return target
    return str(config.DOWNLOAD_URL)
