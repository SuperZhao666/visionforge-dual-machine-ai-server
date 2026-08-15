"""Stable purchase-session status contracts."""
from __future__ import annotations

from dataclasses import dataclass

from app.domain.growth import ValueStrEnum


class PurchaseStatus(ValueStrEnum):
    OPEN = "open"
    PENDING = "pending"
    PAID = "paid"
    DELIVERED = "delivered"
    REFUND_REQUIRED = "refund_required"
    CANCELLED = "cancelled"
    ABANDONED = "abandoned"
    EXPIRED = "expired"
    INVALID = "invalid"


@dataclass(frozen=True)
class PurchaseStatusRecord:
    """Minimal persistence projection needed to determine public page state."""

    session_status: str
    order_status: str
    order_id: int
    expires_at: str = ""


@dataclass(frozen=True)
class PublicPurchaseStatus:
    """Public, privacy-safe status returned to an unauthenticated purchase page."""

    is_found: bool
    status: PurchaseStatus
    status_text: str
    is_terminal: bool
    order_id: int
    expires_at: str
    remaining_seconds: int

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.is_found,
            "status": self.status.value,
            "status_text": self.status_text,
            "terminal": self.is_terminal,
            "order_id": self.order_id,
            "expires_at": self.expires_at,
            "remaining_seconds": self.remaining_seconds,
        }
