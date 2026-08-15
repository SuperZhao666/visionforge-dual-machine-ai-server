"""Business rules for the privacy-safe purchase-page status endpoint."""
from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.domain.purchase import PublicPurchaseStatus, PurchaseStatus, PurchaseStatusRecord


PURCHASE_STATUS_TEXT = {
    PurchaseStatus.OPEN: "选择套餐",
    PurchaseStatus.PENDING: "待支付",
    PurchaseStatus.PAID: "已支付，正在到账",
    PurchaseStatus.DELIVERED: "已到账",
    PurchaseStatus.REFUND_REQUIRED: "付款已收到，待退款处理",
    PurchaseStatus.CANCELLED: "已取消",
    PurchaseStatus.EXPIRED: "已过期",
    PurchaseStatus.INVALID: "无效会话",
}
TERMINAL_PURCHASE_STATUSES = {
    PurchaseStatus.DELIVERED,
    PurchaseStatus.REFUND_REQUIRED,
    PurchaseStatus.CANCELLED,
    PurchaseStatus.EXPIRED,
    PurchaseStatus.INVALID,
}
MAX_PURCHASE_TOKEN_LENGTH = 128


class PurchaseStatusRepository(Protocol):
    def find_by_token(self, token: str) -> PurchaseStatusRecord | None:
        """Return the minimal status projection for a purchase token."""


class PurchaseStatusService:
    def __init__(self, repository: PurchaseStatusRepository):
        self._repository = repository

    def get_public_status(self, token: str) -> PublicPurchaseStatus:
        safe_token = _safe_token(token)
        record = self._repository.find_by_token(safe_token) if safe_token else None
        if record is None:
            return self._build_status(PurchaseStatus.INVALID, is_found=False, order_id=0, expires_at="")
        status = self._effective_status(record)
        if status in {PurchaseStatus.OPEN, PurchaseStatus.PENDING, PurchaseStatus.PAID} and _remaining_seconds(record.expires_at) <= 0:
            status = PurchaseStatus.EXPIRED
        return self._build_status(
            status,
            is_found=True,
            order_id=record.order_id,
            expires_at=record.expires_at,
        )

    @staticmethod
    def _effective_status(record: PurchaseStatusRecord) -> PurchaseStatus:
        order_status = _parse_status(record.order_status)
        session_status = _parse_status(record.session_status)
        if order_status in {PurchaseStatus.DELIVERED, PurchaseStatus.REFUND_REQUIRED}:
            return order_status
        if str(record.session_status or "").strip() == "abandoned":
            return PurchaseStatus.CANCELLED
        if session_status in {PurchaseStatus.CANCELLED, PurchaseStatus.EXPIRED}:
            return session_status
        if order_status is not PurchaseStatus.INVALID:
            return order_status
        return session_status

    @staticmethod
    def _build_status(
        status: PurchaseStatus,
        *,
        is_found: bool,
        order_id: int,
        expires_at: str,
    ) -> PublicPurchaseStatus:
        return PublicPurchaseStatus(
            is_found=is_found,
            status=status,
            status_text=PURCHASE_STATUS_TEXT.get(status, PURCHASE_STATUS_TEXT[PurchaseStatus.INVALID]),
            is_terminal=status in TERMINAL_PURCHASE_STATUSES,
            order_id=max(0, int(order_id)),
            expires_at=str(expires_at or ""),
            remaining_seconds=_remaining_seconds(expires_at),
        )


def _parse_status(value: str) -> PurchaseStatus:
    try:
        return PurchaseStatus(str(value or "").strip())
    except ValueError:
        return PurchaseStatus.INVALID


def _safe_token(token: str) -> str:
    safe_token = str(token or "").strip()
    if len(safe_token) > MAX_PURCHASE_TOKEN_LENGTH:
        return ""
    return safe_token


def _remaining_seconds(expires_at: str) -> int:
    try:
        deadline = datetime.strptime(str(expires_at or ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0
    return max(0, int((deadline - datetime.utcnow()).total_seconds()))
