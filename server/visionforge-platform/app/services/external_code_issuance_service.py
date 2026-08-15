"""Issue one server-authoritative redemption code for an opaque external request."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from app.config import config
from app.database import get_connection
from app.services.redemption_service import code_from_derivation_ref, issue_codes_locked


REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
MAX_TRACE_ID_LENGTH = 120


@dataclass(frozen=True)
class ExternalCodeResult:
    issuance_id: int
    trace_id: str
    product_key: str
    product_name: str
    duration_seconds: int
    redemption_code: str
    download_url: str
    duplicate: bool


class ExternalCodeIssuanceError(ValueError):
    def __init__(self, error_code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.status_code = status_code


def issue_external_code(*, product_key: str, request_id: str, trace_id: str = "") -> ExternalCodeResult:
    """Atomically issue one code; retries with the same opaque ID return the same code."""
    safe_product_key = _product_key(product_key)
    safe_request_id = _request_id(request_id)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = _find_existing(conn, safe_request_id)
        if existing:
            result = _existing_result(conn, existing, safe_product_key)
            conn.commit()
            return result
        result = _issue_new(conn, safe_product_key, safe_request_id, trace_id)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _find_existing(conn, request_id: str):
    return conn.execute(
        "SELECT e.id, e.trace_id, e.product_key, rc.derivation_ref, rc.duration_seconds, dp.display_name "
        "FROM external_code_issuances e "
        "JOIN redemption_codes rc ON rc.id = e.redemption_code_id "
        "JOIN duration_products dp ON dp.product_key = e.product_key WHERE e.request_id = ?",
        (request_id,),
    ).fetchone()


def _existing_result(conn, row, requested_product_key: str) -> ExternalCodeResult:
    if str(row["product_key"]) != requested_product_key:
        raise ExternalCodeIssuanceError(
            "IDEMPOTENCY_CONFLICT",
            "该外部请求已绑定其他时长产品，拒绝重复发码",
            409,
        )
    return ExternalCodeResult(
        issuance_id=int(row["id"]),
        trace_id=str(row["trace_id"]),
        product_key=str(row["product_key"]),
        product_name=str(row["display_name"]),
        duration_seconds=int(row["duration_seconds"]),
        redemption_code=code_from_derivation_ref(str(row["derivation_ref"])),
        download_url=_download_url(conn),
        duplicate=True,
    )


def _issue_new(conn, product_key: str, request_id: str, trace_id: str) -> ExternalCodeResult:
    settings = conn.execute("SELECT code_expiry_days FROM growth_settings WHERE id = 1").fetchone()
    try:
        issuance = issue_codes_locked(
            conn,
            product_key=product_key,
            quantity=1,
            channel="integration",
            issuer_type="external_order",
            request_key=f"external:{request_id}",
            note="opaque external order issuance",
            expires_days=int(settings["code_expiry_days"] if settings else 365),
        )
    except LookupError as exc:
        raise ExternalCodeIssuanceError("PRODUCT_NOT_AVAILABLE", "时长产品不存在或已停用", 404) from exc
    code_row = conn.execute(
        "SELECT id FROM redemption_codes WHERE batch_id = ? AND ordinal = 1",
        (issuance.batch_id,),
    ).fetchone()
    safe_trace_id = str(trace_id or "").strip()[:MAX_TRACE_ID_LENGTH] or uuid.uuid4().hex
    cursor = conn.execute(
        "INSERT INTO external_code_issuances "
        "(request_id, product_key, issuance_batch_id, redemption_code_id, trace_id) VALUES (?, ?, ?, ?, ?)",
        (request_id, issuance.product_key, issuance.batch_id, int(code_row["id"]), safe_trace_id),
    )
    return ExternalCodeResult(
        issuance_id=int(cursor.lastrowid),
        trace_id=safe_trace_id,
        product_key=issuance.product_key,
        product_name=issuance.product_name,
        duration_seconds=issuance.duration_seconds,
        redemption_code=issuance.codes[0],
        download_url=_download_url(conn),
        duplicate=False,
    )


def _download_url(conn) -> str:
    row = conn.execute("SELECT download_url FROM growth_settings WHERE id = 1").fetchone()
    configured = str(row["download_url"] or "").strip() if row else ""
    return configured or f"{str(config.SITE_URL).rstrip('/')}/download"


def _product_key(value: str) -> str:
    clean = str(value or "").strip().lower()
    if not clean or len(clean) > 32:
        raise ExternalCodeIssuanceError("INVALID_REQUEST", "product_key 无效")
    return clean


def _request_id(value: str) -> str:
    clean = str(value or "").strip()
    if not REQUEST_ID_RE.fullmatch(clean):
        raise ExternalCodeIssuanceError("INVALID_REQUEST", "request_id 无效")
    return clean
