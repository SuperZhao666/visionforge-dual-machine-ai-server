"""On-demand redemption-code issuance and atomic single-use redemption."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.config import config
from app.database import get_connection
from app.domain.growth import IssuanceBatchStatus, RedemptionCodeStatus, TimeCreditSource
from app.services.code_encoding import base32_custom
from app.services.redemption_constants import (
    CODE_ALPHABET,
    CODE_VERSION,
    MAX_BATCH_QUANTITY,
    MAX_ISSUANCE_NOTE_LENGTH,
)
from app.services.time_credit_service import credit_time_locked


CODE_EXPIRY_DAYS_RANGE = (1, 3650)


@dataclass(frozen=True)
class IssuanceResult:
    batch_id: int
    product_key: str
    product_name: str
    duration_seconds: int
    codes: tuple[str, ...]


@dataclass(frozen=True)
class RedemptionResult:
    ok: bool
    credited: bool = False
    error_code: str = ""
    message: str = ""
    code_id: int = 0
    product_key: str = ""
    product_name: str = ""
    credited_seconds: int = 0
    balance_seconds: int = 0
    redeemed_at: str = ""


def issue_codes(
    *,
    product_key: str,
    quantity: int,
    channel: str,
    issuer_type: str,
    issuer_id: int = 0,
    request_key: str = "",
    note: str = "",
    expires_days: int | None = None,
) -> IssuanceResult:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        result = issue_codes_locked(
            conn,
            product_key=product_key,
            quantity=quantity,
            channel=channel,
            issuer_type=issuer_type,
            issuer_id=issuer_id,
            request_key=request_key,
            note=note,
            expires_days=expires_days,
        )
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def issue_codes_locked(
    conn,
    *,
    product_key: str,
    quantity: int,
    channel: str,
    issuer_type: str,
    issuer_id: int = 0,
    request_key: str = "",
    note: str = "",
    expires_days: int | None = None,
) -> IssuanceResult:
    safe_quantity = int(quantity)
    if not 1 <= safe_quantity <= MAX_BATCH_QUANTITY:
        raise ValueError(f"quantity must be between 1 and {MAX_BATCH_QUANTITY}")
    safe_product_key = str(product_key or "").strip().lower()
    if not safe_product_key or len(safe_product_key) > 32:
        raise ValueError("product_key must be between 1 and 32 characters")
    product = conn.execute(
        "SELECT product_key, display_name, duration_seconds FROM duration_products "
        "WHERE product_key = ? AND enabled = 1",
        (safe_product_key,),
    ).fetchone()
    if not product:
        raise LookupError("duration product not found or disabled")

    safe_channel = _bounded_required_text(channel, field_name="channel", max_length=32).lower()
    safe_issuer_type = _bounded_required_text(issuer_type, field_name="issuer_type", max_length=32).lower()
    safe_request_key = str(request_key or "").strip()
    if len(safe_request_key) > 160:
        raise ValueError("request_key must be at most 160 characters")
    safe_request_key = safe_request_key or secrets.token_urlsafe(24)
    safe_note = str(note or "").strip()
    if len(safe_note) > MAX_ISSUANCE_NOTE_LENGTH:
        raise ValueError(f"note must be at most {MAX_ISSUANCE_NOTE_LENGTH} characters")
    expiry = _expiry_text(expires_days)
    existing_batch = conn.execute(
        "SELECT id, product_key, quantity FROM code_issuance_batches WHERE request_key = ?",
        (safe_request_key,),
    ).fetchone()
    if existing_batch:
        if str(existing_batch["product_key"]) != safe_product_key or int(existing_batch["quantity"]) != safe_quantity:
            raise RuntimeError("issuance request idempotency conflict")
        rows = conn.execute(
            "SELECT derivation_ref FROM redemption_codes WHERE batch_id = ? ORDER BY ordinal",
            (existing_batch["id"],),
        ).fetchall()
        return IssuanceResult(
            batch_id=int(existing_batch["id"]),
            product_key=safe_product_key,
            product_name=str(product["display_name"]),
            duration_seconds=int(product["duration_seconds"]),
            codes=tuple(_derive_code(str(row["derivation_ref"])) for row in rows),
        )

    cursor = conn.execute(
        "INSERT INTO code_issuance_batches "
        "(request_key, channel, issuer_type, issuer_id, product_key, quantity, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            safe_request_key,
            safe_channel,
            safe_issuer_type,
            int(issuer_id or 0),
            safe_product_key,
            safe_quantity,
            safe_note,
        ),
    )
    batch_id = int(cursor.lastrowid)
    codes: list[str] = []
    for ordinal in range(1, safe_quantity + 1):
        derivation_ref = f"batch:{batch_id}:item:{ordinal}:product:{safe_product_key}"
        code = _derive_code(derivation_ref)
        conn.execute(
            "INSERT INTO redemption_codes "
            "(batch_id, ordinal, code_digest, code_suffix, key_version, derivation_ref, product_key, "
            "duration_seconds, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                batch_id,
                ordinal,
                _code_digest(code),
                normalize_code(code)[-4:],
                CODE_VERSION,
                derivation_ref,
                safe_product_key,
                int(product["duration_seconds"]),
                RedemptionCodeStatus.ISSUED,
                expiry,
            ),
        )
        codes.append(code)
    return IssuanceResult(
        batch_id=batch_id,
        product_key=safe_product_key,
        product_name=str(product["display_name"]),
        duration_seconds=int(product["duration_seconds"]),
        codes=tuple(codes),
    )


def redeem_code(user_id: int, raw_code: str) -> RedemptionResult:
    normalized = normalize_code(raw_code)
    if not _valid_code(normalized):
        return _redemption_error("CODE_INVALID_OR_USED", "兑换码无效或已被使用")
    digest = _code_digest(normalized)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT rc.*, dp.display_name FROM redemption_codes rc "
            "JOIN duration_products dp ON dp.product_key = rc.product_key WHERE rc.code_digest = ?",
            (digest,),
        ).fetchone()
        if not row:
            conn.rollback()
            return _redemption_error("CODE_INVALID_OR_USED", "兑换码无效或已被使用")

        code_id = int(row["id"])
        status = str(row["status"])
        if status == RedemptionCodeStatus.REDEEMED:
            owner_id = int(row["redeemed_by_user_id"] or 0)
            if owner_id != int(user_id):
                conn.rollback()
                return _redemption_error("CODE_INVALID_OR_USED", "兑换码无效或已被使用")
            balance = _balance_seconds(conn, int(user_id))
            conn.rollback()
            return RedemptionResult(
                ok=True,
                credited=False,
                message="该兑换码已兑换，未重复增加时长",
                code_id=code_id,
                product_key=str(row["product_key"]),
                product_name=str(row["display_name"]),
                credited_seconds=int(row["duration_seconds"]),
                balance_seconds=balance,
                redeemed_at=str(row["redeemed_at"] or ""),
            )
        if status == RedemptionCodeStatus.REVOKED:
            conn.rollback()
            return _redemption_error("CODE_REVOKED", "兑换码已被废止")
        if status == RedemptionCodeStatus.EXPIRED or _is_expired(str(row["expires_at"] or "")):
            if status == RedemptionCodeStatus.ISSUED:
                conn.execute(
                    "UPDATE redemption_codes SET status = ? WHERE id = ?",
                    (RedemptionCodeStatus.EXPIRED, code_id),
                )
                conn.commit()
            else:
                conn.rollback()
            return _redemption_error("CODE_EXPIRED", "兑换码已过期")
        if status != RedemptionCodeStatus.ISSUED:
            conn.rollback()
            return _redemption_error("CODE_INVALID_OR_USED", "兑换码无效或已被使用")

        updated = conn.execute(
            "UPDATE redemption_codes SET status = ?, redeemed_by_user_id = ?, "
            "redeemed_at = datetime('now') WHERE id = ? AND status = ?",
            (RedemptionCodeStatus.REDEEMED, int(user_id), code_id, RedemptionCodeStatus.ISSUED),
        ).rowcount
        if updated != 1:
            conn.rollback()
            return _redemption_error("CODE_INVALID_OR_USED", "兑换码无效或已被使用")
        try:
            credit = credit_time_locked(
                conn,
                user_id=int(user_id),
                seconds=int(row["duration_seconds"]),
                source_type=TimeCreditSource.REDEMPTION,
                source_ref=f"redemption:{code_id}",
            )
        except ValueError as exc:
            conn.rollback()
            if "maximum balance" in str(exc):
                return _redemption_error("BALANCE_LIMIT_EXCEEDED", "账户余额已达到上限，无法兑换该时长")
            raise
        if not credit.credited:
            raise RuntimeError("redemption credit invariant violated")
        redeemed_at = str(
            conn.execute("SELECT redeemed_at FROM redemption_codes WHERE id = ?", (code_id,)).fetchone()["redeemed_at"]
        )
        conn.commit()
        return RedemptionResult(
            ok=True,
            credited=True,
            message="兑换成功",
            code_id=code_id,
            product_key=str(row["product_key"]),
            product_name=str(row["display_name"]),
            credited_seconds=int(row["duration_seconds"]),
            balance_seconds=credit.balance_seconds,
            redeemed_at=redeemed_at,
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def revoke_batch(batch_id: int) -> int:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE redemption_codes SET status = ? WHERE batch_id = ? AND status = ?",
            (RedemptionCodeStatus.REVOKED, int(batch_id), RedemptionCodeStatus.ISSUED),
        ).rowcount
        conn.execute(
            "UPDATE code_issuance_batches SET status = ? WHERE id = ?",
            (IssuanceBatchStatus.REVOKED, int(batch_id)),
        )
        conn.commit()
        return int(changed)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def normalize_code(raw_code: str) -> str:
    return "".join(ch for ch in str(raw_code or "").upper() if ch.isalnum())


def _bounded_required_text(value: object, *, field_name: str, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("channel and issuer_type are required")
    if len(text) > max_length:
        raise ValueError(f"{field_name} must be at most {max_length} characters")
    return text


def code_from_derivation_ref(derivation_ref: str) -> str:
    """Recreate an issued code for an idempotent private issuance retry."""
    return _derive_code(str(derivation_ref))


def _derive_code(derivation_ref: str) -> str:
    digest = hmac.new(_derivation_key(), str(derivation_ref).encode("utf-8"), hashlib.sha256).digest()
    payload = base32_custom(digest[:15], 24)
    checksum = base32_custom(hashlib.sha256(payload.encode("ascii")).digest()[:2], 2)
    body = payload + checksum
    return "VF1-" + "-".join(body[index:index + 4] for index in range(0, len(body), 4))


def _valid_code(normalized: str) -> bool:
    if len(normalized) != 29 or not normalized.startswith("VF1"):
        return False
    body = normalized[3:]
    if any(ch not in CODE_ALPHABET for ch in body):
        return False
    payload, checksum = body[:24], body[24:]
    expected = base32_custom(hashlib.sha256(payload.encode("ascii")).digest()[:2], 2)
    return hmac.compare_digest(checksum, expected)


def _code_digest(raw_code: str) -> str:
    normalized = normalize_code(raw_code)
    digest = hmac.new(_lookup_key(), normalized.encode("ascii", "ignore"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def _secret_material() -> bytes:
    value = str(getattr(config, "REDEMPTION_CODE_SECRET", "") or config.SECRET_KEY)
    return value.encode("utf-8")


def _derivation_key() -> bytes:
    return hmac.new(_secret_material(), b"visionforge:redemption:derive:v1", hashlib.sha256).digest()


def _lookup_key() -> bytes:
    return hmac.new(_secret_material(), b"visionforge:redemption:lookup:v1", hashlib.sha256).digest()


def _expiry_text(expires_days: int | None) -> str | None:
    if expires_days is None:
        return None
    safe_days = int(expires_days)
    if not CODE_EXPIRY_DAYS_RANGE[0] <= safe_days <= CODE_EXPIRY_DAYS_RANGE[1]:
        raise ValueError("expires_days must be between 1 and 3650")
    return (datetime.now(timezone.utc) + timedelta(days=safe_days)).strftime("%Y-%m-%d %H:%M:%S")


def _is_expired(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return datetime.now(timezone.utc) >= parsed


def _balance_seconds(conn, user_id: int) -> int:
    row = conn.execute("SELECT balance_seconds FROM time_balance WHERE user_id = ?", (int(user_id),)).fetchone()
    return int(row["balance_seconds"] if row else 0)


def _redemption_error(error_code: str, message: str) -> RedemptionResult:
    return RedemptionResult(ok=False, error_code=error_code, message=message)
