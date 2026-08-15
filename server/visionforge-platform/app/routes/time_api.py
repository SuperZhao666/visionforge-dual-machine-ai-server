"""Time-based billing API — register, login, balance, session, heartbeat billing."""
from __future__ import annotations

import hashlib
import logging
import json
import re
import sqlite3
import time
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request
from fastapi.responses import HTMLResponse, JSONResponse
from app.config import config
from app.database import get_connection
from app.security import (
    ACCOUNT_PASSWORD_MAX_LENGTH,
    authenticated_client_rate_key,
    complete_account_login_attempt,
    create_access_token,
    hash_password,
    limiter,
    reserve_account_login_attempt,
    verify_password,
)
from app.services.payment_channels import (
    DEFAULT_PAYMENT_METHOD,
    PAYMENT_CHANNELS,
    normalize_payment_method,
    payment_method_label,
)
from app.services.payment_qr_service import payment_qr_filename, payment_qr_ready
from app.services.payment_service import PLAN_BY_KEY, PLAN_SECONDS, PLANS, PaymentSlotOccupiedError
from app.repositories.purchase_checkout_repository import SqlitePurchaseCheckoutRepository
from app.repositories.purchase_status_repository import SqlitePurchaseStatusRepository
from app.services.purchase_checkout_service import (
    PurchaseAccountUnavailable,
    PurchaseCheckoutError,
    PurchaseCheckoutService,
)
from app.services.purchase_status_service import PurchaseStatusService
from app.templating import templates
from app.services.email_service import (
    VerificationSendStatus,
    consume_verification_code,
    mask_email,
    normalize_email,
    send_verification_code,
)
from app.services.lease_service import (
    MAX_CLIENT_VERSION_LENGTH,
    RuntimeLeaseSigningUnavailable,
    runtime_lease_token_hash,
    sign_runtime_lease,
    verify_runtime_lease,
)
from app.services.auth_session_service import (
    establish_login_locked,
    extend_runtime_block_from_active_sessions_locked,
    invalidate_login_locked,
    new_login_instance_id,
    revoke_user_runtime_sessions_locked,
    validate_login_context_locked,
)
from app.services.log_service import log_upload_policy
from app.services.minimum_client_policy import evaluate_minimum_client_version
from app.services.referral_service import (
    ReferralError,
    apply_referral_locked,
    ensure_invite_code_locked,
)
from app.services.time_credit_service import credit_time_locked
from app.domain.growth import TimeCreditSource

logger = logging.getLogger("time_api")
router = APIRouter()
DEVELOPMENT_UNVERIFIED_MANIFEST_HASH = hashlib.sha256(
    b"visionforge-development-unverified-manifest-v1"
).hexdigest()
PurchaseTokenPath = Annotated[str, Path(min_length=1, max_length=128)]
purchase_status_service = PurchaseStatusService(SqlitePurchaseStatusRepository())
purchase_checkout_service = PurchaseCheckoutService(SqlitePurchaseCheckoutRepository())

# How many seconds per heartbeat tick.
HEARTBEAT_INTERVAL = 5
HEARTBEAT_IDEMPOTENCY_VERSION = "v1"
# Max offline duration before forced re-login (seconds)
MAX_OFFLINE_SECONDS = 45


WELCOME_BONUS_SECONDS = 3600  # 1 hour free for new users
USERNAME_MAX_LENGTH = 64
PASSWORD_MAX_LENGTH = ACCOUNT_PASSWORD_MAX_LENGTH
MAX_DEVICE_CODE_LENGTH = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
RUNTIME_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
MAX_DEVICE_PROFILE_JSON_LENGTH = 8192
MAX_INTEGRITY_FILES_JSON_LENGTH = 20000


class LeaseRenewalTooEarly(ValueError):
    def __init__(self, retry_after_seconds: int):
        super().__init__("runtime lease renewal requested too early")
        self.retry_after_seconds = max(1, int(retry_after_seconds))


def _safe_int(value, default: int = 0, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        result = int(value)
    except Exception:
        result = int(default)
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def _valid_username(value: str) -> bool:
    text = str(value or "").strip()
    return bool(3 <= len(text) <= USERNAME_MAX_LENGTH and USERNAME_RE.fullmatch(text))


def _cancel_purchase_session(
    conn,
    token: str,
    order_id: int | None = None,
    *,
    cancel_order: bool = True,
    session_status: str = "cancelled",
) -> None:
    """Backward-compatible adapter; purchase SQL remains in the repository."""
    SqlitePurchaseCheckoutRepository.transition_checkout_status(
        conn,
        token,
        order_id,
        cancel_order=cancel_order,
        session_status=session_status,
    )


def _account_status(conn, uid: int) -> tuple[str, str]:
    row = conn.execute("SELECT status, ban_reason FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return "missing", "账号不存在"
    status = str(row["status"] or "active")
    reason = str(row["ban_reason"] or "")
    if status == "banned" and not reason:
        reason = "账号已被管理员封禁"
    if status == "disabled" and not reason:
        reason = "账号已被管理员停用"
    return status, reason


def _blocked_response(status: str, reason: str):
    return JSONResponse({
        "ok": False,
        "error": reason or "账号不可用",
        "account_status": status,
        "ban_reason": reason,
    }, status_code=403)


def _valid_email(email: str) -> bool:
    return bool(EMAIL_RE.fullmatch(normalize_email(email)))


def _email_taken(conn, email: str, exclude_user_id: int = 0) -> bool:
    normalized = normalize_email(email)
    if not normalized:
        return False
    row = conn.execute(
        "SELECT id FROM users WHERE lower(email) = lower(?) AND id != ? LIMIT 1",
        (normalized, int(exclude_user_id or 0)),
    ).fetchone()
    return bool(row)


def _email_fields(email: str) -> dict[str, str]:
    normalized = normalize_email(email)
    return {"email": normalized, "masked_email": mask_email(normalized)}


def _account_error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "message": message, "error": message},
        status_code=status_code,
    )


def _verification_send_error(status: VerificationSendStatus) -> JSONResponse:
    if status is VerificationSendStatus.COOLDOWN:
        cooldown_seconds = config.EMAIL_CODE_SEND_COOLDOWN_SECONDS
        return JSONResponse(
            {
                "ok": False,
                "error": "email_code_cooldown",
                "message": f"该邮箱验证码发送过于频繁，请{cooldown_seconds}秒后再试",
            },
            status_code=429,
            headers={"Retry-After": str(cooldown_seconds)},
        )
    if status is VerificationSendStatus.DELIVERY_FAILED:
        return JSONResponse(
            {
                "ok": False,
                "error": "email_delivery_failed",
                "message": "邮件服务未能向该邮箱投递验证码，请确认邮箱地址可正常收信后稍后重试",
            },
            status_code=503,
        )
    raise ValueError(f"Unsupported verification send status: {status}")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _json_within_limit(value, *, max_length: int, fallback: str) -> str:
    try:
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        return fallback
    return serialized if len(serialized) <= max_length else fallback


def _device_profile_json(profile: dict) -> str:
    serialized = _json_within_limit(profile, max_length=MAX_DEVICE_PROFILE_JSON_LENGTH, fallback="")
    if serialized:
        return serialized
    summary = {
        "truncated": True,
        "device_code": str(profile.get("device_code") or "")[:MAX_DEVICE_CODE_LENGTH],
        "client_version": str(profile.get("client_version") or "")[:MAX_CLIENT_VERSION_LENGTH],
        "keys": [str(key)[:80] for key in list(profile.keys())[:64]],
    }
    return _json_within_limit(summary, max_length=MAX_DEVICE_PROFILE_JSON_LENGTH, fallback='{"truncated":true}')


def _integrity_files_json(files: list) -> str:
    kept = []
    serialized = "[]"
    for item in files[:64]:
        candidate = [*kept, item]
        candidate_json = _json_within_limit(candidate, max_length=MAX_INTEGRITY_FILES_JSON_LENGTH, fallback="")
        if not candidate_json:
            break
        kept = candidate
        serialized = candidate_json
    return serialized


def _device_payload(body: dict) -> tuple[str, str, str]:
    code = str(body.get("device_code") or body.get("machine_code") or "").strip().upper()
    client_version = str(body.get("client_version") or "").strip()
    profile = body.get("device_profile")
    if not isinstance(profile, dict):
        profile = {}
    if code and not profile.get("device_code"):
        profile["device_code"] = code
    if client_version and not profile.get("client_version"):
        profile["client_version"] = client_version
    profile_json = _device_profile_json(profile)
    return code, profile_json or "{}", client_version


def _device_code_error_response(device_code: str) -> JSONResponse | None:
    if len(device_code) > MAX_DEVICE_CODE_LENGTH:
        return JSONResponse(
            {"ok": False, "error": "invalid_device_code", "message": "invalid device code"},
            status_code=400,
        )
    return None


def _client_version_error_response(client_version: str) -> JSONResponse | None:
    if len(client_version) > MAX_CLIENT_VERSION_LENGTH:
        return JSONResponse(
            {"ok": False, "error": "invalid_client_version", "message": "invalid client version"},
            status_code=400,
        )
    return None


def _minimum_client_version_error_response(
    conn,
    client_version: str,
) -> JSONResponse | None:
    verdict = evaluate_minimum_client_version(conn, client_version)
    if verdict.allowed:
        return None
    logger.warning(
        "Runtime client version rejected reason=%s client_version=%s minimum=%s",
        verdict.reason,
        verdict.client_version[:MAX_CLIENT_VERSION_LENGTH],
        verdict.minimum_supported_version[:MAX_CLIENT_VERSION_LENGTH],
    )
    return JSONResponse(
        {
            "ok": False,
            "error": "client_update_required",
            "message": "当前客户端版本已停止服务，请更新到官方最新版本。",
            "minimum_supported_version": verdict.minimum_supported_version,
            "client_version": verdict.client_version,
        },
        status_code=426,
    )


def _runtime_security_settings(conn) -> dict:
    row = conn.execute(
        "SELECT enforce_integrity, lease_ttl_seconds FROM runtime_security_settings WHERE id = 1"
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT OR IGNORE INTO runtime_security_settings "
            "(id, enforce_integrity, lease_ttl_seconds) VALUES (1, 0, 15)"
        )
        row = conn.execute(
            "SELECT enforce_integrity, lease_ttl_seconds FROM runtime_security_settings WHERE id = 1"
        ).fetchone()
    ttl = _safe_int(row["lease_ttl_seconds"] if row else 15, 15, minimum=15, maximum=15)
    database_enforced = bool(row["enforce_integrity"] if row else 0)
    production_enforced = bool(config.REQUIRE_RUNTIME_INTEGRITY)
    return {
        "enforce_integrity": database_enforced or production_enforced,
        "database_enforced": database_enforced,
        "production_enforced": production_enforced,
        "lease_ttl_seconds": ttl,
        "single_active_session": True,
    }


def _integrity_payload(body: dict) -> dict:
    raw = body.get("integrity") if isinstance(body, dict) else None
    if not isinstance(raw, dict):
        raw = {}
    manifest_hash = str(raw.get("manifest_hash") or body.get("integrity_manifest_hash") or "").strip().lower()[:128]
    files = raw.get("files")
    if not isinstance(files, list):
        files = []
    files_json = _integrity_files_json(files)
    return {
        "manifest_hash": manifest_hash,
        "files_json": files_json,
        "schema": str(raw.get("schema") or "")[:80],
        "executable_sha256": _normalize_sha256(
            raw.get("executable_sha256") or body.get("executable_sha256")
        ),
        "executable_size": _safe_int(
            raw.get("executable_size") or body.get("executable_size"), 0, minimum=0
        ),
    }


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _normalize_sha256(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if _SHA256_RE.fullmatch(text) else ""


def _lease_bound_manifest_hash(reported_manifest_hash: object) -> str:
    """Return the exact digest bound into a strict v2 runtime lease.

    Production never reaches signing without a valid reported manifest. A
    named development-only sentinel preserves local test/source workflows
    without weakening the formal claim schema or pretending it is attested.
    """
    manifest_hash = _normalize_sha256(reported_manifest_hash)
    if manifest_hash:
        if (
            config.REQUIRE_RUNTIME_INTEGRITY
            and manifest_hash == DEVELOPMENT_UNVERIFIED_MANIFEST_HASH
        ):
            return ""
        return manifest_hash
    if config.REQUIRE_RUNTIME_INTEGRITY:
        return ""
    return DEVELOPMENT_UNVERIFIED_MANIFEST_HASH


def _integrity_files_from_json(files_json: str) -> list[dict]:
    try:
        data = json.loads(files_json or "[]")
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _trusted_executable_hashes_from_files_json(files_json: str) -> set[str]:
    """Read an explicit executable role, or one unambiguous legacy EXE entry."""
    role_hashes: set[str] = set()
    legacy_executables: list[str] = []
    for item in _integrity_files_from_json(files_json):
        path = str(item.get("path") or "").replace("\\", "/").lower()
        role = str(item.get("role") or "").strip().lower()
        digest = _normalize_sha256(item.get("sha256"))
        if not digest:
            continue
        if role == "executable" and path == "@executable":
            role_hashes.add(digest)
        elif path.endswith(".exe"):
            legacy_executables.append(digest)
    if role_hashes:
        return role_hashes
    return {legacy_executables[0]} if len(legacy_executables) == 1 else set()


def _matches_allowlisted_file_hash(conn, integrity: dict, client_version: str) -> bool:
    """Apply the development-only executable-hash compatibility fallback."""
    if config.REQUIRE_RUNTIME_INTEGRITY:
        return False
    explicit_hash = _normalize_sha256(integrity.get("executable_sha256"))
    client_exe_hashes = (
        {explicit_hash}
        if explicit_hash
        else _trusted_executable_hashes_from_files_json(str(integrity.get("files_json") or ""))
    )
    if not client_exe_hashes:
        return False
    rows = conn.execute(
        "SELECT file_hashes_json FROM client_integrity_allowlist "
        "WHERE enabled = 1 AND (client_version = ? OR client_version = '*')",
        (str(client_version or ""),),
    ).fetchall()
    for row in rows:
        allowed_exe_hashes = _trusted_executable_hashes_from_files_json(
            str(row["file_hashes_json"] or "")
        )
        if allowed_exe_hashes and client_exe_hashes.intersection(allowed_exe_hashes):
            return True
    return False


def _check_client_integrity(conn, body: dict, client_version: str) -> dict:
    settings = _runtime_security_settings(conn)
    production_enforced = bool(settings["production_enforced"])
    integrity = _integrity_payload(body)
    manifest_hash = integrity["manifest_hash"]
    lease_manifest_hash = _lease_bound_manifest_hash(manifest_hash)
    if (
        production_enforced
        and _normalize_sha256(manifest_hash)
        == DEVELOPMENT_UNVERIFIED_MANIFEST_HASH
    ):
        return {
            **integrity,
            "lease_manifest_hash": "",
            "accepted": False,
            "status": "development_manifest_forbidden",
            "settings": settings,
        }
    if not manifest_hash:
        if production_enforced:
            return {
                **integrity,
                "lease_manifest_hash": "",
                "accepted": False,
                "status": "missing_integrity",
                "settings": settings,
            }
        if _matches_allowlisted_file_hash(conn, integrity, client_version):
            return {
                **integrity,
                "lease_manifest_hash": lease_manifest_hash,
                "accepted": True,
                "status": "allowlisted_file_hash",
                "settings": settings,
            }
        accepted = not settings["enforce_integrity"]
        return {
            **integrity,
            "lease_manifest_hash": lease_manifest_hash,
            "accepted": accepted,
            "status": "missing_not_enforced" if accepted else "missing_integrity",
            "settings": settings,
        }
    if production_enforced:
        row = conn.execute(
            "SELECT id FROM client_integrity_allowlist "
            "WHERE enabled = 1 AND manifest_hash = ? AND client_version = ? "
            "LIMIT 1",
            (manifest_hash, str(client_version or "")),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM client_integrity_allowlist "
            "WHERE enabled = 1 AND manifest_hash = ? "
            "AND (client_version = ? OR client_version = '*') LIMIT 1",
            (manifest_hash, str(client_version or "")),
        ).fetchone()
    if row:
        status = "allowlisted"
        accepted = True
    elif (
        not production_enforced
        and _matches_allowlisted_file_hash(conn, integrity, client_version)
    ):
        status = "allowlisted_file_hash"
        accepted = True
    else:
        accepted = not settings["enforce_integrity"]
        status = "observed_not_enforced" if accepted else "not_allowlisted"
    return {
        **integrity,
        "lease_manifest_hash": lease_manifest_hash,
        "accepted": accepted,
        "status": status,
        "settings": settings,
    }


def _runtime_security_response(settings: dict, integrity: dict) -> dict:
    return {
        "enforce_integrity": bool(settings.get("enforce_integrity")),
        "lease_ttl_seconds": int(settings.get("lease_ttl_seconds") or 15),
        "single_active_session": True,
        "integrity_status": str(integrity.get("status") or ""),
    }


def _integrity_log_summary(body: dict, integrity: dict, client_version: str, uid: int, machine_code: str, request: Request) -> dict:
    files = _integrity_files_from_json(str(integrity.get("files_json") or "[]"))
    exe_files = []
    for item in files:
        path = str(item.get("path") or "")
        if not path.replace("\\", "/").lower().endswith(".exe"):
            continue
        exe_files.append({
            "path": path[:240],
            "sha256": str(item.get("sha256") or "")[:80],
            "size": _safe_int(item.get("size"), 0, minimum=0),
            "error": str(item.get("error") or "")[:120],
        })
    return {
        "user_id": int(uid or 0),
        "device_code": str(machine_code or body.get("device_code") or "")[:128],
        "client_version": str(client_version or body.get("client_version") or "")[:128],
        "client_ip": _client_ip(request),
        "integrity_status": str(integrity.get("status") or "")[:120],
        "manifest_hash": str(integrity.get("manifest_hash") or "")[:128],
        "executable_sha256": str(integrity.get("executable_sha256") or "")[:80],
        "executable_size": _safe_int(integrity.get("executable_size"), 0, minimum=0),
        "schema": str(integrity.get("schema") or "")[:80],
        "file_count": len(files),
        "exe_files": exe_files[:20],
        "enforce_integrity": bool((integrity.get("settings") or {}).get("enforce_integrity")),
    }


def _log_integrity_rejected(body: dict, integrity: dict, client_version: str, uid: int, machine_code: str, request: Request, endpoint: str) -> None:
    try:
        summary = _integrity_log_summary(body, integrity, client_version, uid, machine_code, request)
        logger.warning("client_integrity_rejected endpoint=%s summary=%s", endpoint, json.dumps(summary, ensure_ascii=False, sort_keys=True))
    except Exception:
        logger.exception("failed to log client integrity rejection")


def _record_user_device(conn, uid: int, request: Request, body: dict, event: str) -> str:
    device_code, profile_json, client_version = _device_payload(body)
    if not device_code:
        return ""
    ip = _client_ip(request)
    heartbeat_inc = 1 if event == "heartbeat" else 0
    login_at = event in {"login", "register"}
    session_at = event in {"session_start", "heartbeat", "session_end"}
    conn.execute(
        "INSERT INTO user_devices "
        "(user_id, device_code, device_profile, client_version, first_ip, last_ip, "
        "last_login_at, last_session_at, heartbeat_count) "
        "VALUES (?, ?, ?, ?, ?, ?, "
        "CASE WHEN ? THEN datetime('now') ELSE NULL END, "
        "CASE WHEN ? THEN datetime('now') ELSE NULL END, ?) "
        "ON CONFLICT(user_id, device_code) DO UPDATE SET "
        "device_profile = CASE WHEN excluded.device_profile != '{}' THEN excluded.device_profile ELSE user_devices.device_profile END, "
        "client_version = CASE WHEN excluded.client_version != '' THEN excluded.client_version ELSE user_devices.client_version END, "
        "last_ip = excluded.last_ip, last_seen_at = datetime('now'), "
        "last_login_at = CASE WHEN ? THEN datetime('now') ELSE user_devices.last_login_at END, "
        "last_session_at = CASE WHEN ? THEN datetime('now') ELSE user_devices.last_session_at END, "
        "heartbeat_count = user_devices.heartbeat_count + ?",
        (
            uid, device_code, profile_json, client_version, ip, ip,
            1 if login_at else 0, 1 if session_at else 0, heartbeat_inc,
            1 if login_at else 0, 1 if session_at else 0, heartbeat_inc,
        ),
    )
    return device_code


def _device_info(body: dict) -> tuple[str, str, str]:
    device_code, profile_json, client_version = _device_payload(body)
    return device_code, profile_json, client_version


def _runtime_instance_id(body: dict) -> str:
    value = str(body.get("runtime_instance_id") or "").strip()
    return value if RUNTIME_INSTANCE_RE.fullmatch(value) else ""


def _runtime_instance_required_response() -> JSONResponse:
    return JSONResponse(
        {
            "ok": False,
            "error": "client_upgrade_required",
            "message": "当前客户端版本不支持单账号单运行实例，请先更新客户端。",
        },
        status_code=426,
    )


def _runtime_lease_signing_unavailable_response() -> JSONResponse:
    return JSONResponse(
        {
            "ok": False,
            "error": "runtime_lease_signing_unavailable",
            "message": "运行授权服务暂时不可用，本次未扣费，请稍后重试。",
        },
        status_code=503,
    )


def _consume_balance_locked(conn, uid: int, seconds: int) -> tuple[bool, int, int]:
    row = conn.execute(
        "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
        (uid,),
    ).fetchone()
    if not row or int(row["balance_seconds"] or 0) <= 0:
        return False, 0, 0
    current = int(row["balance_seconds"] or 0)
    deducted = max(1, int(seconds or HEARTBEAT_INTERVAL))
    if current < deducted:
        return False, current, 0
    new_balance = max(0, current - deducted)
    conn.execute(
        "UPDATE time_balance SET balance_seconds = ?, "
        "total_consumed_seconds = total_consumed_seconds + ?, "
        "last_heartbeat_at = datetime('now'), updated_at = datetime('now') "
        "WHERE user_id = ?",
        (new_balance, deducted, uid),
    )
    return True, new_balance, deducted


def _next_lease_segment(current_expiry: object, lease_ttl_seconds: int) -> tuple[int, int, int]:
    """Build the next paid segment immediately after the last issued segment."""
    current_text = str(current_expiry or "").strip()
    if not current_text:
        raise ValueError("active runtime session is missing lease expiry")
    current_epoch = int(datetime.fromisoformat(current_text.replace("Z", "+00:00")).timestamp())
    segment_limit = max(HEARTBEAT_INTERVAL, int(lease_ttl_seconds))
    desired_expiry = int(time.time()) + segment_limit
    extension = desired_expiry - current_epoch
    if extension < HEARTBEAT_INTERVAL:
        raise LeaseRenewalTooEarly(HEARTBEAT_INTERVAL - extension)
    extension = min(segment_limit, extension)
    return current_epoch, current_epoch + extension, extension


def _balance_seconds_locked(conn, uid: int) -> int:
    row = conn.execute(
        "SELECT balance_seconds FROM time_balance WHERE user_id = ?",
        (uid,),
    ).fetchone()
    return max(0, int(row["balance_seconds"] or 0)) if row else 0


def _heartbeat_identity(body: dict) -> tuple[str, int, str]:
    heartbeat_id = str(body.get("heartbeat_id") or "").strip()
    raw_sequence = body.get("heartbeat_sequence")
    has_id = bool(heartbeat_id)
    has_sequence = raw_sequence is not None and raw_sequence != ""
    if has_id != has_sequence:
        return "", 0, "invalid_heartbeat_identity"
    if not has_id:
        return "", 0, ""
    if isinstance(raw_sequence, bool):
        return "", 0, "invalid_heartbeat_identity"
    try:
        sequence = int(raw_sequence)
    except (TypeError, ValueError):
        return "", 0, "invalid_heartbeat_identity"
    if not 1 <= sequence <= 9_223_372_036_854_775_807:
        return "", 0, "invalid_heartbeat_identity"
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", heartbeat_id):
        return "", 0, "invalid_heartbeat_identity"
    return heartbeat_id, sequence, ""


def _stored_heartbeat_response(raw_response: str) -> dict | None:
    try:
        response = json.loads(str(raw_response or ""))
    except Exception:
        return None
    return response if isinstance(response, dict) and response.get("ok") is True else None


def _log_heartbeat_status(
    request: Request,
    *,
    status: str,
    error: str,
    user_id: int,
    session_id: int,
    sequence: int = 0,
) -> None:
    level = logging.INFO if status in {"ok", "idempotent", "not_due"} else logging.WARNING
    logger.log(
        level,
        "Billing heartbeat status=%s error=%s user=%d session=%d sequence=%d trace_id=%s",
        status,
        error or "none",
        user_id,
        session_id,
        sequence,
        str(getattr(request.state, "trace_id", "") or "none"),
    )


def _close_stale_sessions_locked(conn, uid: int | None = None) -> int:
    params: list[object] = [f"-{MAX_OFFLINE_SECONDS} seconds"]
    where_user = ""
    if uid is not None:
        where_user = "AND user_id = ?"
        params.append(uid)
    stale_users = conn.execute(
        "SELECT DISTINCT user_id FROM time_sessions "
        "WHERE status = 'active' AND COALESCE(last_heartbeat_at, started_at) <= datetime('now', ?) "
        f"{where_user}",
        params,
    ).fetchall()
    for row in stale_users:
        extend_runtime_block_from_active_sessions_locked(conn, int(row["user_id"]))
    return conn.execute(
        "UPDATE time_sessions SET status = 'stale', ended_at = datetime('now'), ended_reason = 'heartbeat_timeout' "
        "WHERE status = 'active' AND COALESCE(last_heartbeat_at, started_at) <= datetime('now', ?) "
        f"{where_user}",
        params,
    ).rowcount


def _auth_uid(request: Request) -> int | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        from app.security import decode_access_token
        payload = decode_access_token(auth[7:])
        return int(payload["sub"])
    except Exception:
        return None


def _auth_error_response(error: str, *, balance_seconds: int | None = None) -> JSONResponse:
    code = str(error or "invalid_token").strip().lower()
    messages = {
        "login_superseded": "账号已在另一台设备或另一个程序实例重新登录，当前登录已失效，请重新登录。",
        "login_device_mismatch": "当前登录令牌与本机设备不匹配，请在本机重新登录。",
        "missing_device_code": "客户端缺少设备标识，请更新客户端后重新登录。",
        "account_disabled": "账号当前不可用，请联系管理员。",
        "invalid_token": "登录状态已失效，请重新登录。",
    }
    status_code = {
        "login_device_mismatch": 409,
        "missing_device_code": 400,
        "account_disabled": 403,
    }.get(code, 401)
    payload: dict[str, object] = {
        "ok": False,
        "error": code,
        "message": messages.get(code, messages["invalid_token"]),
    }
    if balance_seconds is not None:
        payload["balance_seconds"] = max(0, int(balance_seconds))
    return JSONResponse(payload, status_code=status_code)


def _decode_client_payload(request: Request) -> tuple[dict | None, JSONResponse | None]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, _auth_error_response("invalid_token")
    try:
        from app.security import decode_access_token

        return decode_access_token(auth[7:]), None
    except HTTPException as exc:
        detail = str(exc.detail or "invalid_token").strip().lower().replace(" ", "_")
        if detail not in {"login_superseded", "account_disabled"}:
            detail = "invalid_token"
        return None, _auth_error_response(detail)
    except Exception:
        return None, _auth_error_response("invalid_token")


def _public_site_url(request: Request) -> str:
    configured = str(config.SITE_URL or "").strip().rstrip("/")
    if configured and "localhost" not in configured and "127.0.0.1" not in configured:
        if configured.startswith("http://81.70.189.154"):
            return "https://www.visionforge.cloud"
        return configured
    return str(request.base_url).rstrip("/")


def _purchase_remaining_seconds(expires_at: str) -> int:
    try:
        deadline = datetime.strptime(str(expires_at or ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0
    return max(0, int((deadline - datetime.utcnow()).total_seconds()))


def _purchase_page_html(
    token: str,
    session: dict | None,
    order: dict | None = None,
    message: str = "",
    *,
    payment_options: dict[tuple[str, str], dict[str, object]] | None = None,
    error_code: str = "",
) -> str:
    """渲染购买页（模板 app/templates/purchase.html）。

    只负责把会话/订单状态整理成模板上下文；状态语义、表单与轮询契约保持不变。
    """
    safe_token = str(token or "").strip()
    session_status = str(session.get("status") if session else "invalid")
    status_text = {
        "open": "选择套餐",
        "pending": "等待支付",
        "delivered": "已到账",
        "cancelled": "已取消",
        "expired": "已过期",
        "invalid": "无效会话",
    }.get(session_status, session_status)
    payment_options = payment_options or {}
    ctx: dict = {
        "token": safe_token,
        "status_text": status_text,
        "message": str(message or ""),
        "error_code": str(error_code or ""),
        "view": "invalid",
        "order": None,
        "plans": None,
        "poll_mode": None,
        "celebrate": False,
    }

    if order:
        plan = PLAN_BY_KEY.get(str(order.get("plan") or ""))
        payment_method = normalize_payment_method(order.get("payment_method"), default=DEFAULT_PAYMENT_METHOD)
        qr = f"/static/img/{payment_qr_filename(plan.key, payment_method)}" if plan and payment_method else ""
        stored_order_status = str(order.get("status") or session_status)
        order_status = stored_order_status
        if stored_order_status not in {"delivered", "refund_required"} and session_status in {"cancelled", "abandoned", "expired"}:
            order_status = "cancelled" if session_status == "abandoned" else session_status
        order_status_text = {
            "pending": "待支付",
            "paid": "已支付，正在到账",
            "delivered": "已到账",
            "refund_required": "付款已收到，待退款处理",
            "cancelled": "已取消",
            "expired": "已过期",
        }.get(order_status, order_status)
        closed_title = ""
        closed_detail = ""
        if order_status == "cancelled":
            closed_title = "本次订单已取消"
            closed_detail = "需要购买时，请回到客户端重新打开购买页面。"
        elif order_status == "refund_required":
            closed_title = "付款已收到，正在安排退款"
            closed_detail = "该账号当前无法接收时长；请联系管理员处理退款。"
        elif order_status == "expired":
            closed_title = "本次订单已过期"
            closed_detail = "请回到客户端重新创建购买会话。"
        ctx.update(
            view="order",
            order={
                "oid": int(order.get("id") or 0),
                "merchant_order_no": str(order.get("merchant_order_no") or order.get("id") or ""),
                "plan_name": plan.name if plan else str(order.get("plan") or ""),
                "amount": float(order.get("amount") or 0),
                "payment_method": payment_method,
                "payment_label": payment_method_label(payment_method),
                "order_status": order_status,
                "order_status_text": order_status_text,
                "remaining_seconds": _purchase_remaining_seconds(str(session.get("expires_at") or "")),
                "qr": qr,
                "can_cancel": order_status == "pending",
                "closed_title": closed_title,
                "closed_detail": closed_detail,
            },
            poll_mode="order" if order_status == "pending" else None,
            celebrate=order_status == "delivered",
        )
    elif session:
        plans_ctx = []
        for plan in PLANS:
            buttons = []
            for channel in PAYMENT_CHANNELS:
                if not payment_qr_ready(plan.key, channel.key):
                    continue
                option = payment_options.get((plan.key, channel.key), {"available": True, "remaining_seconds": 0})
                label = "支付宝支付" if channel.key == "alipay" else channel.label
                if bool(option.get("available", True)):
                    buttons.append({"key": channel.key, "label": label, "available": True, "busy_text": ""})
                else:
                    remaining = max(0, int(option.get("remaining_seconds") or 0))
                    minutes, seconds = divmod(remaining, 60)
                    buttons.append({
                        "key": channel.key,
                        "label": label,
                        "available": False,
                        "busy_text": f"{label}暂被占用 · {minutes}分{seconds:02d}秒",
                    })
            plans_ctx.append({
                "key": plan.key,
                "name": plan.name,
                "desc": plan.desc,
                "price": plan.price,
                "buttons": buttons,
            })
        ctx.update(view="plans", plans=plans_ctx, poll_mode="plans")

    return templates.get_template("purchase.html").render(**ctx)

@router.post("/api/client/register-code")
async def client_register_code(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    email = normalize_email(str(body.get("email", "")))
    if not _valid_email(email):
        return JSONResponse({"ok": False, "error": "请输入有效邮箱地址"}, status_code=400)

    conn = get_connection()
    try:
        if _email_taken(conn, email):
            return JSONResponse({"ok": False, "error": "该邮箱已绑定其他账号"}, status_code=409)
    finally:
        conn.close()

    send_status = send_verification_code(
        email,
        "register",
        trace_id=str(getattr(request.state, "trace_id", "")),
    )
    if send_status is not VerificationSendStatus.SENT:
        return _verification_send_error(send_status)
    return {"ok": True, "message": "验证码已发送，请查收邮箱"}


@router.post("/api/client/register")
async def client_register(request: Request):
    """Register a new user. Auto-credits 1 hour free time. Returns login token."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    email = normalize_email(str(body.get("email", "")))
    email_code = str(body.get("email_code") or body.get("code") or "").strip()
    invite_code = str(body.get("invite_code") or "").strip().upper()
    device_code, _, client_version = _device_payload(body)
    device_error = _device_code_error_response(device_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error

    if not username or not password or len(password) < 8:
        return JSONResponse({"ok": False, "error": "用户名和密码不能为空，密码至少8位"}, status_code=400)
    if len(username) > USERNAME_MAX_LENGTH:
        return JSONResponse({"ok": False, "error": "用户名不能超过64个字符"}, status_code=400)
    if len(password) > PASSWORD_MAX_LENGTH:
        return JSONResponse({"ok": False, "error": "密码不能超过128个字符"}, status_code=400)
    if not _valid_username(username):
        return JSONResponse({"ok": False, "error": "用户名只能包含字母、数字、下划线和连字符"}, status_code=400)
    if not _valid_email(email):
        return JSONResponse({"ok": False, "error": "注册必须绑定有效邮箱"}, status_code=400)
    if not email_code:
        return JSONResponse({"ok": False, "error": "请输入邮箱验证码"}, status_code=400)

    if len(invite_code) > 32:
        return JSONResponse(
            {"ok": False, "error": "邀请码无效", "error_code": "INVITE_CODE_INVALID"},
            status_code=400,
        )

    pwd_hash = hash_password(password)
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        version_error = _minimum_client_version_error_response(
            conn,
            client_version,
        )
        if version_error is not None:
            conn.execute("ROLLBACK")
            return version_error
        if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            conn.rollback()
            return JSONResponse({"ok": False, "error": "该用户名已被注册"}, status_code=409)
        if _email_taken(conn, email):
            conn.rollback()
            return JSONResponse({"ok": False, "error": "该邮箱已绑定其他账号"}, status_code=409)
        if not consume_verification_code(conn, email, email_code, "register"):
            conn.rollback()
            return JSONResponse({"ok": False, "error": "邮箱验证码错误或已过期"}, status_code=400)

        login_instance_id = new_login_instance_id()
        cursor = conn.execute(
            "INSERT INTO users "
            "(username, email, password_hash, auth_version, login_device_code, login_instance_id, login_started_at) "
            "VALUES (?, ?, ?, 0, ?, ?, datetime('now'))",
            (username, email, pwd_hash, device_code, login_instance_id),
        )
        uid = int(cursor.lastrowid)
        welcome_credit = credit_time_locked(
            conn,
            user_id=uid,
            seconds=WELCOME_BONUS_SECONDS,
            source_type=TimeCreditSource.WELCOME,
            source_ref=f"welcome:{uid}",
        )
        own_invite_code = ensure_invite_code_locked(conn, uid)
        referral_reward = apply_referral_locked(
            conn,
            invitee_user_id=uid,
            invite_code=invite_code,
            registration_event_id=f"registration:{uid}",
            device_code=str(body.get("device_code") or ""),
            ip_address=_client_ip(request),
        )
        if not device_code:
            conn.rollback()
            return _auth_error_response("missing_device_code")
        _record_user_device(conn, uid, request, body, "register")
        upload_policy = log_upload_policy(conn, uid)
        conn.commit()

        token = create_access_token(
            uid,
            False,
            0,
            device_code=device_code,
            login_instance_id=login_instance_id,
            client_version=client_version,
        )
        logger.info(
            "New user registered uid=%d welcome_seconds=%d referral_rewarded=%s device=%s",
            uid,
            WELCOME_BONUS_SECONDS,
            bool(referral_reward),
            device_code,
        )
    except ReferralError as exc:
        conn.rollback()
        return JSONResponse(
            {"ok": False, "error": exc.message, "error_code": exc.error_code},
            status_code=400,
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        logger.warning("Registration uniqueness conflict")
        return JSONResponse({"ok": False, "error": "用户名或邮箱已被注册"}, status_code=409)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "token": token,
        "user_id": uid,
        "username": username,
        **_email_fields(email),
        "balance_seconds": welcome_credit.balance_seconds,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
        "account_status": "active",
        "ban_reason": "",
        "device_code": device_code,
        "login_instance_id": login_instance_id,
        "auth_version": 0,
        "welcome_bonus": True,
        "invite_code": own_invite_code,
        "referral_rewarded": bool(referral_reward),
        "log_upload_policy": upload_policy,
    }


@router.post("/api/client/login")
async def client_login(request: Request):
    """Client login: username + password. Returns token + balance."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    device_code, _, client_version = _device_payload(body)
    device_error = _device_code_error_response(device_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error
    if not username or not password:
        return JSONResponse({"ok": False, "error": "missing fields"}, status_code=400)
    if not device_code:
        return _auth_error_response("missing_device_code")
    if len(username) > USERNAME_MAX_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        return JSONResponse({"ok": False, "error": "用户名或密码错误"}, status_code=401)

    client_ip = _client_ip(request)
    attempt_id, retry_after = reserve_account_login_attempt(username, client_ip)
    if not attempt_id:
        return JSONResponse(
            {
                "ok": False,
                "error": "login_rate_limited",
                "message": "该账号登录失败次数过多，请稍后再试。",
                "retry_after_seconds": retry_after,
            },
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    conn = get_connection()
    try:
        candidate = conn.execute(
            "SELECT id, email, password_hash, is_admin, auth_version, status, ban_reason, deleted_at "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not candidate or not verify_password(password, candidate["password_hash"]):
            complete_account_login_attempt(attempt_id, username, success=False)
            return JSONResponse({"ok": False, "error": "用户名或密码错误"}, status_code=401)
        complete_account_login_attempt(attempt_id, username, success=True)

        conn.execute("BEGIN IMMEDIATE")
        user = conn.execute(
            "SELECT id, email, password_hash, is_admin, auth_version, status, ban_reason, deleted_at "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not user or str(user["password_hash"] or "") != str(candidate["password_hash"] or ""):
            conn.execute("ROLLBACK")
            return JSONResponse({"ok": False, "error": "用户名或密码错误"}, status_code=401)
        uid = int(user["id"])
        if user["deleted_at"] is not None or user["status"] != "active":
            conn.execute("ROLLBACK")
            return _blocked_response(str(user["status"]), str(user["ban_reason"] or "账号不可用"))

        version_error = _minimum_client_version_error_response(
            conn,
            client_version,
        )
        if version_error is not None:
            conn.execute("ROLLBACK")
            return version_error
        login_instance = establish_login_locked(conn, uid, device_code)
        balance = conn.execute(
            "SELECT balance_seconds FROM time_balance WHERE user_id = ?", (uid,)
        ).fetchone()
        if not balance:
            conn.execute(
                "INSERT OR IGNORE INTO time_balance (user_id) VALUES (?)", (uid,)
            )
            balance_seconds = 0
        else:
            balance_seconds = int(balance["balance_seconds"] or 0)

        email = normalize_email(str(user["email"] or ""))
        _record_user_device(conn, uid, request, body, "login")
        upload_policy = log_upload_policy(conn, uid)
        conn.commit()

        token = create_access_token(
            uid,
            bool(user["is_admin"]),
            login_instance.auth_version,
            device_code=device_code,
            login_instance_id=login_instance.login_instance_id,
            client_version=client_version,
        )

        logger.info(
            "Client login: user_id=%d balance=%ds device=%s auth_version=%d revoked_sessions=%d trace_id=%s",
            uid,
            balance_seconds,
            device_code,
            login_instance.auth_version,
            login_instance.revoked_session_count,
            str(getattr(request.state, "trace_id", "") or "none"),
        )

    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "token": token,
        "user_id": uid,
        "username": username,
        **_email_fields(email),
        "balance_seconds": balance_seconds,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
        "account_status": "active",
        "ban_reason": "",
        "device_code": device_code,
        "login_instance_id": login_instance.login_instance_id,
        "auth_version": login_instance.auth_version,
        "log_upload_policy": upload_policy,
    }


@router.get("/api/client/balance")
@limiter.limit("30/minute", key_func=authenticated_client_rate_key)
async def client_balance(request: Request):
    """Get current time balance."""
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    uid = int(payload["sub"])

    conn = get_connection()
    try:
        account_state, ban_reason = _account_status(conn, uid)
        user = conn.execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone()
        email_fields = _email_fields(str(user["email"] or "")) if user else _email_fields("")
        row = conn.execute(
            "SELECT balance_seconds, total_consumed_seconds FROM time_balance WHERE user_id = ?",
            (uid,),
        ).fetchone()
        if not row:
            return {
                "ok": True,
                **email_fields,
                "balance_seconds": 0,
                "total_consumed_seconds": 0,
                "account_status": account_state,
                "ban_reason": ban_reason,
                "heartbeat_interval": HEARTBEAT_INTERVAL,
                "log_upload_policy": log_upload_policy(conn, uid),
            }
        return {
            "ok": True,
            **email_fields,
            "balance_seconds": row["balance_seconds"],
            "total_consumed_seconds": row["total_consumed_seconds"],
            "account_status": account_state,
            "ban_reason": ban_reason,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
            "log_upload_policy": log_upload_policy(conn, uid),
        }
    finally:
        conn.close()


@router.post("/api/client/account/password")
@limiter.limit("10/minute", key_func=authenticated_client_rate_key)
async def client_change_password(request: Request):
    """Change the authenticated user's password and rotate all login tokens."""
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    uid = int(payload["sub"])
    try:
        body = await request.json()
    except Exception:
        return _account_error("请求格式无效", 400)
    if not isinstance(body, dict):
        return _account_error("请求格式无效", 400)

    current_password = str(body.get("current_password") or "")
    new_password = str(body.get("new_password") or "")
    if not current_password or len(current_password) > PASSWORD_MAX_LENGTH:
        return _account_error("请输入当前密码", 400)
    if not 8 <= len(new_password) <= PASSWORD_MAX_LENGTH:
        return _account_error("新密码长度必须为 8 至 128 个字符", 400)
    if current_password == new_password:
        return _account_error("新密码不能与当前密码相同", 400)

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        login_context, login_error = validate_login_context_locked(conn, payload)
        if login_error or login_context is None:
            conn.execute("ROLLBACK")
            return _auth_error_response(login_error)
        user = conn.execute(
            "SELECT email, password_hash, is_admin, auth_version, status, ban_reason, "
            "login_device_code, login_instance_id "
            "FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if not user:
            conn.rollback()
            return _account_error("登录状态已失效，请重新登录", 401)
        if str(user["status"] or "active") != "active":
            conn.rollback()
            return _account_error(str(user["ban_reason"] or "账号不可用"), 403)
        if not verify_password(current_password, str(user["password_hash"] or "")):
            conn.rollback()
            return _account_error("当前密码不正确", 401)

        auth_version = int(user["auth_version"] or 0) + 1
        conn.execute(
            "UPDATE users SET password_hash = ?, auth_version = ?, updated_at = datetime('now') WHERE id = ?",
            (hash_password(new_password), auth_version, uid),
        )
        revoke_user_runtime_sessions_locked(conn, uid, "password_changed")
        conn.commit()
        email = normalize_email(str(user["email"] or ""))
        is_admin = bool(user["is_admin"])
        login_device_code = str(user["login_device_code"] or "")
        login_instance_id = str(user["login_instance_id"] or "")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "message": "密码已更新，其他登录状态已失效",
        "token": create_access_token(
            uid,
            is_admin,
            auth_version,
            device_code=login_device_code,
            login_instance_id=login_instance_id,
            client_version=str(payload.get("ver") or ""),
        ),
        "login_instance_id": login_instance_id,
        "auth_version": auth_version,
        **_email_fields(email),
    }


@router.post("/api/client/logout")
@limiter.limit("20/minute", key_func=authenticated_client_rate_key)
async def client_logout(request: Request):
    """Invalidate the current login generation and every active runtime lease."""
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    device_code, _, client_version = _device_payload(body)
    device_error = _device_code_error_response(device_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        login_context, login_error = validate_login_context_locked(
            conn,
            payload,
            request_device_code=device_code,
            require_device=True,
        )
        if login_error or login_context is None:
            conn.execute("ROLLBACK")
            return _auth_error_response(login_error)
        revoked = invalidate_login_locked(conn, login_context.user_id, "client_logout")
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    logger.info(
        "Client logout: user_id=%d revoked_sessions=%d trace_id=%s",
        login_context.user_id,
        revoked,
        str(getattr(request.state, "trace_id", "") or "none"),
    )
    return {"ok": True}


@router.post("/api/client/account/email-code")
@limiter.limit("5/minute", key_func=authenticated_client_rate_key)
async def client_change_email_code(request: Request):
    """Send a verification code to a new, unbound email address."""
    uid = _auth_uid(request)
    if uid is None:
        return _account_error("登录状态已失效，请重新登录", 401)
    try:
        body = await request.json()
    except Exception:
        return _account_error("请求格式无效", 400)
    if not isinstance(body, dict):
        return _account_error("请求格式无效", 400)

    new_email = normalize_email(str(body.get("new_email") or ""))
    if not _valid_email(new_email):
        return _account_error("请输入有效邮箱地址", 400)

    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT email, status, ban_reason FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if not user:
            return _account_error("登录状态已失效，请重新登录", 401)
        if str(user["status"] or "active") != "active":
            return _account_error(str(user["ban_reason"] or "账号不可用"), 403)
        if normalize_email(str(user["email"] or "")) == new_email:
            return _account_error("新邮箱不能与当前邮箱相同", 400)
        if _email_taken(conn, new_email, uid):
            return _account_error("该邮箱已绑定其他账号", 409)
    finally:
        conn.close()

    send_status = send_verification_code(
        new_email,
        "change_email",
        trace_id=str(getattr(request.state, "trace_id", "")),
    )
    if send_status is not VerificationSendStatus.SENT:
        return _verification_send_error(send_status)
    return {
        "ok": True,
        "message": "验证码已发送，请查收新邮箱",
        **_email_fields(new_email),
    }


@router.post("/api/client/account/email")
@limiter.limit("10/minute", key_func=authenticated_client_rate_key)
async def client_change_email(request: Request):
    """Verify the current password and atomically bind a verified new email."""
    uid = _auth_uid(request)
    if uid is None:
        return _account_error("登录状态已失效，请重新登录", 401)
    try:
        body = await request.json()
    except Exception:
        return _account_error("请求格式无效", 400)
    if not isinstance(body, dict):
        return _account_error("请求格式无效", 400)

    current_password = str(body.get("current_password") or "")
    new_email = normalize_email(str(body.get("new_email") or ""))
    email_code = str(body.get("email_code") or body.get("code") or "").strip()
    if not current_password or len(current_password) > PASSWORD_MAX_LENGTH:
        return _account_error("请输入当前密码", 400)
    if not _valid_email(new_email):
        return _account_error("请输入有效邮箱地址", 400)
    if not re.fullmatch(r"\d{6}", email_code):
        return _account_error("请输入 6 位邮箱验证码", 400)

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        user = conn.execute(
            "SELECT email, password_hash, status, ban_reason FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if not user:
            conn.rollback()
            return _account_error("登录状态已失效，请重新登录", 401)
        if str(user["status"] or "active") != "active":
            conn.rollback()
            return _account_error(str(user["ban_reason"] or "账号不可用"), 403)
        if not verify_password(current_password, str(user["password_hash"] or "")):
            conn.rollback()
            return _account_error("当前密码不正确", 401)
        if normalize_email(str(user["email"] or "")) == new_email:
            conn.rollback()
            return _account_error("新邮箱不能与当前邮箱相同", 400)
        if _email_taken(conn, new_email, uid):
            conn.rollback()
            return _account_error("该邮箱已绑定其他账号", 409)
        if not consume_verification_code(conn, new_email, email_code, "change_email"):
            conn.rollback()
            return _account_error("邮箱验证码错误、已过期或已使用", 400)

        conn.execute(
            "UPDATE users SET email = ?, updated_at = datetime('now') WHERE id = ?",
            (new_email, uid),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _account_error("该邮箱已绑定其他账号", 409)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "message": "邮箱已更新",
        **_email_fields(new_email),
    }


@router.post("/api/client/purchase-link")
@limiter.limit("60/minute", key_func=authenticated_client_rate_key)
async def client_purchase_link(request: Request):
    uid = _auth_uid(request)
    if uid is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    try:
        checkout = purchase_checkout_service.acquire_checkout(
            uid,
            _client_ip(request),
            str(getattr(request.state, "trace_id", "") or ""),
        )
    except PurchaseAccountUnavailable as exc:
        return _blocked_response(exc.account_state, str(exc))
    return {
        "ok": True,
        "token": checkout.token,
        "purchase_token": checkout.token,
        "url": f"{_public_site_url(request)}/client/purchase/{checkout.token}",
        "expires_at": checkout.expires_at,
        "payment_methods": purchase_checkout_service.supported_payment_methods(),
        "reused": checkout.reused,
        "status": checkout.status,
        "order_id": checkout.order_id,
    }


@router.get("/api/client/purchase-status/{token}")
@limiter.limit("120/minute", key_func=authenticated_client_rate_key)
async def client_purchase_status(request: Request, token: PurchaseTokenPath):
    uid = _auth_uid(request)
    if uid is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return purchase_checkout_service.get_authenticated_status(uid, token)


@router.get("/api/client/purchase-history")
@limiter.limit("30/minute", key_func=authenticated_client_rate_key)
async def client_purchase_history(request: Request, limit: int = 5):
    uid = _auth_uid(request)
    if uid is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    safe_limit = max(1, min(int(limit or 5), 50))
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT o.id, o.plan, o.amount, o.status, o.payment_method, o.created_at, COALESCE(tr.seconds, 0) AS seconds
            FROM orders o
            LEFT JOIN time_recharges tr ON tr.order_id = o.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC
            LIMIT ?
            """,
            (uid, safe_limit),
        ).fetchall()
    finally:
        conn.close()
    items = []
    for row in rows:
        item = dict(row)
        if not item.get("seconds"):
            item["seconds"] = PLAN_SECONDS.get(str(item.get("plan") or ""), 0)
        items.append(item)
    return {"ok": True, "items": items}


@router.get("/client/purchase", response_class=HTMLResponse)
@limiter.limit("60/minute")
async def client_purchase_missing_token(request: Request):
    return HTMLResponse(_purchase_page_html("", None, None, "请从 VisionForge 客户端重新打开购买页面。"), status_code=400)


@router.get("/client/purchase/{token}/status")
@limiter.limit("120/minute")
async def client_purchase_page_status(request: Request, token: PurchaseTokenPath):
    status = purchase_status_service.get_public_status(token)
    trace_id = str(getattr(request.state, "trace_id", "") or "")
    if status.is_terminal:
        logger.info(
            "purchase page terminal status trace_id=%s order_id=%s status=%s",
            trace_id,
            status.order_id,
            status.status.value,
        )
    response = JSONResponse(status.to_dict(), status_code=200 if status.is_found else 404)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@router.get("/client/purchase/{token}", response_class=HTMLResponse)
@limiter.limit("60/minute")
async def client_purchase_page(request: Request, token: PurchaseTokenPath):
    safe_token = str(token or "").strip()
    page = purchase_checkout_service.get_page(safe_token)
    return HTMLResponse(_purchase_page_html(safe_token, page.session, page.order, payment_options=page.payment_options))


@router.post("/client/purchase/{token}/order", response_class=HTMLResponse)
@limiter.limit("20/minute")
async def client_purchase_create_order(request: Request, token: PurchaseTokenPath):
    safe_token = str(token or "").strip()
    form = await request.form()
    plan_key = str(form.get("plan") or "").strip()
    payment_method = normalize_payment_method(form.get("payment_method"), default=DEFAULT_PAYMENT_METHOD)
    try:
        page = purchase_checkout_service.create_order(
            safe_token,
            plan_key,
            payment_method,
            _client_ip(request),
            str(getattr(request.state, "trace_id", "") or ""),
        )
        order_no = str((page.order or {}).get("merchant_order_no") or "")
        return HTMLResponse(_purchase_page_html(
            safe_token,
            page.session,
            page.order,
            f"订单已创建，订单号 {order_no}。请按二维码金额支付。",
        ))
    except PaymentSlotOccupiedError as exc:
        trace_id = str(getattr(request.state, "trace_id", "") or "")
        logger.warning(
            "purchase slot conflict trace_id=%s plan=%s method=%s remaining_seconds=%s",
            trace_id,
            plan_key,
            payment_method,
            exc.remaining_seconds,
        )
        page = purchase_checkout_service.get_page(safe_token)
        return HTMLResponse(
            _purchase_page_html(
                safe_token,
                page.session,
                page.order,
                "该固定金额当前正在等待另一笔付款，请选择支付宝支付或其他套餐。",
                payment_options=page.payment_options,
                error_code=exc.error_code,
            ),
            status_code=409,
        )
    except PurchaseCheckoutError as exc:
        page = purchase_checkout_service.get_page(safe_token)
        return HTMLResponse(
            _purchase_page_html(safe_token, page.session, page.order, str(exc), payment_options=page.payment_options),
            status_code=exc.status_code,
        )


@router.post("/client/purchase/{token}/cancel", response_class=HTMLResponse)
@limiter.limit("60/minute")
async def client_purchase_cancel(request: Request, token: PurchaseTokenPath):
    safe_token = str(token or "").strip()
    try:
        page = purchase_checkout_service.cancel_checkout(
            safe_token,
            str(getattr(request.state, "trace_id", "") or ""),
        )
        message = "订单已到账，不能取消。" if (page.order or {}).get("status") == "delivered" else "本次购买已取消。"
        return HTMLResponse(_purchase_page_html(safe_token, page.session, page.order, message))
    except PurchaseCheckoutError as exc:
        return HTMLResponse(_purchase_page_html(safe_token, None, None, str(exc)), status_code=exc.status_code)


@router.post("/client/purchase/{token}/abandon")
@limiter.limit("60/minute")
async def client_purchase_abandon(request: Request, token: PurchaseTokenPath):
    purchase_checkout_service.acknowledge_abandon(
        token,
        str(getattr(request.state, "trace_id", "") or ""),
    )
    return {"ok": True}


@router.post("/api/client/session-start")
@limiter.limit("10/minute", key_func=authenticated_client_rate_key)
async def session_start(request: Request):
    """Start a new usage session. Called once when user begins using the software."""
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    uid = int(payload["sub"])

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    machine_code, profile_json, client_version = _device_info(body)
    device_error = _device_code_error_response(machine_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error
    if not machine_code:
        return _auth_error_response("missing_device_code")
    runtime_instance_id = _runtime_instance_id(body)
    if not runtime_instance_id:
        return _runtime_instance_required_response()
    client_ip = request.client.host if request.client else ""

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        login_context, login_error = validate_login_context_locked(
            conn,
            payload,
            request_device_code=machine_code,
            require_device=True,
        )
        if login_error or login_context is None:
            conn.execute("ROLLBACK")
            return _auth_error_response(login_error)
        version_error = _minimum_client_version_error_response(
            conn,
            client_version,
        )
        if version_error is not None:
            conn.execute("ROLLBACK")
            return version_error
        account_state, ban_reason = _account_status(conn, uid)
        if account_state != "active":
            conn.execute("ROLLBACK")
            return _blocked_response(account_state, ban_reason)
        _close_stale_sessions_locked(conn, uid)
        handoff = conn.execute(
            "SELECT runtime_blocked_until_epoch, CAST(strftime('%s', 'now') AS INTEGER) AS now_epoch "
            "FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        blocked_until = int(handoff["runtime_blocked_until_epoch"] or 0) if handoff else 0
        now_epoch = int(handoff["now_epoch"] or 0) if handoff else 0
        if blocked_until > now_epoch:
            retry_after = max(1, blocked_until - now_epoch)
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "runtime_handoff_pending",
                    "message": f"上一运行实例的已签名租约尚未到期，请{retry_after}秒后自动重试。",
                    "retry_after_seconds": retry_after,
                    "runtime_blocked_until_epoch": blocked_until,
                    "balance_seconds": _balance_seconds_locked(conn, uid),
                },
                status_code=409,
                headers={"Retry-After": str(retry_after)},
            )
        active = conn.execute(
            "SELECT id FROM time_sessions WHERE user_id = ? AND status = 'active' LIMIT 1",
            (uid,),
        ).fetchone()
        if active:
            balance_seconds = _balance_seconds_locked(conn, uid)
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "session_already_active",
                    "message": "当前登录实例已有运行中的计费会话，请先停止原会话。",
                    "session_id": int(active["id"]),
                    "balance_seconds": balance_seconds,
                },
                status_code=409,
            )
        _record_user_device(conn, uid, request, body, "session_start")
        integrity = _check_client_integrity(conn, body, client_version)
        security_settings = integrity["settings"]
        if not integrity["accepted"]:
            _log_integrity_rejected(body, integrity, client_version, uid, machine_code, request, "session-start")
            conn.execute("ROLLBACK")
            return JSONResponse({
                "ok": False,
                "error": "client_integrity_rejected",
                "message": "客户端版本或完整性校验未通过，请更新到官方版本。",
                "integrity_status": integrity["status"],
                "runtime_security": _runtime_security_response(security_settings, integrity),
            }, status_code=426)
        initial_lease_charge = int(security_settings["lease_ttl_seconds"])
        ok, balance_seconds, deducted = _consume_balance_locked(
            conn,
            uid,
            initial_lease_charge,
        )
        if not ok:
            conn.execute("ROLLBACK")
            return JSONResponse({
                "ok": False,
                "error": "insufficient_balance",
                "balance_seconds": balance_seconds,
            }, status_code=402)
        cursor = conn.execute(
            "INSERT INTO time_sessions "
            "(user_id, login_auth_version, login_instance_id, runtime_instance_id, machine_code, client_version, device_profile, "
            "integrity_manifest_hash, integrity_status, ip_address, started_at, last_heartbeat_at, "
            "seconds_consumed, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, 'active')",
            (
                uid,
                login_context.auth_version,
                login_context.login_instance_id,
                runtime_instance_id,
                machine_code,
                client_version,
                profile_json,
                integrity["lease_manifest_hash"],
                integrity["status"],
                client_ip,
                deducted,
            ),
        )
        session_id = cursor.lastrowid
        try:
            lease = sign_runtime_lease(
                user_id=uid,
                session_id=session_id,
                device_code=machine_code,
                client_version=client_version,
                manifest_hash=integrity["lease_manifest_hash"],
                auth_version=login_context.auth_version,
                login_instance_id=login_context.login_instance_id,
                runtime_instance_id=runtime_instance_id,
                ttl_seconds=security_settings["lease_ttl_seconds"],
            )
        except RuntimeLeaseSigningUnavailable:
            conn.execute("ROLLBACK")
            logger.exception("Runtime lease signing unavailable during session start")
            return _runtime_lease_signing_unavailable_response()
        conn.execute(
            "UPDATE time_sessions SET lease_expires_at = ?, lease_token_hash = ? WHERE id = ?",
            (lease["lease_expires_at"], runtime_lease_token_hash(lease["lease_token"]), session_id),
        )
        upload_policy = log_upload_policy(conn, uid)
        conn.commit()
        logger.info("Session started: user=%d session=%d", uid, session_id)
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "session_id": session_id,
        "device_code": machine_code,
        "runtime_instance_id": runtime_instance_id,
        "balance_seconds": balance_seconds,
        "deducted": deducted,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
        "billing_capabilities": {
            "heartbeat_idempotency": HEARTBEAT_IDEMPOTENCY_VERSION,
            "runtime_instance_id": "required",
            "lease_segments": "v2",
        },
        "lease_token": lease["lease_token"],
        "lease_expires_at": lease["lease_expires_at"],
        "lease_ttl_seconds": lease["lease_ttl_seconds"],
        "runtime_security": _runtime_security_response(security_settings, integrity),
        "log_upload_policy": upload_policy,
    }


@router.post("/api/client/session-heartbeat")
@limiter.limit("30/minute", key_func=authenticated_client_rate_key)
async def session_heartbeat(request: Request):
    """Heartbeat: deduct HEARTBEAT_INTERVAL seconds from balance.

    Called at the server-provided interval while the software is running.
    Server deducts time atomically. Returns remaining balance.
    If balance is insufficient, returns error so client can stop.
    """
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    uid = int(payload["sub"])

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    requested_session_id = _safe_int(body.get("session_id"), 0, minimum=0)
    if not requested_session_id:
        return JSONResponse(
            {"ok": False, "error": "missing_session_id", "message": "计费心跳缺少有效会话编号。"},
            status_code=400,
        )
    machine_code, profile_json, client_version = _device_info(body)
    device_error = _device_code_error_response(machine_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error
    if not machine_code:
        return _auth_error_response("missing_device_code")
    runtime_instance_id = _runtime_instance_id(body)
    if not runtime_instance_id:
        return _runtime_instance_required_response()
    request_lease_token = str(body.get("lease_token") or "").strip()
    if not request_lease_token:
        return JSONResponse(
            {"ok": False, "error": "missing_runtime_lease", "message": "计费心跳缺少运行租约。"},
            status_code=409,
        )
    request_lease_hash = runtime_lease_token_hash(request_lease_token)
    heartbeat_id, heartbeat_sequence, identity_error = _heartbeat_identity(body)
    if identity_error:
        _log_heartbeat_status(
            request,
            status="terminal",
            error=identity_error,
            user_id=uid,
            session_id=0,
        )
        return JSONResponse({"ok": False, "error": identity_error}, status_code=400)

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        login_context, login_error = validate_login_context_locked(
            conn,
            payload,
            request_device_code=machine_code,
            require_device=True,
        )
        if login_error or login_context is None:
            balance_seconds = _balance_seconds_locked(conn, uid)
            conn.execute("ROLLBACK")
            return _auth_error_response(login_error, balance_seconds=balance_seconds)
        account_state, ban_reason = _account_status(conn, uid)
        if account_state != "active":
            conn.execute("ROLLBACK")
            return _blocked_response(account_state, ban_reason)
        stale_session_count = _close_stale_sessions_locked(conn, uid)

        active = conn.execute(
            "SELECT id, login_auth_version, login_instance_id, runtime_instance_id, machine_code, client_version, integrity_manifest_hash, "
            "last_heartbeat_sequence, last_heartbeat_id, last_heartbeat_response, "
            "lease_expires_at, lease_token_hash, last_request_lease_hash "
            "FROM time_sessions "
            "WHERE user_id = ? AND id = ? AND status = 'active' LIMIT 1",
            (uid, requested_session_id),
        ).fetchone()
        if not active:
            balance_seconds = _balance_seconds_locked(conn, uid)
            current_active = conn.execute(
                "SELECT id FROM time_sessions WHERE user_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
                (uid,),
            ).fetchone()
            error_code = "session_superseded" if current_active else "no_active_session"
            _log_heartbeat_status(
                request,
                status="terminal",
                error=error_code,
                user_id=uid,
                session_id=requested_session_id,
                sequence=heartbeat_sequence,
            )
            if stale_session_count:
                conn.commit()
            else:
                conn.execute("ROLLBACK")
            return JSONResponse({
                "ok": False,
                "error": error_code,
                "message": (
                    "当前计费会话已被新的运行会话替代。"
                    if current_active
                    else "当前计费会话已结束，请重新启动。"
                ),
                "balance_seconds": balance_seconds,
            }, status_code=409)
        active_id = int(active["id"])
        active_client_version = str(active["client_version"] or "").strip()
        active_manifest_hash = str(
            active["integrity_manifest_hash"] or ""
        ).strip().lower()
        if client_version and client_version != active_client_version:
            extend_runtime_block_from_active_sessions_locked(conn, uid)
            conn.execute(
                "UPDATE time_sessions SET status = 'ended', "
                "ended_at = datetime('now'), ended_reason = 'client_version_mismatch' "
                "WHERE id = ? AND status = 'active'",
                (active_id,),
            )
            conn.commit()
            return JSONResponse(
                {
                    "ok": False,
                    "error": "client_version_mismatch",
                    "message": "运行会话版本已发生变化，请重新启动官方客户端。",
                },
                status_code=409,
            )
        version_error = _minimum_client_version_error_response(
            conn,
            active_client_version,
        )
        if version_error is not None:
            extend_runtime_block_from_active_sessions_locked(conn, uid)
            conn.execute(
                "UPDATE time_sessions SET status = 'ended', "
                "ended_at = datetime('now'), ended_reason = 'client_update_required' "
                "WHERE id = ? AND status = 'active'",
                (active_id,),
            )
            conn.commit()
            return version_error
        if (
            int(active["login_auth_version"]) != login_context.auth_version
            or str(active["login_instance_id"] or "") != login_context.login_instance_id
        ):
            balance_seconds = _balance_seconds_locked(conn, uid)
            _log_heartbeat_status(
                request,
                status="terminal",
                error="login_superseded",
                user_id=uid,
                session_id=requested_session_id,
                sequence=heartbeat_sequence,
            )
            conn.execute("ROLLBACK")
            return _auth_error_response("login_superseded", balance_seconds=balance_seconds)
        if str(active["machine_code"] or "").strip().upper() != machine_code:
            balance_seconds = _balance_seconds_locked(conn, uid)
            _log_heartbeat_status(
                request,
                status="terminal",
                error="session_device_mismatch",
                user_id=uid,
                session_id=requested_session_id,
                sequence=heartbeat_sequence,
            )
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "session_device_mismatch",
                    "message": "计费会话与当前设备不匹配，运行已停止。",
                    "balance_seconds": balance_seconds,
                },
                status_code=409,
            )
        if str(active["runtime_instance_id"] or "").strip() != runtime_instance_id:
            balance_seconds = _balance_seconds_locked(conn, uid)
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "runtime_instance_mismatch",
                    "message": "计费会话与当前运行实例不匹配。",
                    "balance_seconds": balance_seconds,
                },
                status_code=409,
            )
        lease_ok, lease_reason, verified_lease_payload = verify_runtime_lease(
            request_lease_token,
            user_id=uid,
            session_id=active_id,
            auth_version=login_context.auth_version,
            device_code=machine_code,
            login_instance_id=login_context.login_instance_id,
            expected_runtime_instance_id=runtime_instance_id,
            expected_client_version=active_client_version,
            expected_manifest_hash=active_manifest_hash,
            allow_future_for_renewal=bool(runtime_instance_id),
        )
        if not lease_ok:
            balance_seconds = _balance_seconds_locked(conn, uid)
            logger.warning(
                "Runtime lease rejected reason=%s user=%d session=%d trace_id=%s",
                lease_reason,
                uid,
                active_id,
                str(getattr(request.state, "trace_id", "") or "none"),
            )
            _log_heartbeat_status(
                request,
                status="terminal",
                error="invalid_runtime_lease",
                user_id=uid,
                session_id=active_id,
                sequence=heartbeat_sequence,
            )
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "invalid_runtime_lease",
                    "message": "运行租约无效或已过期，请重新启动。",
                    "balance_seconds": balance_seconds,
                },
                status_code=409,
            )
        _record_user_device(conn, uid, request, body, "heartbeat")
        integrity = _check_client_integrity(conn, body, active_client_version)
        security_settings = integrity["settings"]
        if not integrity["accepted"]:
            _log_integrity_rejected(body, integrity, active_client_version, uid, machine_code, request, "session-heartbeat")
            extend_runtime_block_from_active_sessions_locked(conn, uid)
            conn.execute(
                "UPDATE time_sessions SET status = 'ended', ended_at = datetime('now'), ended_reason = 'integrity_rejected' "
                "WHERE id = ? AND status = 'active'",
                (active_id,),
            )
            conn.commit()
            return JSONResponse({
                "ok": False,
                "error": "client_integrity_rejected",
                "message": "客户端版本或完整性校验未通过，请更新到官方版本。",
                "integrity_status": integrity["status"],
                "balance_seconds": _balance_seconds_locked(conn, uid),
                "runtime_security": _runtime_security_response(security_settings, integrity),
            }, status_code=426)
        heartbeat_manifest_hash = str(
            integrity.get("lease_manifest_hash") or ""
        ).strip().lower()
        if heartbeat_manifest_hash != active_manifest_hash:
            extend_runtime_block_from_active_sessions_locked(conn, uid)
            conn.execute(
                "UPDATE time_sessions SET status = 'ended', "
                "ended_at = datetime('now'), ended_reason = 'integrity_context_changed' "
                "WHERE id = ? AND status = 'active'",
                (active_id,),
            )
            conn.commit()
            return JSONResponse(
                {
                    "ok": False,
                    "error": "integrity_context_changed",
                    "message": "运行会话完整性上下文已变化，请重新启动官方客户端。",
                },
                status_code=409,
            )
        if heartbeat_id:
            last_sequence = int(active["last_heartbeat_sequence"] or 0)
            last_id = str(active["last_heartbeat_id"] or "")
            balance_seconds = _balance_seconds_locked(conn, uid)
            if heartbeat_sequence < last_sequence:
                _log_heartbeat_status(
                    request,
                    status="terminal",
                    error="heartbeat_sequence_replayed",
                    user_id=uid,
                    session_id=active_id,
                    sequence=heartbeat_sequence,
                )
                conn.execute("ROLLBACK")
                return JSONResponse({
                    "ok": False,
                    "error": "heartbeat_sequence_replayed",
                    "balance_seconds": balance_seconds,
                }, status_code=409)
            if heartbeat_sequence == last_sequence and last_sequence > 0:
                if (
                    heartbeat_id != last_id
                    or request_lease_hash != str(active["last_request_lease_hash"] or "")
                ):
                    _log_heartbeat_status(
                        request,
                        status="terminal",
                        error="heartbeat_identity_conflict",
                        user_id=uid,
                        session_id=active_id,
                        sequence=heartbeat_sequence,
                    )
                    conn.execute("ROLLBACK")
                    return JSONResponse({
                        "ok": False,
                        "error": "heartbeat_identity_conflict",
                        "balance_seconds": balance_seconds,
                    }, status_code=409)
                stored_response = _stored_heartbeat_response(active["last_heartbeat_response"])
                conn.execute("ROLLBACK")
                if stored_response is None:
                    _log_heartbeat_status(
                        request,
                        status="terminal",
                        error="heartbeat_idempotency_state_missing",
                        user_id=uid,
                        session_id=active_id,
                        sequence=heartbeat_sequence,
                    )
                    return JSONResponse({
                        "ok": False,
                        "error": "heartbeat_idempotency_state_missing",
                        "balance_seconds": balance_seconds,
                    }, status_code=409)
                _log_heartbeat_status(
                    request,
                    status="idempotent",
                    error="",
                    user_id=uid,
                    session_id=active_id,
                    sequence=heartbeat_sequence,
                )
                return stored_response
        if request_lease_hash != str(active["lease_token_hash"] or ""):
            balance_seconds = _balance_seconds_locked(conn, uid)
            _log_heartbeat_status(
                request,
                status="terminal",
                error="runtime_lease_superseded",
                user_id=uid,
                session_id=active_id,
                sequence=heartbeat_sequence,
            )
            conn.execute("ROLLBACK")
            return JSONResponse(
                {
                    "ok": False,
                    "error": "runtime_lease_superseded",
                    "message": "运行租约已被新的心跳替代，请重新启动。",
                    "balance_seconds": balance_seconds,
                },
                status_code=409,
            )
        renewal_retry_after_seconds = 0
        try:
            segment_not_before, segment_expires_at, renewal_charge = _next_lease_segment(
                active["lease_expires_at"],
                int(security_settings["lease_ttl_seconds"]),
            )
        except LeaseRenewalTooEarly as exc:
            renewal_retry_after_seconds = exc.retry_after_seconds
            lease = {
                "lease_token": request_lease_token,
                "lease_expires_at": str(active["lease_expires_at"] or ""),
                "lease_ttl_seconds": max(
                    1,
                    int(
                        verified_lease_payload.get("ttl")
                        or security_settings["lease_ttl_seconds"]
                    ),
                ),
            }
            new_balance = _balance_seconds_locked(conn, uid)
            deducted = 0
        else:
            try:
                lease = sign_runtime_lease(
                    user_id=uid,
                    session_id=active_id,
                    device_code=machine_code,
                    client_version=active_client_version,
                    manifest_hash=active_manifest_hash,
                    auth_version=login_context.auth_version,
                    login_instance_id=login_context.login_instance_id,
                    runtime_instance_id=runtime_instance_id,
                    ttl_seconds=security_settings["lease_ttl_seconds"],
                    not_before_epoch=segment_not_before,
                    expires_at_epoch=segment_expires_at,
                )
            except RuntimeLeaseSigningUnavailable:
                conn.execute("ROLLBACK")
                logger.exception("Runtime lease signing unavailable during heartbeat")
                return _runtime_lease_signing_unavailable_response()
            ok, new_balance, deducted = _consume_balance_locked(conn, uid, renewal_charge)
            if not ok:
                extend_runtime_block_from_active_sessions_locked(conn, uid)
                conn.execute(
                    "UPDATE time_sessions SET status = 'ended', ended_at = datetime('now'), ended_reason = 'insufficient_balance' "
                    "WHERE id = ? AND status = 'active'",
                    (active_id,),
                )
                conn.commit()
                _log_heartbeat_status(
                    request,
                    status="terminal",
                    error="insufficient_balance",
                    user_id=uid,
                    session_id=active_id,
                    sequence=heartbeat_sequence,
                )
                return JSONResponse({
                    "ok": False,
                    "error": "insufficient_balance",
                    "balance_seconds": new_balance,
                    "lease_expires_at": str(active["lease_expires_at"] or ""),
                    "lease_ttl_seconds": int(security_settings["lease_ttl_seconds"]),
                }, status_code=402)
        next_lease_hash = runtime_lease_token_hash(lease["lease_token"])
        upload_policy = log_upload_policy(conn, uid)
        response_payload = {
            "ok": True,
            "balance_seconds": max(0, new_balance),
            "deducted": deducted,
            "device_code": machine_code,
            "session_id": active_id,
            "runtime_instance_id": runtime_instance_id,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
            "lease_token": lease["lease_token"],
            "lease_expires_at": lease["lease_expires_at"],
            "lease_ttl_seconds": lease["lease_ttl_seconds"],
            "runtime_security": _runtime_security_response(security_settings, integrity),
            "log_upload_policy": upload_policy,
        }
        if heartbeat_id:
            response_payload["heartbeat_id"] = heartbeat_id
            response_payload["heartbeat_sequence"] = heartbeat_sequence
        if renewal_retry_after_seconds:
            response_payload["lease_renewal"] = "not_due"
            response_payload["retry_after_seconds"] = renewal_retry_after_seconds
        stored_response_json = (
            json.dumps(response_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if heartbeat_id
            else ""
        )
        conn.execute(
            "UPDATE time_sessions SET seconds_consumed = seconds_consumed + ?, "
            "last_heartbeat_at = datetime('now'), "
            "lease_expires_at = ?, "
            "lease_token_hash = ?, "
            "last_request_lease_hash = ?, "
            "machine_code = CASE WHEN machine_code = '' THEN ? ELSE machine_code END, "
            "device_profile = CASE WHEN ? != '{}' THEN ? ELSE device_profile END, "
            "integrity_status = ?, "
            "last_heartbeat_sequence = CASE WHEN ? != '' THEN ? ELSE last_heartbeat_sequence END, "
            "last_heartbeat_id = CASE WHEN ? != '' THEN ? ELSE last_heartbeat_id END, "
            "last_heartbeat_response = CASE WHEN ? != '' THEN ? ELSE last_heartbeat_response END "
            "WHERE id = ? AND status = 'active'",
            (
                deducted,
                lease["lease_expires_at"],
                next_lease_hash,
                request_lease_hash,
                machine_code,
                profile_json,
                profile_json,
                integrity["status"],
                heartbeat_id,
                heartbeat_sequence,
                heartbeat_id,
                heartbeat_id,
                heartbeat_id,
                stored_response_json,
                active_id,
            ),
        )
        conn.commit()
        _log_heartbeat_status(
            request,
            status="not_due" if renewal_retry_after_seconds else "ok",
            error="",
            user_id=uid,
            session_id=active_id,
            sequence=heartbeat_sequence,
        )
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    return response_payload


@router.post("/api/client/session-end")
@limiter.limit("10/minute", key_func=authenticated_client_rate_key)
async def session_end(request: Request):
    """End the current usage session."""
    payload, auth_error = _decode_client_payload(request)
    if auth_error is not None or payload is None:
        return auth_error
    uid = int(payload["sub"])

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    requested_session_id = _safe_int(body.get("session_id"), 0, minimum=0)
    if not requested_session_id:
        return JSONResponse(
            {"ok": False, "error": "missing_session_id", "message": "结束会话请求缺少有效会话编号。"},
            status_code=400,
        )
    machine_code, _, client_version = _device_info(body)
    device_error = _device_code_error_response(machine_code)
    if device_error is not None:
        return device_error
    client_version_error = _client_version_error_response(client_version)
    if client_version_error is not None:
        return client_version_error
    if not machine_code:
        return _auth_error_response("missing_device_code")
    runtime_instance_id = _runtime_instance_id(body)
    if not runtime_instance_id:
        return _runtime_instance_required_response()

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        login_context, login_error = validate_login_context_locked(
            conn,
            payload,
            request_device_code=machine_code,
            require_device=True,
        )
        if login_error or login_context is None:
            conn.execute("ROLLBACK")
            return _auth_error_response(login_error)
        active = conn.execute(
            "SELECT login_auth_version, login_instance_id, runtime_instance_id, machine_code FROM time_sessions "
            "WHERE user_id = ? AND id = ? AND status = 'active'",
            (uid, requested_session_id),
        ).fetchone()
        if not active:
            conn.execute("ROLLBACK")
            return JSONResponse(
                {"ok": False, "error": "session_superseded", "message": "当前计费会话已失效。"},
                status_code=409,
            )
        if (
            int(active["login_auth_version"]) != login_context.auth_version
            or str(active["login_instance_id"] or "") != login_context.login_instance_id
        ):
            conn.execute("ROLLBACK")
            return _auth_error_response("login_superseded")
        if str(active["machine_code"] or "").strip().upper() != machine_code:
            conn.execute("ROLLBACK")
            return JSONResponse(
                {"ok": False, "error": "session_device_mismatch", "message": "计费会话与当前设备不匹配。"},
                status_code=409,
            )
        if str(active["runtime_instance_id"] or "").strip() != runtime_instance_id:
            conn.execute("ROLLBACK")
            return JSONResponse(
                {"ok": False, "error": "runtime_instance_mismatch"},
                status_code=409,
            )
        _record_user_device(conn, uid, request, body, "session_end")
        extend_runtime_block_from_active_sessions_locked(conn, uid)
        conn.execute(
            "UPDATE time_sessions SET status = 'ended', ended_at = datetime('now'), "
            "ended_reason = 'client_session_end' "
            "WHERE user_id = ? AND id = ? AND status = 'active'",
            (uid, requested_session_id),
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

    logger.info("Session ended: user=%d", uid)
    return {"ok": True}
