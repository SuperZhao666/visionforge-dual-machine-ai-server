"""User invite-code ownership, referral binding, and immediate rewards."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from app.config import config
from app.database import get_connection
from app.domain.growth import ReferralStatus, TimeCreditSource
from app.services.code_encoding import base32_custom
from app.services.time_credit_service import credit_time_locked


MAX_REGISTRATION_EVENT_ID_LENGTH = 120


class ReferralError(ValueError):
    def __init__(self, error_code: str, message: str):
        super().__init__(message)
        self.error_code = error_code
        self.message = message


@dataclass(frozen=True)
class ReferralRewardResult:
    referral_id: int
    inviter_user_id: int
    reward_seconds: int


def ensure_invite_code(user_id: int) -> str:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        code = ensure_invite_code_locked(conn, int(user_id))
        conn.commit()
        return code
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_invite_code_locked(conn, user_id: int) -> str:
    if not conn.execute(
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
        (int(user_id),),
    ).fetchone():
        raise LookupError("user not found")
    row = conn.execute(
        "SELECT code FROM invite_codes WHERE user_id = ?",
        (int(user_id),),
    ).fetchone()
    if row:
        return str(row["code"])
    digest = hmac.new(
        _invite_key(),
        f"user:{int(user_id)}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    code = "VF" + base32_custom(digest[:7], 10)
    conn.execute(
        "INSERT INTO invite_codes (user_id, code, status) VALUES (?, ?, 'active')",
        (int(user_id), code),
    )
    return code


def apply_referral_locked(
    conn,
    *,
    invitee_user_id: int,
    invite_code: str,
    registration_event_id: str,
    device_code: str = "",
    ip_address: str = "",
) -> ReferralRewardResult | None:
    normalized_code = str(invite_code or "").strip().upper()
    if not normalized_code:
        return None
    settings = conn.execute(
        "SELECT referral_enabled, referral_reward_seconds FROM growth_settings WHERE id = 1"
    ).fetchone()
    if not settings or not bool(settings["referral_enabled"]):
        raise ReferralError("REFERRAL_DISABLED", "邀请奖励当前未开放")
    invite = conn.execute(
        "SELECT ic.id, ic.user_id FROM invite_codes ic "
        "JOIN users u ON u.id = ic.user_id "
        "WHERE upper(ic.code) = ? AND ic.status = 'active' "
        "AND u.status = 'active' AND u.deleted_at IS NULL",
        (normalized_code,),
    ).fetchone()
    if not invite:
        raise ReferralError("INVITE_CODE_INVALID", "邀请码无效")
    inviter_user_id = int(invite["user_id"])
    if inviter_user_id == int(invitee_user_id):
        raise ReferralError("SELF_INVITE_NOT_ALLOWED", "不能使用自己的邀请码")

    safe_registration_event_id = str(registration_event_id or "").strip()
    if not safe_registration_event_id or len(safe_registration_event_id) > MAX_REGISTRATION_EVENT_ID_LENGTH:
        raise ReferralError("REGISTRATION_EVENT_INVALID", "registration event id is invalid")

    reward_seconds = int(settings["referral_reward_seconds"])
    if reward_seconds <= 0:
        raise ReferralError("REFERRAL_REWARD_INVALID", "邀请奖励配置无效")
    cursor = conn.execute(
        "INSERT INTO referrals "
        "(invite_code_id, inviter_user_id, invitee_user_id, registration_event_id, status, "
        "reward_seconds, device_fingerprint, ip_fingerprint) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            int(invite["id"]),
            inviter_user_id,
            int(invitee_user_id),
            safe_registration_event_id,
            ReferralStatus.REGISTERED,
            reward_seconds,
            _fingerprint("device", device_code),
            _fingerprint("ip", ip_address),
        ),
    )
    referral_id = int(cursor.lastrowid)
    try:
        credit = credit_time_locked(
            conn,
            user_id=inviter_user_id,
            seconds=reward_seconds,
            source_type=TimeCreditSource.REFERRAL,
            source_ref=f"referral:{referral_id}",
        )
    except ValueError as exc:
        if "maximum balance" in str(exc):
            raise ReferralError("REFERRAL_BALANCE_LIMIT", "邀请人余额已达到上限") from exc
        raise
    if not credit.credited:
        raise RuntimeError("referral credit invariant violated")
    conn.execute(
        "UPDATE referrals SET status = ?, reward_recharge_id = ?, rewarded_at = datetime('now') "
        "WHERE id = ?",
        (ReferralStatus.REWARDED, credit.recharge_id, referral_id),
    )
    return ReferralRewardResult(referral_id, inviter_user_id, reward_seconds)


def referral_summary(user_id: int, *, limit: int = 50) -> dict:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        code = ensure_invite_code_locked(conn, int(user_id))
        settings = conn.execute(
            "SELECT referral_enabled, referral_reward_seconds FROM growth_settings WHERE id = 1"
        ).fetchone()
        aggregate = conn.execute(
            "SELECT COUNT(*) AS invite_count, COALESCE(SUM(reward_seconds), 0) AS reward_seconds "
            "FROM referrals WHERE inviter_user_id = ? AND status = ?",
            (int(user_id), ReferralStatus.REWARDED),
        ).fetchone()
        rows = conn.execute(
            "SELECT r.id, r.status, r.reward_seconds, r.created_at, r.rewarded_at, u.username "
            "FROM referrals r JOIN users u ON u.id = r.invitee_user_id "
            "WHERE r.inviter_user_id = ? ORDER BY r.id DESC LIMIT ?",
            (int(user_id), max(1, min(int(limit), 100))),
        ).fetchall()
        conn.commit()
        return {
            "invite_code": code,
            "enabled": bool(settings["referral_enabled"] if settings else False),
            "reward_seconds_each": int(settings["referral_reward_seconds"] if settings else 0),
            "invite_count": int(aggregate["invite_count"] if aggregate else 0),
            "reward_seconds": int(aggregate["reward_seconds"] if aggregate else 0),
            "items": [
                {
                    "id": int(row["id"]),
                    "username_masked": _mask_username(str(row["username"] or "")),
                    "status": str(row["status"]),
                    "reward_seconds": int(row["reward_seconds"]),
                    "created_at": str(row["created_at"]),
                    "rewarded_at": str(row["rewarded_at"] or ""),
                }
                for row in rows
            ],
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _invite_key() -> bytes:
    secret = str(getattr(config, "REDEMPTION_CODE_SECRET", "") or config.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, b"visionforge:invite:v1", hashlib.sha256).digest()


def _fingerprint(kind: str, value: str) -> str:
    clean = str(value or "").strip()
    if not clean:
        return ""
    return hmac.new(_invite_key(), f"{kind}:{clean}".encode("utf-8"), hashlib.sha256).hexdigest()


def _mask_username(username: str) -> str:
    clean = str(username or "")
    if len(clean) <= 2:
        return clean[:1] + "*"
    return clean[:2] + "*" * min(6, len(clean) - 2)
