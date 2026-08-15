"""Email service via QQ SMTP for verification codes and password reset."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import smtplib
import secrets
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum
from app.config import config
from app.database import get_connection

logger = logging.getLogger("email")

# How long codes are valid (seconds)
CODE_EXPIRY = 600  # 10 minutes
CODE_LENGTH = 6
SEND_COOLDOWN_SECONDS = config.EMAIL_CODE_SEND_COOLDOWN_SECONDS


class VerificationSendStatus(str, Enum):
    SENT = "sent"
    COOLDOWN = "cooldown"
    DELIVERY_FAILED = "delivery_failed"


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def mask_email(email: str) -> str:
    """Return a useful account hint without exposing the full mailbox locally."""
    normalized = normalize_email(email)
    if "@" not in normalized:
        return ""
    local, domain = normalized.rsplit("@", 1)
    visible = local[:2] if len(local) > 1 else local[:1]
    return f"{visible}{'*' * max(3, len(local) - len(visible))}@{domain}"


def email_log_id(email: str) -> str:
    """Return a stable, non-reversible identifier for email delivery logs."""
    return hmac.new(
        config.SECRET_KEY.encode("utf-8"),
        normalize_email(email).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]


def _code_digest(email: str, code: str, purpose: str) -> str:
    payload = f"{normalize_email(email)}|{purpose}|{str(code).strip()}".encode("utf-8")
    digest = hmac.new(config.SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def _code_matches(stored: str, email: str, code: str, purpose: str) -> bool:
    stored_value = str(stored or "")
    if stored_value.startswith("hmac-sha256:"):
        return hmac.compare_digest(stored_value, _code_digest(email, code, purpose))
    return hmac.compare_digest(stored_value, str(code).strip())


def _create_codes_table():
    """Ensure the verification codes table exists."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'reset_password',
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_codes_email_purpose ON email_codes(email, purpose, created_at)")
    conn.commit()
    conn.close()


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send an email through the configured SMTP relay. Returns True on success."""
    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        logger.error("SMTP credentials are not configured")
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = f"VisionForge <{config.SMTP_USER}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as server:
            if config.SMTP_USE_TLS:
                server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_USER, [to_email], msg.as_string())
        return True
    except smtplib.SMTPResponseException as exc:
        response_text = (
            exc.smtp_error.decode("ascii", errors="ignore")
            if isinstance(exc.smtp_error, bytes)
            else str(exc.smtp_error or "")
        )
        enhanced_status = re.search(r"\b[245]\.\d{1,3}\.\d{1,3}\b", response_text)
        logger.error(
            "Verification email delivery rejected error_type=%s smtp_code=%s enhanced_status=%s",
            type(exc).__name__,
            exc.smtp_code,
            enhanced_status.group(0) if enhanced_status else "unknown",
        )
        return False
    except Exception as e:
        logger.error(
            "Verification email delivery failed error_type=%s",
            type(e).__name__,
        )
        return False


def generate_code() -> str:
    """Generate a 6-digit verification code."""
    return "".join(secrets.choice("0123456789") for _ in range(CODE_LENGTH))


def _remove_undelivered_code(code_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM email_codes WHERE id = ? AND used = 0", (int(code_id),))
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Undelivered verification code cleanup failed code_id=%s", code_id)
        raise
    finally:
        conn.close()


def send_verification_code(
    email: str,
    purpose: str,
    *,
    trace_id: str = "",
) -> VerificationSendStatus:
    """Generate and send a verification code to the given email. Stores in DB."""
    _create_codes_table()
    email = normalize_email(email)
    anonymized_email = email_log_id(email)
    trace_id = str(trace_id or "none")
    code = generate_code()
    code_id = 0

    # Store code
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        recent = conn.execute(
            "SELECT created_at FROM email_codes WHERE email = ? AND purpose = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (email, purpose),
        ).fetchone()
        if recent:
            try:
                from datetime import datetime, timezone, timedelta
                created = datetime.fromisoformat(str(recent["created_at"]))
                if datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc) < timedelta(seconds=SEND_COOLDOWN_SECONDS):
                    conn.execute("ROLLBACK")
                    logger.info(
                        "Verification code cooldown trace_id=%s purpose=%s email_id=%s retry_after_s=%s",
                        trace_id,
                        purpose,
                        anonymized_email,
                        SEND_COOLDOWN_SECONDS,
                    )
                    return VerificationSendStatus.COOLDOWN
            except Exception:
                pass
        cursor = conn.execute(
            "INSERT INTO email_codes (email, code, purpose) VALUES (?, ?, ?)",
            (email, _code_digest(email, code, purpose), purpose),
        )
        code_id = int(cursor.lastrowid)
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    # Build email
    if purpose == "register":
        subject = f"VisionForge 注册验证码：{code}"
        body = f"""欢迎注册 VisionForge！

您的验证码是：{code}

验证码10分钟内有效，请勿泄露给他人。

VisionForge 是一款基于深度学习的 AI 瞄准辅助系统，
支持 GPU 加速推理、多驱动兼容、全量日志回传。

如非本人操作，请忽略此邮件。

—— VisionForge 团队"""
    elif purpose == "reset_password":
        subject = f"VisionForge 密码重置验证码：{code}"
        body = f"""您正在申请重置 VisionForge 账号的登录密码。

验证码：{code}
（10分钟内有效，请勿泄露给他人）

如非本人操作，请忽略此邮件。

—— VisionForge 团队"""
    elif purpose == "change_email":
        subject = f"VisionForge 邮箱修改验证码：{code}"
        body = f"""您正在申请修改 VisionForge 账号的绑定邮箱。

验证码：{code}
（10分钟内有效，请勿泄露给他人）

如非本人操作，请忽略此邮件。

—— VisionForge 团队"""
    else:
        subject = "VisionForge - 验证码"
        body = f"验证码：{code}（有效期 10 分钟）"

    if send_email(email, subject, body):
        logger.info(
            "Verification code issued trace_id=%s purpose=%s email_id=%s",
            trace_id,
            purpose,
            anonymized_email,
        )
        return VerificationSendStatus.SENT

    _remove_undelivered_code(code_id)
    logger.warning(
        "Verification code not issued trace_id=%s purpose=%s email_id=%s status=delivery_failed",
        trace_id,
        purpose,
        anonymized_email,
    )
    return VerificationSendStatus.DELIVERY_FAILED


def consume_verification_code(conn, email: str, code: str, purpose: str) -> bool:
    """Consume one valid code using the caller's transaction."""
    normalized = normalize_email(email)
    row = conn.execute(
        """SELECT id, code, created_at FROM email_codes
           WHERE email = ? AND purpose = ? AND used = 0
           ORDER BY created_at DESC LIMIT 1""",
        (normalized, purpose),
    ).fetchone()
    if not row:
        return False

    try:
        created = datetime.fromisoformat(str(row["created_at"]))
        if datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc) > timedelta(seconds=CODE_EXPIRY):
            return False
    except (TypeError, ValueError):
        return False

    if not _code_matches(str(row["code"]), normalized, code, purpose):
        return False
    updated = conn.execute(
        "UPDATE email_codes SET used = 1 WHERE id = ? AND used = 0",
        (row["id"],),
    ).rowcount
    return updated == 1


def verify_code(email: str, code: str, purpose: str) -> bool:
    """Verify and atomically consume an email verification code."""
    _create_codes_table()
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        accepted = consume_verification_code(conn, email, code, purpose)
        if accepted:
            conn.commit()
        else:
            conn.rollback()
        return accepted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
