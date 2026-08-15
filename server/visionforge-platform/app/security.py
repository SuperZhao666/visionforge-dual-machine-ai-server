"""Authentication, JWT, CAPTCHA, brute force protection, rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import logging
import random
import time
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config import config

logger = logging.getLogger("security")
ACCOUNT_PASSWORD_MAX_LENGTH = 128

limiter = Limiter(key_func=get_remote_address)
CSRF_COOKIE_NAME = "vf_csrf"
CSRF_FORM_FIELD = "csrf_token"


def authenticated_client_rate_key(request: Request) -> str:
    """Isolate authenticated client limits without retaining bearer secrets."""
    authorization = str(request.headers.get("Authorization") or "")
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        return f"bearer:{digest}"
    return f"ip:{get_remote_address(request)}"

# ── CAPTCHA ───────────────────────────────────────────────────────
# Simple math CAPTCHA: "3 + 7 = ?" stored with HMAC-signed token
# No external dependencies, no image generation, hard enough for bots

_captcha_secret = config.SECRET_KEY.encode()[:32] if config.SECRET_KEY else b"fallback-captcha-key"


def generate_captcha() -> tuple[str, str, str]:
    """Generate a math CAPTCHA. Returns (token, question, answer)."""
    a = random.randint(1, 15)
    b = random.randint(1, 15)
    ops = ["+", "-", "*"]
    op = random.choice(ops)
    if op == "+":
        answer = str(a + b)
    elif op == "-":
        # Ensure positive result
        if a < b:
            a, b = b, a
        answer = str(a - b)
    else:
        answer = str(a * b)

    question = f"{a} {op} {b} = ?"
    # Sign: token = answer:expiry:HMAC
    expiry = int(time.time()) + 300  # 5 minutes
    payload = f"{answer}:{expiry}"
    sig = hmac.new(_captcha_secret, payload.encode(), hashlib.sha256).hexdigest()[:16]
    token = f"{expiry}:{sig}"
    return token, question, answer


def verify_captcha(token: str, user_answer: str) -> bool:
    """Verify a CAPTCHA answer against its signed token."""
    try:
        parts = token.split(":")
        if len(parts) != 2:
            return False
        expiry = int(parts[0])
        received_sig = parts[1]
        if time.time() > expiry:
            return False
        # We need the answer to verify, so we check all reasonable answers
        # Instead reconstruct: the token format is expiry:sig where sig=HMAC(answer:expiry)
        payload = f"{user_answer.strip()}:{expiry}"
        expected_sig = hmac.new(_captcha_secret, payload.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(expected_sig, received_sig)
    except (ValueError, IndexError):
        return False


# ── Passwords ─────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_password_bytes(password), hashed.encode("utf-8"))
    except (TypeError, ValueError):
        return False


def _password_bytes(password: str) -> bytes:
    """Keep bcrypt inputs within its 72-byte limit while retaining legacy hashes."""
    raw = str(password).encode("utf-8")
    return raw if len(raw) <= 72 else hashlib.sha256(raw).digest()


# ── JWT ───────────────────────────────────────────────────────────

def create_access_token(
    user_id: int,
    is_admin: bool = False,
    auth_version: int = 0,
    *,
    device_code: str = "",
    login_instance_id: str = "",
    client_version: str = "",
) -> str:
    payload = {
        "sub": str(user_id),
        "admin": is_admin,
        "av": int(auth_version),
        "did": str(device_code or "").strip().upper(),
        "lid": str(login_instance_id or "").strip(),
        "ver": str(client_version or "").strip()[:80],
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        user_id = int(payload.get("sub") or 0)
        token_version = int(payload.get("av") or 0)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    from app.database import get_connection

    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT auth_version, status, deleted_at, login_device_code, login_instance_id FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if user["deleted_at"] is not None or str(user["status"] or "active") != "active":
        raise HTTPException(status_code=401, detail="account_disabled")
    if int(user["auth_version"] or 0) != token_version:
        raise HTTPException(status_code=401, detail="login_superseded")
    db_login_instance_id = str(user["login_instance_id"] or "").strip()
    db_device_code = str(user["login_device_code"] or "").strip().upper()
    if db_login_instance_id and str(payload.get("lid") or "").strip() != db_login_instance_id:
        raise HTTPException(status_code=401, detail="login_superseded")
    if db_device_code and str(payload.get("did") or "").strip().upper() != db_device_code:
        raise HTTPException(status_code=401, detail="login_superseded")
    return payload


async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    return decode_access_token(auth_header[7:])


async def require_admin(payload: dict = Depends(get_current_user)) -> dict:
    if not payload.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    from app.database import get_connection

    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT is_admin, status FROM users WHERE id = ?",
            (int(payload.get("sub") or 0),),
        ).fetchone()
    finally:
        conn.close()
    if not user or not bool(user["is_admin"]) or str(user["status"] or "") != "active":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload


# ── CSRF Token ────────────────────────────────────────────────────

def generate_csrf_token() -> str:
    """Generate a CSRF token signed with the app secret."""
    nonce = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[:16]
    expiry = int(time.time()) + 3600  # 1 hour
    payload = f"{nonce}:{expiry}"
    sig = hmac.new(_captcha_secret, payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{nonce}:{expiry}:{sig}"


def verify_csrf_token(token: str) -> bool:
    """Verify a CSRF token."""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False
        nonce, expiry_str, received_sig = parts
        expiry = int(expiry_str)
        if time.time() > expiry:
            return False
        payload = f"{nonce}:{expiry}"
        expected_sig = hmac.new(_captcha_secret, payload.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(expected_sig, received_sig)
    except (ValueError, IndexError):
        return False


async def require_form_csrf(request: Request) -> None:
    if request.method.upper() in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    cookie_token = str(request.cookies.get(CSRF_COOKIE_NAME) or "")
    try:
        form = await request.form()
        form_token = str(form.get(CSRF_FORM_FIELD) or "")
    except Exception:
        form_token = ""
    if (
        not cookie_token
        or not form_token
        or not verify_csrf_token(cookie_token)
        or not verify_csrf_token(form_token)
        or not hmac.compare_digest(cookie_token, form_token)
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# ── Brute force protection ────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
CLIENT_LOGIN_MAX_FAILED_ATTEMPTS = 10
CLIENT_LOGIN_MAX_FAILED_ATTEMPTS_PER_IP = 300


def _ensure_login_attempts_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time "
        "ON login_attempts(ip, created_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time "
        "ON login_attempts(username, created_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at "
        "ON login_attempts(created_at)"
    )


def reserve_account_login_attempt(username: str, client_ip: str) -> tuple[int, int]:
    """Reserve one password attempt against one account, never a shared IP bucket."""
    from app.database import get_connection

    normalized_username = str(username or "").strip()[:128]
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _ensure_login_attempts_table(conn)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("DELETE FROM login_attempts WHERE created_at <= ?", (cutoff,))
        failures = int(conn.execute(
            "SELECT COUNT(*) AS c FROM login_attempts "
            "WHERE username = ? AND success = 0 AND created_at > ?",
            (normalized_username, cutoff),
        ).fetchone()["c"])
        source_failures = int(conn.execute(
            "SELECT COUNT(*) AS c FROM login_attempts "
            "WHERE ip = ? AND success = 0 AND created_at > ?",
            (str(client_ip or "")[:128], cutoff),
        ).fetchone()["c"])
        if (
            failures >= CLIENT_LOGIN_MAX_FAILED_ATTEMPTS
            or source_failures >= CLIENT_LOGIN_MAX_FAILED_ATTEMPTS_PER_IP
        ):
            conn.commit()
            return 0, LOCKOUT_MINUTES * 60
        cursor = conn.execute(
            "INSERT INTO login_attempts (username, ip, success) VALUES (?, ?, 0)",
            (normalized_username, str(client_ip or "")[:128]),
        )
        conn.commit()
        return int(cursor.lastrowid), 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def complete_account_login_attempt(attempt_id: int, username: str, *, success: bool) -> None:
    """Finalize a reserved account attempt; a valid password clears that account's failures."""
    if int(attempt_id or 0) <= 0 or not success:
        return
    from app.database import get_connection

    normalized_username = str(username or "").strip()[:128]
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _ensure_login_attempts_table(conn)
        conn.execute(
            "UPDATE login_attempts SET success = 1 WHERE id = ? AND username = ?",
            (int(attempt_id), normalized_username),
        )
        conn.execute(
            "DELETE FROM login_attempts WHERE username = ? AND success = 0",
            (normalized_username,),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def check_login_brute_force(username: str, client_ip: str) -> str | None:
    """Check if login should be blocked due to brute force.
    Returns error message if blocked, None if allowed.
    """
    from app.database import get_connection
    conn = get_connection()
    try:
        _ensure_login_attempts_table(conn)

        # Count recent failures from this IP
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        ip_failures = conn.execute(
            "SELECT COUNT(*) as c FROM login_attempts WHERE ip = ? AND success = 0 AND created_at > ?",
            (client_ip, cutoff),
        ).fetchone()["c"]

        if ip_failures >= MAX_FAILED_ATTEMPTS:
            logger.warning("Brute force blocked: ip=%s username=%s failures=%d", client_ip, username, ip_failures)
            return f"登录尝试次数过多，请{LOCKOUT_MINUTES}分钟后再试"
        return None
    finally:
        conn.close()


def record_login_attempt(username: str, client_ip: str, success: bool) -> None:
    """Record a login attempt for brute force tracking."""
    from app.database import get_connection
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO login_attempts (username, ip, success) VALUES (?, ?, ?)",
            (username, client_ip, 1 if success else 0),
        )
        conn.commit()
    except Exception:
        logger.exception(
            "Failed to record login attempt: username=%s ip=%s success=%s",
            username,
            client_ip,
            success,
        )
    finally:
        conn.close()


# ── TOTP (admin 2FA) ──────────────────────────────────────────────

def verify_totp(secret: str, code: str) -> bool:
    """Verify TOTP code for admin 2FA. FAIL CLOSED if pyotp missing."""
    if not secret:
        return True
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    except ImportError:
        logger.error("TOTP secret set but pyotp not installed — 2FA UNAVAILABLE")
        return False
