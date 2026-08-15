"""Admin authentication — login, logout, cookie session lookup."""
from __future__ import annotations

import logging
import urllib.parse

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import RedirectResponse
from app.database import get_connection
from app.config import config
from app.security import (
    check_login_brute_force,
    create_access_token,
    limiter,
    record_login_attempt,
    require_form_csrf,
    verify_password,
    verify_totp,
)
from app.services.auth_session_service import (
    establish_login_locked,
    invalidate_login_locked,
    validate_login_context_locked,
)

logger = logging.getLogger("auth")
router = APIRouter(dependencies=[Depends(require_form_csrf)])


@router.post("/auth/login")
@limiter.limit("10/minute")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(""),
):
    """Admin login — only users with is_admin=1 can access the panel."""
    normalized_username = username.strip()
    client_ip = request.client.host if request.client else ""
    blocked = check_login_brute_force(normalized_username, client_ip)
    if blocked:
        return RedirectResponse(url=f"/login?error={urllib.parse.quote(blocked)}", status_code=303)

    conn = get_connection()
    try:
        candidate = conn.execute(
            "SELECT id, password_hash, is_admin, auth_version, status, deleted_at FROM users "
            "WHERE username = ? AND is_admin = 1",
            (normalized_username,),
        ).fetchone()
        password_valid = bool(candidate and candidate["deleted_at"] is None and str(candidate["status"] or "") == "active" and verify_password(password, candidate["password_hash"]))
        totp_valid = bool(password_valid and verify_totp(config.ADMIN_TOTP_SECRET, totp_code.strip()))
        if not password_valid or not totp_valid:
            record_login_attempt(normalized_username, client_ip, False)
            return RedirectResponse(url="/login?error=用户名或密码错误", status_code=303)
        conn.execute("BEGIN IMMEDIATE")
        user = conn.execute(
            "SELECT id, password_hash, is_admin, auth_version, status, deleted_at FROM users "
            "WHERE username = ? AND is_admin = 1",
            (normalized_username,),
        ).fetchone()
        if (
            not user
            or user["deleted_at"] is not None
            or str(user["status"] or "") != "active"
            or str(user["password_hash"] or "") != str(candidate["password_hash"] or "")
        ):
            conn.execute("ROLLBACK")
            record_login_attempt(normalized_username, client_ip, False)
            return RedirectResponse(url="/login?error=用户名或密码错误", status_code=303)
        login_instance = establish_login_locked(conn, int(user["id"]), "")
        conn.commit()
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    record_login_attempt(normalized_username, client_ip, True)
    token = create_access_token(
        user["id"],
        True,
        login_instance.auth_version,
        login_instance_id=login_instance.login_instance_id,
    )
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(key="vf_token", value=token, httponly=True,
                        secure=config.COOKIE_SECURE, max_age=604800, path="/", samesite="strict")
    return response


def _logout_redirect() -> RedirectResponse:
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("vf_token", path="/")
    return response


async def _revoke_admin_login(request: Request) -> None:
    token = request.cookies.get("vf_token")
    if token:
        try:
            from app.security import decode_access_token

            payload = decode_access_token(token)
            conn = get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                login_context, login_error = validate_login_context_locked(conn, payload)
                if not login_error and login_context is not None:
                    invalidate_login_locked(conn, login_context.user_id, "admin_logout")
                    conn.commit()
                else:
                    conn.execute("ROLLBACK")
            finally:
                conn.close()
        except Exception:
            logger.warning("Admin logout token revocation failed", exc_info=True)


@router.post("/auth/logout")
async def logout(request: Request):
    await _revoke_admin_login(request)
    return _logout_redirect()


@router.get("/auth/logout")
async def legacy_logout():
    """Compatibility path: clear the cookie without a state-changing GET."""
    return _logout_redirect()


async def get_user_from_cookie(request: Request) -> dict | None:
    token = request.cookies.get("vf_token")
    if not token:
        return None
    try:
        from app.security import decode_access_token
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT id, username, email, is_admin FROM users WHERE id = ? AND is_admin = 1",
                (user_id,),
            ).fetchone()
            return dict(user) if user else None
        finally:
            conn.close()
    except Exception:
        return None
