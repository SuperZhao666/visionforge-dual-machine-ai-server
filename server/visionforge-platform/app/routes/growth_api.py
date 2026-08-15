"""Client redemption/referral APIs and private code-issuance integrations."""
from __future__ import annotations

import html
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.security import decode_access_token, limiter
from app.services.external_code_issuance_service import (
    ExternalCodeIssuanceError,
    issue_external_code,
)
from app.services.integration_auth_service import (
    IntegrationAuthError,
    authenticate_integration_request,
)
from app.services.growth_query_service import (
    invite_landing_info,
    is_redemption_enabled,
    latest_download_target,
    list_time_entries,
)
from app.services.redemption_service import redeem_code
from app.services.referral_service import referral_summary


router = APIRouter()
logger = logging.getLogger("growth_api")
MAX_CODE_ISSUANCE_BODY_BYTES = 64 * 1024


@router.post("/api/client/redemptions")
@limiter.limit("10/minute")
async def client_redeem(request: Request):
    user_id = _auth_user_id(request)
    if user_id is None:
        return _error("INVALID_TOKEN", "登录状态已失效，请重新登录", 401)
    try:
        body = await request.json()
    except Exception:
        return _error("INVALID_REQUEST", "请求格式无效", 400)
    if not isinstance(body, dict):
        return _error("INVALID_REQUEST", "invalid request payload", 400)
    if not is_redemption_enabled():
        return _error("REDEMPTION_DISABLED", "兑换功能当前未开放", 503)
    result = redeem_code(user_id, str(body.get("code") or ""))
    trace_id = _trace_id(request)
    if not result.ok:
        logger.warning(
            "redemption rejected trace_id=%s user_id=%s error_code=%s",
            trace_id,
            user_id,
            result.error_code,
        )
        status_code = 410 if result.error_code in {"CODE_EXPIRED", "CODE_REVOKED"} else 409
        return _error(result.error_code, result.message, status_code)
    logger.info(
        "redemption completed trace_id=%s user_id=%s code_id=%s credited=%s seconds=%s",
        trace_id,
        user_id,
        result.code_id,
        result.credited,
        result.credited_seconds,
    )
    return {
        "ok": True,
        "credited": result.credited,
        "message": result.message,
        "product_key": result.product_key,
        "product_name": result.product_name,
        "credited_seconds": result.credited_seconds,
        "balance_seconds": result.balance_seconds,
        "redeemed_at": result.redeemed_at,
    }


@router.get("/api/client/referrals")
@limiter.limit("30/minute")
async def client_referrals(request: Request, limit: int = 50):
    user_id = _auth_user_id(request)
    if user_id is None:
        return _error("INVALID_TOKEN", "登录状态已失效，请重新登录", 401)
    return {"ok": True, **referral_summary(user_id, limit=limit)}


@router.get("/api/client/referrals/summary")
@limiter.limit("30/minute")
async def client_referral_summary(request: Request):
    user_id = _auth_user_id(request)
    if user_id is None:
        return _error("INVALID_TOKEN", "登录状态已失效，请重新登录", 401)
    data = referral_summary(user_id, limit=10)
    data.pop("items", None)
    return {"ok": True, **data}


@router.get("/api/client/time/entries")
@limiter.limit("30/minute")
async def client_time_entries(request: Request, limit: int = 50):
    user_id = _auth_user_id(request)
    if user_id is None:
        return _error("INVALID_TOKEN", "登录状态已失效，请重新登录", 401)
    return {"ok": True, "items": list_time_entries(user_id, limit)}


@router.post("/api/integrations/code-issuances/issue")
@limiter.limit("120/minute")
async def external_code_issue(request: Request):
    """Return one fresh code for a paid order; Xianyu owns delivery and order state."""
    trace_id = _trace_id(request)
    try:
        content_length = str(request.headers.get("content-length") or "").strip()
        if content_length:
            declared_length = int(content_length)
            if declared_length < 0:
                return _error("INVALID_REQUEST", "invalid content-length", 400)
            if declared_length > MAX_CODE_ISSUANCE_BODY_BYTES:
                return _error("PAYLOAD_TOO_LARGE", "payload too large", 413)
        raw_body = await request.body()
        if len(raw_body) > MAX_CODE_ISSUANCE_BODY_BYTES:
            return _error("PAYLOAD_TOO_LARGE", "payload too large", 413)
        service_id = authenticate_integration_request(
            method=request.method,
            path=request.url.path,
            body=raw_body,
            headers=request.headers,
        )
        body = await request.json()
        if not isinstance(body, dict):
            return _error("INVALID_REQUEST", "请求参数无效", 400)
        result = issue_external_code(
            product_key=body.get("product_key"),
            request_id=body.get("request_id"),
            trace_id=trace_id,
        )
    except IntegrationAuthError as exc:
        logger.warning(
            "external code auth rejected trace_id=%s error_code=%s",
            trace_id,
            exc.error_code,
        )
        return _error("UNAUTHORIZED", "unauthorized", 401)
    except ExternalCodeIssuanceError as exc:
        logger.warning(
            "external code rejected trace_id=%s error_code=%s",
            trace_id,
            exc.error_code,
        )
        return _error(exc.error_code, exc.message, exc.status_code)
    except (TypeError, ValueError):
        return _error("INVALID_REQUEST", "请求参数无效", 400)
    logger.info(
        "external code issued trace_id=%s service_id=%s issuance_id=%s duplicate=%s product_key=%s",
        trace_id,
        service_id,
        result.issuance_id,
        result.duplicate,
        result.product_key,
    )
    return {
        "ok": True,
        "data": {
            "product_key": result.product_key,
            "product_name": result.product_name,
            "duration_seconds": result.duration_seconds,
            "redemption_code": result.redemption_code,
            "download_url": result.download_url,
        },
        "issuance_id": result.issuance_id,
        "trace_id": trace_id,
        "duplicate": result.duplicate,
    }


@router.get("/i/{invite_code}", response_class=HTMLResponse)
async def invite_landing(invite_code: str):
    info = invite_landing_info(invite_code)
    if not info:
        return HTMLResponse("邀请码无效", status_code=404)
    safe_code = html.escape(info.invite_code)
    safe_download = html.escape(info.download_url, quote=True)
    return HTMLResponse(
        "<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' "
        "content='width=device-width,initial-scale=1'><title>VisionForge 邀请</title>"
        "<style>body{font-family:system-ui;background:#0b1020;color:#eef3ff;margin:0;padding:48px}"
        ".card{max-width:680px;margin:auto;background:#151d31;padding:32px;border-radius:18px}"
        "code{font-size:26px;color:#67e8b3}a{display:inline-block;margin-top:20px;padding:12px 18px;"
        "background:#7367f0;color:white;text-decoration:none;border-radius:9px}</style>"
        f"<div class='card'><h1>好友邀请你使用 VisionForge</h1><p>注册时填写邀请码：</p>"
        f"<code>{safe_code}</code><p>安装客户端后，进入注册页面填写该邀请码。</p>"
        f"<a href='{safe_download}'>下载 VisionForge 客户端</a></div></html>"
    )


@router.get("/download")
async def public_download():
    return RedirectResponse(latest_download_target(), status_code=307)


def _auth_user_id(request: Request) -> int | None:
    auth = str(request.headers.get("Authorization") or "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return int(decode_access_token(auth[7:])["sub"])
    except Exception:
        return None


def _error(error_code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": error_code, "error_code": error_code, "message": message},
        status_code=status_code,
    )


def _trace_id(request: Request) -> str:
    return str(getattr(request.state, "trace_id", "") or "")
