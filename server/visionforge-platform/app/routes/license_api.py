from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.security import limiter
from app.models import LicenseActivateRequest, LicenseVerifyRequest
from app.database import get_connection
from app.services.license_service import verify_key_text


PLAN_DAYS = {"day": 1, "week": 7, "month": 31, "permanent": None}
PERMANENT_EXPIRIES = {"permanent", "永久", "never"}

router = APIRouter()


def _expiration_state(value: object) -> str:
    expires_at = str(value or "").strip()
    if not expires_at:
        return "missing"
    if expires_at.lower() in PERMANENT_EXPIRIES:
        return "valid"
    from datetime import datetime, timezone
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return "invalid"
    return "expired" if expiry <= datetime.now(timezone.utc) else "valid"


@router.post("/api/license/activate")
@limiter.limit("10/minute")
async def activate_license(request: Request, body: LicenseActivateRequest):
    """Activate a license key. Client sends key_text + machine_code."""
    payload = verify_key_text(body.key_text)
    if payload is None:
        return JSONResponse({
            "success": False, "message": "卡密无效：签名验证失败或格式错误",
        }, status_code=400)

    license_id = str(payload.get("license_id", ""))
    if not license_id:
        return JSONResponse({"success": False, "message": "卡密缺少 license_id"}, status_code=400)

    conn = get_connection()
    key_row = conn.execute(
        "SELECT id, status, hwid_hash, plan, expires_at FROM license_keys WHERE license_id = ?",
        (license_id,),
    ).fetchone()

    if not key_row:
        conn.close()
        return JSONResponse({"success": False, "message": "卡密未找到"}, status_code=404)

    status = key_row["status"]
    bound_hwid = key_row["hwid_hash"]
    machine_code = body.machine_code.strip().upper()

    if status == "revoked":
        conn.close()
        return JSONResponse({"success": False, "message": "此卡密已被吊销"}, status_code=403)
    if status == "expired":
        conn.close()
        return JSONResponse({"success": False, "message": "此卡密已过期"}, status_code=403)

    if status == "active":
        # Guard: active keys MUST have a bound HWID. If somehow None, reject.
        if not bound_hwid:
            conn.close()
            return JSONResponse({
                "success": False,
                "message": "卡密数据异常（未绑定机器码），请联系客服",
            }, status_code=500)
        if bound_hwid != machine_code:
            conn.close()
            return JSONResponse({
                "success": False,
                "message": "此卡密已绑定到另一台电脑，如需换绑请联系客服",
            }, status_code=403)
        import json as _json
        plan = str(key_row["plan"] or "")
        expires_at = str(key_row["expires_at"] or "")
        if plan not in PLAN_DAYS:
            conn.close()
            return JSONResponse({"success": False, "message": "卡密套餐数据异常，请联系客服"}, status_code=500)
        expiry_state = _expiration_state(expires_at)
        if expiry_state != "valid":
            conn.close()
            status_code = 403 if expiry_state == "expired" else 500
            return JSONResponse({"success": False, "message": "卡密已过期或到期数据异常"}, status_code=status_code)
        features = _json.dumps(payload.get("features", ["aim"]), ensure_ascii=False)
        conn.close()
        return {
            "success": True, "message": "卡密已激活（复用）",
            "plan": plan, "expires_at": expires_at, "features": features,
        }

    # status == "unused": First activation — calculate expiry from NOW
    key_plan = str(key_row["plan"] or "").strip()
    if key_plan not in PLAN_DAYS:
        conn.close()
        return JSONResponse({
            "success": False,
            "message": "卡密套餐数据异常，请联系客服",
        }, status_code=400)
    days = PLAN_DAYS.get(key_plan)
    if days is None:
        expire_sql = "'permanent'"
    else:
        expire_sql = f"datetime('now', '+{days} days')"

    result = conn.execute(
        f"UPDATE license_keys SET hwid_hash = ?, status = 'active', bound_at = datetime('now'), "
        f"expires_at = {expire_sql} "
        f"WHERE license_id = ? AND status = 'unused'",
        (machine_code, license_id),
    )
    if result.rowcount == 0:
        conn.close()
        return JSONResponse({
            "success": False,
            "message": "激活失败：卡密可能已被他人抢先激活，请刷新重试",
        }, status_code=409)

    conn.execute(
        "INSERT INTO activation_logs (license_id, hwid, client_version, ip) VALUES (?, ?, ?, ?)",
        (license_id, machine_code, body.client_version,
         request.client.host if request.client else ""),
    )
    conn.commit()

    persisted = conn.execute(
        "SELECT plan, expires_at FROM license_keys WHERE license_id = ?",
        (license_id,),
    ).fetchone()
    import json as _json
    plan = str(persisted["plan"] or "") if persisted else ""
    expires_at = str(persisted["expires_at"] or "") if persisted else ""
    features = _json.dumps(payload.get("features", ["aim"]), ensure_ascii=False)
    conn.close()
    return {
        "success": True, "message": "激活成功",
        "plan": plan, "expires_at": expires_at, "features": features,
    }


@router.post("/api/license/verify")
@limiter.limit("30/minute")
async def verify_license(request: Request, body: LicenseVerifyRequest):
    """Verify a license at client startup."""
    payload = verify_key_text(body.key_text)
    if payload is None:
        return JSONResponse({"valid": False, "reason": "卡密签名验证失败"}, status_code=400)

    license_id = str(payload.get("license_id", ""))
    machine_code = body.machine_code.strip().upper()

    conn = get_connection()
    key_row = conn.execute(
        "SELECT status, hwid_hash, plan, expires_at FROM license_keys WHERE license_id = ?",
        (license_id,),
    ).fetchone()
    conn.close()

    if not key_row:
        return {"valid": False, "reason": "卡密未找到"}
    if key_row["status"] == "revoked":
        return {"valid": False, "reason": "卡密已被吊销"}
    if key_row["status"] == "expired":
        return {"valid": False, "reason": "卡密已过期"}
    if key_row["status"] != "active":
        return {"valid": False, "reason": "license not activated"}
    if str(key_row["plan"] or "") not in PLAN_DAYS:
        return {"valid": False, "reason": "license plan data is invalid"}
    if not key_row["hwid_hash"]:
        return {"valid": False, "reason": "license activation data is incomplete"}
    if key_row["hwid_hash"] and key_row["hwid_hash"] != machine_code:
        return {"valid": False, "reason": "机器码不匹配"}

    expires_at = key_row["expires_at"]
    expiry_state = _expiration_state(expires_at)
    if expiry_state == "missing":
        return {"valid": False, "reason": "license expiration data is incomplete"}
    if expiry_state == "invalid":
        return {"valid": False, "reason": "license expiration data is invalid"}
    if expiry_state == "expired":
        return {"valid": False, "reason": "license expired"}
    days_left = None
    if str(expires_at or "").strip().lower() not in PERMANENT_EXPIRIES:
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = max(0, int((exp - now).total_seconds() // 86400) + 1)
        except (TypeError, ValueError, OverflowError):
            return {"valid": False, "reason": "license expiration data is invalid"}
    return {"valid": True, "reason": "OK", "plan": key_row["plan"], "days_left": days_left}
