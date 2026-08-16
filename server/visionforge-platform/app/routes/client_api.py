"""Client API: version, update manifest, announcements, help FAQs and heartbeat."""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import config
from app.database import get_connection
from app.security import limiter
from app.services.release_service import ReleaseService, ReleaseValidationError, public_manifest
from dual_machine_service.release_manifest import CURRENT_RELEASE_ID, CURRENT_RELEASE_VERSION

logger = logging.getLogger("client_api")
router = APIRouter()
release_service = ReleaseService()


def _latest_release(channel: str = "stable") -> dict | None:
    return release_service.latest(channel)


def _with_current_release_identity(payload: dict) -> dict:
    result = dict(payload)
    result["release_id"] = CURRENT_RELEASE_ID
    result["release_version"] = CURRENT_RELEASE_VERSION
    return result


@router.get("/api/client/version")
async def client_version():
    """Return the latest available client version and download info."""
    release = _latest_release("stable")
    if not release:
        return _with_current_release_identity({
            "latest_version": CURRENT_RELEASE_VERSION,
            "download_url": str(config.SITE_URL or "").rstrip("/") + "/static/releases/",
            "release_notes": "稳定版本，推荐所有用户更新。",
        })
    return _with_current_release_identity(public_manifest(release))


@router.get("/update/{channel}.json")
async def update_manifest(channel: str, schema: int | None = None):
    """Public update manifest consumed by VisionForge clients."""
    try:
        release = _latest_release(channel)
    except ReleaseValidationError as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=422)
    if not release:
        return JSONResponse({"ok": False, "message": "no published release"}, status_code=404)
    try:
        return _with_current_release_identity(public_manifest(
            release,
            legacy_bridge_only=bool(release.get("payload_b64") and schema != 2),
        ))
    except ReleaseValidationError as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=409)


@router.get("/api/client/announcements")
@limiter.limit("60/minute")
async def client_announcements(request: Request, limit: int = 3):
    """Return active server-published announcements for clients."""
    safe_limit = max(1, min(int(limit or 3), 10))
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, title, body, level, created_at, starts_at, ends_at
            FROM announcements
            WHERE enabled = 1
              AND (starts_at = '' OR starts_at <= ?)
              AND (ends_at = '' OR ends_at >= ?)
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (now, now, safe_limit),
        ).fetchall()
    finally:
        conn.close()
    return {
        "ok": True,
        "items": [
            {
                "id": str(row["id"]),
                "title": row["title"],
                "body": row["body"],
                "level": row["level"],
                "created_at": row["created_at"],
                "starts_at": row["starts_at"],
                "ends_at": row["ends_at"],
                "url": "",
            }
            for row in rows
        ],
    }


@router.get("/api/client/help-faqs")
@limiter.limit("60/minute")
async def client_help_faqs(request: Request, limit: int = 30):
    """Return server-managed help center FAQ content for clients."""
    safe_limit = max(1, min(int(limit or 30), 50))
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, question, answer, sort_order, created_at, updated_at
            FROM help_faqs
            WHERE enabled = 1
            ORDER BY sort_order ASC, id ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    finally:
        conn.close()
    return {
        "ok": True,
        "items": [
            {
                "id": str(row["id"]),
                "question": row["question"],
                "answer": row["answer"],
                "sort_order": int(row["sort_order"] or 0),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ],
    }


@router.post("/api/client/heartbeat")
@limiter.limit("30/minute")
async def client_heartbeat(request: Request):
    """Receive periodic heartbeat from client with runtime status."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False}, status_code=400)

    license_id = str(body.get("license_id", ""))
    session_id = str(body.get("session_id", ""))
    if len(license_id) > 32 or len(session_id) > 64:
        return JSONResponse({"ok": False}, status_code=400)
    status = body.get("status", {})

    logger.debug(
        "Heartbeat: license=%s session=%s fps=%s",
        license_id,
        session_id,
        status.get("inference_fps", "?") if isinstance(status, dict) else "?",
    )

    return {"ok": True, "server_time": datetime.utcnow().isoformat()}
