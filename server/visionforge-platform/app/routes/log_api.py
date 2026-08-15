"""Log upload and crash report API endpoints for VisionForge clients."""
from __future__ import annotations

import json as _json
import re as _re
import zipfile
from io import BytesIO
from pathlib import PurePosixPath

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse

from app.database import get_connection
from app.security import decode_access_token, limiter
from app.services.log_service import log_upload_policy, store_log_file

router = APIRouter()

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_CRASH_BODY_BYTES = 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
UPLOAD_READ_CHUNK_BYTES = 1024 * 1024


def _auth_user_id(request: Request) -> int | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return int(decode_access_token(auth[7:]).get("sub") or 0) or None
    except Exception:
        return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _safe_json_obj(text: str) -> dict:
    try:
        data = _json.loads(text or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _content_length_error(request: Request, max_bytes: int, *, overhead_bytes: int = 0) -> JSONResponse | None:
    declared = request.headers.get("content-length", "").strip()
    if not declared:
        return None
    try:
        value = int(declared)
    except ValueError:
        return JSONResponse({"ok": False, "error": "invalid content-length"}, status_code=400)
    if value < 0:
        return JSONResponse({"ok": False, "error": "invalid content-length"}, status_code=400)
    if value > max_bytes + overhead_bytes:
        return JSONResponse({"ok": False, "error": "payload too large"}, status_code=413)
    return None


async def _read_upload_limited(file: UploadFile, max_bytes: int) -> bytes:
    content = bytearray()
    while True:
        chunk = await file.read(UPLOAD_READ_CHUNK_BYTES)
        if not chunk:
            return bytes(content)
        content.extend(chunk)
        if len(content) > max_bytes:
            raise ValueError("payload too large")


def _zip_validation_error(content: bytes) -> str:
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                return "zip contains too many entries"
            total_size = 0
            for info in infos:
                normalized = PurePosixPath(info.filename.replace("\\", "/"))
                if normalized.is_absolute() or ".." in normalized.parts:
                    return "zip contains an unsafe path"
                total_size += max(0, int(info.file_size))
                if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    return "zip expands beyond the allowed size"
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return "invalid zip bundle"
    return ""


@router.get("/api/client/log-upload-policy")
@limiter.limit("60/minute")
async def client_log_upload_policy(request: Request):
    user_id = _auth_user_id(request)
    if user_id is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    conn = get_connection()
    try:
        return {"ok": True, "policy": log_upload_policy(conn, user_id)}
    finally:
        conn.close()


@router.post("/api/client/log-bundles")
@limiter.limit("12/hour")
async def upload_client_log_bundle(
    request: Request,
    file: UploadFile = File(...),
    client_id: str = Form(default="", max_length=96),
    session_id: str = Form(..., max_length=96),
    file_type: str = Form(default="bug_report_zip", max_length=32),
    filename: str = Form(default="", max_length=160),
    size: str = Form(default="0", max_length=32),
    mtime_ns: str = Form(default="0", max_length=32),
    machine_info: str = Form(default="{}", max_length=32768),
    reason: str = Form(default="scheduled", max_length=120),
):
    """Receive periodic client bug-report ZIP bundles.

    This is intentionally ZIP-only. Fine-grained logs stay inside the bundle;
    the database stores searchable metadata so the system disk is not filled
    with many tiny per-event uploads.
    """
    user_id = _auth_user_id(request)
    if user_id is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    conn = get_connection()
    try:
        policy = log_upload_policy(conn, user_id)
    finally:
        conn.close()
    if not policy.get("enabled", True):
        return {"ok": True, "skipped": True, "message": "log upload disabled", "policy": policy}

    max_bytes = int(policy.get("max_bundle_bytes") or MAX_UPLOAD_BYTES)
    length_error = _content_length_error(request, max_bytes, overhead_bytes=64 * 1024)
    if length_error is not None:
        return length_error
    if not file.filename:
        return JSONResponse({"ok": False, "error": "missing file"}, status_code=400)

    original = filename.strip() or file.filename
    if not original.lower().endswith(".zip"):
        return JSONResponse({"ok": False, "error": "only zip bug-report bundles are accepted"}, status_code=400)

    try:
        content = await _read_upload_limited(file, max_bytes)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"bundle exceeds {max_bytes // 1024 // 1024}MB limit"}, status_code=413)
    if not content:
        return JSONResponse({"ok": False, "error": "empty file"}, status_code=400)
    zip_error = _zip_validation_error(content)
    if zip_error:
        return JSONResponse({"ok": False, "error": zip_error}, status_code=400)
    try:
        declared_size = int(size or 0)
    except ValueError:
        return JSONResponse({"ok": False, "error": "invalid declared size"}, status_code=400)
    if declared_size > 0 and declared_size != len(content):
        return JSONResponse({"ok": False, "error": "declared size does not match upload"}, status_code=400)

    machine = _safe_json_obj(machine_info)
    machine["client_id"] = client_id[:96]
    machine["reason"] = reason
    metadata = {
        "reason": reason,
        "client_id": client_id[:96],
        "declared_file_type": file_type[:32],
        "declared_size": size,
        "mtime_ns": mtime_ns,
        "remote_ip": _client_ip(request),
        "bundle_kind": "bug_report_zip",
    }
    try:
        meta = store_log_file(
            session_id,
            "bug_report_zip",
            original,
            content,
            user_id=user_id,
            machine_info=machine,
            ip_address=_client_ip(request),
            metadata=metadata,
        )
        return {"ok": True, "message": "bundle uploaded", "data": meta, "policy": policy}
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception:
        import logging

        logging.getLogger("log_api").exception("Log bundle upload failed")
        return JSONResponse({"ok": False, "error": "internal error"}, status_code=500)


@router.post("/api/logs/upload")
@limiter.limit("10/minute")
async def upload_logs(
    request: Request,
    file: UploadFile = File(...),
    session_id: str = Form(..., max_length=64),
    file_type: str = Form(default="txt", max_length=16),
    machine_info: str = Form(default="{}", max_length=4096),
):
    """Legacy single-file upload endpoint kept for old clients."""
    user_id = _auth_user_id(request)
    if user_id is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    length_error = _content_length_error(request, MAX_UPLOAD_BYTES, overhead_bytes=64 * 1024)
    if length_error is not None:
        return length_error

    if not file.filename:
        return JSONResponse({"ok": False, "message": "No file provided"}, status_code=400)
    if not _re.match(r"^[a-z0-9_]+$", file_type):
        return JSONResponse({"ok": False, "message": "Invalid file_type"}, status_code=400)

    try:
        content = await _read_upload_limited(file, MAX_UPLOAD_BYTES)
    except ValueError:
        return JSONResponse({"ok": False, "message": f"File exceeds {MAX_UPLOAD_BYTES // 1024 // 1024}MB limit"}, status_code=413)
    if len(content) == 0:
        return JSONResponse({"ok": False, "message": "Empty file"}, status_code=400)
    try:
        meta = store_log_file(
            session_id,
            file_type,
            file.filename,
            content,
            user_id=user_id,
            machine_info=machine_info,
            ip_address=_client_ip(request),
        )
        return {"ok": True, "message": "Uploaded", "data": meta}
    except ValueError as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=400)
    except Exception:
        import logging

        logging.getLogger("log_api").exception("Log upload failed")
        return JSONResponse({"ok": False, "message": "Internal error"}, status_code=500)


@router.post("/api/logs/crash")
@limiter.limit("30/minute")
async def report_crash(request: Request):
    """Legacy real-time crash report endpoint."""
    user_id = _auth_user_id(request)
    if user_id is None:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    length_error = _content_length_error(request, MAX_CRASH_BODY_BYTES)
    if length_error is not None:
        return length_error
    body_bytes = await request.body()
    if len(body_bytes) > MAX_CRASH_BODY_BYTES:
        return JSONResponse({"ok": False, "error": "payload too large"}, status_code=413)
    try:
        body = _json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, _json.JSONDecodeError):
        return JSONResponse({"ok": False, "message": "Invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "message": "Invalid JSON object"}, status_code=400)

    raw_session_id = str(body.get("session_id", "unknown"))
    raw_crash_type = str(body.get("crash_type", "unhandled_exception"))
    if len(raw_session_id) > 64 or len(raw_crash_type) > 32:
        return JSONResponse({"ok": False, "message": "Invalid crash report fields"}, status_code=400)

    session_id = _re.sub(r"[^a-zA-Z0-9_.-]", "_", raw_session_id) or "unknown"
    machine_info = str(body.get("machine_info", "{}"))
    crash_type = _re.sub(r"[^a-zA-Z0-9_.-]", "_", raw_crash_type) or "unhandled_exception"
    crash_data = str(body.get("crash_data", ""))

    content = _json.dumps({
        "crash_type": crash_type,
        "crash_data": crash_data,
        "machine_info": machine_info,
    }, ensure_ascii=False, indent=2).encode("utf-8")

    try:
        meta = store_log_file(
            session_id,
            "crash",
            f"crash_{crash_type}.json",
            content,
            user_id=user_id,
            machine_info=machine_info,
            ip_address=_client_ip(request),
        )
        return {"ok": True, "message": "Crash reported", "data": meta}
    except Exception:
        import logging

        logging.getLogger("log_api").exception("Crash report failed")
        return JSONResponse({"ok": False, "message": "Internal error"}, status_code=500)
