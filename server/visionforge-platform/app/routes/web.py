"""Public web routes — landing page + admin login."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.templating import templates
from app.config import config

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "user": None,
        "download_url": config.DOWNLOAD_URL,
        "download_text": config.DOWNLOAD_TEXT,
    })


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    error = request.query_params.get("error", "")
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(request, "login.html", {
        "user": None, "error": error, "msg": msg,
        "totp_enabled": bool(config.ADMIN_TOTP_SECRET),
    })
