import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from app.database import init_db
from app.security import CSRF_COOKIE_NAME, generate_csrf_token, limiter, verify_csrf_token
from app.config import config
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# ── Server-side logging ─────────────────────────────────────────
LOG_DIR = Path(__file__).resolve().parents[2] / "server_logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "server.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("main")
_CONTENT_HASH_PATH_RE = re.compile(r"^/static/releases/[0-9a-f]{64}\.(?:exe|vfdiff)$")


def _is_public_release_artifact_path(path: str) -> bool:
    return bool(_CONTENT_HASH_PATH_RE.fullmatch(path))


def _is_blocked_release_static_path(path: str) -> bool:
    return path.startswith("/static/releases/") and not _is_public_release_artifact_path(path)


def _is_immutable_release_response(path: str, status_code: int) -> bool:
    return status_code in {200, 206, 304} and _is_public_release_artifact_path(path)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    logger.info("VisionForge Platform started")
    try:
        yield
    finally:
        logger.info("VisionForge Platform stopped")


app = FastAPI(title="VisionForge Platform", version="1.0.0", lifespan=lifespan)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    trace_id = uuid.uuid4().hex
    started_at = time.perf_counter()
    request.state.trace_id = trace_id
    csrf_path = request.url.path.startswith("/admin") or request.url.path in {"/login", "/auth/login"}
    csrf_token = str(request.cookies.get(CSRF_COOKIE_NAME) or "") if csrf_path else ""
    set_csrf_cookie = bool(csrf_path and not verify_csrf_token(csrf_token))
    if set_csrf_cookie:
        csrf_token = generate_csrf_token()
    request.state.csrf_token = csrf_token
    if _is_blocked_release_static_path(request.url.path):
        response = HTMLResponse("Not Found", status_code=404)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Trace-Id"] = trace_id
    if _is_immutable_release_response(request.url.path, response.status_code):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.url.path.startswith("/update/") or request.url.path == "/api/client/version":
        response.headers["Cache-Control"] = "no-store"
    if set_csrf_cookie:
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=True,
            secure=config.COOKIE_SECURE,
            samesite="strict",
            path="/",
            max_age=3600,
        )
    if request.url.path.startswith(
        (
            "/api/client/register-code",
            "/api/client/register",
            "/api/client/account/email-code",
            "/api/client/redemptions",
            "/api/client/referrals",
            "/api/integrations/code-issuances",
            "/api/client/runtime",
        )
    ):
        logger.info(
            "request trace_id=%s method=%s path=%s status=%s duration_ms=%.1f",
            trace_id,
            request.method,
            request.url.path,
            response.status_code,
            (time.perf_counter() - started_at) * 1000,
        )
    return response

# Static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
(static_dir / "css").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

from app.templating import templates  # noqa: E402


# Custom error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, _):
    return HTMLResponse(
        templates.env.get_template("404.html").render(request=request),
        status_code=404,
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, _):
    return HTMLResponse(
        templates.env.get_template("500.html").render(request=request),
        status_code=500,
    )


# Routes
from app.routes.auth import router as auth_router  # noqa: E402
app.include_router(auth_router, tags=["auth"])

from app.routes.web import router as web_router  # noqa: E402
app.include_router(web_router)

from app.routes.payment import router as payment_router  # noqa: E402
app.include_router(payment_router, tags=["payment"])

from app.routes.admin import router as admin_router  # noqa: E402
app.include_router(admin_router)

from app.routes.payment_admin import router as payment_admin_router  # noqa: E402
app.include_router(payment_admin_router, tags=["payment-admin"])

from app.routes.growth_admin import router as growth_admin_router  # noqa: E402
app.include_router(growth_admin_router, tags=["growth-admin"])

from app.routes.dual_machine_admin import router as dual_machine_admin_router  # noqa: E402
app.include_router(dual_machine_admin_router, tags=["dual-machine-admin"])

from app.routes.admin_api import router as admin_api_router  # noqa: E402
app.include_router(admin_api_router, tags=["admin-api"])

from app.routes.license_api import router as license_router  # noqa: E402
app.include_router(license_router, tags=["license"])

from app.routes.log_api import router as log_router  # noqa: E402
app.include_router(log_router, tags=["logs"])

from app.routes.client_api import router as client_router  # noqa: E402
app.include_router(client_router, tags=["client"])

from app.routes.time_api import router as time_router  # noqa: E402
app.include_router(time_router, tags=["time"])

from app.routes.growth_api import router as growth_router  # noqa: E402
app.include_router(growth_router, tags=["redemption-referral-code-issuance"])

from app.routes.runtime_api import router as runtime_router  # noqa: E402
app.include_router(runtime_router, tags=["runtime"])

from app.routes.runtime_admin import router as runtime_admin_router  # noqa: E402
app.include_router(runtime_admin_router, tags=["runtime-admin"])
