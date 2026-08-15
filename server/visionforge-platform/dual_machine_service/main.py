"""FastAPI factory for the isolated dual-machine sidecar."""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .audit import write_audit_event
from .card_service import CardActivationService
from .database import connect_database, initialize_database
from .errors import DualMachineServiceError
from .network import client_ip
from .pair_generation_composition import (
    build_pair_generation_authorization_service,
)
from .routes import limiter, router
from .internal_admin_routes import router as internal_admin_router
from .settings import DualMachineSettings
from .usage_service import UsageService


logger = logging.getLogger("dual_machine_service")


def create_app(
    settings: DualMachineSettings | None = None,
) -> FastAPI:
    runtime_settings = settings or DualMachineSettings.from_environment()
    runtime_settings.validate_runtime()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        initialize_database(runtime_settings)
        application.state.activation_service = CardActivationService(
            runtime_settings,
        )
        application.state.usage_service = UsageService(runtime_settings)
        application.state.pair_generation_service = (
            build_pair_generation_authorization_service(runtime_settings)
        )
        logger.info("dual_machine_service_started")
        try:
            yield
        finally:
            logger.info("dual_machine_service_stopped")

    application = FastAPI(
        title="VisionForge Dual Machine Service",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.limiter = limiter
    application.state.settings = runtime_settings
    application.add_exception_handler(
        RateLimitExceeded,
        _rate_limit_exceeded_handler,
    )
    application.add_exception_handler(
        DualMachineServiceError,
        _service_error_handler,
    )
    application.middleware("http")(_security_middleware)
    application.include_router(router)
    application.include_router(internal_admin_router)

    @application.get("/healthz", include_in_schema=False)
    def healthz():
        connection = connect_database(runtime_settings)
        try:
            connection.execute("SELECT 1").fetchone()
            return {"ok": True, "service": "dual-machine"}
        finally:
            connection.close()

    return application


async def _security_middleware(request: Request, call_next):
    trace_id = uuid.uuid4().hex
    request.state.trace_id = trace_id
    started_at = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), microphone=()"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Trace-Id"] = trace_id
    logger.info(
        "dual_machine_request trace_id=%s method=%s path=%s "
        "status=%s duration_ms=%.1f",
        trace_id,
        request.method,
        request.url.path,
        response.status_code,
        (time.perf_counter() - started_at) * 1000,
    )
    return response


async def _service_error_handler(
    request: Request,
    error: DualMachineServiceError,
) -> JSONResponse:
    logger.warning(
        "dual_machine_request_rejected trace_id=%s error=%s",
        str(getattr(request.state, "trace_id", "")),
        error.code,
    )
    await run_in_threadpool(
        _write_rejection_audit,
        request.app.state.settings,
        trace_id=str(getattr(request.state, "trace_id", "") or ""),
        path=request.url.path,
        method=request.method,
        ip_address=client_ip(request),
        error_code=error.code,
    )
    return JSONResponse(
        {"ok": False, "error": error.code},
        status_code=error.status_code,
    )


def _write_rejection_audit(
    settings: DualMachineSettings,
    *,
    trace_id: str,
    path: str,
    method: str,
    ip_address: str,
    error_code: str,
) -> None:
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        write_audit_event(
            connection,
            event_type="api_request_rejected",
            subject_type="api_route",
            subject_id=str(path)[:128],
            result="rejected",
            error_code=error_code,
            trace_id=trace_id,
            ip_address=ip_address,
            detail={"method": str(method)[:16]},
        )
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        logger.exception(
            "dual_machine_rejection_audit_failed trace_id=%s",
            trace_id,
        )
    finally:
        connection.close()
