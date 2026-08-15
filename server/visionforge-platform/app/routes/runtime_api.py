"""Authenticated client runtime delivery endpoints."""
from __future__ import annotations

import logging
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response

from app.database import get_connection
from app.repositories.runtime_repository import RuntimeRepository
from app.security import get_current_user
from app.services.runtime_catalog_service import (
    apply_event_retention,
    authorize_same_origin_artifact,
    catalog_component,
    catalog_envelope,
    component_record_matches,
    create_runtime_ticket,
)
from app.services.minimum_client_policy import evaluate_minimum_client_version


logger = logging.getLogger("runtime_api")
router = APIRouter(prefix="/api/client/runtime")


class DownloadTicketRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9._-]+$")
    version: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9._-]+$")


class RuntimeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=80)
    status: str = Field(default="", max_length=40)
    error_code: str = Field(default="", max_length=80)
    failure_stage: str = Field(default="", max_length=40, pattern=r"^[a-z0-9_]*$")
    http_status: int = Field(default=0, ge=0, le=599)
    app_version: str = Field(default="", max_length=80)
    os_name: str = Field(default="", max_length=80)
    architecture: str = Field(default="", max_length=40)
    cpu_model: str = Field(default="", max_length=160)
    cpu_cores_physical: int = Field(default=0, ge=0, le=1024)
    cpu_cores_logical: int = Field(default=0, ge=0, le=1024)
    gpu_model: str = Field(default="", max_length=160)
    driver_version: str = Field(default="", max_length=40)
    compute_capability: str = Field(default="", max_length=16, pattern=r"^(?:\d{1,2}\.\d{1,2})?$")
    component_id: str = Field(default="", max_length=80)
    component_version: str = Field(default="", max_length=80)
    duration_ms: Any = 0
    bytes_count: Any = 0
    final_provider: Literal[
        "",
        "TensorrtExecutionProvider",
        "CUDAExecutionProvider",
        "DmlExecutionProvider",
        "CPUExecutionProvider",
    ] = ""


class RuntimeEventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=1, max_length=80)
    events: list[RuntimeEvent] = Field(min_length=1, max_length=50)


def _token_client_version(user: dict) -> str:
    return str(user.get("ver") or "legacy-unknown").strip()[:80]


def _require_supported_client_version(conn, client_version: str) -> str:
    verdict = evaluate_minimum_client_version(conn, client_version)
    if verdict.allowed:
        return verdict.client_version
    raise HTTPException(
        status_code=426,
        detail={
            "error": "client_update_required",
            "minimum_supported_version": verdict.minimum_supported_version,
            "client_version": verdict.client_version,
            "reason": verdict.reason,
        },
    )


@router.get("/catalog")
async def get_runtime_catalog(user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        _require_supported_client_version(conn, _token_client_version(user))
        row = RuntimeRepository(conn).active_catalog(int(user["sub"]))
        if not row:
            raise HTTPException(status_code=404, detail="no runtime catalog is available")
        return catalog_envelope(row)
    finally:
        conn.close()


@router.post("/download-ticket")
async def create_download_ticket(body: DownloadTicketRequest, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        user_id = int(user["sub"])
        client_version = _require_supported_client_version(
            conn,
            _token_client_version(user),
        )
        repository = RuntimeRepository(conn)
        catalog = repository.active_catalog(user_id)
        component = repository.component(body.component_id, body.version)
        signed_component = (
            catalog_component(catalog, body.component_id, body.version)
            if catalog is not None
            else None
        )
        if not component or signed_component is None:
            raise HTTPException(status_code=404, detail="runtime component is not published for this account")
        if not component_record_matches(component, signed_component):
            raise HTTPException(status_code=503, detail="runtime component metadata is inconsistent")
        try:
            url, expires = create_runtime_ticket(
                signed_component.object_key,
                user_id=user_id,
                client_version=client_version,
                catalog_payload_sha256=str(catalog["payload_sha256"]),
            )
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"ok": True, "url": url, "expires_at": expires}
    finally:
        conn.close()


@router.get("/artifacts/{object_key:path}")
async def download_same_origin_artifact(
    object_key: str,
    ticket_version: Annotated[int, Query(alias="tv", ge=2, le=2)],
    user_id: Annotated[int, Query(alias="uid", gt=0)],
    client_version: Annotated[str, Query(alias="ver", min_length=1, max_length=80)],
    catalog_payload_sha256: Annotated[
        str,
        Query(alias="catalog", min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
    ],
    expires: Annotated[int, Query(gt=0)],
    sig: Annotated[str, Query(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")],
):
    try:
        artifact, _normalized_key, ticket = authorize_same_origin_artifact(
            object_key,
            expires,
            sig,
            ticket_version=ticket_version,
            user_id=user_id,
            client_version=client_version,
            catalog_payload_sha256=catalog_payload_sha256,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="runtime artifact not found") from exc
    conn = get_connection()
    try:
        _require_supported_client_version(conn, ticket.client_version)
        user = conn.execute(
            "SELECT status, deleted_at FROM users WHERE id = ?",
            (ticket.user_id,),
        ).fetchone()
        if (
            not user
            or user["deleted_at"] is not None
            or str(user["status"] or "") != "active"
        ):
            raise HTTPException(status_code=403, detail="runtime ticket user is unavailable")
        active_catalog = RuntimeRepository(conn).active_catalog(ticket.user_id)
        if (
            not active_catalog
            or str(active_catalog["payload_sha256"])
            != ticket.catalog_payload_sha256
        ):
            raise HTTPException(status_code=403, detail="runtime ticket catalog is no longer active")
    finally:
        conn.close()
    internal_path = "/_runtime_artifacts/" + quote(artifact.name, safe="-._~")
    return Response(
        headers={
            "X-Accel-Redirect": internal_path,
            "Cache-Control": "private, no-store",
            "Content-Type": "application/zip",
        },
    )


@router.post("/events")
async def upload_runtime_events(body: RuntimeEventBatch, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        repository = RuntimeRepository(conn)
        inserted = repository.store_events(
            int(user["sub"]),
            body.attempt_id,
            [event.model_dump() for event in body.events],
        )
        apply_event_retention(repository)
        conn.commit()
        return {"ok": True, "accepted": inserted}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
