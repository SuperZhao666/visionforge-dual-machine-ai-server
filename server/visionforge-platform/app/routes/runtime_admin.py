"""Admin API for offline-signed runtime catalogs and rollout controls."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from app.database import get_connection
from app.repositories.runtime_repository import RuntimeRepository
from app.security import require_admin
from app.services.admin_service import write_admin_audit
from app.services.runtime_catalog_service import (
    component_record_matches,
    validate_catalog_delivery,
    validate_offline_signed_catalog,
)


router = APIRouter(prefix="/api/admin/runtime", dependencies=[Depends(require_admin)])
RuntimeComponentId = Annotated[str, Path(min_length=1, max_length=80, pattern=r"^[a-z0-9._-]+$")]
RuntimeComponentVersion = Annotated[str, Path(min_length=1, max_length=80, pattern=r"^[a-z0-9._-]+$")]
PositivePathId = Annotated[int, Path(ge=1)]


class CatalogPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(pattern=r"^(pilot|stable)$")
    algorithm: str = "Ed25519"
    key_id: str = Field(min_length=1, max_length=80)
    payload_b64: str = Field(min_length=1, max_length=3_000_000)
    signature_b64: str = Field(min_length=1, max_length=1024)


class AllowlistRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(default="pilot", pattern=r"^(pilot|stable)$")
    note: str = Field(default="", max_length=500)


class CatalogActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=2, max_length=500)


def _audit(conn, request: Request, admin: dict, action: str, target_id: object, detail: dict | None = None) -> None:
    write_admin_audit(
        conn,
        admin_user_id=int(admin.get("sub") or 0),
        ip_address=request.client.host if request.client else "",
        action=action,
        target_type="runtime",
        target_id=target_id,
        detail=detail or {},
    )


@router.post("/catalogs")
async def publish_runtime_catalog(request: Request, body: CatalogPublishRequest, admin: dict = Depends(require_admin)):
    envelope = body.model_dump()
    try:
        catalog = validate_offline_signed_catalog(envelope, body.channel)
        await run_in_threadpool(validate_catalog_delivery, catalog)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_id = RuntimeRepository(conn).publish_catalog(catalog, envelope)
        _audit(conn, request, admin, "runtime.catalog.publish", release_id, {
            "catalog_version": catalog.catalog_version,
            "channel": catalog.channel,
            "payload_sha256": catalog.payload_sha256,
        })
        conn.commit()
        return {"ok": True, "release_id": release_id, "catalog_version": catalog.catalog_version}
    except ValueError as exc:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.post("/components/{component_id}/{version}/disable")
async def disable_runtime_component(
    component_id: RuntimeComponentId,
    version: RuntimeComponentVersion,
    request: Request,
    admin: dict = Depends(require_admin),
):
    conn = get_connection()
    try:
        changed = conn.execute(
            "UPDATE runtime_components SET enabled = 0, updated_at = datetime('now') "
            "WHERE component_id = ? AND version = ?",
            (component_id.lower(), version.lower()),
        ).rowcount
        if not changed:
            raise HTTPException(status_code=404, detail="runtime component not found")
        _audit(conn, request, admin, "runtime.component.disable", f"{component_id}@{version}")
        conn.commit()
        return {"ok": True, "disabled": True}
    finally:
        conn.close()


@router.put("/allowlist/{user_id}")
async def set_runtime_allowlist(
    user_id: PositivePathId,
    body: AllowlistRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    conn = get_connection()
    try:
        if not conn.execute(
            "SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="user not found")
        conn.execute(
            "INSERT INTO runtime_rollout_allowlist (user_id,channel,note) VALUES (?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET channel=excluded.channel,note=excluded.note,updated_at=datetime('now')",
            (user_id, body.channel, body.note),
        )
        _audit(conn, request, admin, "runtime.allowlist.set", user_id, {"channel": body.channel, "note": body.note})
        conn.commit()
        return {"ok": True, "user_id": user_id, "channel": body.channel}
    finally:
        conn.close()


@router.delete("/allowlist/{user_id}")
async def remove_runtime_allowlist(user_id: PositivePathId, request: Request, admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        deleted = conn.execute(
            "DELETE FROM runtime_rollout_allowlist WHERE user_id = ?", (user_id,)
        ).rowcount
        if deleted:
            _audit(conn, request, admin, "runtime.allowlist.remove", user_id)
        conn.commit()
        return {"ok": True, "user_id": user_id}
    finally:
        conn.close()


@router.post("/catalogs/{release_id}/disable")
async def disable_runtime_catalog(release_id: PositivePathId, request: Request, admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        changed = conn.execute(
            "UPDATE runtime_catalog_releases SET enabled = 0, updated_at = datetime('now') WHERE id = ?",
            (release_id,),
        ).rowcount
        if not changed:
            raise HTTPException(status_code=404, detail="runtime catalog not found")
        _audit(conn, request, admin, "runtime.catalog.disable", release_id)
        conn.commit()
        return {"ok": True, "disabled": True}
    finally:
        conn.close()


@router.post("/catalogs/{release_id}/activate")
async def activate_runtime_catalog(
    release_id: PositivePathId,
    body: CatalogActivationRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Atomically reactivate a previously signed catalog for emergency rollback."""
    conn = get_connection()
    try:
        target = conn.execute(
            "SELECT id,channel,algorithm,key_id,payload_b64,signature_b64,payload_sha256 "
            "FROM runtime_catalog_releases WHERE id = ?",
            (release_id,),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="runtime catalog not found")
        channel = str(target["channel"])
        envelope = {
            "channel": channel,
            "algorithm": str(target["algorithm"]),
            "key_id": str(target["key_id"]),
            "payload_b64": str(target["payload_b64"]),
            "signature_b64": str(target["signature_b64"]),
        }
        try:
            catalog = validate_offline_signed_catalog(envelope, channel)
            await run_in_threadpool(validate_catalog_delivery, catalog)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        repository = RuntimeRepository(conn)
        for signed_component in catalog.components:
            stored_component = repository.component(
                signed_component.component_id,
                signed_component.version,
            )
            if not component_record_matches(stored_component, signed_component):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "runtime catalog component is disabled or inconsistent: "
                        f"{signed_component.component_id}@{signed_component.version}"
                    ),
                )

        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT payload_sha256 FROM runtime_catalog_releases WHERE id = ?",
            (release_id,),
        ).fetchone()
        if not current or str(current["payload_sha256"]) != catalog.payload_sha256:
            raise HTTPException(status_code=409, detail="runtime catalog changed during activation")
        conn.execute(
            "UPDATE runtime_catalog_releases SET enabled = 0, updated_at = datetime('now') WHERE channel = ?",
            (channel,),
        )
        _audit(conn, request, admin, "runtime.catalog.activate", release_id, {"channel": channel, "reason": body.reason})
        conn.execute(
            "UPDATE runtime_catalog_releases SET enabled = 1, updated_at = datetime('now') WHERE id = ?",
            (release_id,),
        )
        conn.commit()
        return {"ok": True, "release_id": release_id, "channel": channel, "reason": body.reason}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
