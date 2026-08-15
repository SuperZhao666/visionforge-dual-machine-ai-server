"""Loopback-only administrative API consumed by the authenticated web panel."""
from __future__ import annotations

import secrets
from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from .admin_bridge_auth import verify_admin_request
from .admin_service import DualMachineAdminService
from .card_service import CardIssuanceService


class StrictAdminRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        strict=True,
    )


class IssueBatchRequest(StrictAdminRequest):
    request_id: str = Field(default_factory=lambda: secrets.token_hex(16))
    product_key: str = Field(min_length=1, max_length=32)
    quantity: int = Field(ge=1, le=500)
    channel: str = Field(default="xianyu", min_length=1, max_length=32)
    note: str = Field(default="", max_length=500)
    expires_at_epoch: int | None = Field(default=None, gt=0)


class ReasonRequest(StrictAdminRequest):
    reason: str = Field(min_length=2, max_length=200)


class RevokeBatchRequest(ReasonRequest):
    revoke_activated_entitlements: bool = False


class UpdateBatchRequest(ReasonRequest):
    note: str = Field(default="", max_length=500)
    expires_at_epoch: int | None = Field(default=None, gt=0)


class UpdateCodeRequest(ReasonRequest):
    admin_note: str = Field(default="", max_length=500)
    expires_at_epoch: int | None = Field(default=None, gt=0)


BatchId = Annotated[int, Path(ge=1)]
CodeId = Annotated[int, Path(ge=1)]
EntitlementId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
BindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]


async def _authorize_admin_bridge(request: Request) -> None:
    body = await request.body()
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    await run_in_threadpool(
        verify_admin_request,
        request.app.state.settings,
        method=request.method,
        request_target=target,
        headers={key.lower(): value for key, value in request.headers.items()},
        client_host=request.client.host if request.client else "",
        body=body,
    )


router = APIRouter(
    prefix="/internal/dual-machine-admin/v1",
    dependencies=[Depends(_authorize_admin_bridge)],
    include_in_schema=False,
)


def _admin(request: Request) -> DualMachineAdminService:
    return DualMachineAdminService(request.app.state.settings)


def _trace_id(request: Request) -> str:
    return str(getattr(request.state, "trace_id", "") or "")


def _deleted_filter(value: Literal["active", "deleted", "all"]):
    if value == "all":
        return None
    return value == "deleted"


@router.get("/products")
def list_products(request: Request, enabled: bool | None = None):
    return _admin(request).list_products(enabled=enabled)


@router.get("/batches")
def list_batches(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str = Query(default="", max_length=16),
    deleted: Literal["active", "deleted", "all"] = "active",
    query: str = Query(default="", max_length=128),
):
    return _admin(request).list_batches(
        limit=limit,
        offset=offset,
        status=status,
        deleted=_deleted_filter(deleted),
        query=query,
    )


@router.post("/batches")
def issue_batch(request: Request, body: IssueBatchRequest):
    result = CardIssuanceService(request.app.state.settings).issue_batch(
        request_id=body.request_id,
        product_key=body.product_key,
        quantity=body.quantity,
        channel=body.channel,
        note=body.note,
        expires_at_epoch=body.expires_at_epoch,
        trace_id=_trace_id(request),
    )
    return {"ok": True, **asdict(result)}


@router.patch("/batches/{batch_id}")
def update_batch(
    request: Request,
    batch_id: BatchId,
    body: UpdateBatchRequest,
):
    return _admin(request).update_batch(
        batch_id,
        note=body.note,
        expires_at_epoch=body.expires_at_epoch,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post("/batches/{batch_id}/revoke")
def revoke_batch(
    request: Request,
    batch_id: BatchId,
    body: RevokeBatchRequest,
):
    return _admin(request).revoke_batch(
        batch_id,
        reason=body.reason,
        revoke_activated_entitlements=body.revoke_activated_entitlements,
        trace_id=_trace_id(request),
    )


@router.post("/batches/{batch_id}/restore")
def restore_batch(
    request: Request,
    batch_id: BatchId,
    body: ReasonRequest,
):
    return _admin(request).restore_batch(
        batch_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.delete("/batches/{batch_id}")
def delete_batch(
    request: Request,
    batch_id: BatchId,
    body: ReasonRequest,
):
    return _admin(request).delete_batch(
        batch_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post("/batches/{batch_id}/unarchive")
def unarchive_batch(
    request: Request,
    batch_id: BatchId,
    body: ReasonRequest,
):
    return _admin(request).unarchive_batch(
        batch_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.get("/batches/{batch_id}/codes")
def list_codes(
    request: Request,
    batch_id: BatchId,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str = Query(default="", max_length=16),
    deleted: Literal["active", "deleted", "all"] = "active",
    query: str = Query(default="", max_length=128),
):
    return _admin(request).list_codes(
        batch_id=batch_id,
        limit=limit,
        offset=offset,
        status=status,
        deleted=_deleted_filter(deleted),
        query=query,
    )


@router.get("/codes")
def list_all_codes(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str = Query(default="", max_length=16),
    deleted: Literal["active", "deleted", "all"] = "active",
    query: str = Query(default="", max_length=128),
):
    return _admin(request).list_all_codes(
        limit=limit,
        offset=offset,
        status=status,
        deleted=_deleted_filter(deleted),
        query=query,
    )


@router.post("/batches/{batch_id}/export")
def export_batch_codes(request: Request, batch_id: BatchId):
    return _admin(request).export_batch_codes(
        batch_id,
        trace_id=_trace_id(request),
    )


@router.post("/codes/{code_id}/revoke")
def revoke_code(request: Request, code_id: CodeId, body: ReasonRequest):
    return _admin(request).revoke_code(
        code_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.patch("/codes/{code_id}")
def update_code(
    request: Request,
    code_id: CodeId,
    body: UpdateCodeRequest,
):
    return _admin(request).update_code(
        code_id,
        admin_note=body.admin_note,
        expires_at_epoch=body.expires_at_epoch,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post("/codes/{code_id}/restore")
def restore_code(request: Request, code_id: CodeId, body: ReasonRequest):
    return _admin(request).restore_code(
        code_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.delete("/codes/{code_id}")
def delete_code(request: Request, code_id: CodeId, body: ReasonRequest):
    return _admin(request).delete_code(
        code_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post("/codes/{code_id}/unarchive")
def unarchive_code(
    request: Request,
    code_id: CodeId,
    body: ReasonRequest,
):
    return _admin(request).unarchive_code(
        code_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.get("/entitlements/{entitlement_id}")
def entitlement_summary(request: Request, entitlement_id: EntitlementId):
    return _admin(request).entitlement_summary(entitlement_id)


@router.post("/entitlements/{entitlement_id}/revoke")
def revoke_entitlement(
    request: Request,
    entitlement_id: EntitlementId,
    body: ReasonRequest,
):
    return _admin(request).revoke_entitlement(
        entitlement_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post("/entitlements/{entitlement_id}/restore")
def restore_entitlement(
    request: Request,
    entitlement_id: EntitlementId,
    body: ReasonRequest,
):
    return _admin(request).restore_entitlement(
        entitlement_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.post(
    "/entitlements/{entitlement_id}/device-bindings/{binding_id}/unbind",
)
def unbind_entitlement_device(
    request: Request,
    entitlement_id: EntitlementId,
    binding_id: BindingId,
    body: ReasonRequest,
):
    return _admin(request).unbind_entitlement_device(
        entitlement_id,
        binding_id,
        reason=body.reason,
        trace_id=_trace_id(request),
    )


@router.get("/audit")
def list_audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str = Query(default="", max_length=80),
    query: str = Query(default="", max_length=128),
):
    return _admin(request).list_audit(
        limit=limit,
        offset=offset,
        event_type=event_type,
        query=query,
    )
