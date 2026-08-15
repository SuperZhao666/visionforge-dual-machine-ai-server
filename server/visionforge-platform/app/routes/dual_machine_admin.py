"""Cookie-authenticated admin UI for isolated dual-machine card operations."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import config
from app.database import get_connection
from app.routes.auth import get_user_from_cookie
from app.security import require_form_csrf
from app.services.admin_service import write_admin_audit
from app.services.dual_machine_admin_client import (
    DUAL_MACHINE_PRODUCT_KEYS,
    DualMachineAdminClient,
    DualMachineAdminClientError,
    get_dual_machine_admin_client,
)
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_form_csrf)])
logger = logging.getLogger("dual_machine_admin")

_PAGE_PATH = "/admin/dual-machine-cards"
_NETWORK_PAGE_PATH = "/admin/card-network"
_PRODUCT_ORDER = ("day", "week", "month", "permanent")
_PRODUCT_LABELS = {
    "day": "天卡",
    "week": "周卡",
    "month": "月卡",
    "permanent": "永久卡",
}
_BATCH_STATUSES = frozenset({"", "active", "revoked"})
_CODE_STATUSES = frozenset({"", "issued", "activated", "revoked", "expired"})
_DELETED_FILTERS = frozenset({"active", "deleted", "all"})
_ENTITLEMENT_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_CODE_SUFFIX_PATTERN = re.compile(r"^[23456789A-HJ-NP-Z]{1,4}$")
_CARD_ALPHABET = frozenset("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
_MAX_CODE_EXPIRY_SECONDS = 10 * 365 * 24 * 60 * 60
_SENSITIVE_KEYS = frozenset(
    {
        "card_code",
        "card_codes",
        "code",
        "codes",
        "code_digest",
        "derivation_ref",
        "derivation_reference",
        "license_code",
        "plaintext_code",
        "raw_code",
    }
)
_SUCCESS_MESSAGES = {
    "batch_issued": "卡密已签发，可在下方直接复制；批量导出为可选操作。",
    "batch_updated": "批次信息已更新。",
    "batch_revoked": "批次已停用。",
    "batch_restored": "批次已恢复。",
    "batch_archived": "批次已归档；业务数据仍保留。",
    "batch_unarchived": "批次已解除归档；原停用状态保持不变。",
    "code_revoked": "卡密已停用。",
    "code_updated": "卡密备注和发放有效期已更新。",
    "code_restored": "卡密已恢复。",
    "code_archived": "卡密已归档；业务数据仍保留。",
    "code_unarchived": "卡密已解除归档；原状态保持不变。",
    "entitlement_revoked": "双机授权已停用。",
    "entitlement_restored": "双机授权已恢复；未补时，用户需用原卡密重新绑定。",
    "device_unbound": "当前设备已解绑；活跃会话已结束，用户需用原卡密重新绑定。",
}
_ERROR_MESSAGES = {
    "invalid_product": "仅允许签发天卡、周卡、月卡或永久卡。",
    "invalid_quantity": "签发数量必须在 1 到 500 之间。",
    "invalid_note": "备注不能超过 500 个字符。",
    "invalid_expiry": "到期时间必须为空，或为未来十年内的 Unix 时间戳。",
    "invalid_reason": "操作原因必须为 2 到 200 个字符。",
    "sensitive_text": "备注或操作原因不得包含完整卡密；请改用卡密记录 ID 或末四位。",
    "invalid_identifier": "目标标识无效。",
    "invalid_search": "搜索条件格式不安全；卡密只能用记录 ID 或末四位查询。",
    "invalid_export": "侧车未返回可导出的卡密数据。",
    "bridge_unavailable": "双机侧车管理桥接不可用，请检查本机服务和桥接密钥。",
    "bridge_auth_failed": "双机侧车桥接鉴权失败，请检查双方密钥与系统时间。",
    "not_found": "目标不存在或已不可访问。",
    "product_unavailable": "所选双机卡产品当前不可签发。",
    "batch_has_activated": "批次已有卡密完成激活，不能再修改批次备注或兑换截止时间。",
    "batch_not_active": "卡密所属批次未启用，请先恢复批次。",
    "code_already_activated": "该卡密已经激活；如需停用，请操作对应双机授权。",
    "code_expired": "该卡密已过兑换截止时间，不能直接恢复。",
    "code_not_revoked": "只有已停用的卡密可以恢复。",
    "entitlement_not_revoked": "只有已停用的双机授权可以恢复。",
    "entitlement_source_unavailable": "来源卡密或批次未启用，不能恢复授权。",
    "device_binding_not_current": "只能解绑当前设备；历史绑定不可重复解绑。",
    "target_archived": "目标已归档，不能执行该操作；归档数据仍完整保留。",
    "operation_failed": "双机卡管理操作失败，请稍后重试。",
}


async def _admin_user(request: Request) -> dict[str, Any] | None:
    user = await get_user_from_cookie(request)
    return user if user and user.get("is_admin") else None


@router.get(_NETWORK_PAGE_PATH, response_class=HTMLResponse)
async def admin_card_network(request: Request):
    """Render a focused card-network dashboard over the sidecar contract."""

    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    payloads = await _load_card_network_payloads(
        get_dual_machine_admin_client()
    )
    load_error = _first_client_error(*payloads.values())
    context = {
        "active_page": "card_network",
        "user": user,
        "bridge_ready": bool(
            len(
                str(
                    config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET or ""
                ).encode("utf-8")
            )
            >= 32
        ),
        "product_options": _product_options(
            _safe_rows(payloads["products"], "products")
        ),
        "stats": {
            "batches": _payload_int(payloads["batches"], "total"),
            "issued": _payload_int(payloads["issued"], "total"),
            "activated": _payload_int(payloads["activated"], "total"),
            "revoked": _payload_int(payloads["revoked"], "total"),
            "expired": _payload_int(payloads["expired"], "total"),
            "archived": _payload_int(payloads["archived"], "total"),
        },
        "recent_batches": _safe_rows(payloads["batches"], "batches"),
        "recent_codes": _safe_rows(payloads["codes"], "codes"),
        "recent_audit": _safe_rows(
            payloads["audit"],
            "events",
            "audit",
        ),
        "error": _client_error_message(load_error) if load_error else "",
        "success": "",
    }
    response = templates.TemplateResponse(
        request,
        "admin/card_network.html",
        context,
    )
    _apply_sensitive_headers(response)
    return response


async def _load_card_network_payloads(
    client: DualMachineAdminClient,
) -> dict[str, dict[str, Any] | Exception]:
    calls = {
        "products": client.list_products(enabled=True),
        "batches": client.list_batches(limit=6, deleted="active"),
        "codes": client.list_all_codes(limit=8, deleted="active"),
        "issued": client.list_all_codes(
            limit=1,
            status="issued",
            deleted="active",
        ),
        "activated": client.list_all_codes(
            limit=1,
            status="activated",
            deleted="active",
        ),
        "revoked": client.list_all_codes(
            limit=1,
            status="revoked",
            deleted="active",
        ),
        "expired": client.list_all_codes(
            limit=1,
            status="expired",
            deleted="active",
        ),
        "archived": client.list_all_codes(limit=1, deleted="deleted"),
        "audit": client.list_audit(limit=8),
    }
    results = await asyncio.gather(
        *(_capture_client_call(call) for call in calls.values())
    )
    return dict(zip(calls, results, strict=True))


def _record_main_admin_audit(
    request: Request,
    user: Mapping[str, Any],
    *,
    action: str,
    target_type: str,
    target_id: object,
    detail: Mapping[str, Any] | None = None,
) -> None:
    trace_id = str(getattr(request.state, "trace_id", "") or "")
    safe_detail = _sanitize_public_data(dict(detail or {}))
    safe_detail["trace_id"] = trace_id
    connection = None
    try:
        connection = get_connection()
        connection.execute("BEGIN IMMEDIATE")
        write_admin_audit(
            connection,
            admin_user_id=int(user["id"]),
            ip_address=request.client.host if request.client else "",
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=safe_detail,
        )
        connection.commit()
    except Exception:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        logger.exception(
            "dual_machine_admin_audit_failed trace_id=%s action=%s",
            trace_id,
            str(action)[:120],
        )
    finally:
        if connection is not None:
            connection.close()


@router.get(_PAGE_PATH, response_class=HTMLResponse)
async def admin_dual_machine_cards(request: Request):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    filters = _page_filters(request)
    client = get_dual_machine_admin_client()
    products_payload, batches_payload, audit_payload = await _load_page_lists(
        client,
        filters,
    )
    load_error = _first_client_error(
        products_payload,
        batches_payload,
        audit_payload,
    )

    codes_payload: dict[str, Any] | Exception
    plaintext_payload: dict[str, Any] | Exception = {}
    if filters["batch_id"]:
        codes_payload, plaintext_payload = await asyncio.gather(
            _capture_client_call(
                client.list_codes(
                    filters["batch_id"],
                    limit=100,
                    offset=filters["code_offset"],
                    status=filters["code_status"],
                    deleted=filters["code_deleted"],
                    query=filters["code_query"],
                )
            ),
            _capture_client_call(
                client.export_batch_codes(filters["batch_id"])
            ),
        )
    else:
        codes_payload = await _capture_client_call(
            client.list_all_codes(
                limit=100,
                offset=filters["code_offset"],
                status=filters["code_status"],
                deleted=filters["code_deleted"],
                query=filters["code_query"],
            )
        )
    load_error = load_error or _first_client_error(
        codes_payload,
        plaintext_payload,
    )

    entitlement_payload: dict[str, Any] | Exception = {}
    if filters["entitlement_id"]:
        entitlement_payload = await _capture_client_call(
            client.entitlement_summary(filters["entitlement_id"])
        )
        load_error = load_error or _first_client_error(entitlement_payload)

    products = _safe_rows(products_payload, "products")
    batches = _safe_rows(batches_payload, "batches")
    codes = _safe_rows(codes_payload, "codes")
    _attach_plaintext_codes(codes, plaintext_payload)
    events = _safe_rows(audit_payload, "events", "audit")
    selected_batch = _safe_mapping(codes_payload, "batch")
    if not selected_batch and filters["batch_id"]:
        selected_batch = next(
            (
                row
                for row in batches
                if _safe_int(row.get("id"), minimum=1) == filters["batch_id"]
            ),
            {},
        )

    context = {
        "active_page": "dual_machine_cards",
        "user": user,
        "bridge_ready": bool(
            len(str(config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET or "").encode("utf-8"))
            >= 32
        ),
        "product_options": _product_options(products),
        "batches": batches,
        "batch_total": _payload_int(batches_payload, "total"),
        "codes": codes,
        "code_total": _payload_int(codes_payload, "total"),
        "selected_batch": selected_batch,
        "entitlement": _safe_entitlement(entitlement_payload),
        "audit_events": events,
        "audit_total": _payload_int(audit_payload, "total"),
        "filters": filters,
        "links": _pagination_links(
            filters, batches_payload, codes_payload, audit_payload
        ),
        "success": _SUCCESS_MESSAGES.get(
            _short_text(request.query_params.get("success"), 48),
            "",
        ),
        "error": _ERROR_MESSAGES.get(
            _short_text(request.query_params.get("error"), 48),
            "",
        )
        or (_client_error_message(load_error) if load_error else ""),
    }
    response = templates.TemplateResponse(
        request,
        "admin/dual_machine_cards.html",
        context,
    )
    _apply_sensitive_headers(response)
    return response


@router.post(f"{_PAGE_PATH}/issue")
async def issue_dual_machine_batch(
    request: Request,
    product_key: str = Form(""),
    quantity: int = Form(1),
    note: str = Form(""),
    expires_at_epoch: str = Form(""),
):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    safe_product = str(product_key or "").strip().lower()
    safe_note = str(note or "").strip()
    expiry = _optional_expiry(expires_at_epoch)
    if safe_product not in DUAL_MACHINE_PRODUCT_KEYS:
        return _redirect(error="invalid_product")
    if not 1 <= int(quantity) <= 500:
        return _redirect(error="invalid_quantity")
    if len(safe_note) > 500:
        return _redirect(error="invalid_note")
    if _looks_like_plaintext_card(safe_note):
        return _redirect(error="sensitive_text")
    if expiry is _INVALID:
        return _redirect(error="invalid_expiry")
    try:
        result = await get_dual_machine_admin_client().issue_batch(
            request_id=secrets.token_hex(16),
            product_key=safe_product,
            quantity=int(quantity),
            channel="admin_web",
            note=safe_note,
            expires_at_epoch=expiry,
        )
    except DualMachineAdminClientError as exc:
        _record_main_admin_audit(
            request,
            user,
            action="dual_machine.batch_issue_failed",
            target_type="dual_machine_product",
            target_id=safe_product,
            detail={"quantity": int(quantity), "error_code": exc.code},
        )
        return _redirect(error=_client_error_token(exc))
    codes = result.get("codes")
    if not isinstance(codes, list) or not codes:
        _record_main_admin_audit(
            request,
            user,
            action="dual_machine.batch_issue_response_invalid",
            target_type="dual_machine_batch",
            target_id=_safe_int(result.get("batch_id"), minimum=1),
            detail={"product_key": safe_product, "quantity": int(quantity)},
        )
        return _redirect(error="invalid_export")
    batch_id = _safe_int(result.get("batch_id"), minimum=1)
    if batch_id <= 0:
        return _redirect(error="invalid_export")
    _record_main_admin_audit(
        request,
        user,
        action="dual_machine.batch_issued",
        target_type="dual_machine_batch",
        target_id=batch_id,
        detail={"product_key": safe_product, "quantity": len(codes)},
    )
    return _redirect(
        success="batch_issued",
        batch_id=batch_id,
        anchor="dm-code-list",
    )


@router.post(f"{_PAGE_PATH}/filter")
async def filter_dual_machine_admin_page(
    request: Request,
    filter_scope: str = Form(""),
    batch_query: str = Form(""),
    batch_status: str = Form(""),
    batch_deleted: str = Form("active"),
    batch_id: int = Form(0),
    code_query: str = Form(""),
    code_status: str = Form(""),
    code_deleted: str = Form("active"),
    audit_event_type: str = Form(""),
    audit_query: str = Form(""),
):
    if not await _admin_user(request):
        return RedirectResponse("/login", status_code=303)
    scope = str(filter_scope or "").strip().lower()
    params: dict[str, str] = {}
    if scope == "batch":
        raw_query = _short_text(batch_query, 128)
        if _looks_like_plaintext_card(raw_query):
            return _redirect(error="invalid_search")
        params = {
            "batch_query": raw_query,
            "batch_status": _allowed_value(batch_status, _BATCH_STATUSES, ""),
            "batch_deleted": _allowed_value(
                batch_deleted,
                _DELETED_FILTERS,
                "active",
            ),
        }
    elif scope == "code":
        safe_code_query = (
            _safe_code_query(code_query)
            if batch_id > 0
            else _safe_non_card_query(code_query, 128)
        )
        if str(code_query or "").strip() and not safe_code_query:
            return _redirect(error="invalid_search", batch_id=batch_id)
        params = {
            "code_query": safe_code_query,
            "code_status": _allowed_value(code_status, _CODE_STATUSES, ""),
            "code_deleted": _allowed_value(
                code_deleted,
                _DELETED_FILTERS,
                "active",
            ),
        }
        if batch_id > 0:
            params["batch_id"] = str(batch_id)
    elif scope == "audit":
        safe_event_type = _safe_non_card_query(audit_event_type, 80)
        safe_audit_query = _safe_non_card_query(audit_query, 128)
        unsafe_event_type = bool(
            str(audit_event_type or "").strip() and not safe_event_type
        )
        unsafe_audit_query = bool(
            str(audit_query or "").strip() and not safe_audit_query
        )
        if unsafe_event_type or unsafe_audit_query:
            return _redirect(error="invalid_search", batch_id=batch_id)
        params = {
            "audit_event_type": safe_event_type,
            "audit_query": safe_audit_query,
        }
        if batch_id > 0:
            params["batch_id"] = str(batch_id)
    else:
        return _redirect(error="invalid_search")
    safe_params = {key: value for key, value in params.items() if value}
    location = _PAGE_PATH
    if safe_params:
        location += "?" + urlencode(safe_params)
    return RedirectResponse(location, status_code=303)


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/update")
async def update_dual_machine_batch(
    request: Request,
    batch_id: int,
    note: str = Form(""),
    expires_at_epoch: str = Form(""),
    reason: str = Form(""),
):
    safe_note = str(note or "").strip()
    expiry = _optional_expiry(expires_at_epoch)
    if len(safe_note) > 500:
        return await _authorized_redirect(request, error="invalid_note")
    if _looks_like_plaintext_card(safe_note):
        return await _authorized_redirect(request, error="sensitive_text")
    if expiry is _INVALID:
        return await _authorized_redirect(request, error="invalid_expiry")
    return await _run_action(
        request,
        lambda client: client.update_batch(
            batch_id,
            note=safe_note,
            expires_at_epoch=expiry,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="batch_updated",
        target_id=batch_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/revoke")
async def revoke_dual_machine_batch(
    request: Request,
    batch_id: int,
    reason: str = Form(""),
    revoke_activated_entitlements: str = Form(""),
):
    return await _run_action(
        request,
        lambda client: client.revoke_batch(
            batch_id,
            reason=str(reason or "").strip(),
            revoke_activated_entitlements=bool(revoke_activated_entitlements),
        ),
        reason=reason,
        success="batch_revoked",
        target_id=batch_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/restore")
async def restore_dual_machine_batch(
    request: Request,
    batch_id: int,
    reason: str = Form(""),
):
    return await _run_action(
        request,
        lambda client: client.restore_batch(
            batch_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="batch_restored",
        target_id=batch_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/archive")
async def archive_dual_machine_batch(
    request: Request,
    batch_id: int,
    reason: str = Form(""),
):
    return await _run_action(
        request,
        lambda client: client.archive_batch(
            batch_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="batch_archived",
        target_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/unarchive")
async def unarchive_dual_machine_batch(
    request: Request,
    batch_id: int,
    reason: str = Form(""),
):
    return await _run_action(
        request,
        lambda client: client.unarchive_batch(
            batch_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="batch_unarchived",
        target_id=batch_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/batches/{{batch_id}}/export")
async def export_dual_machine_batch(request: Request, batch_id: int):
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if batch_id <= 0:
        return _redirect(error="invalid_identifier")
    try:
        result = await get_dual_machine_admin_client().export_batch_codes(batch_id)
    except DualMachineAdminClientError as exc:
        _record_main_admin_audit(
            request,
            user,
            action="dual_machine.batch_export_failed",
            target_type="dual_machine_batch",
            target_id=batch_id,
            detail={"error_code": exc.code},
        )
        return _redirect(error=_client_error_token(exc), batch_id=batch_id)
    records = result.get("codes")
    if not isinstance(records, list):
        _record_main_admin_audit(
            request,
            user,
            action="dual_machine.batch_export_response_invalid",
            target_type="dual_machine_batch",
            target_id=batch_id,
        )
        return _redirect(error="invalid_export", batch_id=batch_id)
    rows = []
    for record in records:
        if not isinstance(record, Mapping) or not isinstance(record.get("code"), str):
            _record_main_admin_audit(
                request,
                user,
                action="dual_machine.batch_export_response_invalid",
                target_type="dual_machine_batch",
                target_id=batch_id,
            )
            return _redirect(error="invalid_export", batch_id=batch_id)
        rows.append(
            {
                "batch_id": batch_id,
                "code_id": _safe_int(record.get("id"), minimum=1),
                "ordinal": _safe_int(record.get("ordinal"), minimum=1),
                "status": str(record.get("status") or ""),
                "code_suffix": str(
                    record.get("code_suffix") or record.get("suffix") or ""
                ),
                "card_code": str(record["code"]),
            }
        )
    _record_main_admin_audit(
        request,
        user,
        action="dual_machine.batch_exported",
        target_type="dual_machine_batch",
        target_id=batch_id,
        detail={"exported_count": len(rows)},
    )
    return _csv_response(
        f"dual-machine-batch-{batch_id}.csv",
        rows,
        ("batch_id", "code_id", "ordinal", "status", "code_suffix", "card_code"),
    )


@router.post(f"{_PAGE_PATH}/codes/{{code_id}}/revoke")
async def revoke_dual_machine_code(
    request: Request,
    code_id: int,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    return await _run_action(
        request,
        lambda client: client.revoke_code(
            code_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="code_revoked",
        target_id=code_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/codes/{{code_id}}/update")
async def update_dual_machine_code(
    request: Request,
    code_id: int,
    admin_note: str = Form(""),
    expires_at_epoch: str = Form(""),
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    safe_note = str(admin_note or "").strip()
    expiry = _optional_expiry(expires_at_epoch)
    if len(safe_note) > 500:
        return await _authorized_redirect(request, error="invalid_note")
    if _looks_like_plaintext_card(safe_note):
        return await _authorized_redirect(request, error="sensitive_text")
    if expiry is _INVALID:
        return await _authorized_redirect(request, error="invalid_expiry")
    return await _run_action(
        request,
        lambda client: client.update_code(
            code_id,
            admin_note=safe_note,
            expires_at_epoch=expiry,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="code_updated",
        target_id=code_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/codes/{{code_id}}/restore")
async def restore_dual_machine_code(
    request: Request,
    code_id: int,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    return await _run_action(
        request,
        lambda client: client.restore_code(
            code_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="code_restored",
        target_id=code_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/codes/{{code_id}}/archive")
async def archive_dual_machine_code(
    request: Request,
    code_id: int,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    return await _run_action(
        request,
        lambda client: client.archive_code(
            code_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="code_archived",
        target_id=code_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/codes/{{code_id}}/unarchive")
async def unarchive_dual_machine_code(
    request: Request,
    code_id: int,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    return await _run_action(
        request,
        lambda client: client.unarchive_code(
            code_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="code_unarchived",
        target_id=code_id,
        batch_id=batch_id,
    )


@router.post(f"{_PAGE_PATH}/entitlements/{{entitlement_id}}/revoke")
async def revoke_dual_machine_entitlement(
    request: Request,
    entitlement_id: str,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    safe_entitlement_id = str(entitlement_id or "").strip().lower()
    if not _ENTITLEMENT_PATTERN.fullmatch(safe_entitlement_id):
        return await _authorized_redirect(request, error="invalid_identifier")
    return await _run_action(
        request,
        lambda client: client.revoke_entitlement(
            safe_entitlement_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="entitlement_revoked",
        target_id=1,
        batch_id=batch_id,
        entitlement_id=safe_entitlement_id,
    )


@router.post(f"{_PAGE_PATH}/entitlements/{{entitlement_id}}/restore")
async def restore_dual_machine_entitlement(
    request: Request,
    entitlement_id: str,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    safe_entitlement_id = str(entitlement_id or "").strip().lower()
    if not _ENTITLEMENT_PATTERN.fullmatch(safe_entitlement_id):
        return await _authorized_redirect(request, error="invalid_identifier")
    return await _run_action(
        request,
        lambda client: client.restore_entitlement(
            safe_entitlement_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="entitlement_restored",
        target_id=1,
        batch_id=batch_id,
        entitlement_id=safe_entitlement_id,
    )


@router.post(
    f"{_PAGE_PATH}/entitlements/{{entitlement_id}}/"
    "device-bindings/{binding_id}/unbind",
)
async def unbind_dual_machine_entitlement_device(
    request: Request,
    entitlement_id: str,
    binding_id: str,
    reason: str = Form(""),
    batch_id: int = Form(0),
):
    safe_entitlement_id = str(entitlement_id or "").strip().lower()
    safe_binding_id = str(binding_id or "").strip().lower()
    if (
        not _ENTITLEMENT_PATTERN.fullmatch(safe_entitlement_id)
        or not _ENTITLEMENT_PATTERN.fullmatch(safe_binding_id)
    ):
        return await _authorized_redirect(request, error="invalid_identifier")
    return await _run_action(
        request,
        lambda client: client.unbind_entitlement_device(
            safe_entitlement_id,
            safe_binding_id,
            reason=str(reason or "").strip(),
        ),
        reason=reason,
        success="device_unbound",
        target_id=1,
        batch_id=batch_id,
        entitlement_id=safe_entitlement_id,
        audit_detail={"binding_id": safe_binding_id},
    )


async def _run_action(
    request: Request,
    operation: Callable[[DualMachineAdminClient], Awaitable[dict[str, Any]]],
    *,
    reason: str,
    success: str,
    target_id: int,
    batch_id: int = 0,
    entitlement_id: str = "",
    audit_detail: Mapping[str, Any] | None = None,
) -> RedirectResponse:
    user = await _admin_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    safe_reason = str(reason or "").strip()
    if not 2 <= len(safe_reason) <= 200:
        return _redirect(
            error="invalid_reason",
            batch_id=batch_id,
            entitlement_id=entitlement_id,
        )
    if _looks_like_plaintext_card(safe_reason):
        return _redirect(
            error="sensitive_text",
            batch_id=batch_id,
            entitlement_id=entitlement_id,
        )
    if not 1 <= target_id <= 2_147_483_647 or not 0 <= batch_id <= 2_147_483_647:
        return _redirect(error="invalid_identifier")
    audit_subject = success.split("_", 1)[0]
    audit_target_id: object = entitlement_id or target_id
    try:
        await operation(get_dual_machine_admin_client())
    except DualMachineAdminClientError as exc:
        _record_main_admin_audit(
            request,
            user,
            action=f"dual_machine.{success}_failed",
            target_type=f"dual_machine_{audit_subject}",
            target_id=audit_target_id,
            detail={"error_code": exc.code, **dict(audit_detail or {})},
        )
        return _redirect(
            error=_client_error_token(exc),
            batch_id=batch_id,
            entitlement_id=entitlement_id,
        )
    _record_main_admin_audit(
        request,
        user,
        action=f"dual_machine.{success}",
        target_type=f"dual_machine_{audit_subject}",
        target_id=audit_target_id,
        detail={"result": "ok", **dict(audit_detail or {})},
    )
    return _redirect(
        success=success,
        batch_id=batch_id,
        entitlement_id=entitlement_id,
    )


async def _authorized_redirect(request: Request, *, error: str) -> RedirectResponse:
    if not await _admin_user(request):
        return RedirectResponse("/login", status_code=303)
    return _redirect(error=error)


async def _load_page_lists(
    client: DualMachineAdminClient,
    filters: dict[str, Any],
) -> tuple[dict[str, Any] | Exception, ...]:
    return tuple(
        await asyncio.gather(
            _capture_client_call(client.list_products(enabled=True)),
            _capture_client_call(
                client.list_batches(
                    limit=50,
                    offset=filters["batch_offset"],
                    status=filters["batch_status"],
                    deleted=filters["batch_deleted"],
                    query=filters["batch_query"],
                )
            ),
            _capture_client_call(
                client.list_audit(
                    limit=100,
                    offset=filters["audit_offset"],
                    event_type=filters["audit_event_type"],
                    query=filters["audit_query"],
                )
            ),
        )
    )


async def _capture_client_call(
    awaitable: Awaitable[dict[str, Any]],
) -> dict[str, Any] | Exception:
    try:
        return await awaitable
    except DualMachineAdminClientError as exc:
        return exc


def _page_filters(request: Request) -> dict[str, Any]:
    batch_query = _safe_non_card_query(
        request.query_params.get("batch_query"),
        128,
    )
    batch_id = _query_positive_int(request, "batch_id")
    return {
        "batch_query": batch_query,
        "batch_status": _allowed_value(
            request.query_params.get("batch_status"),
            _BATCH_STATUSES,
            "",
        ),
        "batch_deleted": _allowed_value(
            request.query_params.get("batch_deleted"),
            _DELETED_FILTERS,
            "active",
        ),
        "batch_offset": _query_offset(request, "batch_offset"),
        "batch_id": batch_id,
        "code_query": (
            _safe_code_query(request.query_params.get("code_query"))
            if batch_id
            else _safe_non_card_query(
                request.query_params.get("code_query"),
                128,
            )
        ),
        "code_status": _allowed_value(
            request.query_params.get("code_status"),
            _CODE_STATUSES,
            "",
        ),
        "code_deleted": _allowed_value(
            request.query_params.get("code_deleted"),
            _DELETED_FILTERS,
            "active",
        ),
        "code_offset": _query_offset(request, "code_offset"),
        "entitlement_id": _safe_entitlement_id(
            request.query_params.get("entitlement_id")
        ),
        "audit_event_type": _safe_non_card_query(
            request.query_params.get("audit_event_type"),
            80,
        ),
        "audit_query": _safe_non_card_query(
            request.query_params.get("audit_query"),
            128,
        ),
        "audit_offset": _query_offset(request, "audit_offset"),
    }


def _product_options(products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {
        str(item.get("product_key") or ""): item
        for item in products
        if str(item.get("product_key") or "") in DUAL_MACHINE_PRODUCT_KEYS
    }
    return [
        {
            "product_key": key,
            "display_name": str(
                by_key.get(key, {}).get("display_name") or _PRODUCT_LABELS[key]
            ),
            "duration_seconds": _safe_int(
                by_key.get(key, {}).get("duration_seconds"),
                minimum=0,
            ),
            "authorization_kind": str(
                by_key.get(key, {}).get("authorization_kind") or key
            ),
            "is_permanent": bool(
                by_key.get(key, {}).get("is_permanent") or key == "permanent"
            ),
        }
        for key in _PRODUCT_ORDER
    ]


def _pagination_links(
    filters: dict[str, Any],
    batches_payload: object,
    codes_payload: object,
    audit_payload: object,
) -> dict[str, str]:
    return {
        "batch_previous": _page_link(filters, "batch_offset", -50),
        "batch_next": _next_page_link(filters, "batch_offset", 50, batches_payload),
        "code_previous": _page_link(filters, "code_offset", -100),
        "code_next": _next_page_link(filters, "code_offset", 100, codes_payload),
        "audit_previous": _page_link(filters, "audit_offset", -100),
        "audit_next": _next_page_link(filters, "audit_offset", 100, audit_payload),
    }


def _page_link(filters: dict[str, Any], offset_key: str, delta: int) -> str:
    current = int(filters.get(offset_key) or 0)
    target = current + int(delta)
    if target < 0:
        return ""
    params = _url_filter_params(filters)
    params[offset_key] = str(target)
    return f"{_PAGE_PATH}?{urlencode(params)}"


def _next_page_link(
    filters: dict[str, Any],
    offset_key: str,
    page_size: int,
    payload: object,
) -> str:
    current = int(filters.get(offset_key) or 0)
    total = _payload_int(payload, "total")
    if current + page_size >= total:
        return ""
    return _page_link(filters, offset_key, page_size)


def _url_filter_params(filters: dict[str, Any]) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in filters.items():
        if value not in (None, "", 0, "active"):
            params[key] = str(value)
    return params


def _redirect(
    *,
    success: str = "",
    error: str = "",
    batch_id: int = 0,
    entitlement_id: str = "",
    anchor: str = "",
) -> RedirectResponse:
    params: dict[str, str] = {}
    if success in _SUCCESS_MESSAGES:
        params["success"] = success
    if error in _ERROR_MESSAGES:
        params["error"] = error
    if int(batch_id or 0) > 0:
        params["batch_id"] = str(int(batch_id))
    if _ENTITLEMENT_PATTERN.fullmatch(str(entitlement_id or "")):
        params["entitlement_id"] = str(entitlement_id)
    location = _PAGE_PATH
    if params:
        location += "?" + urlencode(params)
    if anchor == "dm-code-list":
        location += "#dm-code-list"
    return RedirectResponse(location, status_code=303)


def _csv_response(
    filename: str,
    rows: list[dict[str, Any]],
    fieldnames: tuple[str, ...],
) -> Response:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    response = Response(
        content=("\ufeff" + output.getvalue()).encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
    _apply_sensitive_headers(response)
    return response


def _apply_sensitive_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"


def _safe_rows(payload: object, *keys: str) -> list[dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    for key in keys:
        rows = payload.get(key)
        if isinstance(rows, list):
            return [
                _sanitize_public_data(row) for row in rows if isinstance(row, Mapping)
            ]
    return []


def _attach_plaintext_codes(
    rows: list[dict[str, Any]],
    payload: object,
) -> None:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("codes"), list):
        return
    plaintext_by_id: dict[int, str] = {}
    for record in payload["codes"]:
        if not isinstance(record, Mapping):
            continue
        code_id = _safe_int(record.get("id"), minimum=1)
        plaintext = _short_text(record.get("code"), 48)
        normalized = "".join(
            character for character in plaintext.upper() if character.isalnum()
        )
        if (
            code_id > 0
            and len(normalized) == 34
            and normalized.startswith("VFD2")
            and all(character in _CARD_ALPHABET for character in normalized[4:])
        ):
            plaintext_by_id[code_id] = plaintext

    for row in rows:
        plaintext = plaintext_by_id.get(_safe_int(row.get("id"), minimum=1), "")
        expected_suffix = _short_text(row.get("code_suffix"), 4).upper()
        normalized = "".join(
            character for character in plaintext.upper() if character.isalnum()
        )
        if plaintext and (not expected_suffix or normalized.endswith(expected_suffix)):
            row["plaintext_code"] = plaintext


def _safe_mapping(payload: object, key: str) -> dict[str, Any]:
    if isinstance(payload, Mapping) and isinstance(payload.get(key), Mapping):
        return _sanitize_public_data(payload[key])
    return {}


def _safe_entitlement(payload: object) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    nested = payload.get("entitlement")
    value = nested if isinstance(nested, Mapping) else payload
    sanitized = _sanitize_public_data(value)
    entitlement_id = str(sanitized.get("entitlement_id") or "")
    return sanitized if _ENTITLEMENT_PATTERN.fullmatch(entitlement_id) else {}


def _sanitize_public_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = str(key)
            normalized_key = safe_key.lower()
            if (
                normalized_key in _SENSITIVE_KEYS
                or "derivation" in normalized_key
                or "code_digest" in normalized_key
            ):
                continue
            if normalized_key == "detail_json" and isinstance(item, str):
                sanitized[safe_key] = _sanitize_audit_json(item)
            else:
                sanitized[safe_key] = _sanitize_public_data(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_public_data(item) for item in value]
    if isinstance(value, str) and _looks_like_plaintext_card(value):
        return "[redacted-card]"
    return value


def _sanitize_audit_json(value: str) -> str:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return "{}"
    return json.dumps(
        _sanitize_public_data(decoded),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _payload_int(payload: object, key: str) -> int:
    if not isinstance(payload, Mapping):
        return 0
    return _safe_int(payload.get(key), minimum=0)


def _safe_int(value: object, *, minimum: int = 0) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= minimum else 0


def _optional_expiry(value: object) -> int | None | object:
    text = str(value or "").strip()
    if not text:
        return None
    if not text.isascii() or not text.isdecimal():
        return _INVALID
    parsed = int(text)
    now = int(time.time())
    return parsed if now < parsed <= now + _MAX_CODE_EXPIRY_SECONDS else _INVALID


def _query_offset(request: Request, name: str) -> int:
    value = _short_text(request.query_params.get(name), 16)
    return int(value) if value.isdecimal() and int(value) <= 1_000_000 else 0


def _query_positive_int(request: Request, name: str) -> int:
    value = _short_text(request.query_params.get(name), 16)
    return int(value) if value.isdecimal() and 0 < int(value) <= 2_147_483_647 else 0


def _safe_entitlement_id(value: object) -> str:
    candidate = _short_text(value, 32).lower()
    return candidate if _ENTITLEMENT_PATTERN.fullmatch(candidate) else ""


def _safe_code_query(value: object) -> str:
    candidate = _short_text(value, 12).upper()
    if candidate.isdecimal() and len(candidate) <= 10:
        return candidate
    return candidate if _CODE_SUFFIX_PATTERN.fullmatch(candidate) else ""


def _looks_like_plaintext_card(value: str) -> bool:
    normalized = "".join(
        character for character in value.upper() if character.isalnum()
    )
    start = normalized.find("VFD2")
    while start >= 0:
        body = normalized[start + 4 : start + 34]
        if len(body) == 30 and all(character in _CARD_ALPHABET for character in body):
            return True
        start = normalized.find("VFD2", start + 1)
    return False


def _safe_non_card_query(value: object, maximum: int) -> str:
    candidate = _short_text(value, maximum)
    return "" if _looks_like_plaintext_card(candidate) else candidate


def _allowed_value(value: object, allowed: frozenset[str], default: str) -> str:
    candidate = _short_text(value, 32).lower()
    return candidate if candidate in allowed else default


def _short_text(value: object, maximum: int) -> str:
    return str(value or "").strip()[:maximum]


def _first_client_error(*values: object) -> DualMachineAdminClientError | None:
    return next(
        (value for value in values if isinstance(value, DualMachineAdminClientError)),
        None,
    )


def _client_error_token(error: DualMachineAdminClientError) -> str:
    if error.code == "dual_machine_admin_bridge_unavailable":
        return "bridge_unavailable"
    if error.code in {
        "dual_machine_admin_auth_invalid",
        "dual_machine_admin_request_stale",
        "dual_machine_admin_request_replayed",
        "dual_machine_admin_loopback_required",
    }:
        return "bridge_auth_failed"
    if error.status_code == 404 or error.code.endswith("_not_found"):
        return "not_found"
    if error.code == "dual_machine_product_unavailable":
        return "product_unavailable"
    if error.code == "dual_machine_batch_has_activated_codes":
        return "batch_has_activated"
    if error.code == "dual_machine_batch_not_active":
        return "batch_not_active"
    if error.code == "dual_machine_code_already_activated":
        return "code_already_activated"
    if error.code == "dual_machine_code_expired":
        return "code_expired"
    if error.code == "dual_machine_code_not_revoked":
        return "code_not_revoked"
    if error.code == "dual_machine_entitlement_not_revoked":
        return "entitlement_not_revoked"
    if error.code == "dual_machine_entitlement_source_unavailable":
        return "entitlement_source_unavailable"
    if error.code == "dual_machine_device_binding_not_current":
        return "device_binding_not_current"
    if error.code.endswith("_archived"):
        return "target_archived"
    return "operation_failed"


def _client_error_message(error: DualMachineAdminClientError) -> str:
    return _ERROR_MESSAGES[_client_error_token(error)]


_INVALID = object()
