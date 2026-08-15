"""Authenticated loopback client for the isolated dual-machine sidecar."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from app.config import config

DUAL_MACHINE_PRODUCT_KEYS = frozenset({"day", "week", "month", "permanent"})
_ADMIN_PREFIX = "/internal/dual-machine-admin/v1"
_AUTHORIZATION_SCHEME = "VF-Admin-HMAC v1"
_TIMESTAMP_HEADER = "X-VisionForge-Admin-Timestamp"
_NONCE_HEADER = "X-VisionForge-Admin-Nonce"
_SIGNATURE_HEADER = "X-VisionForge-Admin-Signature"
_ALLOWED_BASE_URLS = frozenset(
    {
        "http://127.0.0.1:8010",
        "http://localhost:8010",
        "http://[::1]:8010",
    }
)
_SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_]{1,96}$")
_TIMEOUT = httpx.Timeout(connect=1.0, read=5.0, write=5.0, pool=1.0)


class DualMachineAdminClientError(RuntimeError):
    """Sanitized sidecar failure safe to map to an administrator message."""

    def __init__(self, code: str, status_code: int = 502) -> None:
        safe_code = str(code or "dual_machine_admin_request_failed").strip().lower()
        if not _SAFE_ERROR_CODE.fullmatch(safe_code):
            safe_code = "dual_machine_admin_request_failed"
        super().__init__(safe_code)
        self.code = safe_code
        self.status_code = int(status_code)


class DualMachineAdminClient:
    """Small explicit client; it never follows redirects or trusts proxy env."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        secret: str | bytes | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = str(base_url or config.DUAL_MACHINE_ADMIN_BASE_URL).rstrip("/")
        configured_secret = (
            config.DUAL_MACHINE_ADMIN_BRIDGE_SECRET if secret is None else secret
        )
        self._secret = (
            configured_secret
            if isinstance(configured_secret, bytes)
            else str(configured_secret or "").encode("utf-8")
        )
        self._transport = transport

    async def list_products(self, *, enabled: bool | None = True) -> dict[str, Any]:
        params = [] if enabled is None else [("enabled", _bool_text(enabled))]
        return await self._request("GET", "/products", params=params)

    async def list_batches(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str = "",
        deleted: str = "active",
        query: str = "",
    ) -> dict[str, Any]:
        params = _list_params(limit, offset, status, deleted, query)
        return await self._request("GET", "/batches", params=params)

    async def issue_batch(
        self,
        *,
        request_id: str,
        product_key: str,
        quantity: int,
        channel: str,
        note: str,
        expires_at_epoch: int | None,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/batches",
            payload={
                "request_id": request_id,
                "product_key": product_key,
                "quantity": int(quantity),
                "channel": channel,
                "note": note,
                "expires_at_epoch": expires_at_epoch,
            },
        )

    async def update_batch(
        self,
        batch_id: int,
        *,
        note: str,
        expires_at_epoch: int | None,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "PATCH",
            f"/batches/{int(batch_id)}",
            payload={
                "note": note,
                "expires_at_epoch": expires_at_epoch,
                "reason": reason,
            },
        )

    async def revoke_batch(
        self,
        batch_id: int,
        *,
        reason: str,
        revoke_activated_entitlements: bool,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/batches/{int(batch_id)}/revoke",
            payload={
                "reason": reason,
                "revoke_activated_entitlements": bool(revoke_activated_entitlements),
            },
        )

    async def restore_batch(self, batch_id: int, *, reason: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/batches/{int(batch_id)}/restore",
            payload={"reason": reason},
        )

    async def archive_batch(self, batch_id: int, *, reason: str) -> dict[str, Any]:
        return await self._request(
            "DELETE",
            f"/batches/{int(batch_id)}",
            payload={"reason": reason},
        )

    async def unarchive_batch(
        self,
        batch_id: int,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/batches/{int(batch_id)}/unarchive",
            payload={"reason": reason},
        )

    async def list_codes(
        self,
        batch_id: int,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        deleted: str = "active",
        query: str = "",
    ) -> dict[str, Any]:
        params = _list_params(limit, offset, status, deleted, query)
        return await self._request(
            "GET",
            f"/batches/{int(batch_id)}/codes",
            params=params,
        )

    async def list_all_codes(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        deleted: str = "active",
        query: str = "",
    ) -> dict[str, Any]:
        params = _list_params(limit, offset, status, deleted, query)
        return await self._request("GET", "/codes", params=params)

    async def export_batch_codes(self, batch_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/batches/{int(batch_id)}/export")

    async def revoke_code(self, code_id: int, *, reason: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/codes/{int(code_id)}/revoke",
            payload={"reason": reason},
        )

    async def update_code(
        self,
        code_id: int,
        *,
        admin_note: str,
        expires_at_epoch: int | None,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "PATCH",
            f"/codes/{int(code_id)}",
            payload={
                "admin_note": admin_note,
                "expires_at_epoch": expires_at_epoch,
                "reason": reason,
            },
        )

    async def restore_code(self, code_id: int, *, reason: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/codes/{int(code_id)}/restore",
            payload={"reason": reason},
        )

    async def archive_code(self, code_id: int, *, reason: str) -> dict[str, Any]:
        return await self._request(
            "DELETE",
            f"/codes/{int(code_id)}",
            payload={"reason": reason},
        )

    async def unarchive_code(
        self,
        code_id: int,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/codes/{int(code_id)}/unarchive",
            payload={"reason": reason},
        )

    async def entitlement_summary(self, entitlement_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/entitlements/{entitlement_id}")

    async def revoke_entitlement(
        self,
        entitlement_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/entitlements/{entitlement_id}/revoke",
            payload={"reason": reason},
        )

    async def restore_entitlement(
        self,
        entitlement_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/entitlements/{entitlement_id}/restore",
            payload={"reason": reason},
        )

    async def unbind_entitlement_device(
        self,
        entitlement_id: str,
        binding_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/entitlements/{entitlement_id}/device-bindings/"
            f"{binding_id}/unbind",
            payload={"reason": reason},
        )

    async def list_audit(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: str = "",
        query: str = "",
    ) -> dict[str, Any]:
        params = [("limit", str(int(limit))), ("offset", str(int(offset)))]
        if event_type:
            params.append(("event_type", event_type))
        if query:
            params.append(("query", query))
        return await self._request("GET", "/audit", params=params)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_configuration()
        body = _json_body(payload)
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=_TIMEOUT,
                trust_env=False,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                request = client.build_request(
                    method.upper(),
                    _ADMIN_PREFIX + path,
                    params=params,
                    content=body,
                    headers=headers,
                )
                self._authenticate(request, body)
                response = await client.send(request)
        except httpx.RequestError as exc:
            raise DualMachineAdminClientError(
                "dual_machine_admin_bridge_unavailable",
                503,
            ) from exc
        return _decode_response(response)

    def _validate_configuration(self) -> None:
        if self._base_url not in _ALLOWED_BASE_URLS or len(self._secret) < 32:
            raise DualMachineAdminClientError(
                "dual_machine_admin_bridge_unavailable",
                503,
            )

    def _authenticate(self, request: httpx.Request, body: bytes) -> None:
        timestamp = int(time.time())
        nonce = secrets.token_hex(16)
        request_target = request.url.raw_path.decode("ascii")
        canonical = "\n".join(
            (
                "visionforge-dual-machine-admin-v1",
                request.method.upper(),
                request_target,
                str(timestamp),
                nonce,
                hashlib.sha256(body).hexdigest(),
            )
        ).encode("ascii")
        signature = hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()
        request.headers["Authorization"] = _AUTHORIZATION_SCHEME
        request.headers[_TIMESTAMP_HEADER] = str(timestamp)
        request.headers[_NONCE_HEADER] = nonce
        request.headers[_SIGNATURE_HEADER] = signature


def get_dual_machine_admin_client() -> DualMachineAdminClient:
    return DualMachineAdminClient()


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _list_params(
    limit: int,
    offset: int,
    status: str,
    deleted: str,
    query: str,
) -> list[tuple[str, str]]:
    params = [
        ("limit", str(int(limit))),
        ("offset", str(int(offset))),
        ("deleted", deleted),
    ]
    if status:
        params.append(("status", status))
    if query:
        params.append(("query", query))
    return params


def _json_body(payload: Mapping[str, Any] | None) -> bytes:
    if payload is None:
        return b""
    return json.dumps(
        dict(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_response(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise DualMachineAdminClientError(
            "dual_machine_admin_invalid_response",
            502,
        ) from exc
    if not isinstance(payload, dict):
        raise DualMachineAdminClientError(
            "dual_machine_admin_invalid_response",
            502,
        )
    if response.status_code >= 400 or payload.get("ok") is not True:
        raise DualMachineAdminClientError(
            str(payload.get("error") or "dual_machine_admin_request_failed"),
            response.status_code,
        )
    return payload
