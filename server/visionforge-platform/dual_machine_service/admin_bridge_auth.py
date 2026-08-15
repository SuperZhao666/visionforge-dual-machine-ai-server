"""Authenticated loopback contract for web-admin to sidecar commands."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import sqlite3
import time
from collections.abc import Mapping

from .database import connect_database
from .errors import DualMachineServiceError
from .settings import DualMachineSettings


AUTHORIZATION_SCHEME = "VF-Admin-HMAC v1"
TIMESTAMP_HEADER = "X-VisionForge-Admin-Timestamp"
NONCE_HEADER = "X-VisionForge-Admin-Nonce"
SIGNATURE_HEADER = "X-VisionForge-Admin-Signature"
_NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def sign_admin_request(
    secret: bytes,
    *,
    method: str,
    request_target: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> str:
    """Return the v1 signature without retaining or logging secret material."""
    if len(secret) < 32:
        raise ValueError("admin bridge secret must contain at least 32 bytes")
    canonical = _canonical_request(
        method=method,
        request_target=request_target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify_admin_request(
    settings: DualMachineSettings,
    *,
    method: str,
    request_target: str,
    headers: Mapping[str, str],
    client_host: str,
    body: bytes,
    now_epoch: int | None = None,
) -> None:
    """Fail closed unless the request is loopback, fresh, signed and unique."""
    secret = bytes(settings.admin_bridge_secret)
    if len(secret) < 32:
        raise DualMachineServiceError(
            "dual_machine_admin_bridge_unavailable",
            503,
        )
    if not _is_loopback(client_host):
        raise DualMachineServiceError(
            "dual_machine_admin_loopback_required",
            403,
        )
    authorization = str(headers.get("authorization") or "")
    timestamp_text = str(headers.get(TIMESTAMP_HEADER.lower()) or "")
    nonce = str(headers.get(NONCE_HEADER.lower()) or "")
    signature = str(headers.get(SIGNATURE_HEADER.lower()) or "")
    if (
        authorization != AUTHORIZATION_SCHEME
        or not timestamp_text.isascii()
        or not timestamp_text.isdecimal()
        or not _NONCE_PATTERN.fullmatch(nonce)
        or not _SIGNATURE_PATTERN.fullmatch(signature)
    ):
        raise DualMachineServiceError(
            "dual_machine_admin_auth_invalid",
            401,
        )
    timestamp = int(timestamp_text)
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    if abs(now - timestamp) > int(settings.admin_bridge_max_skew_seconds):
        raise DualMachineServiceError(
            "dual_machine_admin_request_stale",
            401,
        )
    expected = sign_admin_request(
        secret,
        method=method,
        request_target=request_target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    if not hmac.compare_digest(expected, signature):
        raise DualMachineServiceError(
            "dual_machine_admin_auth_invalid",
            401,
        )
    _consume_nonce(settings, nonce=nonce, now_epoch=now)


def _canonical_request(
    *,
    method: str,
    request_target: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> bytes:
    target = str(request_target or "")
    if not target.startswith("/") or "\n" in target or "\r" in target:
        raise ValueError("request target is invalid")
    normalized_method = str(method or "").strip().upper()
    if not normalized_method or not normalized_method.isascii():
        raise ValueError("method is invalid")
    return "\n".join(
        (
            "visionforge-dual-machine-admin-v1",
            normalized_method,
            target,
            str(int(timestamp)),
            str(nonce),
            hashlib.sha256(body).hexdigest(),
        )
    ).encode("ascii")


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_loopback
    except ValueError:
        return False


def _consume_nonce(
    settings: DualMachineSettings,
    *,
    nonce: str,
    now_epoch: int,
) -> None:
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM dm_auth_nonces "
            "WHERE scope = 'internal_admin' AND expires_at_epoch < ?",
            (int(now_epoch),),
        )
        connection.execute(
            "INSERT INTO dm_auth_nonces "
            "(scope, subject_id, nonce_digest, expires_at_epoch) "
            "VALUES ('internal_admin', 'web_admin', ?, ?)",
            (
                hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                int(now_epoch)
                + int(settings.admin_bridge_max_skew_seconds) * 2,
            ),
        )
        connection.commit()
    except sqlite3.IntegrityError as replay:
        if connection.in_transaction:
            connection.rollback()
        raise DualMachineServiceError(
            "dual_machine_admin_request_replayed",
            409,
        ) from replay
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
