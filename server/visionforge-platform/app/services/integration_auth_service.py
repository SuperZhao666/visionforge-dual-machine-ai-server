"""Replay-resistant authentication for private service integrations."""
from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
import time
from collections.abc import Mapping

from app.config import config
from app.database import get_connection


NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,80}$")


class IntegrationAuthError(ValueError):
    def __init__(self, error_code: str):
        super().__init__(error_code)
        self.error_code = error_code


def authenticate_integration_request(
    *,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
) -> str:
    """Validate service identity, signature, timestamp and one-time nonce."""
    configured_service = str(config.CODE_ISSUANCE_SERVICE_ID or "").strip()
    secret = str(config.CODE_ISSUANCE_HMAC_SECRET or "")
    service_id = str(headers.get("X-VF-Service") or "").strip()
    timestamp_text = str(headers.get("X-VF-Timestamp") or "").strip()
    nonce = str(headers.get("X-VF-Nonce") or "").strip()
    supplied_signature = str(headers.get("X-VF-Signature") or "").strip().lower()
    if not configured_service or len(secret) < 32:
        raise IntegrationAuthError("INTEGRATION_NOT_CONFIGURED")
    if service_id != configured_service:
        raise IntegrationAuthError("INVALID_SERVICE_IDENTITY")
    if not NONCE_RE.fullmatch(nonce) or len(supplied_signature) != 64:
        raise IntegrationAuthError("INVALID_SIGNATURE")
    try:
        timestamp = int(timestamp_text)
    except ValueError as exc:
        raise IntegrationAuthError("INVALID_TIMESTAMP") from exc
    max_skew = max(30, min(int(config.CODE_ISSUANCE_MAX_SKEW_SECONDS), 900))
    if abs(int(time.time()) - timestamp) > max_skew:
        raise IntegrationAuthError("REQUEST_EXPIRED")
    expected = _signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=timestamp_text,
        nonce=nonce,
        body=body,
    )
    if not hmac.compare_digest(expected, supplied_signature):
        raise IntegrationAuthError("INVALID_SIGNATURE")
    _consume_nonce(service_id, nonce)
    return service_id


def sign_integration_request(
    *,
    secret: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """Sign a private integration request without coupling it to one channel."""
    return _signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )


def _signature(*, secret: str, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    body_digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join((str(method).upper(), str(path), timestamp, nonce, body_digest))
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _consume_nonce(service_id: str, nonce: str) -> None:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM integration_nonces WHERE created_at < datetime('now', '-1 day')")
        conn.execute(
            "INSERT INTO integration_nonces (service_id, nonce) VALUES (?, ?)",
            (service_id, nonce),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise IntegrationAuthError("REQUEST_REPLAYED") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
