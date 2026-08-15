"""Sanitized audit events owned exclusively by the dual-machine sidecar."""
from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any


def write_audit_event(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    subject_type: str,
    subject_id: str = "",
    result: str = "ok",
    error_code: str = "",
    trace_id: str = "",
    ip_address: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        "INSERT INTO dm_audit_events "
        "(event_id, trace_id, event_type, subject_type, subject_id, "
        "result, error_code, ip_address, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            secrets.token_hex(16),
            _bounded(trace_id, 64),
            _bounded(event_type, 80),
            _bounded(subject_type, 40),
            _bounded(subject_id, 128),
            _bounded(result, 24),
            _bounded(error_code, 80),
            _bounded(ip_address, 128),
            json.dumps(
                detail or {},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )


def _bounded(value: object, maximum: int) -> str:
    return str(value or "")[:int(maximum)]
