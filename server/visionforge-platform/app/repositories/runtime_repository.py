"""SQLite persistence for runtime delivery only."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any


MAX_SQLITE_INTEGER = 2**63 - 1


def _non_negative_event_int(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return min(max(0, parsed), MAX_SQLITE_INTEGER)


@dataclass
class RuntimeRepository:
    connection: sqlite3.Connection

    def active_catalog(self, user_id: int) -> dict[str, Any] | None:
        allowlist = self.connection.execute(
            "SELECT channel FROM runtime_rollout_allowlist WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        channel = str(allowlist["channel"] if allowlist else "stable")
        row = self.connection.execute(
            "SELECT * FROM runtime_catalog_releases WHERE channel = ? AND enabled = 1 "
            "ORDER BY id DESC LIMIT 1",
            (channel,),
        ).fetchone()
        if row is None and channel != "stable":
            row = self.connection.execute(
                "SELECT * FROM runtime_catalog_releases WHERE channel = 'stable' AND enabled = 1 "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def publish_catalog(self, catalog: Any, envelope: dict[str, str]) -> int:
        existing = self.connection.execute(
            "SELECT id,payload_sha256 FROM runtime_catalog_releases "
            "WHERE catalog_version = ? AND channel = ?",
            (catalog.catalog_version, catalog.channel),
        ).fetchone()
        idempotent_release_id: int | None = None
        if existing:
            if str(existing["payload_sha256"]) != catalog.payload_sha256:
                raise ValueError("runtime catalog version is immutable")
            idempotent_release_id = int(existing["id"])
        else:
            previous_versions = self.connection.execute(
                "SELECT catalog_version FROM runtime_catalog_releases WHERE channel = ?",
                (catalog.channel,),
            ).fetchall()
            incoming_version = _catalog_version_key(catalog.catalog_version)
            if any(
                incoming_version <= _catalog_version_key(str(row["catalog_version"]))
                for row in previous_versions
            ):
                raise ValueError("runtime catalog version must increase monotonically")

        for component in catalog.components:
            stored = self.connection.execute(
                "SELECT * FROM runtime_components WHERE component_id = ? AND version = ?",
                (component.component_id, component.version),
            ).fetchone()
            if stored is None:
                continue
            if not _component_matches(stored, component):
                raise ValueError(
                    f"runtime component version is immutable: "
                    f"{component.component_id}@{component.version}"
                )
            if not int(stored["enabled"]):
                raise ValueError(
                    f"runtime component is disabled; publish a new version: "
                    f"{component.component_id}@{component.version}"
                )

        if idempotent_release_id is not None:
            return idempotent_release_id

        self.connection.execute(
            "UPDATE runtime_catalog_releases SET enabled = 0, updated_at = datetime('now') WHERE channel = ?",
            (catalog.channel,),
        )
        values = (
            envelope["algorithm"], envelope["key_id"], envelope["payload_b64"],
            envelope["signature_b64"], catalog.payload_sha256,
        )
        release_id = int(self.connection.execute(
            "INSERT INTO runtime_catalog_releases "
            "(catalog_version, channel, algorithm, key_id, payload_b64, signature_b64, payload_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (catalog.catalog_version, catalog.channel, *values),
        ).lastrowid)
        for component in catalog.components:
            stored = self.connection.execute(
                "SELECT 1 FROM runtime_components WHERE component_id = ? AND version = ?",
                (component.component_id, component.version),
            ).fetchone()
            if stored is not None:
                continue
            self.connection.execute(
                "INSERT INTO runtime_components "
                "(component_id, version, object_key, archive_sha256, archive_size, metadata_json, enabled) "
                "VALUES (?, ?, ?, ?, ?, ?, 1)",
                (
                    component.component_id, component.version, component.object_key,
                    component.archive_sha256, component.archive_size,
                    json.dumps(component.raw, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                ),
            )
        return release_id

    def component(self, component_id: str, version: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM runtime_components WHERE component_id = ? AND version = ? AND enabled = 1",
            (component_id, version),
        ).fetchone()
        return dict(row) if row else None

    def store_events(self, user_id: int, attempt_id: str, events: list[dict[str, Any]]) -> int:
        inserted = 0
        for item in events:
            values = (
                str(item.get("event_id") or "")[:80], user_id, attempt_id[:80],
                str(item.get("event_type") or "")[:80], str(item.get("status") or "")[:40],
                str(item.get("error_code") or "")[:80], str(item.get("failure_stage") or "")[:40],
                min(599, _non_negative_event_int(item.get("http_status"))),
                str(item.get("app_version") or "")[:80],
                str(item.get("os_name") or "")[:80], str(item.get("architecture") or "")[:40],
                str(item.get("cpu_model") or "")[:160],
                _non_negative_event_int(item.get("cpu_cores_physical")),
                _non_negative_event_int(item.get("cpu_cores_logical")),
                str(item.get("gpu_model") or "")[:160], str(item.get("driver_version") or "")[:40],
                str(item.get("compute_capability") or "")[:16],
                str(item.get("component_id") or "")[:80], str(item.get("component_version") or "")[:80],
                _non_negative_event_int(item.get("duration_ms")),
                _non_negative_event_int(item.get("bytes_count")),
                str(item.get("final_provider") or "")[:80],
            )
            if values[0] and values[3]:
                inserted += self.connection.execute(
                    "INSERT OR IGNORE INTO runtime_install_events "
                    "(event_id,user_id,attempt_id,event_type,status,error_code,failure_stage,http_status,app_version,"
                    "os_name,architecture,cpu_model,cpu_cores_physical,cpu_cores_logical,gpu_model,driver_version,"
                    "compute_capability,component_id,component_version,duration_ms,bytes_count,final_provider) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    values,
                ).rowcount
        return inserted


def _catalog_version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _component_matches(stored: sqlite3.Row, component: Any) -> bool:
    try:
        metadata = json.loads(str(stored["metadata_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        str(stored["object_key"]) == component.object_key
        and str(stored["archive_sha256"]) == component.archive_sha256
        and int(stored["archive_size"]) == component.archive_size
        and metadata == component.raw
    )
