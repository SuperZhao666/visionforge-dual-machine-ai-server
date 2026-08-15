"""SQLite persistence for application releases."""
from __future__ import annotations

import sqlite3
from typing import Any


_RELEASE_COLUMNS = (
    "version",
    "channel",
    "notes",
    "url",
    "sha256",
    "installer_url",
    "installer_sha256",
    "min_supported_version",
    "manifest_published_at",
    "mandatory",
    "published",
    "target_size",
    "deltas_json",
    "algorithm",
    "key_id",
    "payload_b64",
    "signature_b64",
)


class ReleaseRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def list(self, channel: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if channel:
            rows = self.connection.execute(
                "SELECT * FROM releases WHERE channel = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                (channel, limit),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM releases ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, release_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM releases WHERE id = ?",
            (release_id,),
        ).fetchone()
        return dict(row) if row else None

    def find(self, version: str, channel: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM releases WHERE version = ? AND channel = ? LIMIT 1",
            (version, channel),
        ).fetchone()
        return dict(row) if row else None

    def published(self, channel: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM releases WHERE channel = ? AND published = 1 LIMIT 1",
            (channel,),
        ).fetchone()
        return dict(row) if row else None

    def signed_publications(self, channel: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id, version, min_supported_version, mandatory, "
            "manifest_published_at, payload_b64, signature_b64 FROM releases "
            "WHERE channel = ? AND payload_b64 != ''",
            (channel,),
        ).fetchall()
        return [dict(row) for row in rows]

    def publication_history(self, channel: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id, version, min_supported_version, mandatory, published, "
            "created_at, manifest_published_at, payload_b64, signature_b64 "
            "FROM releases WHERE channel = ?",
            (channel,),
        ).fetchall()
        return [dict(row) for row in rows]

    def has_signed_publication(self, channel: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM releases WHERE channel = ? AND payload_b64 != '' LIMIT 1",
            (channel,),
        ).fetchone()
        return row is not None

    def save(self, values: dict[str, Any], release_id: int | None = None) -> int:
        if release_id is None:
            existing = self.find(str(values["version"]), str(values["channel"]))
            release_id = int(existing["id"]) if existing else None
        if release_id is None:
            columns = ", ".join(_RELEASE_COLUMNS)
            placeholders = ", ".join("?" for _ in _RELEASE_COLUMNS)
            cursor = self.connection.execute(
                f"INSERT INTO releases ({columns}) VALUES ({placeholders})",
                tuple(values[column] for column in _RELEASE_COLUMNS),
            )
            return int(cursor.lastrowid)
        assignments = ", ".join(f"{column} = ?" for column in _RELEASE_COLUMNS)
        updated = self.connection.execute(
            f"UPDATE releases SET {assignments}, updated_at = datetime('now') WHERE id = ?",
            (*tuple(values[column] for column in _RELEASE_COLUMNS), release_id),
        ).rowcount
        if not updated:
            raise LookupError("release not found")
        return int(release_id)

    def unpublish_channel(self, channel: str, *, except_release_id: int | None = None) -> None:
        if except_release_id is None:
            self.connection.execute(
                "UPDATE releases SET published = 0, updated_at = datetime('now') "
                "WHERE channel = ? AND published = 1",
                (channel,),
            )
            return
        self.connection.execute(
            "UPDATE releases SET published = 0, updated_at = datetime('now') "
            "WHERE channel = ? AND published = 1 AND id != ?",
            (channel, except_release_id),
        )

    def activate(self, release_id: int) -> None:
        updated = self.connection.execute(
            "UPDATE releases SET published = 1, updated_at = datetime('now') WHERE id = ?",
            (release_id,),
        ).rowcount
        if not updated:
            raise LookupError("release not found")

    def delete(self, release_id: int) -> bool:
        return bool(self.connection.execute("DELETE FROM releases WHERE id = ?", (release_id,)).rowcount)
