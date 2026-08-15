"""Validated, transactional publication of application releases."""
from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import config
from app.database import get_connection
from app.repositories.release_repository import ReleaseRepository
from app.services.minimum_client_policy import numeric_version_key as _numeric_version_key


SIGNED_RELEASE_SCHEMA_VERSION = 2
SIGNED_RELEASE_ALGORITHM = "Ed25519"
DELTA_ALGORITHM = "visionforge-exe-delta-v1"
MAX_UPDATE_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_PUBLISHED_AT_FUTURE_SKEW = timedelta(minutes=15)
RELEASE_STATIC_ROOT = Path(__file__).resolve().parents[1] / "static" / "releases"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
_CHANNEL_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_PAYLOAD_FIELDS = {
    "schema_version",
    "channel",
    "version",
    "min_supported_version",
    "mandatory",
    "published_at",
    "target",
    "deltas",
    "notes",
}
_TARGET_FIELDS = {"url", "sha256", "size", "kind"}
_DELTA_FIELDS = {"base_sha256", "url", "sha256", "size", "algorithm"}
_ENVELOPE_FIELDS = {
    "algorithm",
    "key_id",
    "payload_b64",
    "signature_b64",
}
_SIGNED_RELEASE_REQUEST_FIELDS = _ENVELOPE_FIELDS | {
    "channel",
    "legacy_bridge_url",
    "legacy_bridge_sha256",
}


class ReleaseValidationError(ValueError):
    pass


class ReleaseNotFoundError(LookupError):
    pass


class ReleaseConflictError(RuntimeError):
    pass


AuditCallback = Callable[[sqlite3.Connection, int], None]


def normalize_channel(value: object) -> str:
    channel = str(value or "stable").strip().lower()
    if not _CHANNEL_RE.fullmatch(channel):
        raise ReleaseValidationError("invalid release channel")
    return channel


def normalize_version(value: object, *, optional: bool = False) -> str:
    version = str(value or "").strip()
    if optional and not version:
        return ""
    if not _VERSION_RE.fullmatch(version):
        raise ReleaseValidationError("invalid release version")
    return version


def normalize_sha256(value: object, *, optional: bool = False) -> str:
    digest = str(value or "").strip().lower()
    if optional and not digest:
        return ""
    if not _SHA256_RE.fullmatch(digest):
        raise ReleaseValidationError("invalid sha256")
    return digest


def _validate_version_floor(version: str, min_supported_version: str) -> None:
    version_key = _numeric_version_key(version)
    minimum_key = _numeric_version_key(min_supported_version)
    if version_key and minimum_key and minimum_key > version_key:
        raise ReleaseValidationError("min_supported_version must not be newer than version")


def validate_release_url(value: object, *, optional: bool = False) -> str:
    url = str(value or "").strip()
    if optional and not url:
        return ""
    if not url or any(ch.isspace() for ch in url):
        raise ReleaseValidationError("invalid release URL")
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        decoded_path = unquote(parsed.path)
        normalized_path = posixpath.normpath(decoded_path)
        if (
            "?" in url
            or "#" in url
            or not decoded_path.startswith("/static/releases/")
            or normalized_path != decoded_path
        ):
            raise ReleaseValidationError("relative release URLs must stay under /static/releases/")
        return url
    if "?" in url or "#" in url:
        raise ReleaseValidationError(
            "absolute release URLs must not contain query strings or fragments"
        )
    if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ReleaseValidationError("absolute release URLs must use same-origin HTTPS")
    site = urlsplit(_release_site_origin_url())
    if _origin(parsed) != _origin(site):
        raise ReleaseValidationError("third-party release URLs are not allowed")
    return url


def _origin(parsed) -> tuple[str, str, int]:
    scheme = str(parsed.scheme or "").lower()
    default_port = 443 if scheme == "https" else 80
    try:
        port = int(parsed.port or default_port)
    except ValueError as exc:
        raise ReleaseValidationError("invalid port in release URL") from exc
    return scheme, str(parsed.hostname or "").lower(), port


def _release_site_origin_url() -> str:
    value = str(config.SITE_URL or "").strip()
    parsed = urlsplit(value)
    if (
        not value
        or any(ch.isspace() for ch in value)
        or parsed.scheme.lower() != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or "?" in value
        or "#" in value
    ):
        raise ReleaseValidationError("SITE_URL must be an origin-only HTTPS URL")
    _origin(parsed)
    return value.rstrip("/")


def _positive_size(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseValidationError(f"{field_name} must be a positive integer")
    if value > MAX_UPDATE_ARTIFACT_BYTES:
        raise ReleaseValidationError(f"{field_name} exceeds the 512 MiB client limit")
    return value


def _rfc3339_timestamp(value: object) -> str:
    timestamp = str(value or "").strip()
    if not timestamp or len(timestamp) > 40:
        raise ReleaseValidationError("published_at must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseValidationError("published_at must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ReleaseValidationError("published_at must include a timezone")
    if parsed.astimezone(timezone.utc) > datetime.now(timezone.utc) + MAX_PUBLISHED_AT_FUTURE_SKEW:
        raise ReleaseValidationError("published_at exceeds the allowed future clock skew")
    return timestamp


def _timestamp_key(value: object) -> datetime:
    timestamp = _rfc3339_timestamp(value)
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)


def _local_release_path(url: str) -> Path | None:
    parsed = urlsplit(url)
    if parsed.scheme:
        site = urlsplit(str(config.SITE_URL or ""))
        if _origin(parsed) != _origin(site):
            return None
    decoded_path = unquote(parsed.path)
    if not decoded_path.startswith("/static/releases/"):
        return None
    relative = decoded_path.removeprefix("/static/releases/")
    root = RELEASE_STATIC_ROOT.resolve()
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ReleaseValidationError("release file escapes the local releases directory") from exc
    if not candidate.is_file():
        raise ReleaseValidationError("release artifact is not a regular file")
    return candidate


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
    except MemoryError as exc:
        raise ReleaseValidationError("release artifact cannot be read safely") from exc
    return digest.hexdigest()


def _verify_local_artifact(url: str, expected_sha256: str, expected_size: int) -> None:
    try:
        path = _local_release_path(url)
    except FileNotFoundError as exc:
        raise ReleaseValidationError("local release artifact does not exist") from exc
    if path is None:
        raise ReleaseValidationError(
            "signed release artifacts must be served from /static/releases/ on this server"
        )
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise ReleaseValidationError(
            f"local release artifact size mismatch: expected {expected_size}, got {actual_size}"
        )
    actual_sha256 = _hash_file(path)
    if actual_sha256 != expected_sha256:
        raise ReleaseValidationError("local release artifact SHA256 mismatch")


def _verify_legacy_local_artifact(url: str, expected_sha256: str) -> None:
    try:
        path = _local_release_path(url)
    except FileNotFoundError as exc:
        raise ReleaseValidationError("local release artifact does not exist") from exc
    if path is None:
        raise ReleaseValidationError(
            "release artifacts must be served from /static/releases/ on this server"
        )
    if _hash_file(path) != expected_sha256:
        raise ReleaseValidationError("local release artifact SHA256 mismatch")


def _require_content_addressed_filename(url: str, sha256: str, suffix: str) -> None:
    parsed = urlsplit(url)
    decoded_path = unquote(parsed.path)
    if (
        posixpath.dirname(decoded_path) != "/static/releases"
        or posixpath.normpath(decoded_path) != decoded_path
        or parsed.path != decoded_path
        or "?" in url
        or "#" in url
    ):
        raise ReleaseValidationError(
            "release artifacts must be direct children of /static/releases/ on this server"
        )
    basename = posixpath.basename(decoded_path)
    expected = f"{sha256}{suffix}"
    if basename != expected:
        raise ReleaseValidationError(f"release artifact filename must be {expected}")


def _public_key() -> bytes:
    inline = str(config.RUNTIME_CATALOG_PUBLIC_KEY or "").replace("\\n", "\n").strip()
    if inline:
        return inline.encode("utf-8")
    path = str(config.RUNTIME_CATALOG_PUBLIC_KEY_PATH or "").strip()
    if path:
        try:
            return Path(path).read_bytes()
        except OSError as exc:
            raise ReleaseValidationError("release signing public key cannot be read") from exc
    raise ReleaseValidationError("release signing public key is not configured")


def _decode_verified_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    if set(envelope) != _ENVELOPE_FIELDS:
        raise ReleaseValidationError("signed release envelope has invalid fields")
    if envelope.get("algorithm") != SIGNED_RELEASE_ALGORITHM:
        raise ReleaseValidationError("only Ed25519 release manifests are accepted")
    try:
        payload_bytes = base64.b64decode(str(envelope.get("payload_b64") or ""), validate=True)
        if len(payload_bytes) > 3_000_000:
            raise ReleaseValidationError("signed release payload is too large")
        payload = json.loads(payload_bytes.decode("utf-8"))
        signature = base64.b64decode(str(envelope.get("signature_b64") or ""), validate=True)
        key = serialization.load_pem_public_key(_public_key())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("release signing key is not Ed25519")
        key.verify(signature, payload_bytes)
    except ReleaseValidationError:
        raise
    except (InvalidSignature, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError("release manifest signature verification failed") from exc
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise ReleaseValidationError("signed release payload has invalid fields")
    return payload


def _signed_envelope_fields(envelope: dict[str, Any]) -> dict[str, Any]:
    unexpected = set(envelope) - _SIGNED_RELEASE_REQUEST_FIELDS
    if unexpected:
        raise ReleaseValidationError("signed release envelope has invalid fields")
    return {field: envelope.get(field) for field in _ENVELOPE_FIELDS}


def _validated_target(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _TARGET_FIELDS:
        raise ReleaseValidationError("signed release target has invalid fields")
    if value.get("kind") != "onefile_exe":
        raise ReleaseValidationError("signed release target kind must be onefile_exe")
    target = {
        "url": validate_release_url(value.get("url")),
        "sha256": normalize_sha256(value.get("sha256")),
        "size": _positive_size(value.get("size"), "target size"),
        "kind": "onefile_exe",
    }
    if value.get("sha256") != target["sha256"]:
        raise ReleaseValidationError("signed release target sha256 must use lowercase hexadecimal")
    _require_content_addressed_filename(target["url"], target["sha256"], ".exe")
    _verify_local_artifact(target["url"], target["sha256"], target["size"])
    return target


def _validated_deltas(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ReleaseValidationError("deltas must be a list with at most 64 items")
    normalized: list[dict[str, Any]] = []
    seen_bases: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _DELTA_FIELDS:
            raise ReleaseValidationError("signed release delta has invalid fields")
        if item.get("algorithm") != DELTA_ALGORITHM:
            raise ReleaseValidationError("unsupported release delta algorithm")
        base_sha256 = normalize_sha256(item.get("base_sha256"))
        if base_sha256 in seen_bases:
            raise ReleaseValidationError("duplicate release delta base SHA256")
        seen_bases.add(base_sha256)
        delta = {
            "base_sha256": base_sha256,
            "url": validate_release_url(item.get("url")),
            "sha256": normalize_sha256(item.get("sha256")),
            "size": _positive_size(item.get("size"), "delta size"),
            "algorithm": DELTA_ALGORITHM,
        }
        if item.get("base_sha256") != delta["base_sha256"] or item.get("sha256") != delta["sha256"]:
            raise ReleaseValidationError("signed release delta sha256 must use lowercase hexadecimal")
        _require_content_addressed_filename(delta["url"], delta["sha256"], ".vfdiff")
        _verify_local_artifact(delta["url"], delta["sha256"], delta["size"])
        normalized.append(delta)
    return normalized


def validate_signed_release(envelope: dict[str, Any], expected_channel: str) -> dict[str, Any]:
    payload = _decode_verified_payload(envelope)
    if payload.get("schema_version") != SIGNED_RELEASE_SCHEMA_VERSION:
        raise ReleaseValidationError("unsupported signed release schema")
    channel = normalize_channel(payload.get("channel"))
    if channel != normalize_channel(expected_channel):
        raise ReleaseValidationError("signed release channel mismatch")
    version = normalize_version(payload.get("version"))
    min_supported_version = normalize_version(payload.get("min_supported_version"), optional=True)
    if not _numeric_version_key(version):
        raise ReleaseValidationError("signed release version must contain a dotted numeric version")
    if min_supported_version and not _numeric_version_key(min_supported_version):
        raise ReleaseValidationError(
            "signed min_supported_version must contain a dotted numeric version"
        )
    _validate_version_floor(version, min_supported_version)
    if type(payload.get("mandatory")) is not bool:
        raise ReleaseValidationError("mandatory must be a boolean")
    published_at = _rfc3339_timestamp(payload.get("published_at"))
    notes = payload.get("notes")
    if not isinstance(notes, str) or len(notes) > 20_000:
        raise ReleaseValidationError("invalid release notes")
    _release_site_origin_url()
    return {
        "schema_version": SIGNED_RELEASE_SCHEMA_VERSION,
        "channel": channel,
        "version": version,
        "min_supported_version": min_supported_version,
        "mandatory": payload["mandatory"],
        "published_at": published_at,
        "target": _validated_target(payload.get("target")),
        "deltas": _validated_deltas(payload.get("deltas")),
        "notes": notes,
    }


def _legacy_values(data: dict[str, Any], *, published: bool) -> dict[str, Any]:
    version = normalize_version(data.get("version"))
    channel = normalize_channel(data.get("channel"))
    min_supported_version = normalize_version(data.get("min_supported_version"), optional=True)
    _validate_version_floor(version, min_supported_version)
    url = validate_release_url(data.get("url"), optional=True)
    sha256 = normalize_sha256(data.get("sha256"), optional=True)
    installer_url = validate_release_url(data.get("installer_url"), optional=True)
    installer_sha256 = normalize_sha256(data.get("installer_sha256"), optional=True)
    if bool(url) != bool(sha256):
        raise ReleaseValidationError("artifact URL and SHA256 must be provided together")
    if bool(installer_url) != bool(installer_sha256):
        raise ReleaseValidationError("installer URL and SHA256 must be provided together")
    if published and not (url or installer_url):
        raise ReleaseValidationError("published releases require an artifact URL and SHA256")
    if published:
        _release_site_origin_url()
    for artifact_url, artifact_sha256 in (
        (url, sha256),
        (installer_url, installer_sha256),
    ):
        if not artifact_url:
            continue
        _require_content_addressed_filename(artifact_url, artifact_sha256, ".exe")
        if published:
            _verify_legacy_local_artifact(artifact_url, artifact_sha256)
    notes = str(data.get("notes") or "").strip()
    if len(notes) > 20_000:
        raise ReleaseValidationError("release notes are too long")
    return {
        "version": version,
        "channel": channel,
        "notes": notes,
        "url": url,
        "sha256": sha256,
        "installer_url": installer_url,
        "installer_sha256": installer_sha256,
        "min_supported_version": min_supported_version,
        "manifest_published_at": "",
        "mandatory": 1 if bool(data.get("mandatory")) else 0,
        "published": 1 if published else 0,
        "target_size": 0,
        "deltas_json": "[]",
        "algorithm": "",
        "key_id": "",
        "payload_b64": "",
        "signature_b64": "",
    }


def _signed_bridge(envelope: dict[str, Any]) -> tuple[str, str]:
    url = validate_release_url(envelope.get("legacy_bridge_url"), optional=True)
    sha256 = normalize_sha256(envelope.get("legacy_bridge_sha256"), optional=True)
    if bool(url) != bool(sha256):
        raise ReleaseValidationError(
            "legacy bridge URL and SHA256 must be provided together"
        )
    if url:
        _require_content_addressed_filename(url, sha256, ".exe")
        _verify_legacy_local_artifact(url, sha256)
    return url, sha256


def _signed_values(envelope: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    target = payload["target"]
    legacy_bridge_url, legacy_bridge_sha256 = _signed_bridge(envelope)
    return {
        "version": payload["version"],
        "channel": payload["channel"],
        "notes": payload["notes"],
        "url": target["url"],
        "sha256": target["sha256"],
        "installer_url": legacy_bridge_url,
        "installer_sha256": legacy_bridge_sha256,
        "min_supported_version": payload["min_supported_version"],
        "manifest_published_at": payload["published_at"],
        "mandatory": 1 if payload["mandatory"] else 0,
        "published": 1,
        "target_size": target["size"],
        "deltas_json": json.dumps(payload["deltas"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "algorithm": SIGNED_RELEASE_ALGORITHM,
        "key_id": str(envelope.get("key_id") or "").strip(),
        "payload_b64": str(envelope.get("payload_b64") or ""),
        "signature_b64": str(envelope.get("signature_b64") or ""),
    }


def _upsert_integrity_allowlist(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    executable = {
        "path": "@executable",
        "role": "executable",
        "sha256": values["sha256"],
        "size": int(values["target_size"]),
    }
    files_json = json.dumps([executable], sort_keys=True, separators=(",", ":"))
    manifest_hash = hashlib.sha256(files_json.encode("utf-8")).hexdigest()
    conn.execute(
        "INSERT INTO client_integrity_allowlist "
        "(client_version, manifest_hash, file_hashes_json, enabled, note) VALUES (?, ?, ?, 1, ?) "
        "ON CONFLICT(client_version, manifest_hash) DO UPDATE SET "
        "file_hashes_json = excluded.file_hashes_json, enabled = 1, note = excluded.note, "
        "updated_at = datetime('now')",
        (values["version"], manifest_hash, files_json, "created by signed release publication"),
    )


def _disable_allowlists_below_floor(
    conn: sqlite3.Connection,
    minimum_supported_version: str,
) -> None:
    minimum_key = _numeric_version_key(minimum_supported_version)
    if not minimum_key:
        return
    rows = conn.execute(
        "SELECT id, client_version FROM client_integrity_allowlist "
        "WHERE enabled = 1"
    ).fetchall()
    disabled_ids = [
        int(row["id"])
        for row in rows
        if str(row["client_version"] or "").strip() == "*"
        or not _numeric_version_key(str(row["client_version"] or ""))
        or _numeric_version_key(str(row["client_version"] or "")) < minimum_key
    ]
    for allowlist_id in disabled_ids:
        conn.execute(
            "UPDATE client_integrity_allowlist SET enabled = 0, "
            "updated_at = datetime('now') WHERE id = ?",
            (allowlist_id,),
        )


def _stored_release_timestamp(release: dict[str, Any]) -> datetime | None:
    raw_value = str(
        release.get("manifest_published_at") or release.get("created_at") or ""
    ).strip()
    if not raw_value:
        return None
    try:
        parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseConflictError("existing release timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class ReleaseService:
    def list_releases(self, channel: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        normalized = normalize_channel(channel) if channel else None
        conn = get_connection()
        try:
            return ReleaseRepository(conn).list(normalized, max(1, min(int(limit), 500)))
        finally:
            conn.close()

    def latest(self, channel: str = "stable") -> dict[str, Any] | None:
        conn = get_connection()
        try:
            return ReleaseRepository(conn).published(normalize_channel(channel))
        finally:
            conn.close()

    def save_legacy(
        self,
        data: dict[str, Any],
        *,
        published: bool,
        release_id: int | None = None,
        audit: AuditCallback | None = None,
    ) -> dict[str, Any]:
        values = _legacy_values(data, published=published)
        return self._save(values, release_id=release_id, audit=audit)

    def publish_signed(
        self,
        envelope: dict[str, Any],
        *,
        channel: str,
        audit: AuditCallback | None = None,
    ) -> dict[str, Any]:
        signed_envelope = _signed_envelope_fields(envelope)
        key_id = str(signed_envelope.get("key_id") or "").strip()
        if not key_id or len(key_id) > 128:
            raise ReleaseValidationError("invalid release signing key_id")
        payload = validate_signed_release(signed_envelope, channel)
        release_request = {
            **signed_envelope,
            "legacy_bridge_url": envelope.get("legacy_bridge_url"),
            "legacy_bridge_sha256": envelope.get("legacy_bridge_sha256"),
        }
        values = _signed_values(release_request, payload)
        return self._save(values, release_id=None, audit=audit, add_integrity_allowlist=True)

    def _save(
        self,
        values: dict[str, Any],
        *,
        release_id: int | None,
        audit: AuditCallback | None,
        add_integrity_allowlist: bool = False,
    ) -> dict[str, Any]:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            repository = ReleaseRepository(conn)
            existing = repository.find(str(values["version"]), str(values["channel"]))
            current = repository.get(int(release_id)) if release_id is not None else None
            if not add_integrity_allowlist and repository.has_signed_publication(
                str(values["channel"])
            ):
                raise ReleaseConflictError(
                    "legacy release writes are disabled after signed v2 publication on this channel"
                )
            if add_integrity_allowlist and existing and existing.get("payload_b64"):
                signed_identity_fields = (
                    "algorithm",
                    "key_id",
                    "payload_b64",
                    "signature_b64",
                    "installer_url",
                    "installer_sha256",
                )
                if any(
                    str(existing.get(field) or "") != str(values.get(field) or "")
                    for field in signed_identity_fields
                ):
                    raise ReleaseConflictError(
                        "signed release versions are immutable; publish a new version"
                    )
            if add_integrity_allowlist:
                incoming_timestamp = _timestamp_key(values.get("manifest_published_at"))
                incoming_version = _numeric_version_key(str(values.get("version") or ""))
                existing_is_signed = bool(existing and existing.get("payload_b64"))
                prior_releases = {
                    int(row["id"]): row
                    for row in repository.publication_history(str(values["channel"]))
                    if not (
                        existing_is_signed
                        and existing
                        and int(row["id"]) == int(existing["id"])
                    )
                }
                other_timestamps = [
                    timestamp
                    for row in prior_releases.values()
                    if (timestamp := _stored_release_timestamp(row)) is not None
                ]
                if other_timestamps and incoming_timestamp <= max(other_timestamps):
                    raise ReleaseConflictError(
                        "signed release published_at must be newer than every prior channel release"
                    )
                other_versions = [
                    _numeric_version_key(str(row.get("version") or ""))
                    for row in prior_releases.values()
                ]
                if other_versions and incoming_version <= max(other_versions):
                    raise ReleaseConflictError(
                        "signed release version must be newer than every prior channel release"
                    )
                prior_signed_floors: list[tuple[int, ...]] = []
                for row in prior_releases.values():
                    if not str(row.get("payload_b64") or ""):
                        continue
                    prior_floor = str(
                        row.get("min_supported_version") or ""
                    ).strip()
                    if not prior_floor:
                        continue
                    prior_floor_key = _numeric_version_key(prior_floor)
                    if not prior_floor_key:
                        raise ReleaseConflictError(
                            "existing signed release floor is invalid"
                        )
                    prior_signed_floors.append(prior_floor_key)
                incoming_floor = str(
                    values.get("min_supported_version") or ""
                ).strip()
                incoming_floor_key = _numeric_version_key(incoming_floor)
                if prior_signed_floors and not incoming_floor_key:
                    raise ReleaseConflictError(
                        "signed release floor cannot be cleared after activation"
                    )
                if (
                    prior_signed_floors
                    and incoming_floor_key < max(prior_signed_floors)
                ):
                    raise ReleaseConflictError(
                        "signed release floor must not move backwards"
                    )
            if not add_integrity_allowlist:
                signed_row = current if current and current.get("payload_b64") else existing
                if signed_row and signed_row.get("payload_b64"):
                    raise ReleaseConflictError(
                        "signed releases cannot be changed through the legacy release editor"
                    )
            if release_id is not None and existing and int(existing["id"]) != int(release_id):
                raise ReleaseConflictError("release channel and version already exist")
            if values["published"]:
                repository.unpublish_channel(str(values["channel"]))
            saved_id = repository.save(values, release_id=release_id)
            if add_integrity_allowlist:
                if (
                    str(values["channel"]) == "stable"
                    and str(values.get("min_supported_version") or "").strip()
                ):
                    _disable_allowlists_below_floor(
                        conn,
                        str(values["min_supported_version"]),
                    )
                _upsert_integrity_allowlist(conn, values)
            if audit:
                audit(conn, saved_id)
            conn.commit()
            row = repository.get(saved_id)
            if not row:
                raise ReleaseNotFoundError("release not found after save")
            return row
        except (ReleaseValidationError, ReleaseConflictError, ReleaseNotFoundError):
            conn.rollback()
            raise
        except LookupError as exc:
            conn.rollback()
            raise ReleaseNotFoundError("release not found") from exc
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise ReleaseConflictError("release conflicts with an existing channel or version") from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def rollback(
        self,
        version: str,
        channel: str,
        *,
        audit: AuditCallback | None = None,
    ) -> dict[str, Any]:
        safe_version = normalize_version(version)
        safe_channel = normalize_channel(channel)
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            repository = ReleaseRepository(conn)
            if repository.has_signed_publication(safe_channel):
                raise ReleaseConflictError(
                    "legacy rollback is disabled after signed v2 publication on this channel"
                )
            target = repository.find(safe_version, safe_channel)
            if not target:
                raise ReleaseNotFoundError("release not found")
            if target.get("payload_b64"):
                raise ReleaseConflictError(
                    "signed rollback requires rebuilding the prior code as a new higher version"
                )
            repository.unpublish_channel(safe_channel)
            repository.activate(int(target["id"]))
            if audit:
                audit(conn, int(target["id"]))
            conn.commit()
            return repository.get(int(target["id"])) or target
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def delete(self, release_id: int, *, audit: AuditCallback | None = None) -> None:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            repository = ReleaseRepository(conn)
            release = repository.get(release_id)
            if not release:
                raise ReleaseNotFoundError("release not found")
            if release.get("payload_b64"):
                raise ReleaseConflictError("signed release history cannot be deleted")
            if audit:
                audit(conn, release_id)
            repository.delete(release_id)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def public_manifest(
    release: dict[str, Any],
    *,
    legacy_bridge_only: bool = False,
) -> dict[str, Any]:
    notes = str(release.get("notes") or "")
    installer_url = str(release.get("installer_url") or "")
    url = str(release.get("url") or "")
    legacy_url = _absolute_legacy_release_url(url)
    legacy_installer_url = _absolute_legacy_release_url(installer_url)
    signed = bool(release.get("payload_b64"))
    if legacy_bridge_only and signed:
        if not installer_url or not release.get("installer_sha256"):
            raise ReleaseValidationError(
                "signed release has no legacy installer bridge"
            )
        return {
            "ok": True,
            "version": release["version"],
            "latest_version": release["version"],
            "channel": release["channel"],
            "min_supported_version": str(release.get("min_supported_version") or ""),
            "mandatory": True,
            "release_notes": notes,
            "notes": notes,
            "url": "",
            "sha256": "",
            "download_url": legacy_installer_url,
            "download_sha256": str(release.get("installer_sha256") or ""),
            "installer_url": legacy_installer_url,
            "installer_sha256": str(release.get("installer_sha256") or ""),
            "artifact_kind": "installer",
            "published_at": release.get("manifest_published_at") or release.get("created_at"),
        }
    artifact_kind = "onefile_exe" if signed else _legacy_artifact_kind(url, installer_url)
    download_url = legacy_installer_url or legacy_url
    download_sha256 = str(release.get("installer_sha256") or release.get("sha256") or "")
    try:
        deltas = json.loads(str(release.get("deltas_json") or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        deltas = []
    manifest = {
        "ok": True,
        "version": release["version"],
        "latest_version": release["version"],
        "channel": release["channel"],
        "min_supported_version": str(release.get("min_supported_version") or ""),
        "mandatory": bool(release.get("mandatory")),
        "release_notes": notes,
        "notes": notes,
        "url": legacy_url,
        "sha256": str(release.get("sha256") or ""),
        "download_url": download_url,
        "download_sha256": download_sha256,
        "installer_url": legacy_installer_url,
        "installer_sha256": str(release.get("installer_sha256") or ""),
        "artifact_kind": artifact_kind,
        "published_at": release.get("manifest_published_at") or release.get("created_at"),
    }
    if signed:
        manifest.update(
            {
                "schema_version": SIGNED_RELEASE_SCHEMA_VERSION,
                "target": {
                    "url": url,
                    "sha256": str(release.get("sha256") or ""),
                    "size": int(release.get("target_size") or 0),
                    "kind": "onefile_exe",
                },
                "deltas": deltas if isinstance(deltas, list) else [],
                "algorithm": str(release.get("algorithm") or ""),
                "key_id": str(release.get("key_id") or ""),
                "payload_b64": str(release.get("payload_b64") or ""),
                "signature_b64": str(release.get("signature_b64") or ""),
            }
        )
    return manifest


def _absolute_legacy_release_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return value
    site_url = _release_site_origin_url()
    validated = validate_release_url(value)
    if urlsplit(validated).scheme:
        return validated
    return f"{site_url}/{validated.lstrip('/')}"


def _legacy_artifact_kind(url: str, installer_url: str) -> str:
    if installer_url:
        return "installer"
    if url.lower().endswith(".exe"):
        return "onefile_exe"
    return "portable" if url else ""
