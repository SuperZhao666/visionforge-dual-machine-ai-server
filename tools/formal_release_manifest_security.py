from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ENVELOPE_SCHEMA = "visionforge-publishable-release-manifest-envelope-v1"
PAYLOAD_SCHEMA = "visionforge-publishable-release-bundle-v2"
ALGORITHM = "Ed25519"
MAXIMUM_ENVELOPE_BYTES = 512 * 1024
MAXIMUM_PAYLOAD_BYTES = 384 * 1024
ENVELOPE_FIELDS = frozenset(
    {"schema", "algorithm", "key_id", "payload_b64", "signature_b64"}
)
PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "ok",
        "channel",
        "release_version",
        "bundle_sequence",
        "published_at",
        "min_supported_version",
        "revocation_epoch",
        "artifacts",
        "evidence_sources",
    }
)
_NUMERIC_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_CHANNEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_FIELDS = frozenset({"role", "archive_path", "size", "sha256"})
_EVIDENCE_FIELDS = frozenset(
    {"role", "archive_path", "file_count", "size", "files"}
)
_EVIDENCE_FILE_FIELDS = frozenset({"archive_path", "size", "sha256"})


class FormalReleaseManifestError(ValueError):
    pass


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FormalReleaseManifestError("manifest payload is not canonical JSON") from exc
    if len(encoded) > MAXIMUM_PAYLOAD_BYTES:
        raise FormalReleaseManifestError("manifest payload exceeds the size limit")
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormalReleaseManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_object(raw: bytes, *, maximum_bytes: int) -> Mapping[str, Any]:
    if len(raw) > maximum_bytes:
        raise FormalReleaseManifestError("JSON object exceeds the size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormalReleaseManifestError("JSON object is malformed") from exc
    if not isinstance(value, Mapping):
        raise FormalReleaseManifestError("JSON root must be an object")
    return value


def load_private_key(private_key_pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise FormalReleaseManifestError("offline signing key is missing or invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise FormalReleaseManifestError("offline signing key must be Ed25519")
    return key


def load_public_key(public_key_pem: bytes | str) -> Ed25519PublicKey:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise FormalReleaseManifestError("trusted manifest public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise FormalReleaseManifestError("trusted manifest public key must be Ed25519")
    return key


def public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _strict_b64decode(value: object, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise FormalReleaseManifestError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise FormalReleaseManifestError(f"{label} is not canonical base64") from exc
    if len(decoded) > maximum_bytes:
        raise FormalReleaseManifestError(f"{label} exceeds the size limit")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FormalReleaseManifestError(f"{label} is not canonical base64")
    return decoded


def _numeric_version(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not _NUMERIC_VERSION_RE.fullmatch(value):
        raise FormalReleaseManifestError(f"{label} must be a dotted numeric version")
    return tuple(int(part) for part in value.split("."))


def _safe_archive_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(
        part not in ("", ".", "..") and ":" not in part
        for part in path.parts
    )


def _validate_sized_hash_entry(
    item: Mapping[str, Any],
    *,
    fields: frozenset[str],
    label: str,
) -> str:
    if set(item) != fields:
        raise FormalReleaseManifestError(f"{label} fields are invalid")
    archive_path = item.get("archive_path")
    if not _safe_archive_path(archive_path):
        raise FormalReleaseManifestError(f"{label} archive_path is invalid")
    size = item.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise FormalReleaseManifestError(f"{label} size is invalid")
    digest = item.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise FormalReleaseManifestError(f"{label} sha256 is invalid")
    return str(archive_path)


def _validate_artifacts(value: object) -> None:
    if not isinstance(value, list) or not value or len(value) > 256:
        raise FormalReleaseManifestError("manifest artifacts must be a non-empty bounded list")
    roles: set[str] = set()
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise FormalReleaseManifestError("manifest artifact must be an object")
        role = item.get("role")
        if not isinstance(role, str) or not _ROLE_RE.fullmatch(role):
            raise FormalReleaseManifestError("manifest artifact role is invalid")
        if role in roles:
            raise FormalReleaseManifestError("manifest artifact role is duplicated")
        roles.add(role)
        archive_path = _validate_sized_hash_entry(
            item,
            fields=_ARTIFACT_FIELDS,
            label="manifest artifact",
        )
        if archive_path in paths:
            raise FormalReleaseManifestError("manifest artifact archive_path is duplicated")
        paths.add(archive_path)


def _validate_evidence_sources(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_FIELDS:
        raise FormalReleaseManifestError("manifest evidence_sources fields are invalid")
    if value.get("role") != "device_evidence_sources":
        raise FormalReleaseManifestError("manifest evidence_sources role is invalid")
    root = value.get("archive_path")
    if not _safe_archive_path(root):
        raise FormalReleaseManifestError("manifest evidence_sources archive_path is invalid")
    files = value.get("files")
    if not isinstance(files, list) or len(files) > 4096:
        raise FormalReleaseManifestError("manifest evidence_sources files are invalid")
    file_count = value.get("file_count")
    total_size = value.get("size")
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or file_count != len(files)
        or isinstance(total_size, bool)
        or not isinstance(total_size, int)
        or total_size < 0
    ):
        raise FormalReleaseManifestError("manifest evidence_sources counts are invalid")
    paths: set[str] = set()
    observed_size = 0
    prefix = str(root).rstrip("/") + "/"
    for item in files:
        if not isinstance(item, Mapping):
            raise FormalReleaseManifestError("manifest evidence source file must be an object")
        archive_path = _validate_sized_hash_entry(
            item,
            fields=_EVIDENCE_FILE_FIELDS,
            label="manifest evidence source file",
        )
        if not archive_path.startswith(prefix):
            raise FormalReleaseManifestError(
                "manifest evidence source file escapes its declared root"
            )
        if archive_path in paths:
            raise FormalReleaseManifestError(
                "manifest evidence source archive_path is duplicated"
            )
        paths.add(archive_path)
        observed_size += int(item["size"])
    if observed_size != total_size:
        raise FormalReleaseManifestError("manifest evidence_sources size is inconsistent")


def _validate_payload(payload: Mapping[str, Any]) -> None:
    if set(payload) != PAYLOAD_FIELDS:
        raise FormalReleaseManifestError("manifest payload fields are invalid")
    if payload.get("schema") != PAYLOAD_SCHEMA or payload.get("ok") is not True:
        raise FormalReleaseManifestError("manifest payload schema or ok flag is invalid")
    channel = payload.get("channel")
    if not isinstance(channel, str) or not _CHANNEL_RE.fullmatch(channel):
        raise FormalReleaseManifestError("manifest channel is invalid")
    release_key = _numeric_version(payload.get("release_version"), "release_version")
    minimum_key = _numeric_version(
        payload.get("min_supported_version"),
        "min_supported_version",
    )
    if minimum_key > release_key:
        raise FormalReleaseManifestError("min_supported_version exceeds release_version")
    for field, minimum in (("bundle_sequence", 1), ("revocation_epoch", 0)):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise FormalReleaseManifestError(f"manifest {field} is invalid")
    published_at = payload.get("published_at")
    if not isinstance(published_at, str) or not published_at.endswith("Z"):
        raise FormalReleaseManifestError("manifest published_at is invalid")
    try:
        parsed_time = datetime.fromisoformat(published_at[:-1] + "+00:00")
    except ValueError as exc:
        raise FormalReleaseManifestError("manifest published_at is invalid") from exc
    if parsed_time.tzinfo is None or parsed_time.astimezone(UTC) != parsed_time:
        raise FormalReleaseManifestError("manifest published_at is not UTC")
    _validate_artifacts(payload.get("artifacts"))
    _validate_evidence_sources(payload.get("evidence_sources"))


def sign_manifest_payload(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> Mapping[str, str]:
    _validate_payload(payload)
    payload_bytes = canonical_json_bytes(payload)
    signature = private_key.sign(payload_bytes)
    return {
        "schema": ENVELOPE_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": public_key_id(private_key.public_key()),
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_manifest_envelope(
    envelope: Mapping[str, Any],
    trusted_public_key_pem: bytes | str,
) -> Mapping[str, Any]:
    if set(envelope) != ENVELOPE_FIELDS:
        raise FormalReleaseManifestError("manifest envelope fields are invalid")
    if envelope.get("schema") != ENVELOPE_SCHEMA:
        raise FormalReleaseManifestError("manifest envelope schema is invalid")
    if envelope.get("algorithm") != ALGORITHM:
        raise FormalReleaseManifestError("manifest signature algorithm is invalid")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise FormalReleaseManifestError("manifest key_id is invalid")
    public_key = load_public_key(trusted_public_key_pem)
    if key_id != public_key_id(public_key):
        raise FormalReleaseManifestError("manifest key_id does not match the trusted public key")
    payload_bytes = _strict_b64decode(
        envelope.get("payload_b64"),
        "manifest payload_b64",
        MAXIMUM_PAYLOAD_BYTES,
    )
    signature = _strict_b64decode(
        envelope.get("signature_b64"),
        "manifest signature_b64",
        64,
    )
    if len(signature) != 64:
        raise FormalReleaseManifestError("manifest signature length is invalid")
    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise FormalReleaseManifestError("manifest signature verification failed") from exc
    payload = parse_json_object(payload_bytes, maximum_bytes=MAXIMUM_PAYLOAD_BYTES)
    if payload_bytes != canonical_json_bytes(payload):
        raise FormalReleaseManifestError("manifest payload is not canonical JSON")
    _validate_payload(payload)
    return payload
