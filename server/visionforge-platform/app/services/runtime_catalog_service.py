"""Runtime catalog publication, delivery tickets and privacy retention."""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import config
from app.domain.runtime_catalog import CatalogComponent, SignedCatalog, parse_signed_payload
from app.repositories.runtime_repository import RuntimeRepository


_CATALOG_ENVELOPE_FIELDS = {
    "algorithm",
    "key_id",
    "payload_b64",
    "signature_b64",
}
_CATALOG_PUBLISH_FIELDS = _CATALOG_ENVELOPE_FIELDS | {"channel"}
_MIN_TICKET_SECRET_LENGTH = 32
RUNTIME_TICKET_SCHEMA = "visionforge-runtime-download-ticket-v2"
RUNTIME_TICKET_VERSION = 2


@dataclass(frozen=True, slots=True)
class RuntimeTicketClaims:
    user_id: int
    client_version: str
    catalog_payload_sha256: str


def validate_offline_signed_catalog(envelope: dict[str, str], channel: str) -> SignedCatalog:
    if set(envelope) != _CATALOG_PUBLISH_FIELDS:
        raise ValueError("runtime catalog envelope fields are invalid")
    if envelope.get("algorithm") != "Ed25519":
        raise ValueError("only Ed25519 runtime catalogs are accepted")
    catalog = parse_signed_payload(envelope.get("payload_b64", ""), expected_channel=channel)
    try:
        signature = base64.b64decode(envelope.get("signature_b64", ""), validate=True)
        key = serialization.load_pem_public_key(_catalog_public_key())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("runtime catalog key is not Ed25519")
        key.verify(signature, catalog.payload_bytes)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("runtime catalog signature verification failed") from exc
    return catalog


def catalog_envelope(row: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "algorithm": row["algorithm"],
        "key_id": row["key_id"],
        "payload_b64": row["payload_b64"],
        "signature_b64": row["signature_b64"],
    }


def catalog_component(
    row: dict[str, object],
    component_id: str,
    version: str,
) -> CatalogComponent | None:
    catalog = parse_signed_payload(str(row["payload_b64"]), expected_channel=str(row["channel"]))
    return next(
        (
            item
            for item in catalog.components
            if item.component_id == component_id and item.version == version
        ),
        None,
    )


def component_record_matches(
    stored: Mapping[str, object] | None,
    signed: CatalogComponent,
) -> bool:
    return bool(
        stored
        and str(stored["object_key"]) == signed.object_key
        and str(stored["archive_sha256"]) == signed.archive_sha256
        and int(stored["archive_size"]) == signed.archive_size
    )


def validate_catalog_delivery(catalog: SignedCatalog) -> None:
    """Reject publication unless every component has a usable delivery path."""

    secret = str(config.RUNTIME_ARTIFACT_HMAC_SECRET or "")
    if len(secret) < _MIN_TICKET_SECRET_LENGTH:
        raise ValueError("runtime download ticket secret must be at least 32 characters")
    try:
        _same_origin_site_url(str(config.SITE_URL or ""))
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc
    for component in catalog.components:
        object_key = _runtime_object_key(component.object_key)
        expected_key = (
            f"runtime/{component.component_id}/{component.version}/"
            f"{component.archive_sha256}.zip"
        )
        if object_key != expected_key:
            raise ValueError("runtime artifact object key must be canonical and content-addressed")
        artifact = runtime_artifact_path(object_key)
        if not artifact.is_file():
            raise ValueError(f"runtime artifact does not exist: {object_key}")
        if artifact.stat().st_size != component.archive_size:
            raise ValueError(f"runtime artifact size does not match catalog: {object_key}")
        if _sha256_file(artifact) != component.archive_sha256:
            raise ValueError(f"runtime artifact SHA256 does not match catalog: {object_key}")


def create_runtime_ticket(
    object_key: str,
    *,
    user_id: int,
    client_version: str,
    catalog_payload_sha256: str,
) -> tuple[str, int]:
    secret = str(config.RUNTIME_ARTIFACT_HMAC_SECRET or "")
    if len(secret) < _MIN_TICKET_SECRET_LENGTH:
        raise RuntimeError("runtime download ticket secret is not configured")
    normalized_key = _runtime_object_key(object_key)
    ticket_user_id = _ticket_user_id(user_id)
    ticket_client_version = _ticket_client_version(client_version)
    ticket_catalog_sha256 = _ticket_catalog_sha256(catalog_payload_sha256)
    expires = int(time.time()) + int(config.RUNTIME_ARTIFACT_TTL_SECONDS)
    site_url = _same_origin_site_url(str(config.SITE_URL or ""))
    encoded_key = quote(normalized_key, safe="/-._~")
    signature = _same_origin_signature(
        normalized_key,
        expires,
        secret,
        user_id=ticket_user_id,
        client_version=ticket_client_version,
        catalog_payload_sha256=ticket_catalog_sha256,
    )
    query = urlencode(
        {
            "tv": RUNTIME_TICKET_VERSION,
            "uid": ticket_user_id,
            "ver": ticket_client_version,
            "catalog": ticket_catalog_sha256,
            "expires": expires,
            "sig": signature,
        }
    )
    return (
        f"{site_url}/api/client/runtime/artifacts/{encoded_key}"
        f"?{query}",
        expires,
    )


def authorize_same_origin_artifact(
    object_key: str,
    expires: int,
    signature: str,
    *,
    ticket_version: int,
    user_id: int,
    client_version: str,
    catalog_payload_sha256: str,
) -> tuple[Path, str, RuntimeTicketClaims]:
    secret = str(config.RUNTIME_ARTIFACT_HMAC_SECRET or "")
    if len(secret) < _MIN_TICKET_SECRET_LENGTH:
        raise PermissionError("runtime download ticket secret is not configured")
    if int(ticket_version) != RUNTIME_TICKET_VERSION:
        raise PermissionError("runtime download ticket version is unsupported")
    normalized_key = _runtime_object_key(object_key)
    try:
        ticket_user_id = _ticket_user_id(user_id)
        ticket_client_version = _ticket_client_version(client_version)
        ticket_catalog_sha256 = _ticket_catalog_sha256(catalog_payload_sha256)
    except ValueError as exc:
        raise PermissionError("runtime download ticket claims are invalid") from exc
    if int(expires) < int(time.time()):
        raise PermissionError("runtime download ticket expired")
    expected = _same_origin_signature(
        normalized_key,
        int(expires),
        secret,
        user_id=ticket_user_id,
        client_version=ticket_client_version,
        catalog_payload_sha256=ticket_catalog_sha256,
    )
    if not hmac.compare_digest(str(signature), expected):
        raise PermissionError("runtime download ticket signature is invalid")
    artifact = runtime_artifact_path(normalized_key)
    if not artifact.is_file():
        raise FileNotFoundError(normalized_key)
    return (
        artifact,
        normalized_key,
        RuntimeTicketClaims(
            user_id=ticket_user_id,
            client_version=ticket_client_version,
            catalog_payload_sha256=ticket_catalog_sha256,
        ),
    )


def runtime_artifact_path(object_key: str) -> Path:
    normalized_key = _runtime_object_key(object_key)
    configured_root = str(config.RUNTIME_ARTIFACT_ROOT or "").strip()
    if not configured_root:
        raise ValueError("runtime artifact root is not configured")
    root = Path(configured_root).resolve()
    candidate = (root / PurePosixPath(normalized_key).name).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("runtime artifact path escapes configured root") from exc
    return candidate


def _runtime_object_key(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip("/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] != "runtime"
        or path.suffix.lower() != ".zip"
    ):
        raise ValueError("invalid runtime artifact object key")
    return path.as_posix()


def _same_origin_signature(
    object_key: str,
    expires: int,
    secret: str,
    *,
    user_id: int,
    client_version: str,
    catalog_payload_sha256: str,
) -> str:
    payload = "\n".join(
        (
            RUNTIME_TICKET_SCHEMA,
            str(_ticket_user_id(user_id)),
            _ticket_client_version(client_version),
            _ticket_catalog_sha256(catalog_payload_sha256),
            object_key,
            str(int(expires)),
        )
    ).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _ticket_user_id(value: int) -> int:
    user_id = int(value)
    if user_id <= 0:
        raise ValueError("runtime download ticket user is invalid")
    return user_id


def _ticket_client_version(value: str) -> str:
    client_version = str(value or "").strip()
    if (
        not client_version
        or len(client_version) > 80
        or any(character.isspace() for character in client_version)
    ):
        raise ValueError("runtime download ticket client version is invalid")
    return client_version


def _ticket_catalog_sha256(value: str) -> str:
    digest = str(value or "").strip().lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("runtime download ticket catalog hash is invalid")
    return digest


def _same_origin_site_url(value: str) -> str:
    try:
        split = urlsplit(str(value or "").strip())
        port = split.port
    except ValueError as exc:
        raise RuntimeError("same-origin runtime download requires a valid HTTPS site URL") from exc
    if (
        split.scheme.lower() != "https"
        or not split.hostname
        or split.username is not None
        or split.password is not None
        or split.path not in {"", "/"}
        or split.query
        or split.fragment
        or port not in {None, 443}
    ):
        raise RuntimeError("same-origin runtime download requires an origin-only HTTPS site URL")
    return urlunsplit(("https", split.netloc, "", "", ""))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply_event_retention(repository: RuntimeRepository) -> None:
    conn = repository.connection
    groups = conn.execute(
        "SELECT date(created_at) AS event_day,event_type,status,error_code,failure_stage,http_status,app_version,"
        "os_name,architecture,cpu_model,cpu_cores_physical,cpu_cores_logical,gpu_model,driver_version,"
        "compute_capability,component_id,component_version,final_provider,COUNT(*) AS event_count "
        "FROM runtime_install_events WHERE anonymized = 0 AND created_at < datetime('now','-30 days') "
        "GROUP BY event_day,event_type,status,error_code,failure_stage,http_status,app_version,os_name,architecture,"
        "cpu_model,cpu_cores_physical,cpu_cores_logical,gpu_model,driver_version,compute_capability,"
        "component_id,component_version,final_provider"
    ).fetchall()
    for row in groups:
        dimension = "|".join(str(row[key] or "") for key in row.keys() if key != "event_count")
        event_id = "aggregate:" + hashlib.sha256(dimension.encode()).hexdigest()
        conn.execute(
            "INSERT OR REPLACE INTO runtime_install_events "
            "(event_id,user_id,attempt_id,event_type,status,error_code,failure_stage,http_status,app_version,"
            "os_name,architecture,cpu_model,cpu_cores_physical,cpu_cores_logical,gpu_model,driver_version,"
            "compute_capability,component_id,component_version,bytes_count,final_provider,anonymized,created_at) "
            "VALUES (?,NULL,'aggregate',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)",
            (
                event_id, "aggregate:" + str(row["event_type"]), row["status"], row["error_code"],
                row["failure_stage"], row["http_status"], row["app_version"], row["os_name"],
                row["architecture"], row["cpu_model"], row["cpu_cores_physical"],
                row["cpu_cores_logical"], row["gpu_model"], row["driver_version"],
                row["compute_capability"], row["component_id"], row["component_version"],
                int(row["event_count"]), row["final_provider"],
                str(row["event_day"]) + " 00:00:00",
            ),
        )
    conn.execute("DELETE FROM runtime_install_events WHERE anonymized = 0 AND created_at < datetime('now','-30 days')")
    conn.execute("DELETE FROM runtime_install_events WHERE anonymized = 1 AND created_at < datetime('now','-365 days')")


def _catalog_public_key() -> bytes:
    inline = str(config.RUNTIME_CATALOG_PUBLIC_KEY or "").replace("\\n", "\n").strip()
    if inline:
        return inline.encode("utf-8")
    path = str(config.RUNTIME_CATALOG_PUBLIC_KEY_PATH or "").strip()
    if path:
        return Path(path).read_bytes()
    raise ValueError("runtime catalog public key is not configured")
