from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.config import config

logger = logging.getLogger("runtime_lease")

LEASE_TYPE = "vf-runtime-lease-v2"
LEASE_ISSUER = "visionforge-platform"
DEFAULT_LEASE_TTL_SECONDS = 15
MIN_LEASE_TTL_SECONDS = 15
MAX_LEASE_TTL_SECONDS = 15
MIN_SIGNED_LEASE_SEGMENT_SECONDS = 1
# V2 authorization deliberately fails closed on a slow or rolled-back wall
# clock. A future server-time/monotonic IPC anchor may restore skew tolerance;
# backdating ``nbf`` here would otherwise widen replay and paid-use windows.
LEASE_NBF_SKEW_GRACE_SECONDS = 0
MAX_DEVICE_CODE_LENGTH = 128
MAX_LOGIN_INSTANCE_ID_LENGTH = 128
MAX_RUNTIME_INSTANCE_ID_LENGTH = 128
MAX_CLIENT_VERSION_LENGTH = 80
MAX_MANIFEST_HASH_LENGTH = 64
MAX_NONCE_LENGTH = 128
MAX_KEY_ID_LENGTH = 128
MAX_SIGNED_INTEGER = 9_223_372_036_854_775_807


class RuntimeLeaseSigningUnavailable(RuntimeError):
    """Raised when the production RSA signer cannot be loaded safely."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    text = str(text or "").strip()
    text += "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text.encode("ascii"))


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_ttl(value: int | str | None) -> int:
    try:
        ttl = int(value or DEFAULT_LEASE_TTL_SECONDS)
    except Exception:
        ttl = DEFAULT_LEASE_TTL_SECONDS
    return max(MIN_LEASE_TTL_SECONDS, min(MAX_LEASE_TTL_SECONDS, ttl))


def _utc_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bounded_claim(
    value: object,
    *,
    max_length: int,
    field_name: str,
    uppercase: bool = False,
    required: bool = False,
) -> str:
    if required and not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    text = str(value or "").strip()
    if uppercase:
        text = text.upper()
    if required and not text:
        raise ValueError(f"{field_name} is required")
    if len(text) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length")
    return text


def _required_integer_claim(value: object, *, field_name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if not minimum <= value <= MAX_SIGNED_INTEGER:
        raise ValueError(
            f"{field_name} must be between {minimum} and {MAX_SIGNED_INTEGER}"
        )
    return value


def _manifest_hash_claim(value: object) -> str:
    manifest_hash = _bounded_claim(
        value,
        max_length=MAX_MANIFEST_HASH_LENGTH,
        field_name="manifest_hash",
        required=True,
    ).lower()
    if len(manifest_hash) != MAX_MANIFEST_HASH_LENGTH or any(
        character not in "0123456789abcdef" for character in manifest_hash
    ):
        raise ValueError("manifest_hash must be a SHA-256 hex digest")
    return manifest_hash


def _lease_window(
    *,
    now: int,
    ttl_seconds: int | str | None,
    not_before_epoch: int | None,
    expires_at_epoch: int | None,
) -> tuple[int, int, int]:
    if not_before_epoch is None and expires_at_epoch is None:
        ttl = _safe_ttl(ttl_seconds)
        return now - LEASE_NBF_SKEW_GRACE_SECONDS, now + ttl, ttl

    not_before = int(not_before_epoch) if not_before_epoch is not None else now
    requested_ttl = _safe_ttl(ttl_seconds)
    expires_at = int(expires_at_epoch) if expires_at_epoch is not None else not_before + requested_ttl
    ttl = expires_at - not_before
    if not MIN_SIGNED_LEASE_SEGMENT_SECONDS <= ttl <= MAX_LEASE_TTL_SECONDS:
        raise ValueError("runtime lease window must be between 1 and 15 seconds")

    # A delayed heartbeat must never mint a token whose signed ``iat`` falls
    # inside an already-started segment. Shift the whole paid segment forward
    # so ``exp - max(iat, nbf) == ttl`` remains an invariant.
    effective_not_before = max(now, not_before)
    return effective_not_before, effective_not_before + ttl, ttl


def _lease_claim_contract_reason(payload: dict[str, Any]) -> str:
    if payload.get("typ") != LEASE_TYPE or payload.get("iss") != LEASE_ISSUER:
        return "wrong_lease_schema"
    integer_claims: dict[str, int] = {}
    for claim in ("sub", "sid", "av", "iat", "nbf", "exp", "ttl"):
        value = payload.get(claim)
        if isinstance(value, bool) or not isinstance(value, int):
            return "invalid_claims"
        if value > MAX_SIGNED_INTEGER:
            return "invalid_claims"
        integer_claims[claim] = value
    if integer_claims["sub"] <= 0 or integer_claims["sid"] <= 0 or integer_claims["av"] < 0:
        return "invalid_identity_claims"
    if min(integer_claims["iat"], integer_claims["nbf"], integer_claims["exp"]) <= 0:
        return "invalid_window"
    if not (
        MIN_SIGNED_LEASE_SEGMENT_SECONDS
        <= integer_claims["ttl"]
        <= MAX_LEASE_TTL_SECONDS
    ):
        return "invalid_ttl"
    if integer_claims["iat"] - integer_claims["nbf"] > LEASE_NBF_SKEW_GRACE_SECONDS:
        return "invalid_window"
    effective_start = max(integer_claims["iat"], integer_claims["nbf"])
    if integer_claims["exp"] - effective_start != integer_claims["ttl"]:
        return "invalid_window"

    bounded_claims = {
        "did": MAX_DEVICE_CODE_LENGTH,
        "lid": MAX_LOGIN_INSTANCE_ID_LENGTH,
        "rid": MAX_RUNTIME_INSTANCE_ID_LENGTH,
        "ver": MAX_CLIENT_VERSION_LENGTH,
        "nonce": MAX_NONCE_LENGTH,
    }
    for claim, maximum_length in bounded_claims.items():
        raw_value = payload.get(claim)
        if not isinstance(raw_value, str):
            return f"invalid_{claim}_claim"
        value = raw_value.strip()
        if not value or len(value) > maximum_length:
            return f"invalid_{claim}_claim"
    try:
        _manifest_hash_claim(payload.get("manifest_hash"))
    except ValueError:
        return "invalid_integrity_manifest"
    return ""


def _load_private_key_or_none():
    try:
        from app.services.license_service import load_private_key

        return load_private_key()
    except Exception as exc:
        if config.ALLOW_INSECURE_RUNTIME_LEASE_HMAC:
            logger.warning(
                "RSA runtime lease signing unavailable; development HMAC fallback enabled: %r",
                exc,
            )
        else:
            logger.error("RSA runtime lease signing unavailable; refusing to issue lease: %r", exc)
        return None


def _public_key_id(private_key) -> str:
    try:
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_der).hexdigest()[:16]
    except Exception:
        return ""


def sign_runtime_lease(
    *,
    user_id: int,
    session_id: int,
    device_code: str,
    client_version: str,
    manifest_hash: str,
    auth_version: int = 0,
    login_instance_id: str = "",
    ttl_seconds: int | str | None = None,
    not_before_epoch: int | None = None,
    expires_at_epoch: int | None = None,
    runtime_instance_id: str = "",
) -> dict[str, Any]:
    now = int(time.time())
    subject = _required_integer_claim(user_id, field_name="user_id", minimum=1)
    signed_session_id = _required_integer_claim(
        session_id,
        field_name="session_id",
        minimum=1,
    )
    signed_auth_version = _required_integer_claim(
        auth_version,
        field_name="auth_version",
        minimum=0,
    )
    not_before, exp, ttl = _lease_window(
        now=now,
        ttl_seconds=ttl_seconds,
        not_before_epoch=not_before_epoch,
        expires_at_epoch=expires_at_epoch,
    )
    device_claim = _bounded_claim(
        device_code,
        max_length=MAX_DEVICE_CODE_LENGTH,
        field_name="device_code",
        uppercase=True,
        required=True,
    )
    login_claim = _bounded_claim(
        login_instance_id,
        max_length=MAX_LOGIN_INSTANCE_ID_LENGTH,
        field_name="login_instance_id",
        required=True,
    )
    runtime_claim = _bounded_claim(
        runtime_instance_id,
        max_length=MAX_RUNTIME_INSTANCE_ID_LENGTH,
        field_name="runtime_instance_id",
        required=True,
    )
    version_claim = _bounded_claim(
        client_version,
        max_length=MAX_CLIENT_VERSION_LENGTH,
        field_name="client_version",
        required=True,
    )
    manifest_claim = _manifest_hash_claim(manifest_hash)
    payload = {
        "typ": LEASE_TYPE,
        "iss": LEASE_ISSUER,
        "sub": subject,
        "sid": signed_session_id,
        "av": signed_auth_version,
        "did": device_claim,
        "lid": login_claim,
        "rid": runtime_claim,
        "ver": version_claim,
        "manifest_hash": manifest_claim,
        "iat": now,
        "nbf": not_before,
        "exp": exp,
        "ttl": ttl,
        "nonce": secrets.token_hex(12),
    }
    private_key = _load_private_key_or_none()
    if private_key is not None:
        key_id = _public_key_id(private_key)
        if not key_id:
            raise RuntimeLeaseSigningUnavailable("runtime lease signer key id unavailable")
        header = {"alg": "RS256", "typ": "JWT", "kid": key_id}
        signing_input = _b64u(canonical_json(header)) + "." + _b64u(canonical_json(payload))
        sig = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    else:
        if not bool(config.ALLOW_INSECURE_RUNTIME_LEASE_HMAC):
            raise RuntimeLeaseSigningUnavailable("runtime lease RSA signer unavailable")
        header = {"alg": "HS256-dev", "typ": "JWT", "kid": "dev"}
        signing_input = _b64u(canonical_json(header)) + "." + _b64u(canonical_json(payload))
        secret = (config.SECRET_KEY or "dev-runtime-lease").encode("utf-8")
        sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return {
        "lease_token": signing_input + "." + _b64u(sig),
        "lease_expires_at": _utc_iso(exp),
        "lease_ttl_seconds": ttl,
        "lease_payload": payload,
    }


def runtime_lease_token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def verify_runtime_lease(
    token: str,
    *,
    user_id: int,
    session_id: int,
    auth_version: int,
    device_code: str,
    login_instance_id: str,
    expected_runtime_instance_id: str,
    expected_client_version: str,
    expected_manifest_hash: str,
    allow_future_for_renewal: bool = False,
    expiration_grace_seconds: int = 0,
) -> tuple[bool, str, dict[str, Any]]:
    try:
        header_b64, payload_b64, sig_b64 = str(token or "").split(".", 2)
        header = json.loads(_b64u_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64u_decode(payload_b64).decode("utf-8"))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return False, "bad_payload", {}
        raw_key_id = header.get("kid")
        key_id = raw_key_id.strip() if isinstance(raw_key_id, str) else ""
        if (
            header.get("typ") != "JWT"
            or not key_id
            or len(key_id) > MAX_KEY_ID_LENGTH
        ):
            return False, "bad_header", payload
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        algorithm = str(header.get("alg") or "")
        if algorithm == "RS256":
            private_key = _load_private_key_or_none()
            if private_key is None:
                return False, "signing_key_unavailable", payload
            expected_key_id = _public_key_id(private_key)
            if not expected_key_id or not hmac.compare_digest(key_id, expected_key_id):
                return False, "key_id_mismatch", payload
            private_key.public_key().verify(
                _b64u_decode(sig_b64),
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif algorithm == "HS256-dev":
            if not bool(config.ALLOW_INSECURE_RUNTIME_LEASE_HMAC):
                return False, "bad_algorithm", payload
            if key_id != "dev":
                return False, "key_id_mismatch", payload
            secret = (config.SECRET_KEY or "dev-runtime-lease").encode("utf-8")
            expected_signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(_b64u_decode(sig_b64), expected_signature):
                return False, "bad_signature", payload
        else:
            return False, "bad_algorithm", payload

        contract_reason = _lease_claim_contract_reason(payload)
        if contract_reason:
            return False, contract_reason, payload
        now = int(time.time())
        not_before = payload["nbf"]
        issued_at = payload["iat"]
        expires_at = payload["exp"]
        if not allow_future_for_renewal and max(issued_at, not_before) > now:
            return False, "not_yet_valid", payload
        if expires_at + max(0, int(expiration_grace_seconds)) <= now:
            return False, "expired", payload
        expected = {
            "sub": int(user_id),
            "sid": int(session_id),
            "av": int(auth_version),
            "did": str(device_code or "").strip().upper(),
            "lid": str(login_instance_id or "").strip(),
        }
        actual = {
            "sub": payload["sub"],
            "sid": payload["sid"],
            "av": payload["av"],
            "did": str(payload.get("did") or "").strip().upper(),
            "lid": str(payload.get("lid") or "").strip(),
        }
        if actual != expected:
            return False, "claim_mismatch", payload
        expected_runtime = str(expected_runtime_instance_id or "").strip()
        expected_version = str(expected_client_version or "").strip()
        try:
            expected_manifest = _manifest_hash_claim(expected_manifest_hash)
        except ValueError:
            return False, "invalid_expected_binding", payload
        if not expected_runtime or not expected_version:
            return False, "invalid_expected_binding", payload
        if str(payload.get("rid") or "").strip() != expected_runtime:
            return False, "claim_mismatch", payload
        if str(payload.get("ver") or "").strip() != expected_version:
            return False, "claim_mismatch", payload
        if str(payload.get("manifest_hash") or "").strip().lower() != expected_manifest:
            return False, "claim_mismatch", payload
        return True, "ok", payload
    except Exception as exc:
        return False, exc.__class__.__name__, {}


def decode_runtime_lease_unverified(token: str) -> dict[str, Any]:
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return {}
        payload = json.loads(_b64u_decode(parts[1]).decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}
