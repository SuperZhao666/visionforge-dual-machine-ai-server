"""Canonical signed payloads for card activation and metered usage."""
from __future__ import annotations

import hashlib
from typing import Any

from .identity import canonical_json
from .validation import is_nonzero_lower_hex


PROTOCOL_VERSION = 2
ACTIVATION_MODE_ACTIVATE = "activate"
ACTIVATION_MODE_REACTIVATE = "reactivate"
ACTIVATION_MODE_BIND_DEVICE = "bind_device"
ACTIVATION_CONFIRM_DOMAIN = "visionforge-dual-machine-card-activate-v1"
USAGE_START_CHALLENGE_DOMAIN = (
    "visionforge-dual-machine-usage-start-challenge-v1"
)
USAGE_START_DOMAIN = "visionforge-dual-machine-usage-start-v1"
USAGE_START_CANCEL_DOMAIN = (
    "visionforge-dual-machine-usage-start-cancel-v1"
)
USAGE_HEARTBEAT_DOMAIN = "visionforge-dual-machine-usage-heartbeat-v1"
USAGE_STOP_DOMAIN = "visionforge-dual-machine-usage-stop-v1"
ENTITLEMENT_STATUS_DOMAIN = "visionforge-dual-machine-entitlement-status-v1"


def activation_confirmation_payload(
    challenge: dict[str, Any],
    *,
    challenge_token: str,
) -> bytes:
    activation_mode = str(
        challenge.get("activation_mode") or ACTIVATION_MODE_ACTIVATE,
    )
    target_entitlement_id = str(
        challenge.get("target_entitlement_id") or "",
    )
    if activation_mode == ACTIVATION_MODE_ACTIVATE:
        if target_entitlement_id:
            _fail()
    elif activation_mode in {
        ACTIVATION_MODE_REACTIVATE,
        ACTIVATION_MODE_BIND_DEVICE,
    }:
        _require_hex(target_entitlement_id, 32)
    else:
        _fail()
    _require_usage_protocol(challenge)
    _require_hex(challenge.get("request_id"), 32)
    _require_hex(challenge.get("pair_id"), 32)
    _require_hex(challenge.get("challenge_id"), 32)
    _require_hex(challenge.get("host_key_sha256"), 64)
    _require_hex(challenge.get("android_key_sha256"), 64)
    _require_text(challenge.get("host_client_version"), 1, 80)
    _require_text(challenge.get("android_client_version"), 1, 80)
    _require_text(challenge.get("host_device_code"), 1, 128)
    _require_text(challenge.get("android_device_code"), 1, 128)
    _require_text(challenge_token, 1, 256)
    return canonical_json({
        "activation_mode": activation_mode,
        "android_client_version": challenge["android_client_version"],
        "android_device_code": challenge["android_device_code"],
        "android_device_profile_sha256": hashlib.sha256(
            str(
                challenge.get("android_device_profile_json") or "{}",
            ).encode("utf-8"),
        ).hexdigest(),
        "android_key_sha256": challenge["android_key_sha256"],
        "challenge_id": challenge["challenge_id"],
        "challenge_token_sha256": _text_sha256(challenge_token),
        "domain": ACTIVATION_CONFIRM_DOMAIN,
        "host_client_version": challenge["host_client_version"],
        "host_device_code": challenge["host_device_code"],
        "host_key_sha256": challenge["host_key_sha256"],
        "pair_id": challenge["pair_id"],
        "protocol_version": int(challenge["protocol_version"]),
        "request_id": challenge["request_id"],
        "target_entitlement_id": target_entitlement_id,
    })


def usage_start_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("request_id"), 32)
    _require_hex(command.get("request_nonce"), 32)
    _require_hex(command.get("channel_binding_sha256"), 64)
    _require_hex(command.get("start_challenge_id"), 32)
    _require_exact_true(command.get("host_runtime_ready"))
    _require_exact_true(command.get("android_runtime_ready"))
    _require_counter(command.get("host_frames_total"))
    _require_counter(command.get("android_frames_total"))
    _require_text(command.get("start_challenge_token"), 1, 256)
    return canonical_json({
        "android_frames_total": int(command["android_frames_total"]),
        "android_runtime_ready": bool(command["android_runtime_ready"]),
        "channel_binding_sha256": command["channel_binding_sha256"],
        "domain": USAGE_START_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "host_frames_total": int(command["host_frames_total"]),
        "host_runtime_ready": bool(command["host_runtime_ready"]),
        "pair_id": command["pair_id"],
        "protocol_version": int(command["protocol_version"]),
        "request_id": command["request_id"],
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
        "start_challenge_id": command["start_challenge_id"],
        "start_challenge_token_sha256": _text_sha256(
            command["start_challenge_token"],
        ),
    })


def usage_start_cancel_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("request_id"), 32)
    _require_hex(command.get("request_nonce"), 32)
    _require_hex(command.get("start_request_id"), 32)
    _require_hex(command.get("channel_binding_sha256"), 64)
    return canonical_json({
        "channel_binding_sha256": command["channel_binding_sha256"],
        "domain": USAGE_START_CANCEL_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "pair_id": command["pair_id"],
        "protocol_version": int(command["protocol_version"]),
        "request_id": command["request_id"],
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
        "start_request_id": command["start_request_id"],
    })


def usage_start_challenge_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("request_id"), 32)
    _require_hex(command.get("request_nonce"), 32)
    _require_hex(command.get("channel_binding_sha256"), 64)
    return canonical_json({
        "channel_binding_sha256": command["channel_binding_sha256"],
        "domain": USAGE_START_CHALLENGE_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "pair_id": command["pair_id"],
        "protocol_version": int(command["protocol_version"]),
        "request_id": command["request_id"],
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
    })


def usage_heartbeat_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("session_id"), 32)
    _require_hex(command.get("request_id"), 32)
    _require_hex(command.get("request_nonce"), 32)
    _require_hex(command.get("channel_binding_sha256"), 64)
    _require_positive_integer(command.get("sequence"))
    _require_counter(command.get("host_frames_total"))
    _require_counter(command.get("android_frames_total"))
    _require_text(command.get("previous_lease"), 1, 8192)
    return canonical_json({
        "android_frames_total": int(command["android_frames_total"]),
        "channel_binding_sha256": command["channel_binding_sha256"],
        "domain": USAGE_HEARTBEAT_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "host_frames_total": int(command["host_frames_total"]),
        "pair_id": command["pair_id"],
        "previous_lease_sha256": _text_sha256(command["previous_lease"]),
        "protocol_version": int(command["protocol_version"]),
        "request_id": command["request_id"],
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
        "sequence": int(command["sequence"]),
        "session_id": command["session_id"],
    })


def usage_stop_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("session_id"), 32)
    _require_hex(command.get("request_id"), 32)
    _require_hex(command.get("request_nonce"), 32)
    _require_hex(command.get("channel_binding_sha256"), 64)
    _require_text(command.get("previous_lease"), 1, 8192)
    return canonical_json({
        "channel_binding_sha256": command["channel_binding_sha256"],
        "domain": USAGE_STOP_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "pair_id": command["pair_id"],
        "previous_lease_sha256": _text_sha256(command["previous_lease"]),
        "protocol_version": int(command["protocol_version"]),
        "request_id": command["request_id"],
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
        "session_id": command["session_id"],
    })


def entitlement_status_payload(command: dict[str, Any]) -> bytes:
    _require_usage_common(command)
    _require_hex(command.get("request_nonce"), 32)
    return canonical_json({
        "domain": ENTITLEMENT_STATUS_DOMAIN,
        "entitlement_id": command["entitlement_id"],
        "pair_id": command["pair_id"],
        "protocol_version": int(command["protocol_version"]),
        "request_nonce": command["request_nonce"],
        "revocation_version": int(command["revocation_version"]),
    })


def _text_sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _require_usage_common(command: dict[str, Any]) -> None:
    if type(command) is not dict:
        _fail()
    _require_hex(command.get("entitlement_id"), 32)
    _require_hex(command.get("pair_id"), 32)
    _require_usage_protocol(command)
    _require_positive_integer(command.get("revocation_version"))


def _require_usage_protocol(source: dict[str, Any]) -> None:
    if type(source.get("protocol_version")) is not int:
        _fail()
    if source["protocol_version"] != PROTOCOL_VERSION:
        _fail()


def _require_hex(value: object, length: int) -> None:
    if not is_nonzero_lower_hex(value, length):
        _fail()


def _require_counter(value: object) -> None:
    if (
        type(value) is not int
        or value < 0
        or value > (1 << 63) - 1
    ):
        _fail()


def _require_positive_integer(value: object) -> None:
    _require_counter(value)
    if value == 0:
        _fail()


def _require_exact_true(value: object) -> None:
    if value is not True:
        _fail()


def _require_text(value: object, minimum: int, maximum: int) -> None:
    if (
        type(value) is not str
        or not minimum <= len(value) <= maximum
    ):
        _fail()


def _fail() -> None:
    raise ValueError("dual_machine_signed_payload_invalid")
