"""Public card-key and formal-usage APIs for the dual-machine sidecar."""
from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
)
from slowapi import Limiter

from .card_service import CardActivationService
from .errors import DualMachineServiceError
from .network import client_ip, rate_limit_key
from .pair_generation_authorization_service import (
    PairGenerationAuthorizationService,
)
from .usage_service import UsageService
from .validation import is_nonzero_lower_hex


HEX_128_PATTERN = r"^[0-9a-f]{32}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
BASE64_PATTERN = r"^[A-Za-z0-9+/]+={0,2}$"
DEVICE_CODE_PATTERN = r"^[A-Za-z0-9._:-]+$"
# SlowAPI otherwise opens ``.env`` from the process working directory. The
# sidecar must never read or depend on the single-machine service environment.
limiter = Limiter(key_func=rate_limit_key, config_filename=os.devnull)
router = APIRouter(prefix="/api/dual-machine/v1")


def _nonzero_hex_128(value: str) -> str:
    if not is_nonzero_lower_hex(value, 32):
        raise ValueError("identifier must not be all zero")
    return value


def _nonzero_sha256(value: str) -> str:
    if not is_nonzero_lower_hex(value, 64):
        raise ValueError("SHA-256 value must not be all zero")
    return value


def _protocol_v2(value: int) -> int:
    if value != 2:
        raise ValueError("unsupported protocol version")
    return value


def _exact_true(value: bool) -> bool:
    if value is not True:
        raise ValueError("value must be true")
    return value


NonzeroHex128 = Annotated[
    str,
    Field(pattern=HEX_128_PATTERN),
    AfterValidator(_nonzero_hex_128),
]
NonzeroSha256 = Annotated[
    str,
    Field(pattern=SHA256_PATTERN),
    AfterValidator(_nonzero_sha256),
]
ProtocolV2 = Annotated[StrictInt, AfterValidator(_protocol_v2)]
ExactTrue = Annotated[StrictBool, AfterValidator(_exact_true)]


class StrictRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        strict=True,
    )


class PeerIdentity(StrictRequest):
    device_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=DEVICE_CODE_PATTERN,
    )
    client_version: str = Field(min_length=1, max_length=80)
    identity_public_key_b64: str = Field(
        min_length=80,
        max_length=512,
        pattern=BASE64_PATTERN,
    )


class AndroidDeviceProfile(StrictRequest):
    manufacturer: str | None = Field(default=None, max_length=128)
    brand: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    device: str | None = Field(default=None, max_length=128)
    product: str | None = Field(default=None, max_length=128)
    hardware: str | None = Field(default=None, max_length=128)
    os_release: str | None = Field(default=None, max_length=128)
    sdk_int: int | None = Field(default=None, ge=1, le=10_000)
    supported_abis: list[str] | None = Field(
        default=None,
        max_length=16,
    )
    device_fingerprint: NonzeroSha256 | None = None


class ActivationChallengeRequest(StrictRequest):
    request_id: NonzeroHex128
    pair_id: NonzeroHex128
    protocol_version: ProtocolV2
    card_code: str = Field(min_length=20, max_length=128)
    host: PeerIdentity
    android: PeerIdentity
    android_device_profile: AndroidDeviceProfile | None = None


class ActivationConfirmationRequest(StrictRequest):
    challenge_id: NonzeroHex128
    challenge_token: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    host_signature_b64: str = Field(
        min_length=8,
        max_length=256,
        pattern=BASE64_PATTERN,
    )
    android_signature_b64: str = Field(
        min_length=8,
        max_length=256,
        pattern=BASE64_PATTERN,
    )


class SignedUsageRequest(StrictRequest):
    entitlement_id: NonzeroHex128
    pair_id: NonzeroHex128
    protocol_version: ProtocolV2
    revocation_version: int = Field(gt=0)
    host_signature_b64: str = Field(
        min_length=8,
        max_length=256,
        pattern=BASE64_PATTERN,
    )
    android_signature_b64: str = Field(
        min_length=8,
        max_length=256,
        pattern=BASE64_PATTERN,
    )


class SignedPairGenerationRequest(SignedUsageRequest):
    binding_id: NonzeroHex128
    binding_revision: int = Field(gt=0, le=(1 << 63) - 1)


class PairGenerationChallengeRequest(SignedPairGenerationRequest):
    request_id: NonzeroHex128
    allocation_request_id: NonzeroHex128


class PairGenerationCredentialRequest(SignedPairGenerationRequest):
    allocation_request_id: NonzeroHex128
    challenge_id: NonzeroHex128
    server_nonce: NonzeroSha256
    proposal_b64: str = Field(
        min_length=1,
        max_length=684,
        pattern=BASE64_PATTERN,
    )


class UsageStartRequest(SignedUsageRequest):
    request_id: NonzeroHex128
    request_nonce: NonzeroHex128
    channel_binding_sha256: NonzeroSha256
    host_runtime_ready: ExactTrue
    android_runtime_ready: ExactTrue
    # These are authenticated pre-use baselines. They may be zero because no
    # video/control data plane is allowed before the first paid active lease.
    # Every renewal still requires both counters to increase strictly.
    host_frames_total: int = Field(ge=0, le=(1 << 63) - 1)
    android_frames_total: int = Field(ge=0, le=(1 << 63) - 1)
    start_challenge_id: NonzeroHex128
    start_challenge_token: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )


class UsageStartChallengeRequest(SignedUsageRequest):
    request_id: NonzeroHex128
    request_nonce: NonzeroHex128
    channel_binding_sha256: NonzeroSha256


class UsageStartCancellationRequest(SignedUsageRequest):
    request_id: NonzeroHex128
    request_nonce: NonzeroHex128
    start_request_id: NonzeroHex128
    channel_binding_sha256: NonzeroSha256


class UsageHeartbeatRequest(SignedUsageRequest):
    session_id: NonzeroHex128
    request_id: NonzeroHex128
    request_nonce: NonzeroHex128
    channel_binding_sha256: NonzeroSha256
    sequence: int = Field(gt=0, le=(1 << 63) - 1)
    host_frames_total: int = Field(ge=0, le=(1 << 63) - 1)
    android_frames_total: int = Field(ge=0, le=(1 << 63) - 1)
    previous_lease: str = Field(min_length=256, max_length=8192)


class UsageStopRequest(SignedUsageRequest):
    session_id: NonzeroHex128
    request_id: NonzeroHex128
    request_nonce: NonzeroHex128
    channel_binding_sha256: NonzeroSha256
    previous_lease: str = Field(min_length=256, max_length=8192)


class EntitlementStatusRequest(SignedUsageRequest):
    request_nonce: NonzeroHex128


EntitlementIdPath = Annotated[
    str,
    Path(pattern=HEX_128_PATTERN),
    AfterValidator(_nonzero_hex_128),
]
SessionIdPath = Annotated[
    str,
    Path(pattern=HEX_128_PATTERN),
    AfterValidator(_nonzero_hex_128),
]


@router.post("/license-activations/challenges")
@limiter.limit("5/minute")
def create_activation_challenge(
    request: Request,
    body: ActivationChallengeRequest,
):
    return _activation_service(request).create_challenge(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/license-activations/confirm")
@limiter.limit("10/minute")
def confirm_activation(
    request: Request,
    body: ActivationConfirmationRequest,
):
    return _activation_service(request).confirm_activation(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/usage-sessions/start")
@limiter.limit("60/minute")
def start_usage(
    request: Request,
    body: UsageStartRequest,
):
    return _usage_service(request).start_usage(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/pair-generations/challenges")
@limiter.limit("30/minute")
def create_pair_generation_challenge(
    request: Request,
    body: PairGenerationChallengeRequest,
):
    return _pair_generation_service(request).create_generation_challenge(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/pair-generations/credentials")
@limiter.limit("60/minute")
def issue_pair_generation_credential(
    request: Request,
    body: PairGenerationCredentialRequest,
):
    return _pair_generation_service(request).issue_generation_credential(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/usage-sessions/start-cancellations")
@limiter.limit("60/minute")
def cancel_start_usage(
    request: Request,
    body: UsageStartCancellationRequest,
):
    return _usage_service(request).cancel_start_usage(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/usage-sessions/start-challenges")
@limiter.limit("30/minute")
def create_usage_start_challenge(
    request: Request,
    body: UsageStartChallengeRequest,
):
    return _usage_service(request).create_start_challenge(
        body.model_dump(),
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/usage-sessions/{session_id}/heartbeat")
@limiter.limit("300/minute")
def heartbeat_usage(
    request: Request,
    session_id: SessionIdPath,
    body: UsageHeartbeatRequest,
):
    command = body.model_dump()
    if command["session_id"] != session_id:
        raise DualMachineServiceError("session_id_mismatch", 422)
    return _usage_service(request).heartbeat_usage(
        command,
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/usage-sessions/{session_id}/stop")
@limiter.limit("10/minute")
def stop_usage(
    request: Request,
    session_id: SessionIdPath,
    body: UsageStopRequest,
):
    command = body.model_dump()
    if command["session_id"] != session_id:
        raise DualMachineServiceError("session_id_mismatch", 422)
    return _usage_service(request).stop_usage(
        command,
        client_ip=client_ip(request),
        trace_id=_trace_id(request),
    )


@router.post("/entitlements/{entitlement_id}/status")
@limiter.limit("30/minute")
def entitlement_status(
    request: Request,
    entitlement_id: EntitlementIdPath,
    body: EntitlementStatusRequest,
):
    command = body.model_dump()
    if command["entitlement_id"] != entitlement_id:
        raise DualMachineServiceError("entitlement_id_mismatch", 422)
    return _usage_service(request).entitlement_status(command)


def _activation_service(request: Request) -> CardActivationService:
    return request.app.state.activation_service


def _usage_service(request: Request) -> UsageService:
    return request.app.state.usage_service


def _pair_generation_service(
    request: Request,
) -> PairGenerationAuthorizationService:
    return request.app.state.pair_generation_service


def _trace_id(request: Request) -> str:
    return str(getattr(request.state, "trace_id", "") or "")
