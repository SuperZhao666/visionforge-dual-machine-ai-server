"""Server-authoritative formal-use metering for dual-machine cards."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from typing import Any

from .audit import write_audit_event
from .contracts import (
    PROTOCOL_VERSION,
    entitlement_status_payload,
    usage_heartbeat_payload,
    usage_start_cancel_payload,
    usage_start_challenge_payload,
    usage_start_payload,
    usage_stop_payload,
)
from .database import connect_database
from .errors import DualMachineServiceError
from .identity import (
    parse_p256_identity,
    verify_p256_signature,
)
from .settings import DualMachineSettings
from .token_service import (
    RsaTokenCodec,
    TokenInvalid,
)
from .usage_repository import UsageRepository
from .versions import client_version_at_least
from .validation import is_nonzero_lower_hex


LEASE_RETRY_GRACE_SECONDS = 15
USAGE_START_CHALLENGE_TTL_SECONDS = 30
USAGE_NONCE_TTL_SECONDS = 24 * 60 * 60
_USAGE_START_CHALLENGE_TOKEN_DOMAIN = (
    b"vf-dual-machine-usage-start-challenge-token-v1\x00"
)
_USAGE_START_CHALLENGE_DIGEST_DOMAIN = (
    b"vf-dual-machine-usage-start-challenge-digest-v1\x00"
)
_USAGE_NONCE_DOMAIN = b"vf-dual-machine-usage-nonce-v1\x00"
_USAGE_START_CANCEL_AUTHENTICATED_REQUEST_DOMAIN = (
    b"vf-dual-machine-usage-start-cancel-authenticated-request-v1\x00"
)
_EMPTY_LEASE_SHA256 = "0" * 64


class UsageService:
    def __init__(
        self,
        settings: DualMachineSettings,
        *,
        token_codec: RsaTokenCodec | None = None,
    ) -> None:
        self.settings = settings
        self.settings.validate_usage()
        self.token_codec = token_codec or RsaTokenCodec.from_pem_files(
            private_key_path=self.settings.ticket_private_key_path or "",
            public_key_path=self.settings.ticket_public_key_path or "",
            previous_public_key_paths=tuple(
                self.settings.ticket_previous_public_key_paths,
            ),
            private_key_password=(
                self.settings.ticket_private_key_password or ""
            ),
            lease_ttl_seconds=self.settings.usage_lease_ttl_seconds,
        )

    def create_start_challenge(
        self,
        command: dict[str, Any],
        *,
        client_ip: str,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_start_challenge(command)
        signed_payload = usage_start_challenge_payload(normalized)
        request_hash = hashlib.sha256(signed_payload).hexdigest()
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            _verify_entitlement_command(
                entitlement,
                normalized,
                signed_payload,
            )
            _require_active_entitlement(entitlement, normalized)
            connection.execute("BEGIN IMMEDIATE")
            repository.expire_start_challenges(now)
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            _require_active_entitlement(entitlement, normalized)
            existing = repository.start_challenge_by_request(
                normalized["request_id"],
            )
            if existing is not None:
                if not hmac.compare_digest(
                    str(existing["request_payload_hash"]),
                    request_hash,
                ):
                    raise DualMachineServiceError(
                        "usage_start_challenge_request_conflict",
                        409,
                    )
                if (
                    str(existing["status"]) != "issued"
                    or int(existing["expires_at_epoch"]) <= now
                ):
                    raise DualMachineServiceError(
                        "usage_start_challenge_not_reusable",
                        409,
                    )
                response = self._start_challenge_response(existing)
                connection.commit()
                return response
            challenge = {
                **normalized,
                "challenge_id": secrets.token_hex(16),
                "request_payload_hash": request_hash,
                "expires_at_epoch": now
                + USAGE_START_CHALLENGE_TTL_SECONDS,
                "issued_ip": str(client_ip or "")[:128],
            }
            token = self._start_challenge_token(challenge)
            challenge["token_digest"] = self._start_challenge_token_digest(
                token,
            )
            try:
                repository.create_start_challenge(challenge)
            except sqlite3.IntegrityError as exc:
                raise DualMachineServiceError(
                    "usage_start_challenge_already_active",
                    409,
                ) from exc
            write_audit_event(
                connection,
                event_type="usage_start_challenge_issued",
                subject_type="entitlement",
                subject_id=normalized["entitlement_id"],
                trace_id=trace_id,
                ip_address=str(client_ip or "")[:128],
                detail={
                    "challenge_id": challenge["challenge_id"],
                    "pair_id": normalized["pair_id"],
                },
            )
            connection.commit()
            return self._start_challenge_response(challenge)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def start_usage(
        self,
        command: dict[str, Any],
        *,
        now_epoch: int | None = None,
        client_ip: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_start(command)
        signed_payload = usage_start_payload(normalized)
        request_hash = hashlib.sha256(signed_payload).hexdigest()
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            _verify_entitlement_command(
                entitlement,
                normalized,
                signed_payload,
            )
            connection.execute("BEGIN IMMEDIATE")
            if repository.start_cancellation(
                normalized["entitlement_id"],
                normalized["request_id"],
            ) is not None:
                raise DualMachineServiceError(
                    "usage_start_cancelled",
                    409,
                )
            repository.expire_stale_sessions(
                normalized["entitlement_id"],
                now_epoch=now,
            )
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            _verify_entitlement_command(
                entitlement,
                normalized,
                signed_payload,
            )
            existing = repository.session_by_start_request(
                normalized["entitlement_id"],
                normalized["request_id"],
            )
            if existing is not None:
                if not hmac.compare_digest(
                    str(existing["start_request_hash"]),
                    request_hash,
                ):
                    raise DualMachineServiceError(
                        "usage_start_request_conflict",
                        409,
                    )
                initial_charge = repository.ledger_charge(
                    str(existing["session_id"]),
                    0,
                )
                response = self._session_response(
                    entitlement,
                    existing,
                    charged_seconds=(
                        int(initial_charge["charged_seconds"])
                        if initial_charge is not None
                        else 0
                    ),
                )
                connection.commit()
                return response
            _require_active_entitlement(entitlement, normalized)
            if repository.active_session(
                normalized["entitlement_id"],
            ) is not None:
                raise DualMachineServiceError(
                    "usage_session_already_active",
                    409,
                )
            challenge = self._verify_start_challenge(
                repository,
                normalized,
                now_epoch=now,
            )
            if not repository.consume_nonce(
                scope="usage_start",
                subject_id=normalized["entitlement_id"],
                nonce_digest=self._nonce_digest(
                    normalized["request_nonce"],
                ),
                now_epoch=now,
                expires_at_epoch=now + USAGE_NONCE_TTL_SECONDS,
            ):
                raise DualMachineServiceError(
                    "usage_request_replayed",
                    409,
                )
            if not repository.consume_start_challenge(
                str(challenge["challenge_id"]),
                now_epoch=now,
            ):
                raise DualMachineServiceError(
                    "usage_start_challenge_invalid",
                    409,
                )
            balance_before = int(entitlement["remaining_seconds"])
            is_permanent = _is_permanent(entitlement)
            charged_seconds = (
                0
                if is_permanent
                else min(
                    int(self.settings.usage_lease_ttl_seconds),
                    balance_before,
                )
            )
            if not is_permanent and charged_seconds <= 0:
                raise DualMachineServiceError(
                    "usage_balance_exhausted",
                    409,
                )
            session_id = secrets.token_hex(16)
            session_seed = {
                "session_id": session_id,
                "entitlement_id": normalized["entitlement_id"],
                "pair_id": normalized["pair_id"],
                "channel_binding_sha256": normalized[
                    "channel_binding_sha256"
                ],
            }
            if not is_permanent:
                entitlement = repository.debit_entitlement(
                    normalized["entitlement_id"],
                    charged_seconds=charged_seconds,
                )
            lease_duration_seconds = (
                int(self.settings.usage_lease_ttl_seconds)
                if is_permanent
                else charged_seconds
            )
            lease = self.token_codec.issue_usage_lease(
                entitlement,
                session_seed,
                sequence=0,
                phase="active",
                lease_duration_seconds=lease_duration_seconds,
                previous_lease_sha256=_EMPTY_LEASE_SHA256,
                now_epoch=now,
            )
            repository.create_session({
                **session_seed,
                "start_request_id": normalized["request_id"],
                "start_request_hash": request_hash,
                "started_at_epoch": now,
                "last_heartbeat_at_epoch": now,
                "last_host_frames_total": normalized["host_frames_total"],
                "last_android_frames_total": (
                    normalized["android_frames_total"]
                ),
                "current_lease_sha256": lease["usage_lease_sha256"],
                "previous_lease_sha256": _EMPTY_LEASE_SHA256,
                "lease_issued_at_epoch": now,
                "lease_not_before_epoch": (
                    lease["usage_lease_not_before_epoch"]
                ),
                "lease_expires_at_epoch": (
                    lease["usage_lease_expires_at_epoch"]
                ),
                "lease_phase": "active",
                "lease_remaining_seconds": int(
                    entitlement["remaining_seconds"],
                ),
                "seconds_consumed": charged_seconds,
            })
            if not is_permanent:
                repository.add_ledger_charge(
                    charge_id=_charge_id(session_id, 0, request_hash),
                    entitlement_id=normalized["entitlement_id"],
                    session_id=session_id,
                    sequence=0,
                    interval_started_at_epoch=int(
                        lease["usage_lease_not_before_epoch"],
                    ),
                    interval_ended_at_epoch=int(
                        lease["usage_lease_expires_at_epoch"],
                    ),
                    charged_seconds=charged_seconds,
                    balance_before_seconds=balance_before,
                    balance_after_seconds=int(
                        entitlement["remaining_seconds"],
                    ),
                )
            write_audit_event(
                connection,
                event_type="usage_started",
                subject_type="usage_session",
                subject_id=session_id,
                trace_id=trace_id,
                ip_address=str(client_ip or "")[:128],
                detail={
                    "charged_seconds": charged_seconds,
                    "entitlement_id": normalized["entitlement_id"],
                    "lease_expires_at_epoch": int(
                        lease["usage_lease_expires_at_epoch"],
                    ),
                    "sequence": 0,
                },
            )
            session = repository.session(session_id)
            if session is None:
                raise RuntimeError("usage session insert missing")
            connection.commit()
            return _usage_response(
                entitlement,
                session,
                charged_seconds=charged_seconds,
                lease=lease,
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def cancel_start_usage(
        self,
        command: dict[str, Any],
        *,
        now_epoch: int | None = None,
        client_ip: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_start_cancel(command)
        signed_payload = usage_start_cancel_payload(normalized)
        request_hash = hashlib.sha256(signed_payload).hexdigest()
        authenticated_request_hash = (
            self._start_cancellation_authenticated_request_hash(
                normalized,
                signed_payload,
            )
        )
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            replay = _exact_start_cancellation_replay(
                repository,
                normalized,
                authenticated_request_hash,
            )
            if replay is not None:
                return replay
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _verify_start_cancellation_authority(
                repository,
                entitlement,
                normalized,
                signed_payload,
            )
            connection.execute("BEGIN IMMEDIATE")
            replay = _exact_start_cancellation_replay(
                repository,
                normalized,
                authenticated_request_hash,
            )
            if replay is not None:
                connection.commit()
                return replay
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _verify_start_cancellation_authority(
                repository,
                entitlement,
                normalized,
                signed_payload,
            )
            existing = repository.start_cancellation(
                normalized["entitlement_id"],
                normalized["start_request_id"],
            )
            if existing is not None:
                legacy_response = (
                    _upgrade_legacy_start_cancellation_replay(
                        repository,
                        entitlement,
                        existing,
                        normalized,
                        request_hash=request_hash,
                        authenticated_request_hash=(
                            authenticated_request_hash
                        ),
                        now_epoch=now,
                    )
                )
                if legacy_response is not None:
                    write_audit_event(
                        connection,
                        event_type=(
                            "usage_start_cancellation_replay_upgraded"
                        ),
                        subject_type="usage_start_request",
                        subject_id=normalized["start_request_id"],
                        trace_id=trace_id,
                        ip_address=str(client_ip or "")[:128],
                        detail={
                            "entitlement_id": normalized[
                                "entitlement_id"
                            ],
                            "session_id": legacy_response["session_id"],
                            "session_status": legacy_response[
                                "session_status"
                            ],
                        },
                    )
                    connection.commit()
                    return legacy_response
                raise DualMachineServiceError(
                    "usage_start_cancel_request_conflict",
                    409,
                )
            reused_request = (
                repository.start_cancellation_by_cancel_request(
                    normalized["entitlement_id"],
                    normalized["request_id"],
                )
            )
            if reused_request is not None:
                raise DualMachineServiceError(
                    "usage_start_cancel_request_conflict",
                    409,
                )
            if not repository.consume_nonce(
                scope="usage_start_cancel",
                subject_id=(
                    f"{normalized['entitlement_id']}:"
                    f"{normalized['pair_id']}"
                ),
                nonce_digest=self._nonce_digest(
                    normalized["request_nonce"],
                ),
                now_epoch=now,
                expires_at_epoch=now + USAGE_NONCE_TTL_SECONDS,
            ):
                raise DualMachineServiceError(
                    "usage_request_replayed",
                    409,
                )
            session = _terminal_start_cancellation_session(
                repository,
                normalized,
                now_epoch=now,
            )
            response = _start_cancellation_response(
                entitlement,
                normalized["start_request_id"],
                session,
            )
            try:
                repository.create_start_cancellation({
                    "entitlement_id": normalized["entitlement_id"],
                    "start_request_id": normalized["start_request_id"],
                    "cancel_request_id": normalized["request_id"],
                    "cancel_request_hash": request_hash,
                    "authenticated_request_hash": (
                        authenticated_request_hash
                    ),
                    "response_json": _encode_start_cancellation_response(
                        response,
                    ),
                    "channel_binding_sha256": normalized[
                        "channel_binding_sha256"
                    ],
                    "created_at_epoch": now,
                })
            except sqlite3.IntegrityError as exc:
                raise DualMachineServiceError(
                    "usage_start_cancel_request_conflict",
                    409,
                ) from exc
            write_audit_event(
                connection,
                event_type="usage_start_cancelled",
                subject_type="usage_start_request",
                subject_id=normalized["start_request_id"],
                trace_id=trace_id,
                ip_address=str(client_ip or "")[:128],
                detail={
                    "entitlement_id": normalized["entitlement_id"],
                    "session_id": (
                        str(session["session_id"])
                        if session is not None
                        else ""
                    ),
                    "session_status": (
                        str(session["status"])
                        if session is not None
                        else "not_started"
                    ),
                },
            )
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _start_cancellation_authenticated_request_hash(
        self,
        command: dict[str, Any],
        signed_payload: bytes,
    ) -> str:
        authenticated_request = b"\x00".join((
            signed_payload,
            command["host_signature_b64"].encode("ascii"),
            command["android_signature_b64"].encode("ascii"),
        ))
        return hmac.new(
            self._usage_domain_key(
                _USAGE_START_CANCEL_AUTHENTICATED_REQUEST_DOMAIN,
            ),
            authenticated_request,
            hashlib.sha256,
        ).hexdigest()

    def heartbeat_usage(
        self,
        command: dict[str, Any],
        *,
        now_epoch: int | None = None,
        client_ip: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_heartbeat(command)
        signed_payload = usage_heartbeat_payload(normalized)
        request_hash = hashlib.sha256(signed_payload).hexdigest()
        previous_claims = self._verify_previous_lease(
            normalized["previous_lease"],
            now_epoch=now,
        )
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            session = repository.session(normalized["session_id"])
            _verify_entitlement_command(
                entitlement,
                normalized,
                signed_payload,
            )
            _require_session_binding(session, entitlement, normalized)
            connection.execute("BEGIN IMMEDIATE")
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _require_supported_entitlement_versions(
                entitlement,
                self.settings,
            )
            session = repository.session(normalized["session_id"])
            _require_session_binding(session, entitlement, normalized)
            duplicate = self._duplicate_heartbeat_response(
                repository,
                entitlement,
                session,
                normalized,
                request_hash,
            )
            if duplicate is not None:
                connection.commit()
                return duplicate
            _require_lease_binding(
                previous_claims,
                entitlement,
                session,
                expected_sequence=normalized["sequence"] - 1,
            )
            if not repository.consume_nonce(
                scope="usage_heartbeat",
                subject_id=normalized["session_id"],
                nonce_digest=self._nonce_digest(
                    normalized["request_nonce"],
                ),
                now_epoch=now,
                expires_at_epoch=now + USAGE_NONCE_TTL_SECONDS,
            ):
                raise DualMachineServiceError(
                    "usage_request_replayed",
                    409,
                )
            response = self._apply_heartbeat(
                repository,
                entitlement,
                session,
                normalized,
                request_hash=request_hash,
                now_epoch=now,
                client_ip=client_ip,
                trace_id=trace_id,
            )
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def stop_usage(
        self,
        command: dict[str, Any],
        *,
        now_epoch: int | None = None,
        client_ip: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_stop(command)
        signed_payload = usage_stop_payload(normalized)
        previous_claims = self._verify_previous_lease(
            normalized["previous_lease"],
            now_epoch=now,
            grace_seconds=LEASE_RETRY_GRACE_SECONDS,
            not_before_grace_seconds=(
                self.settings.usage_renewal_window_seconds
            ),
        )
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            session = repository.session(normalized["session_id"])
            _verify_entitlement_command(
                entitlement,
                normalized,
                signed_payload,
            )
            _require_session_binding(session, entitlement, normalized)
            _require_lease_binding(
                previous_claims,
                entitlement,
                session,
                expected_sequence=int(session["last_heartbeat_sequence"]),
            )
            connection.execute("BEGIN IMMEDIATE")
            session = repository.session(normalized["session_id"])
            if session is None:
                raise DualMachineServiceError(
                    "usage_session_not_found",
                    404,
                )
            if str(session["status"]) == "active":
                if not hmac.compare_digest(
                    str(session["current_lease_sha256"]),
                    hashlib.sha256(
                        normalized["previous_lease"].encode("ascii"),
                    ).hexdigest(),
                ):
                    raise DualMachineServiceError(
                        "usage_lease_not_current",
                        409,
                    )
                stopped = repository.end_session(
                    normalized["session_id"],
                    now_epoch=now,
                    reason="user_stopped",
                )
                session = repository.session(normalized["session_id"])
                if stopped:
                    write_audit_event(
                        connection,
                        event_type="usage_stopped",
                        subject_type="usage_session",
                        subject_id=normalized["session_id"],
                        trace_id=trace_id,
                        ip_address=str(client_ip or "")[:128],
                        detail={
                            "charged_seconds": 0,
                            "entitlement_id": normalized[
                                "entitlement_id"
                            ],
                        },
                    )
            connection.commit()
            return {
                "ok": True,
                "session_id": normalized["session_id"],
                "status": str(session["status"]),
                "authorization_kind": str(
                    entitlement.get("authorization_kind")
                    or "legacy_balance",
                ),
                "is_permanent": _is_permanent(entitlement),
                "remaining_seconds": int(entitlement["remaining_seconds"]),
                "charged_seconds": 0,
                "billing_started": (
                    _is_permanent(entitlement)
                    or int(session["seconds_consumed"]) > 0
                ),
            }
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def entitlement_status(
        self,
        command: dict[str, Any],
        *,
        now_epoch: int | None = None,
    ) -> dict[str, Any]:
        now = _now(now_epoch)
        normalized = _normalize_status(command)
        signed_payload = entitlement_status_payload(normalized)
        connection = connect_database(self.settings)
        repository = UsageRepository(connection)
        try:
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _verify_entitlement_status_command(
                entitlement,
                normalized,
                signed_payload,
            )
            connection.execute("BEGIN IMMEDIATE")
            entitlement = repository.entitlement(
                normalized["entitlement_id"],
            )
            _verify_entitlement_status_command(
                entitlement,
                normalized,
                signed_payload,
            )
            repository.expire_stale_sessions(
                normalized["entitlement_id"],
                now_epoch=now,
            )
            if not repository.consume_nonce(
                scope="entitlement_status",
                subject_id=normalized["entitlement_id"],
                nonce_digest=self._nonce_digest(
                    normalized["request_nonce"],
                ),
                now_epoch=now,
                expires_at_epoch=now + USAGE_NONCE_TTL_SECONDS,
            ):
                raise DualMachineServiceError(
                    "usage_request_replayed",
                    409,
                )
            active_session = repository.active_session(
                normalized["entitlement_id"],
            )
            effective_session_status = ""
            if active_session is not None:
                effective_session_status = (
                    "active"
                    if int(active_session["lease_expires_at_epoch"]) > now
                    else "ended"
                )
            response = {
                "ok": True,
                "entitlement_id": str(entitlement["entitlement_id"]),
                "pair_id": str(entitlement["pair_id"]),
                "status": str(entitlement["status"]),
                "revocation_version": int(
                    entitlement["revocation_version"],
                ),
                "authorization_kind": str(
                    entitlement.get("authorization_kind")
                    or "legacy_balance",
                ),
                "product_key": str(
                    entitlement.get("product_key") or "",
                ),
                "is_permanent": _is_permanent(entitlement),
                "remaining_seconds": int(
                    entitlement["remaining_seconds"],
                ),
                "total_credited_seconds": int(
                    entitlement["total_credited_seconds"],
                ),
                "total_consumed_seconds": int(
                    entitlement["total_consumed_seconds"],
                ),
                "usage_session_status": effective_session_status,
            }
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_previous_lease(
        self,
        token: str,
        *,
        now_epoch: int,
        grace_seconds: int = LEASE_RETRY_GRACE_SECONDS,
        not_before_grace_seconds: int = 0,
    ) -> dict[str, Any]:
        try:
            return self.token_codec.verify_usage_lease(
                token,
                now_epoch=now_epoch,
                expiration_grace_seconds=grace_seconds,
                not_before_grace_seconds=not_before_grace_seconds,
            )
        except TokenInvalid as exc:
            raise DualMachineServiceError(
                "usage_lease_invalid",
                409,
            ) from exc

    def _start_challenge_response(
        self,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        token = self._start_challenge_token(challenge)
        if not hmac.compare_digest(
            self._start_challenge_token_digest(token),
            str(challenge["token_digest"]),
        ):
            raise RuntimeError("usage start challenge digest mismatch")
        return {
            "ok": True,
            "challenge_id": str(challenge["challenge_id"]),
            "challenge_token": token,
            "challenge_expires_at_epoch": int(
                challenge["expires_at_epoch"],
            ),
            "billing_started": False,
        }

    def _start_challenge_token(
        self,
        challenge: dict[str, Any],
    ) -> str:
        seed = (
            f"{challenge['challenge_id']}:{challenge['request_id']}:"
            f"{challenge['request_payload_hash']}"
        ).encode("ascii")
        signature = hmac.new(
            self._usage_domain_key(
                _USAGE_START_CHALLENGE_TOKEN_DOMAIN,
            ),
            seed,
            hashlib.sha256,
        ).digest()
        return _base64url(signature)

    def _start_challenge_token_digest(self, token: str) -> str:
        return hmac.new(
            self._usage_domain_key(
                _USAGE_START_CHALLENGE_DIGEST_DOMAIN,
            ),
            str(token).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _verify_start_challenge(
        self,
        repository: UsageRepository,
        command: dict[str, Any],
        *,
        now_epoch: int,
    ) -> dict[str, Any]:
        challenge = repository.start_challenge(
            command["start_challenge_id"],
        )
        if (
            challenge is None
            or str(challenge["status"]) != "issued"
            or int(challenge["expires_at_epoch"]) <= int(now_epoch)
            or str(challenge["entitlement_id"])
            != command["entitlement_id"]
            or str(challenge["pair_id"]) != command["pair_id"]
            or str(challenge["channel_binding_sha256"])
            != command["channel_binding_sha256"]
            or not hmac.compare_digest(
                str(challenge["token_digest"]),
                self._start_challenge_token_digest(
                    command["start_challenge_token"],
                ),
            )
        ):
            raise DualMachineServiceError(
                "usage_start_challenge_invalid",
                409,
            )
        return challenge

    def _nonce_digest(self, nonce: str) -> str:
        return hmac.new(
            self._usage_domain_key(_USAGE_NONCE_DOMAIN),
            str(nonce).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _usage_domain_key(self, domain: bytes) -> bytes:
        return hmac.new(
            self.settings.token_secret,
            domain,
            hashlib.sha256,
        ).digest()

    def _duplicate_heartbeat_response(
        self,
        repository: UsageRepository,
        entitlement: dict[str, Any],
        session: dict[str, Any],
        command: dict[str, Any],
        request_hash: str,
    ) -> dict[str, Any] | None:
        if int(command["sequence"]) != int(
            session["last_heartbeat_sequence"],
        ):
            return None
        if (
            str(session["last_request_id"]) != command["request_id"]
            or not hmac.compare_digest(
                str(session["last_request_hash"]),
                request_hash,
            )
            or not hmac.compare_digest(
                str(session["previous_lease_sha256"]),
                hashlib.sha256(
                    command["previous_lease"].encode("ascii"),
                ).hexdigest(),
            )
        ):
            raise DualMachineServiceError(
                "usage_heartbeat_replay_conflict",
                409,
            )
        charge = repository.ledger_charge(
            str(session["session_id"]),
            int(command["sequence"]),
        )
        return self._session_response(
            entitlement,
            session,
            charged_seconds=(
                int(charge["charged_seconds"])
                if charge is not None
                else 0
            ),
        )

    def _apply_heartbeat(
        self,
        repository: UsageRepository,
        entitlement: dict[str, Any],
        session: dict[str, Any],
        command: dict[str, Any],
        *,
        request_hash: str,
        now_epoch: int,
        client_ip: str,
        trace_id: str,
    ) -> dict[str, Any]:
        _require_entitlement_binding(entitlement, command)
        if (
            str(session["status"]) != "active"
            or int(command["sequence"])
            != int(session["last_heartbeat_sequence"]) + 1
            or not hmac.compare_digest(
                str(session["current_lease_sha256"]),
                hashlib.sha256(
                    command["previous_lease"].encode("ascii"),
                ).hexdigest(),
            )
        ):
            raise DualMachineServiceError(
                "usage_heartbeat_state_invalid",
                409,
            )
        renewal_opens_at = (
            int(session["lease_expires_at_epoch"])
            - int(self.settings.usage_renewal_window_seconds)
        )
        if now_epoch < renewal_opens_at:
            raise DualMachineServiceError(
                "usage_heartbeat_too_early",
                429,
            )
        if (
            int(command["host_frames_total"])
            <= int(session["last_host_frames_total"])
            or int(command["android_frames_total"])
            <= int(session["last_android_frames_total"])
        ):
            repository.end_session(
                str(session["session_id"]),
                now_epoch=now_epoch,
                reason="usage_progress_not_confirmed",
            )
            self._commit_then_raise(
                repository.connection,
                "usage_progress_not_confirmed",
                409,
            )
        balance_before = int(entitlement["remaining_seconds"])
        is_permanent = _is_permanent(entitlement)
        if (
            str(entitlement["status"]) != "active"
            or (not is_permanent and balance_before <= 0)
        ):
            repository.end_session(
                str(session["session_id"]),
                now_epoch=now_epoch,
                reason="balance_exhausted",
            )
            self._commit_then_raise(
                repository.connection,
                "usage_balance_exhausted",
                409,
            )
        charged_seconds = (
            0
            if is_permanent
            else min(
                int(self.settings.usage_lease_ttl_seconds),
                balance_before,
            )
        )
        if not is_permanent and charged_seconds <= 0:
            repository.end_session(
                str(session["session_id"]),
                now_epoch=now_epoch,
                reason="balance_exhausted",
            )
            self._commit_then_raise(
                repository.connection,
                "usage_balance_exhausted",
                409,
            )
        previous_lease_sha256 = str(session["current_lease_sha256"])
        next_not_before = max(
            now_epoch,
            int(session["lease_expires_at_epoch"]),
        )
        if not is_permanent:
            entitlement = repository.debit_entitlement(
                str(entitlement["entitlement_id"]),
                charged_seconds=charged_seconds,
            )
        balance_after = int(entitlement["remaining_seconds"])
        lease_duration_seconds = (
            int(self.settings.usage_lease_ttl_seconds)
            if is_permanent
            else charged_seconds
        )
        lease = self.token_codec.issue_usage_lease(
            entitlement,
            session,
            sequence=int(command["sequence"]),
            phase="active",
            lease_duration_seconds=lease_duration_seconds,
            previous_lease_sha256=previous_lease_sha256,
            now_epoch=now_epoch,
            not_before_epoch=next_not_before,
        )
        if not is_permanent:
            repository.add_ledger_charge(
                charge_id=_charge_id(
                    str(session["session_id"]),
                    int(command["sequence"]),
                    request_hash,
                ),
                entitlement_id=str(entitlement["entitlement_id"]),
                session_id=str(session["session_id"]),
                sequence=int(command["sequence"]),
                interval_started_at_epoch=int(
                    lease["usage_lease_not_before_epoch"],
                ),
                interval_ended_at_epoch=int(
                    lease["usage_lease_expires_at_epoch"],
                ),
                charged_seconds=charged_seconds,
                balance_before_seconds=balance_before,
                balance_after_seconds=balance_after,
            )
        repository.record_heartbeat(
            str(session["session_id"]),
            request_id=command["request_id"],
            request_hash=request_hash,
            sequence=int(command["sequence"]),
            host_frames_total=int(command["host_frames_total"]),
            android_frames_total=int(command["android_frames_total"]),
            lease_sha256=str(lease.get("usage_lease_sha256") or ""),
            previous_lease_sha256=previous_lease_sha256,
            heartbeat_at_epoch=now_epoch,
            lease_issued_at_epoch=now_epoch,
            lease_not_before_epoch=int(
                lease["usage_lease_not_before_epoch"],
            ),
            lease_expires_at_epoch=int(
                lease["usage_lease_expires_at_epoch"],
            ),
            lease_phase="active",
            lease_remaining_seconds=balance_after,
            charged_seconds=charged_seconds,
        )
        write_audit_event(
            repository.connection,
            event_type="usage_renewed",
            subject_type="usage_session",
            subject_id=str(session["session_id"]),
            trace_id=trace_id,
            ip_address=str(client_ip or "")[:128],
            detail={
                "charged_seconds": charged_seconds,
                "entitlement_id": str(entitlement["entitlement_id"]),
                "lease_expires_at_epoch": int(
                    lease["usage_lease_expires_at_epoch"],
                ),
                "sequence": int(command["sequence"]),
            },
        )
        session = repository.session(str(session["session_id"]))
        if session is None:
            raise RuntimeError("updated usage session missing")
        return _usage_response(
            entitlement,
            session,
            charged_seconds=charged_seconds,
            lease=lease,
        )

    def _session_response(
        self,
        entitlement: dict[str, Any],
        session: dict[str, Any],
        *,
        charged_seconds: int,
    ) -> dict[str, Any]:
        if (
            str(session["status"]) != "active"
            or not str(session["current_lease_sha256"])
        ):
            lease: dict[str, Any] = {}
        else:
            lease_entitlement = {
                **entitlement,
                "remaining_seconds": int(
                    session["lease_remaining_seconds"],
                ),
            }
            lease_duration = (
                int(session["lease_expires_at_epoch"])
                - int(session["lease_not_before_epoch"])
            )
            lease = self.token_codec.issue_usage_lease(
                lease_entitlement,
                session,
                sequence=int(session["last_heartbeat_sequence"]),
                phase=str(session["lease_phase"]),
                lease_duration_seconds=lease_duration,
                previous_lease_sha256=str(
                    session["previous_lease_sha256"],
                ),
                now_epoch=int(session["lease_issued_at_epoch"]),
                not_before_epoch=int(
                    session["lease_not_before_epoch"],
                ),
            )
            if not hmac.compare_digest(
                str(lease["usage_lease_sha256"]),
                str(session["current_lease_sha256"]),
            ):
                raise RuntimeError("stored usage lease digest mismatch")
        return _usage_response(
            entitlement,
            session,
            charged_seconds=charged_seconds,
            lease=lease,
        )

    @staticmethod
    def _commit_then_raise(
        connection,
        code: str,
        status_code: int,
    ) -> None:
        connection.commit()
        raise DualMachineServiceError(code, status_code)


def _verify_entitlement_command(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    _require_entitlement_binding(entitlement, command)
    _verify_device_signatures(entitlement, command, signed_payload)


def _verify_entitlement_status_command(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    _require_status_binding(entitlement, command)
    _verify_device_signatures(entitlement, command, signed_payload)


def _verify_start_cancellation_command(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    # A server-revoked session is already terminal. Its original device pair
    # may prove a pending cancellation with the older revocation version so
    # the client can leave STOPPING without reopening or renewing usage.
    _require_status_binding(entitlement, command)
    _verify_device_signatures(entitlement, command, signed_payload)


def _verify_start_cancellation_authority(
    repository: UsageRepository,
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    try:
        _verify_start_cancellation_command(
            entitlement,
            command,
            signed_payload,
        )
        return
    except DualMachineServiceError as current_error:
        if not _can_use_historical_start_cancellation(
            entitlement,
            command,
        ):
            raise current_error

    _verify_historical_start_cancellation_signatures(
        repository,
        entitlement,
        command,
        signed_payload,
    )
    session = repository.session_by_start_request(
        command["entitlement_id"],
        command["start_request_id"],
    )
    if session is not None:
        _require_start_cancellation_binding(session, command)
        return
    _require_historical_start_challenge(repository, command)


def _can_use_historical_start_cancellation(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
) -> bool:
    return bool(
        entitlement is not None
        and str(entitlement["entitlement_id"])
        == command["entitlement_id"]
        and int(entitlement["protocol_version"])
        == int(command["protocol_version"])
        and int(command["revocation_version"])
        < int(entitlement["revocation_version"])
    )


def _verify_historical_start_cancellation_signatures(
    repository: UsageRepository,
    entitlement: dict[str, Any],
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    bindings = repository.entitlement_bindings_for_pair(
        command["entitlement_id"],
        command["pair_id"],
    )
    for binding in bindings:
        if bool(binding["is_current"]):
            continue
        historical_entitlement = {
            **entitlement,
            **binding,
        }
        try:
            _verify_device_signatures(
                historical_entitlement,
                command,
                signed_payload,
            )
            return
        except DualMachineServiceError as error:
            if error.code != "usage_device_proof_invalid":
                raise
    raise DualMachineServiceError(
        "usage_device_proof_invalid",
        403,
    )


def _require_historical_start_challenge(
    repository: UsageRepository,
    command: dict[str, Any],
) -> None:
    challenge = repository.start_challenge_by_request(
        command["start_request_id"],
    )
    if (
        challenge is None
        or str(challenge["entitlement_id"])
        != command["entitlement_id"]
        or str(challenge["pair_id"]) != command["pair_id"]
        or str(challenge["channel_binding_sha256"])
        != command["channel_binding_sha256"]
    ):
        raise DualMachineServiceError(
            "usage_start_cancel_request_conflict",
            409,
        )


def _verify_device_signatures(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
    signed_payload: bytes,
) -> None:
    try:
        verify_p256_signature(
            parse_p256_identity(
                str(entitlement["host_identity_public_key_b64"]),
            ),
            command["host_signature_b64"],
            signed_payload,
        )
        verify_p256_signature(
            parse_p256_identity(
                str(entitlement["android_identity_public_key_b64"]),
            ),
            command["android_signature_b64"],
            signed_payload,
        )
    except ValueError as exc:
        raise DualMachineServiceError(
            "usage_device_proof_invalid",
            403,
        ) from exc


def _require_entitlement_binding(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
) -> None:
    if (
        entitlement is None
        or str(entitlement["entitlement_id"])
        != command["entitlement_id"]
        or str(entitlement["pair_id"]) != command["pair_id"]
        or int(entitlement["protocol_version"])
        != int(command["protocol_version"])
        or int(entitlement["revocation_version"])
        != int(command["revocation_version"])
    ):
        raise DualMachineServiceError(
            "dual_machine_entitlement_invalid",
            409,
        )


def _require_status_binding(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
) -> None:
    # 状态查询的绑定规则：entitlement_id / pair_id / protocol 必须一致；
    # rv 不一致时，仅当数据库状态已为 revoked 且客户端持有较旧 rv，
    # 才允许其获知 revoked 与最新 rv（管理员吊销后 rv 已递增）。
    # active/exhausted 的 rv 不一致以及未来 rv 一律拒绝。
    if (
        entitlement is None
        or str(entitlement["entitlement_id"])
        != command["entitlement_id"]
        or str(entitlement["pair_id"]) != command["pair_id"]
        or int(entitlement["protocol_version"])
        != int(command["protocol_version"])
    ):
        raise DualMachineServiceError(
            "dual_machine_entitlement_invalid",
            409,
        )
    current_rv = int(entitlement["revocation_version"])
    request_rv = int(command["revocation_version"])
    if request_rv == current_rv:
        return
    if (
        str(entitlement["status"]) == "revoked"
        and request_rv < current_rv
    ):
        return
    raise DualMachineServiceError(
        "dual_machine_entitlement_invalid",
        409,
    )


def _require_active_entitlement(
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
) -> None:
    _require_entitlement_binding(entitlement, command)
    if (
        str(entitlement["status"]) != "active"
        or (
            not _is_permanent(entitlement)
            and int(entitlement["remaining_seconds"]) <= 0
        )
    ):
        raise DualMachineServiceError(
            "dual_machine_entitlement_inactive",
            409,
        )


def _is_permanent(entitlement: dict[str, Any] | None) -> bool:
    return bool(
        entitlement is not None
        and str(
            entitlement.get("authorization_kind") or "legacy_balance",
        )
        == "permanent"
    )


def _require_supported_entitlement_versions(
    entitlement: dict[str, Any] | None,
    settings: DualMachineSettings,
) -> None:
    if entitlement is None:
        return
    if (
        not client_version_at_least(
            entitlement["host_client_version"],
            settings.minimum_host_client_version,
        )
        or not client_version_at_least(
            entitlement["android_client_version"],
            settings.minimum_android_client_version,
        )
    ):
        raise DualMachineServiceError(
            "dual_machine_client_update_required",
            426,
        )


def _require_session_binding(
    session: dict[str, Any] | None,
    entitlement: dict[str, Any] | None,
    command: dict[str, Any],
) -> None:
    _require_entitlement_binding(entitlement, command)
    if (
        session is None
        or str(session["session_id"]) != command["session_id"]
        or str(session["entitlement_id"]) != command["entitlement_id"]
        or str(session["pair_id"]) != command["pair_id"]
        or str(session["channel_binding_sha256"])
        != command["channel_binding_sha256"]
    ):
        raise DualMachineServiceError("usage_session_not_found", 404)


def _require_start_cancellation_binding(
    session: dict[str, Any] | None,
    command: dict[str, Any],
) -> None:
    if session is None:
        return
    if (
        str(session["pair_id"]) != command["pair_id"]
        or str(session["channel_binding_sha256"])
        != command["channel_binding_sha256"]
    ):
        raise DualMachineServiceError(
            "usage_start_cancel_request_conflict",
            409,
        )


def _require_lease_binding(
    claims: dict[str, Any],
    entitlement: dict[str, Any],
    session: dict[str, Any],
    *,
    expected_sequence: int,
) -> None:
    expected = {
        "sub": str(entitlement["entitlement_id"]),
        "pid": str(entitlement["pair_id"]),
        "sid": str(session["session_id"]),
        "pv": int(entitlement["protocol_version"]),
        "rv": int(entitlement["revocation_version"]),
        "hkh": str(entitlement["host_key_sha256"]),
        "akh": str(entitlement["android_key_sha256"]),
        "cbh": str(session["channel_binding_sha256"]),
        "pth": str(session["previous_lease_sha256"]),
        "seq": int(expected_sequence),
        "phase": str(session["lease_phase"]),
        "authorization_kind": str(
            entitlement.get("authorization_kind") or "legacy_balance",
        ),
        "is_permanent": _is_permanent(entitlement),
        "remaining": int(session["lease_remaining_seconds"]),
        "iat": int(session["lease_issued_at_epoch"]),
        "nbf": int(session["lease_not_before_epoch"]),
        "exp": int(session["lease_expires_at_epoch"]),
    }
    actual = {
        key: (
            int(claims.get(key, -1))
            if key in {
                "pv",
                "rv",
                "seq",
                "remaining",
                "iat",
                "nbf",
                "exp",
            }
            else bool(claims.get(key))
            if key == "is_permanent"
            else str(claims.get(key) or "")
        )
        for key in expected
    }
    if actual != expected:
        raise DualMachineServiceError("usage_lease_claim_mismatch", 409)


def _normalize_start(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_progress(command)
    if (
        command.get("host_runtime_ready") is not True
        or command.get("android_runtime_ready") is not True
    ):
        raise DualMachineServiceError("usage_runtime_not_ready", 409)
    normalized.update({
        "host_runtime_ready": True,
        "android_runtime_ready": True,
        "start_challenge_id": _hex_128(
            command.get("start_challenge_id"),
            "start_challenge_id",
        ),
        "start_challenge_token": _challenge_token(
            command.get("start_challenge_token"),
        ),
    })
    return normalized


def _normalize_start_challenge(
    command: dict[str, Any],
) -> dict[str, Any]:
    normalized = _normalize_usage_common(command)
    normalized.update({
        "request_id": _hex_128(command.get("request_id"), "request_id"),
        "request_nonce": _hex_128(
            command.get("request_nonce"),
            "request_nonce",
        ),
        "channel_binding_sha256": _sha256_hex(
            command.get("channel_binding_sha256"),
            "channel_binding_sha256",
        ),
    })
    return normalized


def _normalize_start_cancel(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_usage_common(command)
    normalized.update({
        "request_id": _hex_128(command.get("request_id"), "request_id"),
        "request_nonce": _hex_128(
            command.get("request_nonce"),
            "request_nonce",
        ),
        "start_request_id": _hex_128(
            command.get("start_request_id"),
            "start_request_id",
        ),
        "channel_binding_sha256": _sha256_hex(
            command.get("channel_binding_sha256"),
            "channel_binding_sha256",
        ),
    })
    return normalized


def _normalize_heartbeat(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_progress(command)
    normalized.update({
        "session_id": _hex_128(command.get("session_id"), "session_id"),
        "sequence": _positive_int(command.get("sequence"), "sequence"),
        "previous_lease": _token(command.get("previous_lease")),
    })
    return normalized


def _normalize_stop(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_usage_common(command)
    normalized.update({
        "session_id": _hex_128(command.get("session_id"), "session_id"),
        "request_id": _hex_128(command.get("request_id"), "request_id"),
        "request_nonce": _hex_128(
            command.get("request_nonce"),
            "request_nonce",
        ),
        "channel_binding_sha256": _sha256_hex(
            command.get("channel_binding_sha256"),
            "channel_binding_sha256",
        ),
        "previous_lease": _token(command.get("previous_lease")),
    })
    return normalized


def _normalize_status(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_usage_common(command)
    normalized["request_nonce"] = _hex_128(
        command.get("request_nonce"),
        "request_nonce",
    )
    return normalized


def _normalize_usage_common(
    command: dict[str, Any],
) -> dict[str, Any]:
    try:
        protocol_version = command["protocol_version"]
        revocation_version = command["revocation_version"]
        if (
            type(protocol_version) is not int
            or type(revocation_version) is not int
        ):
            raise TypeError("usage versions must be integers")
        host_signature = str(command["host_signature_b64"]).strip()
        android_signature = str(
            command["android_signature_b64"],
        ).strip()
    except Exception as exc:
        raise DualMachineServiceError("usage_request_invalid", 422) from exc
    if (
        protocol_version != PROTOCOL_VERSION
        or revocation_version <= 0
        or not 8 <= len(host_signature) <= 256
        or not 8 <= len(android_signature) <= 256
    ):
        raise DualMachineServiceError("usage_request_invalid", 422)
    return {
        "entitlement_id": _hex_128(
            command.get("entitlement_id"),
            "entitlement_id",
        ),
        "pair_id": _hex_128(command.get("pair_id"), "pair_id"),
        "protocol_version": protocol_version,
        "revocation_version": revocation_version,
        "host_signature_b64": host_signature,
        "android_signature_b64": android_signature,
    }


def _normalize_progress(command: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_usage_common(command)
    normalized.update({
        "request_id": _hex_128(command.get("request_id"), "request_id"),
        "request_nonce": _hex_128(
            command.get("request_nonce"),
            "request_nonce",
        ),
        "channel_binding_sha256": _sha256_hex(
            command.get("channel_binding_sha256"),
            "channel_binding_sha256",
        ),
        "host_frames_total": _counter(
            command.get("host_frames_total"),
            "host_frames_total",
        ),
        "android_frames_total": _counter(
            command.get("android_frames_total"),
            "android_frames_total",
        ),
    })
    return normalized


def _usage_response(
    entitlement: dict[str, Any],
    session: dict[str, Any],
    *,
    charged_seconds: int,
    lease: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": True,
        "entitlement_id": str(entitlement["entitlement_id"]),
        "pair_id": str(entitlement["pair_id"]),
        "session_id": str(session["session_id"]),
        "status": str(session["status"]),
        "sequence": int(session["last_heartbeat_sequence"]),
        "authorization_kind": str(
            entitlement.get("authorization_kind") or "legacy_balance",
        ),
        "product_key": str(entitlement.get("product_key") or ""),
        "is_permanent": _is_permanent(entitlement),
        "charged_seconds": int(charged_seconds),
        "remaining_seconds": int(entitlement["remaining_seconds"]),
        "total_consumed_seconds": int(
            entitlement["total_consumed_seconds"],
        ),
        "billing_started": (
            _is_permanent(entitlement)
            or int(session["seconds_consumed"]) > 0
        ),
        **lease,
    }


def _upgrade_legacy_start_cancellation_replay(
    repository: UsageRepository,
    entitlement: dict[str, Any] | None,
    cancellation: dict[str, Any],
    command: dict[str, Any],
    *,
    request_hash: str,
    authenticated_request_hash: str,
    now_epoch: int,
) -> dict[str, Any] | None:
    # V5 persisted the canonical payload hash but not the original ECDSA
    # signature bytes or response. The first fully authenticated retry whose
    # stored IDs/hash/channel all match chooses the signature bytes pinned by
    # V6. Once backfilled, even a valid same-key re-sign is not exact replay.
    stored_authenticated_hash = str(
        cancellation.get("authenticated_request_hash") or "",
    )
    stored_response = str(cancellation.get("response_json") or "")
    if stored_authenticated_hash or stored_response:
        if not stored_authenticated_hash or not stored_response:
            raise RuntimeError(
                "usage start cancellation replay upgrade incomplete",
            )
        return None
    if entitlement is None:
        raise RuntimeError("authenticated cancellation entitlement missing")
    _require_legacy_start_cancellation_match(
        cancellation,
        command,
        request_hash=request_hash,
    )
    session = _terminal_start_cancellation_session(
        repository,
        command,
        now_epoch=now_epoch,
    )
    response = _start_cancellation_response(
        entitlement,
        command["start_request_id"],
        session,
    )
    if not repository.backfill_start_cancellation_replay(
        cancellation,
        authenticated_request_hash=authenticated_request_hash,
        response_json=_encode_start_cancellation_response(response),
    ):
        raise RuntimeError(
            "usage start cancellation replay upgrade lost",
        )
    return response


def _require_legacy_start_cancellation_match(
    cancellation: dict[str, Any],
    command: dict[str, Any],
    *,
    request_hash: str,
) -> None:
    if (
        str(cancellation["entitlement_id"])
        != command["entitlement_id"]
        or str(cancellation["start_request_id"])
        != command["start_request_id"]
        or str(cancellation["cancel_request_id"])
        != command["request_id"]
        or not hmac.compare_digest(
            str(cancellation["cancel_request_hash"]),
            request_hash,
        )
        or str(cancellation["channel_binding_sha256"])
        != command["channel_binding_sha256"]
    ):
        raise DualMachineServiceError(
            "usage_start_cancel_request_conflict",
            409,
        )


def _terminal_start_cancellation_session(
    repository: UsageRepository,
    command: dict[str, Any],
    *,
    now_epoch: int,
) -> dict[str, Any] | None:
    session = repository.session_by_start_request(
        command["entitlement_id"],
        command["start_request_id"],
    )
    _require_start_cancellation_binding(session, command)
    if session is None or str(session["status"]) != "active":
        return session
    session_id = str(session["session_id"])
    if not repository.end_session(
        session_id,
        now_epoch=now_epoch,
        reason="client_start_cancelled",
    ):
        raise RuntimeError("active usage start cancellation failed")
    session = repository.session(session_id)
    if session is None or str(session["status"]) == "active":
        raise RuntimeError("cancelled usage session still active")
    return session


def _start_cancellation_response(
    entitlement: dict[str, Any],
    start_request_id: str,
    session: dict[str, Any] | None,
) -> dict[str, Any]:
    session_status = (
        str(session["status"])
        if session is not None
        else "not_started"
    )
    if session_status not in {
        "not_started",
        "ended",
        "exhausted",
        "revoked",
    }:
        raise RuntimeError("usage start cancellation left active session")
    return {
        "ok": True,
        "start_request_id": str(start_request_id),
        "session_id": (
            str(session["session_id"])
            if session is not None
            else ""
        ),
        "session_status": session_status,
        "remaining_seconds": int(entitlement["remaining_seconds"]),
        "charged_seconds": 0,
        "billing_started": bool(
            session is not None
            and (
                _is_permanent(entitlement)
                or int(session["seconds_consumed"]) > 0
            )
        ),
        "authorization_kind": str(
            entitlement.get("authorization_kind") or "legacy_balance",
        ),
        "is_permanent": _is_permanent(entitlement),
    }


def _exact_start_cancellation_replay(
    repository: UsageRepository,
    command: dict[str, Any],
    authenticated_request_hash: str,
) -> dict[str, Any] | None:
    cancellation = repository.start_cancellation(
        command["entitlement_id"],
        command["start_request_id"],
    )
    if cancellation is None:
        return None
    stored_hash = str(
        cancellation.get("authenticated_request_hash") or "",
    )
    if (
        str(cancellation["cancel_request_id"]) != command["request_id"]
        or not stored_hash
        or not hmac.compare_digest(
            stored_hash,
            authenticated_request_hash,
        )
    ):
        return None
    return _decode_start_cancellation_response(cancellation)


def _encode_start_cancellation_response(response: dict[str, Any]) -> str:
    return json.dumps(
        response,
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _decode_start_cancellation_response(
    cancellation: dict[str, Any],
) -> dict[str, Any]:
    raw_response = str(cancellation.get("response_json") or "")
    if not raw_response or len(raw_response) > 4_096:
        raise RuntimeError("usage start cancellation response missing")
    try:
        response = json.loads(raw_response)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "usage start cancellation response invalid",
        ) from exc
    expected_keys = {
        "ok",
        "start_request_id",
        "session_id",
        "session_status",
        "remaining_seconds",
        "charged_seconds",
        "billing_started",
        "authorization_kind",
        "is_permanent",
    }
    if not isinstance(response, dict) or set(response) != expected_keys:
        raise RuntimeError("usage start cancellation response invalid")
    start_request_id = str(response["start_request_id"])
    session_id = str(response["session_id"])
    session_status = str(response["session_status"])
    if (
        response["ok"] is not True
        or start_request_id != str(cancellation["start_request_id"])
        or session_status
        not in {"not_started", "ended", "exhausted", "revoked"}
        or (
            session_status == "not_started"
            and (session_id or response["billing_started"] is not False)
        )
        or (
            session_status != "not_started"
            and not re.fullmatch(r"[0-9a-f]{32}", session_id)
        )
        or type(response["remaining_seconds"]) is not int
        or int(response["remaining_seconds"]) < 0
        or response["charged_seconds"] != 0
        or type(response["billing_started"]) is not bool
        or not isinstance(response["authorization_kind"], str)
        or type(response["is_permanent"]) is not bool
    ):
        raise RuntimeError("usage start cancellation response invalid")
    return {
        "ok": True,
        "start_request_id": start_request_id,
        "session_id": session_id,
        "session_status": session_status,
        "remaining_seconds": int(response["remaining_seconds"]),
        "charged_seconds": 0,
        "billing_started": bool(response["billing_started"]),
        "authorization_kind": str(response["authorization_kind"]),
        "is_permanent": bool(response["is_permanent"]),
    }


def _charge_id(
    session_id: str,
    sequence: int,
    request_hash: str,
) -> str:
    return hashlib.sha256(
        f"{session_id}:{int(sequence)}:{request_hash}".encode("ascii"),
    ).hexdigest()[:32]


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _hex_128(value: object, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not is_nonzero_lower_hex(text, 32):
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    return text


def _sha256_hex(value: object, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not is_nonzero_lower_hex(text, 64):
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    return text


def _counter(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    counter = value
    if not 0 <= counter <= (1 << 63) - 1:
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    return counter


def _positive_int(value: object, field_name: str) -> int:
    number = _counter(value, field_name)
    if number <= 0:
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    return number


def _token(value: object) -> str:
    token = str(value or "").strip()
    if not 256 <= len(token) <= 8192:
        raise DualMachineServiceError("usage_lease_invalid", 422)
    return token


def _challenge_token(value: object) -> str:
    token = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise DualMachineServiceError(
            "usage_start_challenge_invalid",
            422,
        )
    return token


def _now(value: int | None) -> int:
    now = int(time.time()) if value is None else int(value)
    if now <= 0:
        raise ValueError("now_epoch must be positive")
    return now
