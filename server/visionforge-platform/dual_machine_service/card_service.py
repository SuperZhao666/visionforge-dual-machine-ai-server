"""Card issuance and two-device activation without user accounts."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from .audit import write_audit_event
from .contracts import (
    ACTIVATION_MODE_ACTIVATE,
    ACTIVATION_MODE_BIND_DEVICE,
    ACTIVATION_MODE_REACTIVATE,
    PROTOCOL_VERSION,
    activation_confirmation_payload,
)
from .database import connect_database
from .errors import DualMachineServiceError
from .identity import (
    P256Identity,
    canonical_json,
    parse_p256_identity,
    verify_p256_signature,
)
from .license_codes import (
    card_code_digest,
    card_code_suffix,
    derive_card_code,
    is_valid_card_code,
)
from .license_repository import LicenseRepository
from .pair_security_bootstrap import (
    PairSecurityBootstrapError,
    _PairSecurityBootstrapResult,
    _PairSecurityBootstrapService,
    _VerifiedActivationBindingProof,
    _verified_activation_binding_proof,
)
from .settings import DualMachineSettings
from .versions import client_version_at_least, normalize_client_version
from .validation import is_nonzero_lower_hex


ACTIVATION_CHALLENGE_TTL_SECONDS = 120
MAX_BATCH_QUANTITY = 500
MAX_CODE_EXPIRY_SECONDS = 10 * 365 * 24 * 60 * 60
_CHALLENGE_TOKEN_DOMAIN = b"vf-dual-machine-activation-token-v1\x00"
_CHALLENGE_DIGEST_DOMAIN = b"vf-dual-machine-activation-digest-v1\x00"
TERM_AUTHORIZATION_KINDS = frozenset({
    "day",
    "week",
    "month",
    "permanent",
})
ANDROID_DEVICE_PROFILE_TEXT_FIELDS = (
    "manufacturer",
    "brand",
    "model",
    "device",
    "product",
    "hardware",
    "os_release",
)


@dataclass(frozen=True, slots=True)
class CardIssuanceResult:
    batch_id: int
    product_key: str
    product_name: str
    duration_seconds: int
    authorization_kind: str
    codes: tuple[str, ...]


class CardIssuanceService:
    def __init__(self, settings: DualMachineSettings) -> None:
        self.settings = settings

    def issue_batch(
        self,
        *,
        request_id: str,
        product_key: str,
        quantity: int,
        channel: str,
        note: str = "",
        expires_at_epoch: int | None = None,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> CardIssuanceResult:
        self.settings.validate_card_issuance()
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        normalized = _normalize_issuance(
            request_id=request_id,
            product_key=product_key,
            quantity=quantity,
            channel=channel,
            note=note,
            expires_at_epoch=expires_at_epoch,
            now_epoch=now,
        )
        connection = connect_database(self.settings)
        repository = LicenseRepository(connection)
        try:
            connection.execute("BEGIN IMMEDIATE")
            product = repository.product(normalized["product_key"])
            if (
                product is None
                or not bool(product["enabled"])
                or str(product["authorization_kind"])
                not in TERM_AUTHORIZATION_KINDS
            ):
                raise DualMachineServiceError(
                    "dual_machine_product_unavailable",
                    404,
                )
            existing = repository.batch_by_request(
                normalized["request_id"],
            )
            if existing is not None:
                _require_same_batch(existing, normalized)
                records = repository.code_derivation_records(
                    int(existing["id"]),
                )
                if (
                    existing.get("deleted_at") is not None
                    or any(record.get("deleted_at") is not None for record in records)
                ):
                    raise DualMachineServiceError(
                        "dual_machine_issuance_request_archived",
                        409,
                    )
                keyring = self.settings.license_code_keyring()
                codes = tuple(
                    _derive_stored_card_code(record, keyring)
                    for record in records
                )
                connection.commit()
                return _issuance_response(existing, product, codes)

            batch_id = repository.create_batch(**normalized)
            batch_derivation_salt = secrets.token_hex(16)
            codes: list[str] = []
            for ordinal in range(1, normalized["quantity"] + 1):
                derivation_ref = (
                    f"batch:{batch_id}:salt:{batch_derivation_salt}:"
                    f"item:{ordinal}:"
                    f"product:{normalized['product_key']}"
                )
                code = derive_card_code(
                    self.settings.license_code_secret,
                    derivation_ref,
                )
                repository.create_code(
                    batch_id=batch_id,
                    ordinal=ordinal,
                    code_digest=card_code_digest(
                        self.settings.license_code_secret,
                        code,
                        key_version=self.settings.license_code_key_version,
                    ),
                    code_suffix=card_code_suffix(code),
                    key_version=self.settings.license_code_key_version,
                    derivation_ref=derivation_ref,
                    product_key=normalized["product_key"],
                    duration_seconds=int(product["duration_seconds"]),
                    authorization_kind=str(
                        product["authorization_kind"],
                    ),
                    expires_at_epoch=normalized["expires_at_epoch"],
                )
                codes.append(code)
            write_audit_event(
                connection,
                event_type="license_batch_issued",
                subject_type="license_batch",
                subject_id=str(batch_id),
                trace_id=trace_id,
                detail={
                    "product_key": normalized["product_key"],
                    "quantity": normalized["quantity"],
                    "key_version": int(
                        self.settings.license_code_key_version,
                    ),
                },
            )
            connection.commit()
            batch = repository.batch_by_request(normalized["request_id"])
            if batch is None:
                raise RuntimeError("dual-machine batch insert missing")
            return _issuance_response(batch, product, tuple(codes))
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


class CardActivationService:
    def __init__(self, settings: DualMachineSettings) -> None:
        self.settings = settings
        self._pair_security_bootstrap = _PairSecurityBootstrapService()

    def create_challenge(
        self,
        command: dict[str, Any],
        *,
        client_ip: str,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> dict[str, Any]:
        self.settings.validate_activation()
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        normalized, host_identity, android_identity = (
            _normalize_activation_request(command)
        )
        _require_supported_client_versions(normalized, self.settings)
        code = normalized.pop("card_code")
        connection = connect_database(self.settings)
        repository = LicenseRepository(connection)
        try:
            connection.execute("BEGIN IMMEDIATE")
            repository.expire_challenges(now)
            card, digest = _find_card_by_code(
                repository,
                self.settings.license_code_keyring(),
                code,
            )
            activation_mode, target_entitlement_id = (
                _activation_target(
                    repository,
                    card,
                    host_key_sha256=host_identity.fingerprint_sha256,
                    android_key_sha256=(
                        android_identity.fingerprint_sha256
                    ),
                    android_device_profile=(
                        normalized["android_device_profile"]
                    ),
                    now_epoch=now,
                )
            )
            if activation_mode == ACTIVATION_MODE_ACTIVATE:
                activation_mode, target_entitlement_id = (
                    _new_card_activation_target(
                        repository,
                        normalized["pair_id"],
                        host_key_sha256=host_identity.fingerprint_sha256,
                        android_key_sha256=(
                            android_identity.fingerprint_sha256
                        ),
                        android_device_profile=(
                            normalized["android_device_profile"]
                        ),
                    )
                )
            request_payload_hash = hashlib.sha256(canonical_json({
                **normalized,
                "card_code_digest": digest,
                "host_key_sha256": host_identity.fingerprint_sha256,
                "android_key_sha256": android_identity.fingerprint_sha256,
                "activation_mode": activation_mode,
                "target_entitlement_id": target_entitlement_id,
            })).hexdigest()

            existing = repository.challenge_by_request(
                normalized["request_id"],
            )
            if existing is not None:
                if (
                    not hmac.compare_digest(
                        str(existing["request_payload_hash"]),
                        request_payload_hash,
                    )
                    or int(existing["license_code_id"]) != int(card["id"])
                ):
                    raise DualMachineServiceError(
                        "activation_request_conflict",
                        409,
                    )
                if (
                    str(existing["status"]) != "issued"
                    or int(existing["expires_at_epoch"]) <= now
                ):
                    raise DualMachineServiceError(
                        "activation_request_not_reusable",
                        409,
                    )
                response = self._challenge_response(existing)
                connection.commit()
                return response

            challenge = {
                **normalized,
                "challenge_id": secrets.token_hex(16),
                "request_payload_hash": request_payload_hash,
                "license_code_id": int(card["id"]),
                "host_identity_public_key_b64": host_identity.public_key_b64,
                "host_key_sha256": host_identity.fingerprint_sha256,
                "android_identity_public_key_b64": (
                    android_identity.public_key_b64
                ),
                "android_key_sha256": android_identity.fingerprint_sha256,
                "expires_at_epoch": now + ACTIVATION_CHALLENGE_TTL_SECONDS,
                "issued_ip": _bounded_ip(client_ip),
                "activation_mode": activation_mode,
                "target_entitlement_id": target_entitlement_id,
                "android_device_profile_json": json.dumps(
                    normalized["android_device_profile"],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
            token = self._challenge_token(challenge)
            challenge["token_digest"] = self._token_digest(token)
            try:
                repository.create_challenge(challenge)
            except sqlite3.IntegrityError as exc:
                raise DualMachineServiceError(
                    "activation_already_in_progress",
                    409,
                ) from exc
            write_audit_event(
                connection,
                event_type="license_activation_challenge_issued",
                subject_type="license_code",
                subject_id=str(card["id"]),
                trace_id=trace_id,
                ip_address=_bounded_ip(client_ip),
                detail={
                    "challenge_id": challenge["challenge_id"],
                    "pair_id": challenge["pair_id"],
                    "activation_mode": activation_mode,
                    "android_device_profile_sha256": (
                        _profile_sha256(
                            normalized["android_device_profile"],
                        )
                    ),
                },
            )
            connection.commit()
            return self._challenge_response(challenge)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def confirm_activation(
        self,
        command: dict[str, Any],
        *,
        client_ip: str,
        now_epoch: int | None = None,
        trace_id: str = "",
    ) -> dict[str, Any]:
        self.settings.validate_activation()
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        normalized = _normalize_activation_confirmation(command)
        connection = connect_database(self.settings)
        repository = LicenseRepository(connection)
        try:
            challenge = repository.challenge_by_id(
                normalized["challenge_id"],
            )
            self._verify_confirmation(challenge, normalized, now_epoch=now)

            connection.execute("BEGIN IMMEDIATE")
            challenge = repository.challenge_by_id(
                normalized["challenge_id"],
            )
            verified_pair_proof = self._verify_confirmation(
                challenge,
                normalized,
                now_epoch=now,
            )
            if str(challenge["status"]) == "consumed":
                activation_mode = str(challenge["activation_mode"])
                if activation_mode == ACTIVATION_MODE_BIND_DEVICE:
                    entitlement = repository.entitlement_by_id(
                        str(challenge["target_entitlement_id"]),
                    )
                    if entitlement is None:
                        raise RuntimeError(
                            "consumed binding challenge has no entitlement",
                        )
                    activation = repository.activation_by_code_id(
                        int(challenge["license_code_id"]),
                    )
                    if activation is None:
                        raise RuntimeError(
                            "consumed binding challenge has no activation",
                        )
                    response = _response_with_pair_security(
                        connection,
                        _binding_response(entitlement, activation),
                    )
                    connection.commit()
                    return response
                activation = repository.activation_by_challenge(
                    normalized["challenge_id"],
                )
                if activation is None:
                    raise RuntimeError(
                        "consumed activation challenge has no activation",
                    )
                response = _response_with_pair_security(
                    connection,
                    _activation_response(activation, activation_mode),
                )
                connection.commit()
                return response

            activation_mode = str(challenge["activation_mode"])
            if activation_mode == ACTIVATION_MODE_BIND_DEVICE:
                response = self._confirm_device_binding(
                    connection,
                    repository,
                    challenge,
                    verified_pair_proof=verified_pair_proof,
                    client_ip=client_ip,
                    now_epoch=now,
                    trace_id=trace_id,
                )
                connection.commit()
                return response

            card = repository.code_for_activation_by_id(
                int(challenge["license_code_id"]),
            )
            if not _card_is_available(card, now_epoch=now):
                raise _license_unavailable()
            target_entitlement_id = str(
                challenge.get("target_entitlement_id") or "",
            )
            existing_entitlement = repository.entitlement_by_pair_id(
                str(challenge["pair_id"]),
            )
            reactivated = activation_mode == ACTIVATION_MODE_REACTIVATE
            try:
                if reactivated:
                    if (
                        existing_entitlement is None
                        or str(existing_entitlement["entitlement_id"])
                        != target_entitlement_id
                    ):
                        raise DualMachineServiceError(
                            "activation_entitlement_already_exists",
                            409,
                        )
                    _require_same_or_unbound_android_device(
                        repository,
                        existing_entitlement,
                        host_key_sha256=str(
                            challenge["host_key_sha256"],
                        ),
                        android_key_sha256=str(
                            challenge["android_key_sha256"],
                        ),
                        android_device_profile_json=str(
                            challenge["android_device_profile_json"],
                        ),
                    )
                    if not repository.reactivate_exhausted_entitlement(
                        target_entitlement_id,
                        _binding_from_challenge(
                            challenge,
                            target_entitlement_id,
                        ),
                        credited_seconds=_credited_seconds(card),
                        authorization_kind=str(
                            card["authorization_kind"],
                        ),
                        product_key=str(card["product_key"]),
                        source_license_code_id=int(card["id"]),
                    ):
                        raise DualMachineServiceError(
                            "activation_entitlement_already_exists",
                            409,
                        )
                    entitlement_id = target_entitlement_id
                else:
                    if existing_entitlement is not None:
                        raise DualMachineServiceError(
                            "activation_entitlement_already_exists",
                            409,
                        )
                    entitlement_id = self._create_entitlement(
                        repository,
                        challenge,
                        card,
                    )
            except sqlite3.IntegrityError as exc:
                raise DualMachineServiceError(
                    "activation_identity_binding_conflict",
                    409,
                ) from exc
            pair_security = self._commit_pair_security_binding(
                connection,
                proof=verified_pair_proof,
                entitlement_id=entitlement_id,
                now_epoch=now,
                client_ip=client_ip,
                trace_id=trace_id,
            )
            if not repository.consume_code(
                code_id=int(card["id"]),
                now_epoch=now,
            ):
                raise _license_unavailable()
            if not repository.consume_challenge(
                challenge_id=str(challenge["challenge_id"]),
                consumed_ip=_bounded_ip(client_ip),
                now_epoch=now,
            ):
                raise DualMachineServiceError(
                    "activation_challenge_invalid",
                    409,
                )
            repository.create_activation(
                activation_id=secrets.token_hex(16),
                code_id=int(card["id"]),
                entitlement_id=entitlement_id,
                challenge_id=str(challenge["challenge_id"]),
                credited_seconds=_credited_seconds(card),
                activated_ip=_bounded_ip(client_ip),
            )
            activation = repository.activation_by_challenge(
                str(challenge["challenge_id"]),
            )
            if activation is None:
                raise RuntimeError("activation insert missing")
            write_audit_event(
                connection,
                event_type=(
                    "license_reactivated_after_exhaustion"
                    if reactivated else "license_activated"
                ),
                subject_type="entitlement",
                subject_id=entitlement_id,
                trace_id=trace_id,
                ip_address=_bounded_ip(client_ip),
                detail={
                    "activation_id": activation["activation_id"],
                    "authorization_kind": card["authorization_kind"],
                    "credited_seconds": _credited_seconds(card),
                    "pair_id": challenge["pair_id"],
                    "reactivated_after_exhaustion": reactivated,
                    "android_device_profile_sha256": (
                        _profile_json_sha256(
                            str(
                                challenge[
                                    "android_device_profile_json"
                                ],
                            ),
                        )
                    ),
                    "pair_binding_revision": (
                        pair_security.state.binding_revision
                    ),
                    "pair_assurance_state": (
                        pair_security.state.assurance_state
                    ),
                },
            )
            response = _response_with_pair_security(
                connection,
                _activation_response(activation, activation_mode),
            )
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _challenge_response(
        self,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        token = self._challenge_token(challenge)
        if not hmac.compare_digest(
            self._token_digest(token),
            str(challenge["token_digest"]),
        ):
            raise RuntimeError("activation challenge digest mismatch")
        proof = activation_confirmation_payload(
            challenge,
            challenge_token=token,
        )
        return {
            "ok": True,
            "activation_mode": str(
                challenge.get("activation_mode")
                or ACTIVATION_MODE_ACTIVATE,
            ),
            "target_entitlement_id": str(
                challenge.get("target_entitlement_id") or "",
            ),
            "android_device_profile_sha256": _profile_json_sha256(
                str(
                    challenge.get("android_device_profile_json") or "{}",
                ),
            ),
            "challenge_id": str(challenge["challenge_id"]),
            "challenge_token": token,
            "challenge_expires_at_epoch": int(
                challenge["expires_at_epoch"],
            ),
            "proof_payload_b64": base64.b64encode(proof).decode("ascii"),
        }

    def _challenge_token(self, challenge: dict[str, Any]) -> str:
        seed = canonical_json({
            "challenge_id": challenge["challenge_id"],
            "request_id": challenge["request_id"],
            "request_payload_hash": challenge["request_payload_hash"],
        })
        signature = hmac.new(
            _domain_key(
                self.settings.token_secret,
                _CHALLENGE_TOKEN_DOMAIN,
            ),
            seed,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    def _token_digest(self, token: str) -> str:
        digest = hmac.new(
            _domain_key(
                self.settings.token_secret,
                _CHALLENGE_DIGEST_DOMAIN,
            ),
            str(token).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def _verify_confirmation(
        self,
        challenge: dict[str, Any] | None,
        command: dict[str, str],
        *,
        now_epoch: int,
    ) -> _VerifiedActivationBindingProof:
        if (
            challenge is None
            or str(challenge["status"]) not in {"issued", "consumed"}
            or (
                str(challenge["status"]) == "issued"
                and int(challenge["expires_at_epoch"]) <= int(now_epoch)
            )
            or not hmac.compare_digest(
                str(challenge["token_digest"]),
                self._token_digest(command["challenge_token"]),
            )
        ):
            raise DualMachineServiceError(
                "activation_challenge_invalid",
                409,
            )
        payload = activation_confirmation_payload(
            challenge,
            challenge_token=command["challenge_token"],
        )
        try:
            verify_p256_signature(
                parse_p256_identity(
                    str(challenge["host_identity_public_key_b64"]),
                ),
                command["host_signature_b64"],
                payload,
            )
            verify_p256_signature(
                parse_p256_identity(
                    str(challenge["android_identity_public_key_b64"]),
                ),
                command["android_signature_b64"],
                payload,
            )
        except ValueError as exc:
            raise DualMachineServiceError(
                "activation_device_proof_invalid",
                403,
            ) from exc
        return _verified_activation_binding_proof(challenge)

    def _commit_pair_security_binding(
        self,
        connection: sqlite3.Connection,
        *,
        proof: _VerifiedActivationBindingProof,
        entitlement_id: str,
        now_epoch: int,
        client_ip: str,
        trace_id: str,
    ) -> _PairSecurityBootstrapResult:
        try:
            result = self._pair_security_bootstrap.commit_verified_binding(
                connection,
                proof=proof,
                entitlement_id=entitlement_id,
                now_epoch=now_epoch,
            )
        except PairSecurityBootstrapError as exc:
            raise DualMachineServiceError(exc.code, 409) from exc
        if result.changed:
            write_audit_event(
                connection,
                event_type="pair_security_binding_activated",
                subject_type="pair_security_state",
                subject_id=result.state.pair_id,
                trace_id=trace_id,
                ip_address=_bounded_ip(client_ip),
                detail={
                    "activation_challenge_id": proof.challenge_id,
                    "activation_mode": proof.activation_mode,
                    "entitlement_id": result.state.entitlement_id,
                    "binding_id": result.state.binding_id,
                    "binding_revision": result.state.binding_revision,
                    "revocation_version": result.state.revocation_version,
                    "assurance_state": result.state.assurance_state,
                    "predecessor_pair_id": result.predecessor_pair_id or "",
                },
            )
        return result

    @staticmethod
    def _create_entitlement(
        repository: LicenseRepository,
        challenge: dict[str, Any],
        card: dict[str, Any],
    ) -> str:
        authorization_kind = str(card["authorization_kind"])
        if authorization_kind not in TERM_AUTHORIZATION_KINDS:
            raise DualMachineServiceError(
                "dual_machine_product_unavailable",
                409,
            )
        entitlement_id = secrets.token_hex(16)
        credited_seconds = _credited_seconds(card)
        # The legacy entitlement table has a uniqueness constraint on the two
        # hash columns. New term authorizations keep actual device hashes in
        # the binding history and use per-entitlement compatibility hashes so
        # hardware identity never becomes a cross-entitlement license lock.
        repository.create_entitlement(
            {
                **challenge,
                "entitlement_id": entitlement_id,
                "host_key_sha256": _compatibility_binding_hash(
                    entitlement_id,
                    "host",
                ),
                "android_key_sha256": _compatibility_binding_hash(
                    entitlement_id,
                    "android",
                ),
                "authorization_kind": authorization_kind,
                "product_key": str(card["product_key"]),
                "source_license_code_id": int(card["id"]),
            },
            credited_seconds=credited_seconds,
        )
        repository.bind_device(
            _binding_from_challenge(challenge, entitlement_id),
        )
        return entitlement_id

    def _confirm_device_binding(
        self,
        connection: sqlite3.Connection,
        repository: LicenseRepository,
        challenge: dict[str, Any],
        *,
        verified_pair_proof: _VerifiedActivationBindingProof,
        client_ip: str,
        now_epoch: int,
        trace_id: str,
    ) -> dict[str, Any]:
        entitlement_id = str(challenge["target_entitlement_id"])
        entitlement = repository.entitlement_by_id(entitlement_id)
        activation = repository.activation_by_code_id(
            int(challenge["license_code_id"]),
        )
        if (
            entitlement is None
            or activation is None
            or str(activation["entitlement_id"]) != entitlement_id
            or str(entitlement["status"]) == "revoked"
        ):
            raise _license_unavailable()
        _require_same_or_unbound_android_device(
            repository,
            entitlement,
            host_key_sha256=str(challenge["host_key_sha256"]),
            android_key_sha256=str(challenge["android_key_sha256"]),
            android_device_profile_json=str(
                challenge.get("android_device_profile_json") or "{}",
            ),
        )
        binding = _binding_from_challenge(challenge, entitlement_id)
        try:
            changed = repository.rebind_entitlement(
                entitlement_id,
                binding,
            )
        except sqlite3.IntegrityError as exc:
            raise DualMachineServiceError(
                "activation_identity_binding_conflict",
                409,
            ) from exc
        pair_security = self._commit_pair_security_binding(
            connection,
            proof=verified_pair_proof,
            entitlement_id=entitlement_id,
            now_epoch=now_epoch,
            client_ip=client_ip,
            trace_id=trace_id,
        )
        if not repository.consume_challenge(
            challenge_id=str(challenge["challenge_id"]),
            consumed_ip=_bounded_ip(client_ip),
            now_epoch=now_epoch,
        ):
            raise DualMachineServiceError(
                "activation_challenge_invalid",
                409,
            )
        connection.execute(
            "UPDATE dm_usage_start_challenges SET status = 'expired' "
            "WHERE entitlement_id = ? AND status = 'issued'",
            (entitlement_id,),
        )
        connection.execute(
            "UPDATE dm_usage_sessions SET status = 'ended', "
            "ended_at_epoch = ?, ended_reason = 'device_rebound' "
            "WHERE entitlement_id = ? AND status = 'active'",
            (int(now_epoch), entitlement_id),
        )
        entitlement = repository.entitlement_by_id(entitlement_id)
        if entitlement is None:
            raise RuntimeError("rebound entitlement missing")
        write_audit_event(
            connection,
            event_type="entitlement_device_bound",
            subject_type="entitlement",
            subject_id=entitlement_id,
            trace_id=trace_id,
            ip_address=_bounded_ip(client_ip),
            detail={
                "changed": changed,
                "pair_id": challenge["pair_id"],
                "pair_binding_revision": (
                    pair_security.state.binding_revision
                ),
                "pair_assurance_state": (
                    pair_security.state.assurance_state
                ),
                "host_key_sha256": challenge["host_key_sha256"],
                "android_key_sha256": challenge["android_key_sha256"],
                "android_device_profile_sha256": (
                    _profile_json_sha256(
                        str(challenge["android_device_profile_json"]),
                    )
                ),
            },
        )
        return _response_with_pair_security(
            connection,
            _binding_response(entitlement, activation),
        )


def _derive_stored_card_code(
    record: dict[str, Any],
    keyring: dict[int, bytes],
) -> str:
    key_version = int(record["key_version"])
    secret = keyring.get(key_version)
    if secret is None:
        raise DualMachineServiceError(
            "license_code_key_version_unavailable",
            503,
        )
    return derive_card_code(secret, str(record["derivation_ref"]))


def _find_card_by_code(
    repository: LicenseRepository,
    keyring: dict[int, bytes],
    code: str,
) -> tuple[dict[str, Any] | None, str]:
    fallback_digest = ""
    for key_version, secret in keyring.items():
        digest = card_code_digest(
            secret,
            code,
            key_version=key_version,
        )
        if not fallback_digest:
            fallback_digest = digest
        card = repository.code_for_activation(digest)
        if card is not None:
            return card, digest
    return None, fallback_digest


def _normalize_issuance(
    *,
    request_id: str,
    product_key: str,
    quantity: int,
    channel: str,
    note: str,
    expires_at_epoch: int | None,
    now_epoch: int,
) -> dict[str, Any]:
    normalized_request = _hex_128(request_id, "request_id")
    normalized_product = str(product_key or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{1,32}", normalized_product):
        raise ValueError("product_key_invalid")
    normalized_quantity = int(quantity)
    if not 1 <= normalized_quantity <= MAX_BATCH_QUANTITY:
        raise ValueError("quantity_invalid")
    normalized_channel = _bounded_text(channel, "channel", 32)
    normalized_note = str(note or "").strip()
    if len(normalized_note) > 500:
        raise ValueError("note_invalid")
    normalized_expiry = (
        int(expires_at_epoch)
        if expires_at_epoch is not None
        else None
    )
    if (
        normalized_expiry is not None
        and not now_epoch < normalized_expiry
        <= now_epoch + MAX_CODE_EXPIRY_SECONDS
    ):
        raise ValueError("expires_at_epoch_invalid")
    return {
        "request_id": normalized_request,
        "product_key": normalized_product,
        "quantity": normalized_quantity,
        "channel": normalized_channel,
        "note": normalized_note,
        "expires_at_epoch": normalized_expiry,
    }


def _normalize_activation_request(
    command: dict[str, Any],
) -> tuple[dict[str, Any], P256Identity, P256Identity]:
    try:
        protocol_version = command["protocol_version"]
        if type(protocol_version) is not int:
            raise TypeError("protocol_version must be an integer")
        card_code = str(command["card_code"])
        host = dict(command["host"])
        android = dict(command["android"])
    except Exception as exc:
        raise DualMachineServiceError("activation_request_invalid", 422) from exc
    if protocol_version != PROTOCOL_VERSION or not is_valid_card_code(card_code):
        raise _license_unavailable()
    try:
        host_identity = parse_p256_identity(
            str(host["identity_public_key_b64"]),
        )
        android_identity = parse_p256_identity(
            str(android["identity_public_key_b64"]),
        )
    except (KeyError, ValueError) as exc:
        raise DualMachineServiceError(
            "activation_identity_invalid",
            422,
        ) from exc
    if hmac.compare_digest(
        host_identity.fingerprint_sha256,
        android_identity.fingerprint_sha256,
    ):
        raise DualMachineServiceError(
            "activation_identities_must_differ",
            422,
        )
    return (
        {
            "request_id": _hex_128(command.get("request_id"), "request_id"),
            "pair_id": _hex_128(command.get("pair_id"), "pair_id"),
            "protocol_version": protocol_version,
            "card_code": card_code,
            "host_device_code": _device_code(host.get("device_code")),
            "host_client_version": _client_version(
                host.get("client_version"),
            ),
            "android_device_code": _device_code(
                android.get("device_code"),
            ),
            "android_client_version": _client_version(
                android.get("client_version"),
            ),
            "android_device_profile": _normalize_android_device_profile(
                command.get("android_device_profile"),
            ),
        },
        host_identity,
        android_identity,
    )


def _normalize_activation_confirmation(
    command: dict[str, Any],
) -> dict[str, str]:
    try:
        challenge_token = str(command["challenge_token"]).strip()
        host_signature = str(command["host_signature_b64"]).strip()
        android_signature = str(command["android_signature_b64"]).strip()
    except Exception as exc:
        raise DualMachineServiceError(
            "activation_confirmation_invalid",
            422,
        ) from exc
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge_token)
        or not 8 <= len(host_signature) <= 256
        or not 8 <= len(android_signature) <= 256
    ):
        raise DualMachineServiceError(
            "activation_confirmation_invalid",
            422,
        )
    return {
        "challenge_id": _hex_128(
            command.get("challenge_id"),
            "challenge_id",
        ),
        "challenge_token": challenge_token,
        "host_signature_b64": host_signature,
        "android_signature_b64": android_signature,
    }


def _require_same_batch(
    existing: dict[str, Any],
    requested: dict[str, Any],
) -> None:
    actual = {
        "product_key": str(existing["product_key"]),
        "quantity": int(existing["quantity"]),
        "channel": str(existing["channel"]),
        "note": str(existing["note"]),
        "expires_at_epoch": (
            int(existing["expires_at_epoch"])
            if existing["expires_at_epoch"] is not None
            else None
        ),
    }
    expected = {
        key: requested[key]
        for key in actual
    }
    if actual != expected:
        raise DualMachineServiceError(
            "card_issuance_request_conflict",
            409,
        )


def _issuance_response(
    batch: dict[str, Any],
    product: dict[str, Any],
    codes: tuple[str, ...],
) -> CardIssuanceResult:
    authorization_kind = str(product["authorization_kind"])
    return CardIssuanceResult(
        batch_id=int(batch["id"]),
        product_key=str(product["product_key"]),
        product_name=str(product["display_name"]),
        duration_seconds=(
            0
            if authorization_kind == "permanent"
            else int(product["duration_seconds"])
        ),
        authorization_kind=authorization_kind,
        codes=codes,
    )


def _card_is_available(
    card: dict[str, Any] | None,
    *,
    now_epoch: int,
) -> bool:
    return bool(
        card is not None
        and str(card["status"]) == "issued"
        and str(card["batch_status"]) == "active"
        and bool(card["product_enabled"])
        and (
            card["expires_at_epoch"] is None
            or int(card["expires_at_epoch"]) > int(now_epoch)
        )
    )


def _activation_response(
    activation: dict[str, Any],
    activation_mode: str,
) -> dict[str, Any]:
    if activation_mode not in {
        ACTIVATION_MODE_ACTIVATE,
        ACTIVATION_MODE_REACTIVATE,
    }:
        raise ValueError("activation_response_mode_invalid")
    authorization_kind = str(
        activation.get("authorization_kind") or "legacy_balance",
    )
    is_permanent = authorization_kind == "permanent"
    return {
        "ok": True,
        "activation_mode": activation_mode,
        "binding_updated": False,
        "activation_id": str(activation["activation_id"]),
        "entitlement_id": str(activation["entitlement_id"]),
        "pair_id": str(activation["pair_id"]),
        "status": str(activation["status"]),
        "revocation_version": int(activation["revocation_version"]),
        "authorization_kind": authorization_kind,
        "product_key": str(activation.get("product_key") or ""),
        "is_permanent": is_permanent,
        "credited_seconds": (
            0 if is_permanent else int(activation["credited_seconds"])
        ),
        "remaining_seconds": int(activation["remaining_seconds"]),
        "total_credited_seconds": int(
            activation["total_credited_seconds"],
        ),
        "total_consumed_seconds": int(
            activation["total_consumed_seconds"],
        ),
        "billing_started": False,
    }


def _response_with_pair_security(
    connection: sqlite3.Connection,
    response: dict[str, Any],
) -> dict[str, Any]:
    row = connection.execute(
        "SELECT s.binding_id, s.binding_revision, s.assurance_state "
        "FROM dm_pair_security_state s "
        "JOIN dm_entitlements e ON e.entitlement_id = s.entitlement_id "
        "JOIN dm_entitlement_device_bindings b "
        "ON b.binding_id = s.binding_id "
        "AND b.entitlement_id = s.entitlement_id "
        "WHERE s.pair_id = ? AND s.entitlement_id = ? "
        "AND s.assurance_state = 'active' "
        "AND e.status = 'active' "
        "AND e.revocation_version = s.revocation_version "
        "AND b.is_current = 1 AND b.pair_id = s.pair_id "
        "AND b.host_key_sha256 = s.host_key_sha256 "
        "AND b.android_key_sha256 = s.android_key_sha256",
        (str(response["pair_id"]), str(response["entitlement_id"])),
    ).fetchone()
    if row is None:
        return dict(response)
    return {
        **response,
        "binding_id": str(row["binding_id"]),
        "binding_revision": int(row["binding_revision"]),
        "pair_assurance_state": str(row["assurance_state"]),
    }


def _binding_response(
    entitlement: dict[str, Any],
    activation: dict[str, Any],
) -> dict[str, Any]:
    authorization_kind = str(
        entitlement.get("authorization_kind") or "legacy_balance",
    )
    is_permanent = authorization_kind == "permanent"
    return {
        "ok": True,
        "activation_mode": ACTIVATION_MODE_BIND_DEVICE,
        "activation_id": str(activation["activation_id"]),
        "entitlement_id": str(entitlement["entitlement_id"]),
        "pair_id": str(entitlement["pair_id"]),
        "status": str(entitlement["status"]),
        "revocation_version": int(entitlement["revocation_version"]),
        "authorization_kind": authorization_kind,
        "product_key": str(entitlement.get("product_key") or ""),
        "is_permanent": is_permanent,
        "credited_seconds": 0,
        "remaining_seconds": int(entitlement["remaining_seconds"]),
        "total_credited_seconds": int(
            entitlement["total_credited_seconds"],
        ),
        "total_consumed_seconds": int(
            entitlement["total_consumed_seconds"],
        ),
        "billing_started": False,
        "binding_updated": True,
    }


def _activation_target(
    repository: LicenseRepository,
    card: dict[str, Any] | None,
    *,
    host_key_sha256: str,
    android_key_sha256: str,
    android_device_profile: dict[str, Any],
    now_epoch: int,
) -> tuple[str, str]:
    if _card_is_available(card, now_epoch=now_epoch):
        return ACTIVATION_MODE_ACTIVATE, ""
    if (
        card is not None
        and str(card["status"]) == "issued"
        and card["expires_at_epoch"] is not None
        and int(card["expires_at_epoch"]) <= int(now_epoch)
    ):
        raise _license_unavailable()
    if card is not None and str(card["status"]) == "activated":
        activation = repository.activation_by_code_id(int(card["id"]))
        if (
            activation is not None
            and str(activation["status"]) != "revoked"
        ):
            entitlement_id = str(activation["entitlement_id"])
            entitlement = repository.entitlement_by_id(entitlement_id)
            if entitlement is None:
                raise _license_unavailable()
            _require_same_or_unbound_android_device(
                repository,
                entitlement,
                host_key_sha256=host_key_sha256,
                android_key_sha256=android_key_sha256,
                android_device_profile_json=json.dumps(
                    android_device_profile,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            return ACTIVATION_MODE_BIND_DEVICE, entitlement_id
    raise _license_unavailable()


def _new_card_target(
    repository: LicenseRepository,
    pair_id: str,
) -> dict[str, Any] | None:
    """Return the exhausted entitlement that a new card may replace."""
    existing = repository.entitlement_by_pair_id(pair_id)
    if existing is None:
        return None
    if (
        str(existing["status"]) == "exhausted"
        and int(existing["remaining_seconds"]) == 0
        and int(existing["total_consumed_seconds"])
        == int(existing["total_credited_seconds"])
    ):
        return existing
    raise DualMachineServiceError(
        "activation_entitlement_already_exists",
        409,
    )


def _new_card_activation_target(
    repository: LicenseRepository,
    pair_id: str,
    *,
    host_key_sha256: str,
    android_key_sha256: str,
    android_device_profile: dict[str, Any],
) -> tuple[str, str]:
    existing = _new_card_target(repository, pair_id)
    if existing is None:
        return ACTIVATION_MODE_ACTIVATE, ""
    _require_same_or_unbound_android_device(
        repository,
        existing,
        host_key_sha256=host_key_sha256,
        android_key_sha256=android_key_sha256,
        android_device_profile_json=json.dumps(
            android_device_profile,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return ACTIVATION_MODE_REACTIVATE, str(existing["entitlement_id"])


def _require_same_or_unbound_android_device(
    repository: LicenseRepository,
    entitlement: dict[str, Any],
    *,
    host_key_sha256: str,
    android_key_sha256: str,
    android_device_profile_json: str,
) -> None:
    entitlement_id = str(entitlement["entitlement_id"])
    current = repository.current_device_binding(entitlement_id)
    if current is None:
        explicitly_unbound = (
            not str(entitlement.get("host_identity_public_key_b64") or "")
            and not str(
                entitlement.get("android_identity_public_key_b64") or "",
            )
        )
        if explicitly_unbound:
            return
        raise DualMachineServiceError(
            "license_device_binding_inconsistent",
            409,
        )

    current_host_key = str(current["host_key_sha256"])
    if not hmac.compare_digest(current_host_key, str(host_key_sha256)):
        raise DualMachineServiceError(
            "license_bound_to_another_device",
            409,
        )
    current_key = str(current["android_key_sha256"])
    current_fingerprint = _device_profile_fingerprint(
        str(current.get("android_device_profile_json") or "{}"),
    )
    requested_fingerprint = _device_profile_fingerprint(
        android_device_profile_json,
    )
    fingerprint_changed = (
        current_fingerprint
        and requested_fingerprint
        and not hmac.compare_digest(
            current_fingerprint, requested_fingerprint,
        )
    )
    if fingerprint_changed:
        raise DualMachineServiceError(
            "license_bound_to_another_device",
            409,
        )
    if hmac.compare_digest(current_key, str(android_key_sha256)):
        return
    # AndroidKeyStore deletes app-owned keys on a clean uninstall.  A card
    # proof may rotate that key only when the unchanged Host identity and both
    # non-empty, normalized physical-device fingerprints agree.  A missing or
    # different fingerprint remains fail-closed.
    if (
        not current_fingerprint
        or not requested_fingerprint
        or not hmac.compare_digest(
            current_fingerprint, requested_fingerprint,
        )
    ):
        raise DualMachineServiceError(
            "license_bound_to_another_device",
            409,
        )


def _device_profile_fingerprint(profile_json: str) -> str:
    try:
        profile = json.loads(str(profile_json))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(profile, dict):
        return ""
    value = str(profile.get("device_fingerprint") or "").lower()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def _credited_seconds(card: dict[str, Any]) -> int:
    if str(card["authorization_kind"]) == "permanent":
        return 0
    return int(card["duration_seconds"])


def _compatibility_binding_hash(
    entitlement_id: str,
    role: str,
) -> str:
    return hashlib.sha256(
        f"term-entitlement:{entitlement_id}:{role}".encode("ascii"),
    ).hexdigest()


def _binding_from_challenge(
    challenge: dict[str, Any],
    entitlement_id: str,
) -> dict[str, Any]:
    return {
        "binding_id": secrets.token_hex(16),
        "entitlement_id": str(entitlement_id),
        "pair_id": str(challenge["pair_id"]),
        "host_device_code": str(challenge["host_device_code"]),
        "host_client_version": str(challenge["host_client_version"]),
        "host_identity_public_key_b64": str(
            challenge["host_identity_public_key_b64"],
        ),
        "host_key_sha256": str(challenge["host_key_sha256"]),
        "android_device_code": str(challenge["android_device_code"]),
        "android_client_version": str(
            challenge["android_client_version"],
        ),
        "android_identity_public_key_b64": str(
            challenge["android_identity_public_key_b64"],
        ),
        "android_key_sha256": str(challenge["android_key_sha256"]),
        "android_device_profile_json": str(
            challenge.get("android_device_profile_json") or "{}",
        ),
    }


def _profile_sha256(profile: dict[str, Any]) -> str:
    payload = json.dumps(
        profile,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _profile_json_sha256(payload)


def _profile_json_sha256(profile_json: str) -> str:
    return hashlib.sha256(str(profile_json).encode("utf-8")).hexdigest()


def _domain_key(secret: bytes, domain: bytes) -> bytes:
    if len(secret) < 32:
        raise ValueError("dual_machine_token_secret_too_short")
    return hmac.new(secret, domain, hashlib.sha256).digest()


def _license_unavailable() -> DualMachineServiceError:
    return DualMachineServiceError("license_unavailable", 409)


def _hex_128(value: object, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not is_nonzero_lower_hex(text, 32):
        raise DualMachineServiceError(
            f"{field_name}_invalid",
            422,
        )
    return text


def _bounded_text(
    value: object,
    field_name: str,
    maximum: int,
) -> str:
    text = str(value or "").strip()
    if not 1 <= len(text) <= int(maximum):
        raise DualMachineServiceError(f"{field_name}_invalid", 422)
    return text


def _normalize_android_device_profile(
    value: object,
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DualMachineServiceError(
            "android_device_profile_invalid",
            422,
        )
    allowed = {
        *ANDROID_DEVICE_PROFILE_TEXT_FIELDS,
        "sdk_int",
        "supported_abis",
        "device_fingerprint",
    }
    if set(value) - allowed:
        raise DualMachineServiceError(
            "android_device_profile_invalid",
            422,
        )
    normalized: dict[str, Any] = {}
    for field_name in ANDROID_DEVICE_PROFILE_TEXT_FIELDS:
        if field_name not in value or value[field_name] is None:
            continue
        if not isinstance(value[field_name], str):
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        text = value[field_name].strip()
        if len(text) > 128:
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        if text:
            normalized[field_name] = text
    if value.get("sdk_int") is not None:
        sdk_int = value["sdk_int"]
        if type(sdk_int) is not int or not 1 <= sdk_int <= 10_000:
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        normalized["sdk_int"] = sdk_int
    if value.get("supported_abis") is not None:
        supported_abis = value["supported_abis"]
        if (
            not isinstance(supported_abis, (list, tuple))
            or len(supported_abis) > 16
        ):
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        normalized_abis: list[str] = []
        for raw_abi in supported_abis:
            if not isinstance(raw_abi, str):
                raise DualMachineServiceError(
                    "android_device_profile_invalid",
                    422,
                )
            abi = raw_abi.strip().lower()
            if not re.fullmatch(r"[a-z0-9._-]{1,32}", abi):
                raise DualMachineServiceError(
                    "android_device_profile_invalid",
                    422,
                )
            normalized_abis.append(abi)
        normalized["supported_abis"] = normalized_abis
    if value.get("device_fingerprint") is not None:
        if not isinstance(value["device_fingerprint"], str):
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        fingerprint = value["device_fingerprint"].strip()
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise DualMachineServiceError(
                "android_device_profile_invalid",
                422,
            )
        normalized["device_fingerprint"] = fingerprint
    return normalized


def _device_code(value: object) -> str:
    device_code = _bounded_text(value, "device_code", 128).upper()
    if not re.fullmatch(r"[A-Z0-9._:-]+", device_code):
        raise DualMachineServiceError("device_code_invalid", 422)
    return device_code


def _bounded_ip(value: str) -> str:
    return str(value or "")[:128]


def _client_version(value: object) -> str:
    try:
        return normalize_client_version(value)
    except ValueError as exc:
        raise DualMachineServiceError(
            "activation_client_version_invalid",
            422,
        ) from exc


def _require_supported_client_versions(
    command: dict[str, Any],
    settings: DualMachineSettings,
) -> None:
    if (
        not client_version_at_least(
            command["host_client_version"],
            settings.minimum_host_client_version,
        )
        or not client_version_at_least(
            command["android_client_version"],
            settings.minimum_android_client_version,
        )
    ):
        raise DualMachineServiceError(
            "dual_machine_client_update_required",
            426,
        )
