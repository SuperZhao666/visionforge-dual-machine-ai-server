"""SQLite data access for dual-machine card activation."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any


def _record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


@dataclass(slots=True)
class LicenseRepository:
    connection: sqlite3.Connection

    def product(self, product_key: str) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_products WHERE product_key = ? LIMIT 1",
            (str(product_key),),
        ).fetchone())

    def batch_by_request(self, request_id: str) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_license_batches WHERE request_id = ? LIMIT 1",
            (str(request_id),),
        ).fetchone())

    def create_batch(
        self,
        *,
        request_id: str,
        product_key: str,
        quantity: int,
        channel: str,
        note: str,
        expires_at_epoch: int | None,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO dm_license_batches "
            "(request_id, product_key, quantity, channel, note, "
            "expires_at_epoch) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(request_id),
                str(product_key),
                int(quantity),
                str(channel),
                str(note),
                (
                    int(expires_at_epoch)
                    if expires_at_epoch is not None
                    else None
                ),
            ),
        )
        return int(cursor.lastrowid)

    def create_code(
        self,
        *,
        batch_id: int,
        ordinal: int,
        code_digest: str,
        code_suffix: str,
        key_version: int,
        derivation_ref: str,
        product_key: str,
        duration_seconds: int,
        authorization_kind: str,
        expires_at_epoch: int | None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_license_codes "
            "(batch_id, ordinal, code_digest, code_suffix, key_version, "
            "derivation_ref, product_key, duration_seconds, "
            "authorization_kind, expires_at_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(batch_id),
                int(ordinal),
                str(code_digest),
                str(code_suffix),
                int(key_version),
                str(derivation_ref),
                str(product_key),
                int(duration_seconds),
                str(authorization_kind),
                (
                    int(expires_at_epoch)
                    if expires_at_epoch is not None
                    else None
                ),
            ),
        )

    def code_derivation_records(
        self,
        batch_id: int,
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT derivation_ref, key_version, deleted_at "
            "FROM dm_license_codes "
            "WHERE batch_id = ? ORDER BY ordinal",
            (int(batch_id),),
        ).fetchall()
        return [dict(row) for row in rows]

    def code_for_activation(
        self,
        code_digest: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT c.*, b.status AS batch_status, "
            "p.enabled AS product_enabled "
            "FROM dm_license_codes c "
            "JOIN dm_license_batches b ON b.id = c.batch_id "
            "JOIN dm_products p ON p.product_key = c.product_key "
            "WHERE c.code_digest = ? LIMIT 1",
            (str(code_digest),),
        ).fetchone())

    def code_for_activation_by_id(
        self,
        code_id: int,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT c.*, b.status AS batch_status, "
            "p.enabled AS product_enabled "
            "FROM dm_license_codes c "
            "JOIN dm_license_batches b ON b.id = c.batch_id "
            "JOIN dm_products p ON p.product_key = c.product_key "
            "WHERE c.id = ? LIMIT 1",
            (int(code_id),),
        ).fetchone())

    def expire_challenges(self, now_epoch: int) -> int:
        cursor = self.connection.execute(
            "UPDATE dm_activation_challenges "
            "SET status = 'expired', revoke_reason = 'challenge_expired' "
            "WHERE status = 'issued' AND expires_at_epoch <= ?",
            (int(now_epoch),),
        )
        return max(0, int(cursor.rowcount or 0))

    def expire_code(self, code_id: int) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_license_codes SET status = 'expired' "
            "WHERE id = ? AND status = 'issued'",
            (int(code_id),),
        )
        return int(cursor.rowcount or 0) == 1

    def challenge_by_request(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_activation_challenges "
            "WHERE request_id = ? LIMIT 1",
            (str(request_id),),
        ).fetchone())

    def challenge_by_id(
        self,
        challenge_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_activation_challenges "
            "WHERE challenge_id = ? LIMIT 1",
            (str(challenge_id),),
        ).fetchone())

    def create_challenge(self, challenge: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO dm_activation_challenges "
            "(challenge_id, request_id, request_payload_hash, token_digest, "
            "license_code_id, pair_id, protocol_version, "
            "host_device_code, host_client_version, "
            "host_identity_public_key_b64, host_key_sha256, "
            "android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "expires_at_epoch, issued_ip, activation_mode, "
            "target_entitlement_id, android_device_profile_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?)",
            (
                challenge["challenge_id"],
                challenge["request_id"],
                challenge["request_payload_hash"],
                challenge["token_digest"],
                int(challenge["license_code_id"]),
                challenge["pair_id"],
                int(challenge["protocol_version"]),
                challenge["host_device_code"],
                challenge["host_client_version"],
                challenge["host_identity_public_key_b64"],
                challenge["host_key_sha256"],
                challenge["android_device_code"],
                challenge["android_client_version"],
                challenge["android_identity_public_key_b64"],
                challenge["android_key_sha256"],
                int(challenge["expires_at_epoch"]),
                challenge["issued_ip"],
                challenge.get("activation_mode", "activate"),
                challenge.get("target_entitlement_id", ""),
                challenge.get("android_device_profile_json", "{}"),
            ),
        )

    def activation_by_code_id(
        self,
        code_id: int,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT a.*, e.* FROM dm_license_activations a "
            "JOIN dm_entitlements e "
            "ON e.entitlement_id = a.entitlement_id "
            "WHERE a.license_code_id = ? LIMIT 1",
            (int(code_id),),
        ).fetchone())

    def entitlement_by_identity_pair(
        self,
        host_key_sha256: str,
        android_key_sha256: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_entitlements "
            "WHERE host_key_sha256 = ? AND android_key_sha256 = ? LIMIT 1",
            (str(host_key_sha256), str(android_key_sha256)),
        ).fetchone())

    def entitlement_by_id(
        self,
        entitlement_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_entitlements "
            "WHERE entitlement_id = ? LIMIT 1",
            (str(entitlement_id),),
        ).fetchone())

    def entitlement_by_pair_id(
        self,
        pair_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_entitlements WHERE pair_id = ? LIMIT 1",
            (str(pair_id),),
        ).fetchone())

    def create_entitlement(
        self,
        entitlement: dict[str, Any],
        *,
        credited_seconds: int,
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_entitlements "
            "(entitlement_id, pair_id, protocol_version, "
            "host_device_code, host_client_version, "
            "host_identity_public_key_b64, host_key_sha256, "
            "android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "remaining_seconds, total_credited_seconds, "
            "authorization_kind, product_key, source_license_code_id, "
            "created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "datetime('now'))",
            (
                entitlement["entitlement_id"],
                entitlement["pair_id"],
                int(entitlement["protocol_version"]),
                entitlement["host_device_code"],
                entitlement["host_client_version"],
                entitlement["host_identity_public_key_b64"],
                entitlement["host_key_sha256"],
                entitlement["android_device_code"],
                entitlement["android_client_version"],
                entitlement["android_identity_public_key_b64"],
                entitlement["android_key_sha256"],
                int(credited_seconds),
                int(credited_seconds),
                entitlement.get(
                    "authorization_kind",
                    "legacy_balance",
                ),
                entitlement.get("product_key", ""),
                entitlement.get("source_license_code_id"),
            ),
        )

    def reactivate_exhausted_entitlement(
        self,
        entitlement_id: str,
        binding: dict[str, Any],
        *,
        credited_seconds: int,
        authorization_kind: str,
        product_key: str,
        source_license_code_id: int,
    ) -> bool:
        """Replace an exhausted term with one newly consumed card.

        The entitlement id and compatibility hashes remain stable so usage
        history keeps its foreign-key owner.  A new revocation version makes
        every pre-reactivation client snapshot stale, and an active usage
        session blocks the transition even if the status row is inconsistent.
        """
        cursor = self.connection.execute(
            "UPDATE dm_entitlements SET "
            "host_device_code = ?, host_client_version = ?, "
            "host_identity_public_key_b64 = ?, "
            "android_device_code = ?, android_client_version = ?, "
            "android_identity_public_key_b64 = ?, "
            "remaining_seconds = ?, total_credited_seconds = ?, "
            "total_consumed_seconds = 0, status = 'active', "
            "revocation_version = revocation_version + 1, "
            "authorization_kind = ?, product_key = ?, "
            "source_license_code_id = ?, updated_at = datetime('now'), "
            "revoked_at = NULL, revoke_reason = '' "
            "WHERE entitlement_id = ? AND pair_id = ? "
            "AND status = 'exhausted' AND remaining_seconds = 0 "
            "AND total_consumed_seconds = total_credited_seconds "
            "AND NOT EXISTS (SELECT 1 FROM dm_usage_sessions s "
            "WHERE s.entitlement_id = dm_entitlements.entitlement_id "
            "AND s.status = 'active')",
            (
                binding["host_device_code"],
                binding["host_client_version"],
                binding["host_identity_public_key_b64"],
                binding["android_device_code"],
                binding["android_client_version"],
                binding["android_identity_public_key_b64"],
                int(credited_seconds),
                int(credited_seconds),
                str(authorization_kind),
                str(product_key),
                int(source_license_code_id),
                str(entitlement_id),
                binding["pair_id"],
            ),
        )
        if int(cursor.rowcount or 0) != 1:
            return False
        self.bind_device({**binding, "entitlement_id": entitlement_id})
        return True

    def bind_device(
        self,
        binding: dict[str, Any],
    ) -> None:
        entitlement_id = str(binding["entitlement_id"])
        self.connection.execute(
            "UPDATE dm_entitlement_device_bindings SET is_current = 0 "
            "WHERE entitlement_id = ? AND is_current = 1",
            (entitlement_id,),
        )
        self.connection.execute(
            "INSERT INTO dm_entitlement_device_bindings "
            "(binding_id, entitlement_id, pair_id, host_device_code, "
            "host_client_version, host_identity_public_key_b64, "
            "host_key_sha256, android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256, "
            "android_device_profile_json, is_current) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(entitlement_id, pair_id, host_key_sha256, "
            "android_key_sha256) DO UPDATE SET "
            "host_device_code = excluded.host_device_code, "
            "host_client_version = excluded.host_client_version, "
            "host_identity_public_key_b64 = "
            "excluded.host_identity_public_key_b64, "
            "android_device_code = excluded.android_device_code, "
            "android_client_version = excluded.android_client_version, "
            "android_identity_public_key_b64 = "
            "excluded.android_identity_public_key_b64, "
            "android_device_profile_json = "
            "excluded.android_device_profile_json, is_current = 1, "
            "last_seen_at = datetime('now')",
            (
                binding["binding_id"],
                entitlement_id,
                binding["pair_id"],
                binding["host_device_code"],
                binding["host_client_version"],
                binding["host_identity_public_key_b64"],
                binding["host_key_sha256"],
                binding["android_device_code"],
                binding["android_client_version"],
                binding["android_identity_public_key_b64"],
                binding["android_key_sha256"],
                binding.get("android_device_profile_json", "{}"),
            ),
        )

    def rebind_entitlement(
        self,
        entitlement_id: str,
        binding: dict[str, Any],
    ) -> bool:
        current = self.entitlement_by_id(entitlement_id)
        if current is None:
            return False
        changed = any(
            str(current[field]) != str(binding[field])
            for field in (
                "pair_id",
                "host_device_code",
                "host_client_version",
                "host_identity_public_key_b64",
                "android_device_code",
                "android_client_version",
                "android_identity_public_key_b64",
            )
        )
        self.connection.execute(
            "UPDATE dm_entitlements SET pair_id = ?, "
            "host_device_code = ?, host_client_version = ?, "
            "host_identity_public_key_b64 = ?, "
            "android_device_code = ?, android_client_version = ?, "
            "android_identity_public_key_b64 = ?, "
            "revocation_version = revocation_version + 1, "
            "updated_at = datetime('now') "
            "WHERE entitlement_id = ?",
            (
                binding["pair_id"],
                binding["host_device_code"],
                binding["host_client_version"],
                binding["host_identity_public_key_b64"],
                binding["android_device_code"],
                binding["android_client_version"],
                binding["android_identity_public_key_b64"],
                str(entitlement_id),
            ),
        )
        self.bind_device({**binding, "entitlement_id": entitlement_id})
        return changed

    def device_bindings(
        self,
        entitlement_id: str,
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM dm_entitlement_device_bindings "
            "WHERE entitlement_id = ? "
            "ORDER BY is_current DESC, created_at DESC",
            (str(entitlement_id),),
        ).fetchall()
        return [dict(row) for row in rows]

    def current_device_binding(
        self,
        entitlement_id: str,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM dm_entitlement_device_bindings "
            "WHERE entitlement_id = ? AND is_current = 1 "
            "ORDER BY created_at DESC LIMIT 1",
            (str(entitlement_id),),
        ).fetchone()
        return dict(row) if row is not None else None

    def consume_code(
        self,
        *,
        code_id: int,
        now_epoch: int,
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_license_codes "
            "SET status = 'activated', activated_at_epoch = ? "
            "WHERE id = ? AND status = 'issued' "
            "AND (expires_at_epoch IS NULL OR expires_at_epoch > ?)",
            (int(now_epoch), int(code_id), int(now_epoch)),
        )
        return int(cursor.rowcount or 0) == 1

    def consume_challenge(
        self,
        *,
        challenge_id: str,
        consumed_ip: str,
        now_epoch: int,
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_activation_challenges "
            "SET status = 'consumed', consumed_ip = ?, "
            "consumed_at_epoch = ? "
            "WHERE challenge_id = ? AND status = 'issued' "
            "AND expires_at_epoch > ?",
            (
                str(consumed_ip),
                int(now_epoch),
                str(challenge_id),
                int(now_epoch),
            ),
        )
        return int(cursor.rowcount or 0) == 1

    def activation_by_challenge(
        self,
        challenge_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT a.*, e.remaining_seconds, e.total_credited_seconds, "
            "e.total_consumed_seconds, e.status, e.revocation_version, "
            "e.pair_id, e.authorization_kind, e.product_key "
            "FROM dm_license_activations a "
            "JOIN dm_entitlements e ON e.entitlement_id = a.entitlement_id "
            "WHERE a.challenge_id = ? LIMIT 1",
            (str(challenge_id),),
        ).fetchone())

    def create_activation(
        self,
        *,
        activation_id: str,
        code_id: int,
        entitlement_id: str,
        challenge_id: str,
        credited_seconds: int,
        activated_ip: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_license_activations "
            "(activation_id, license_code_id, entitlement_id, challenge_id, "
            "credited_seconds, activated_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(activation_id),
                int(code_id),
                str(entitlement_id),
                str(challenge_id),
                int(credited_seconds),
                str(activated_ip),
            ),
        )

    def write_audit(
        self,
        *,
        event_id: str,
        trace_id: str,
        event_type: str,
        subject_type: str,
        subject_id: str,
        result: str,
        error_code: str,
        ip_address: str,
        detail: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_audit_events "
            "(event_id, trace_id, event_type, subject_type, subject_id, "
            "result, error_code, ip_address, detail_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(event_id),
                str(trace_id),
                str(event_type),
                str(subject_type),
                str(subject_id),
                str(result),
                str(error_code),
                str(ip_address),
                json.dumps(
                    detail,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
