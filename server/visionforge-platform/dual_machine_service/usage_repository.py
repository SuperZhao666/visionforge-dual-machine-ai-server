"""SQLite data access for formal dual-machine usage and metering."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any


def _record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


@dataclass(slots=True)
class UsageRepository:
    connection: sqlite3.Connection

    def entitlement(
        self,
        entitlement_id: str,
    ) -> dict[str, Any] | None:
        entitlement = _record(self.connection.execute(
            "SELECT * FROM dm_entitlements "
            "WHERE entitlement_id = ? LIMIT 1",
            (str(entitlement_id),),
        ).fetchone())
        if entitlement is None:
            return None
        binding = self.connection.execute(
            "SELECT pair_id, host_device_code, host_client_version, "
            "host_identity_public_key_b64, host_key_sha256, "
            "android_device_code, android_client_version, "
            "android_identity_public_key_b64, android_key_sha256 "
            "FROM dm_entitlement_device_bindings "
            "WHERE entitlement_id = ? AND is_current = 1 LIMIT 1",
            (str(entitlement_id),),
        ).fetchone()
        if binding is not None:
            entitlement.update(dict(binding))
        return entitlement

    def entitlement_bindings_for_pair(
        self,
        entitlement_id: str,
        pair_id: str,
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT b.pair_id AS pair_id, "
            "e.protocol_version AS protocol_version, "
            "b.host_identity_public_key_b64 "
            "AS host_identity_public_key_b64, "
            "b.host_key_sha256 AS host_key_sha256, "
            "b.android_identity_public_key_b64 "
            "AS android_identity_public_key_b64, "
            "b.android_key_sha256 AS android_key_sha256, "
            "b.is_current AS is_current "
            "FROM dm_entitlement_device_bindings b "
            "JOIN dm_entitlements e "
            "ON e.entitlement_id = b.entitlement_id "
            "WHERE b.entitlement_id = ? AND b.pair_id = ? "
            "ORDER BY b.is_current DESC, b.created_at DESC",
            (str(entitlement_id), str(pair_id)),
        ).fetchall()
        return [dict(row) for row in rows]

    def session(
        self,
        session_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_sessions "
            "WHERE session_id = ? LIMIT 1",
            (str(session_id),),
        ).fetchone())

    def active_session(
        self,
        entitlement_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_sessions "
            "WHERE entitlement_id = ? AND status = 'active' LIMIT 1",
            (str(entitlement_id),),
        ).fetchone())

    def session_by_start_request(
        self,
        entitlement_id: str,
        request_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_sessions "
            "WHERE entitlement_id = ? AND start_request_id = ? LIMIT 1",
            (str(entitlement_id), str(request_id)),
        ).fetchone())

    def start_cancellation(
        self,
        entitlement_id: str,
        start_request_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_start_cancellations "
            "WHERE entitlement_id = ? AND start_request_id = ? LIMIT 1",
            (str(entitlement_id), str(start_request_id)),
        ).fetchone())

    def start_cancellation_by_cancel_request(
        self,
        entitlement_id: str,
        cancel_request_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_start_cancellations "
            "WHERE entitlement_id = ? AND cancel_request_id = ? LIMIT 1",
            (str(entitlement_id), str(cancel_request_id)),
        ).fetchone())

    def create_start_cancellation(
        self,
        cancellation: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_usage_start_cancellations "
            "(entitlement_id, start_request_id, cancel_request_id, "
            "cancel_request_hash, authenticated_request_hash, "
            "response_json, channel_binding_sha256, created_at_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cancellation["entitlement_id"],
                cancellation["start_request_id"],
                cancellation["cancel_request_id"],
                cancellation["cancel_request_hash"],
                cancellation["authenticated_request_hash"],
                cancellation["response_json"],
                cancellation["channel_binding_sha256"],
                int(cancellation["created_at_epoch"]),
            ),
        )

    def backfill_start_cancellation_replay(
        self,
        cancellation: dict[str, Any],
        *,
        authenticated_request_hash: str,
        response_json: str,
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_usage_start_cancellations SET "
            "authenticated_request_hash = ?, response_json = ? "
            "WHERE entitlement_id = ? AND start_request_id = ? "
            "AND cancel_request_id = ? AND cancel_request_hash = ? "
            "AND channel_binding_sha256 = ? "
            "AND authenticated_request_hash = '' AND response_json = ''",
            (
                str(authenticated_request_hash),
                str(response_json),
                str(cancellation["entitlement_id"]),
                str(cancellation["start_request_id"]),
                str(cancellation["cancel_request_id"]),
                str(cancellation["cancel_request_hash"]),
                str(cancellation["channel_binding_sha256"]),
            ),
        )
        return int(cursor.rowcount or 0) == 1

    def expire_start_challenges(self, now_epoch: int) -> int:
        cursor = self.connection.execute(
            "UPDATE dm_usage_start_challenges SET status = 'expired' "
            "WHERE status = 'issued' AND expires_at_epoch <= ?",
            (int(now_epoch),),
        )
        return max(0, int(cursor.rowcount or 0))

    def start_challenge_by_request(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_start_challenges "
            "WHERE request_id = ? LIMIT 1",
            (str(request_id),),
        ).fetchone())

    def start_challenge(
        self,
        challenge_id: str,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_start_challenges "
            "WHERE challenge_id = ? LIMIT 1",
            (str(challenge_id),),
        ).fetchone())

    def create_start_challenge(
        self,
        challenge: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_usage_start_challenges "
            "(challenge_id, request_id, request_payload_hash, token_digest, "
            "entitlement_id, pair_id, channel_binding_sha256, "
            "expires_at_epoch, issued_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                challenge["challenge_id"],
                challenge["request_id"],
                challenge["request_payload_hash"],
                challenge["token_digest"],
                challenge["entitlement_id"],
                challenge["pair_id"],
                challenge["channel_binding_sha256"],
                int(challenge["expires_at_epoch"]),
                challenge["issued_ip"],
            ),
        )

    def consume_start_challenge(
        self,
        challenge_id: str,
        *,
        now_epoch: int,
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_usage_start_challenges "
            "SET status = 'consumed', consumed_at_epoch = ? "
            "WHERE challenge_id = ? AND status = 'issued' "
            "AND expires_at_epoch > ?",
            (
                int(now_epoch),
                str(challenge_id),
                int(now_epoch),
            ),
        )
        return int(cursor.rowcount or 0) == 1

    def expire_stale_sessions(
        self,
        entitlement_id: str,
        *,
        now_epoch: int,
    ) -> int:
        cursor = self.connection.execute(
            "UPDATE dm_usage_sessions "
            "SET status = 'ended', ended_at_epoch = ?, "
            "ended_reason = 'usage_lease_expired' "
            "WHERE entitlement_id = ? AND status = 'active' "
            "AND lease_expires_at_epoch <= ?",
            (
                int(now_epoch),
                str(entitlement_id),
                int(now_epoch),
            ),
        )
        return max(0, int(cursor.rowcount or 0))

    def create_session(
        self,
        session: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_usage_sessions "
            "(session_id, entitlement_id, pair_id, channel_binding_sha256, "
            "start_request_id, "
            "start_request_hash, started_at_epoch, last_heartbeat_at_epoch, "
            "last_host_frames_total, last_android_frames_total, "
            "current_lease_sha256, previous_lease_sha256, "
            "lease_issued_at_epoch, lease_not_before_epoch, "
            "lease_expires_at_epoch, lease_phase, lease_remaining_seconds, "
            "seconds_consumed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session["session_id"],
                session["entitlement_id"],
                session["pair_id"],
                session["channel_binding_sha256"],
                session["start_request_id"],
                session["start_request_hash"],
                int(session["started_at_epoch"]),
                int(session["last_heartbeat_at_epoch"]),
                int(session["last_host_frames_total"]),
                int(session["last_android_frames_total"]),
                session["current_lease_sha256"],
                session["previous_lease_sha256"],
                int(session["lease_issued_at_epoch"]),
                int(session["lease_not_before_epoch"]),
                int(session["lease_expires_at_epoch"]),
                session["lease_phase"],
                int(session["lease_remaining_seconds"]),
                int(session["seconds_consumed"]),
            ),
        )

    def consume_nonce(
        self,
        *,
        scope: str,
        subject_id: str,
        nonce_digest: str,
        now_epoch: int,
        expires_at_epoch: int,
    ) -> bool:
        self.connection.execute(
            "DELETE FROM dm_auth_nonces WHERE expires_at_epoch <= ?",
            (int(now_epoch),),
        )
        try:
            self.connection.execute(
                "INSERT INTO dm_auth_nonces "
                "(scope, subject_id, nonce_digest, expires_at_epoch) "
                "VALUES (?, ?, ?, ?)",
                (
                    str(scope),
                    str(subject_id),
                    str(nonce_digest),
                    int(expires_at_epoch),
                ),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def debit_entitlement(
        self,
        entitlement_id: str,
        *,
        charged_seconds: int,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            "UPDATE dm_entitlements SET "
            "remaining_seconds = remaining_seconds - ?, "
            "total_consumed_seconds = total_consumed_seconds + ?, "
            "status = CASE "
            "WHEN remaining_seconds - ? = 0 THEN 'exhausted' "
            "ELSE status END, "
            "updated_at = datetime('now') "
            "WHERE entitlement_id = ? AND status = 'active' "
            "AND remaining_seconds >= ?",
            (
                int(charged_seconds),
                int(charged_seconds),
                int(charged_seconds),
                str(entitlement_id),
                int(charged_seconds),
            ),
        )
        if int(cursor.rowcount or 0) != 1:
            raise LookupError("dual_machine_entitlement_debit_failed")
        entitlement = self.entitlement(entitlement_id)
        if entitlement is None:
            raise RuntimeError("debited entitlement missing")
        return entitlement

    def add_ledger_charge(
        self,
        *,
        charge_id: str,
        entitlement_id: str,
        session_id: str,
        sequence: int,
        interval_started_at_epoch: int,
        interval_ended_at_epoch: int,
        charged_seconds: int,
        balance_before_seconds: int,
        balance_after_seconds: int,
    ) -> None:
        self.connection.execute(
            "INSERT INTO dm_usage_ledger "
            "(charge_id, entitlement_id, session_id, sequence, "
            "interval_started_at_epoch, interval_ended_at_epoch, "
            "charged_seconds, balance_before_seconds, "
            "balance_after_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(charge_id),
                str(entitlement_id),
                str(session_id),
                int(sequence),
                int(interval_started_at_epoch),
                int(interval_ended_at_epoch),
                int(charged_seconds),
                int(balance_before_seconds),
                int(balance_after_seconds),
            ),
        )

    def ledger_charge(
        self,
        session_id: str,
        sequence: int,
    ) -> dict[str, Any] | None:
        return _record(self.connection.execute(
            "SELECT * FROM dm_usage_ledger "
            "WHERE session_id = ? AND sequence = ? LIMIT 1",
            (str(session_id), int(sequence)),
        ).fetchone())

    def record_heartbeat(
        self,
        session_id: str,
        *,
        request_id: str,
        request_hash: str,
        sequence: int,
        host_frames_total: int,
        android_frames_total: int,
        lease_sha256: str,
        previous_lease_sha256: str,
        heartbeat_at_epoch: int,
        lease_issued_at_epoch: int,
        lease_not_before_epoch: int,
        lease_expires_at_epoch: int,
        lease_phase: str,
        lease_remaining_seconds: int,
        charged_seconds: int,
    ) -> None:
        cursor = self.connection.execute(
            "UPDATE dm_usage_sessions SET "
            "last_heartbeat_at_epoch = ?, "
            "last_heartbeat_sequence = ?, "
            "last_request_id = ?, last_request_hash = ?, "
            "last_host_frames_total = ?, last_android_frames_total = ?, "
            "current_lease_sha256 = ?, previous_lease_sha256 = ?, "
            "lease_issued_at_epoch = ?, lease_not_before_epoch = ?, "
            "lease_expires_at_epoch = ?, lease_phase = ?, "
            "lease_remaining_seconds = ?, "
            "seconds_consumed = seconds_consumed + ? "
            "WHERE session_id = ? AND status = 'active'",
            (
                int(heartbeat_at_epoch),
                int(sequence),
                str(request_id),
                str(request_hash),
                int(host_frames_total),
                int(android_frames_total),
                str(lease_sha256),
                str(previous_lease_sha256),
                int(lease_issued_at_epoch),
                int(lease_not_before_epoch),
                int(lease_expires_at_epoch),
                str(lease_phase),
                int(lease_remaining_seconds),
                int(charged_seconds),
                str(session_id),
            ),
        )
        if int(cursor.rowcount or 0) != 1:
            raise LookupError("dual_machine_usage_session_update_failed")

    def end_session(
        self,
        session_id: str,
        *,
        now_epoch: int,
        reason: str,
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE dm_usage_sessions "
            "SET status = 'ended', ended_at_epoch = ?, ended_reason = ? "
            "WHERE session_id = ? AND status = 'active'",
            (int(now_epoch), str(reason), str(session_id)),
        )
        return int(cursor.rowcount or 0) == 1
