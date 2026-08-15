"""Local-only administration for dual-machine cards and entitlements."""
from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .audit import write_audit_event
from .database import connect_database
from .errors import DualMachineServiceError
from .license_codes import card_code_digest, card_code_suffix, derive_card_code
from .settings import DualMachineSettings
from .usage_repository import UsageRepository
from .validation import is_nonzero_lower_hex

CODE_STATUSES = {"issued", "activated", "revoked", "expired"}
BATCH_STATUSES = {"active", "revoked"}
MAX_CODE_EXPIRY_SECONDS = 10 * 365 * 24 * 60 * 60


class DualMachineAdminService:
    def __init__(self, settings: DualMachineSettings) -> None:
        self.settings = settings

    def list_products(
        self,
        *,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        where = ""
        params: tuple[Any, ...] = ()
        if enabled is not None:
            where = "WHERE enabled = ?"
            params = (1 if bool(enabled) else 0,)
        connection = connect_database(self.settings)
        try:
            rows = connection.execute(
                "SELECT product_key, display_name, duration_seconds, "
                "enabled, authorization_kind, sort_order, created_at, "
                "updated_at FROM dm_products "
                f"{where} ORDER BY sort_order, product_key",
                params,
            ).fetchall()
            products = [_public_product(row) for row in rows]
            return {"ok": True, "total": len(products), "products": products}
        finally:
            connection.close()

    def list_batches(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str = "",
        deleted: bool | None = False,
        query: str = "",
    ) -> dict[str, Any]:
        safe_limit = _limit(limit)
        safe_offset = _offset(offset)
        safe_status = _optional_status(status, BATCH_STATUSES)
        safe_query = _query(query)
        clauses, params = _deleted_clause("b.deleted_at", deleted)
        if safe_status:
            clauses.append("b.status = ?")
            params.append(safe_status)
        if safe_query:
            pattern = _like_pattern(safe_query)
            clauses.append(
                "(CAST(b.id AS TEXT) LIKE ? ESCAPE '\\' "
                "OR b.request_id LIKE ? ESCAPE '\\' "
                "OR b.product_key LIKE ? ESCAPE '\\' "
                "OR p.display_name LIKE ? ESCAPE '\\' "
                "OR b.channel LIKE ? ESCAPE '\\' "
                "OR b.note LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 6)
        where = _where(clauses)
        connection = connect_database(self.settings)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _normalize_expired_codes(connection, now_epoch=int(time.time()))
            total = int(connection.execute(
                "SELECT COUNT(*) FROM dm_license_batches b "
                "JOIN dm_products p ON p.product_key = b.product_key "
                + where,
                params,
            ).fetchone()[0])
            rows = connection.execute(
                "SELECT b.id, b.request_id, b.product_key, p.display_name, "
                "p.authorization_kind, b.quantity, b.channel, b.note, "
                "b.expires_at_epoch, b.status, b.created_at, b.revoked_at, "
                "b.revoke_reason, b.deleted_at, b.delete_reason, "
                "SUM(CASE WHEN c.status = 'issued' AND c.deleted_at IS NULL "
                "THEN 1 ELSE 0 END) AS issued_count, "
                "SUM(CASE WHEN c.status = 'activated' THEN 1 ELSE 0 END) "
                "AS activated_count, "
                "SUM(CASE WHEN c.status = 'revoked' AND c.deleted_at IS NULL "
                "THEN 1 ELSE 0 END) AS revoked_count, "
                "SUM(CASE WHEN c.status = 'expired' AND c.deleted_at IS NULL "
                "THEN 1 ELSE 0 END) AS expired_count, "
                "SUM(CASE WHEN c.deleted_at IS NOT NULL THEN 1 ELSE 0 END) "
                "AS deleted_count FROM dm_license_batches b "
                "JOIN dm_products p ON p.product_key = b.product_key "
                "LEFT JOIN dm_license_codes c ON c.batch_id = b.id "
                + where
                + " GROUP BY b.id ORDER BY b.id DESC LIMIT ? OFFSET ?",
                (*params, safe_limit, safe_offset),
            ).fetchall()
            response = {
                "ok": True,
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
                "batches": [_public_batch(row) for row in rows],
            }
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def list_codes(
        self,
        *,
        batch_id: int,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        deleted: bool | None = False,
        query: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_limit = _limit(limit)
        safe_offset = _offset(offset)
        safe_status = _optional_status(status, CODE_STATUSES)
        safe_query = _query(query)
        clauses, params = _deleted_clause("c.deleted_at", deleted)
        clauses.insert(0, "c.batch_id = ?")
        params.insert(0, safe_batch_id)
        if safe_status:
            clauses.append("c.status = ?")
            params.append(safe_status)
        if safe_query:
            pattern = _like_pattern(safe_query)
            normalized_suffix = "".join(
                character
                for character in safe_query.upper()
                if character.isalnum()
            )[-4:]
            clauses.append(
                "(CAST(c.id AS TEXT) LIKE ? ESCAPE '\\' "
                "OR CAST(c.ordinal AS TEXT) LIKE ? ESCAPE '\\' "
                "OR c.code_suffix LIKE ? ESCAPE '\\' "
                "OR c.product_key LIKE ? ESCAPE '\\' "
                "OR c.code_suffix = ?)"
            )
            params.extend([pattern, pattern, pattern, pattern, normalized_suffix])
        where = _where(clauses)
        connection = connect_database(self.settings)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _normalize_expired_codes(
                connection,
                now_epoch=int(time.time()),
                batch_id=safe_batch_id,
            )
            batch = _batch(connection, safe_batch_id)
            total = int(connection.execute(
                "SELECT COUNT(*) FROM dm_license_codes c " + where,
                params,
            ).fetchone()[0])
            rows = connection.execute(
                "SELECT c.id, c.batch_id, c.ordinal, c.code_suffix, "
                "c.key_version, c.product_key, c.duration_seconds, "
                "c.authorization_kind, c.status, c.expires_at_epoch, "
                "c.admin_note, c.created_at, c.activated_at_epoch, c.revoked_at, "
                "c.revoke_reason, c.revoked_by_batch, c.deleted_at, "
                "c.delete_reason, c.deleted_by_batch, a.activation_id, "
                "a.entitlement_id "
                "FROM dm_license_codes c LEFT JOIN dm_license_activations a "
                "ON a.license_code_id = c.id "
                + where
                + " ORDER BY c.ordinal LIMIT ? OFFSET ?",
                (*params, safe_limit, safe_offset),
            ).fetchall()
            codes = [_public_code(row) for row in rows]
            _attach_device_bindings(connection, codes)
            response = {
                "ok": True,
                "batch": _public_batch_header(batch),
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
                "codes": codes,
            }
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def list_all_codes(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        deleted: bool | None = False,
        query: str = "",
    ) -> dict[str, Any]:
        """List card records across batches without exposing card material."""
        safe_limit = _limit(limit)
        safe_offset = _offset(offset)
        safe_status = _optional_status(status, CODE_STATUSES)
        safe_query = _query(query)
        clauses, params = _deleted_clause("c.deleted_at", deleted)
        if safe_status:
            clauses.append("c.status = ?")
            params.append(safe_status)
        if safe_query:
            pattern = _like_pattern(safe_query)
            normalized_suffix = "".join(
                character
                for character in safe_query.upper()
                if character.isalnum()
            )[-4:]
            clauses.append(
                "(CAST(c.id AS TEXT) LIKE ? ESCAPE '\\' "
                "OR CAST(c.ordinal AS TEXT) LIKE ? ESCAPE '\\' "
                "OR CAST(c.batch_id AS TEXT) LIKE ? ESCAPE '\\' "
                "OR c.code_suffix LIKE ? ESCAPE '\\' "
                "OR c.product_key LIKE ? ESCAPE '\\' "
                "OR c.admin_note LIKE ? ESCAPE '\\' "
                "OR b.request_id LIKE ? ESCAPE '\\' "
                "OR b.note LIKE ? ESCAPE '\\' "
                "OR a.activation_id LIKE ? ESCAPE '\\' "
                "OR a.entitlement_id LIKE ? ESCAPE '\\' "
                "OR EXISTS (SELECT 1 FROM dm_entitlement_device_bindings d "
                "WHERE d.entitlement_id = a.entitlement_id AND ("
                "d.binding_id LIKE ? ESCAPE '\\' "
                "OR d.host_device_code LIKE ? ESCAPE '\\' "
                "OR d.android_device_code LIKE ? ESCAPE '\\' "
                "OR d.host_key_sha256 LIKE ? ESCAPE '\\' "
                "OR d.android_key_sha256 LIKE ? ESCAPE '\\')) "
                "OR c.code_suffix = ?)"
            )
            params.extend([pattern] * 15 + [normalized_suffix])
        where = _where(clauses)
        connection = connect_database(self.settings)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _normalize_expired_codes(connection, now_epoch=int(time.time()))
            total = int(connection.execute(
                "SELECT COUNT(*) FROM dm_license_codes c "
                "JOIN dm_license_batches b ON b.id = c.batch_id "
                "LEFT JOIN dm_license_activations a "
                "ON a.license_code_id = c.id "
                + where,
                params,
            ).fetchone()[0])
            rows = connection.execute(
                "SELECT c.id, c.batch_id, c.ordinal, c.code_suffix, "
                "c.key_version, c.product_key, c.duration_seconds, "
                "c.authorization_kind, c.status, c.expires_at_epoch, "
                "c.admin_note, c.created_at, c.activated_at_epoch, "
                "c.revoked_at, c.revoke_reason, c.revoked_by_batch, "
                "c.deleted_at, c.delete_reason, c.deleted_by_batch, "
                "a.activation_id, a.entitlement_id, "
                "b.status AS batch_status, b.deleted_at AS batch_deleted_at, "
                "p.display_name FROM dm_license_codes c "
                "JOIN dm_license_batches b ON b.id = c.batch_id "
                "JOIN dm_products p ON p.product_key = c.product_key "
                "LEFT JOIN dm_license_activations a "
                "ON a.license_code_id = c.id "
                + where
                + " ORDER BY c.id DESC LIMIT ? OFFSET ?",
                (*params, safe_limit, safe_offset),
            ).fetchall()
            codes = [_public_code(row) for row in rows]
            _attach_device_bindings(connection, codes)
            response = {
                "ok": True,
                "scope": "global",
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
                "codes": codes,
            }
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def list_audit(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: str = "",
        query: str = "",
    ) -> dict[str, Any]:
        safe_limit = _limit(limit)
        safe_offset = _offset(offset)
        safe_event_type = str(event_type or "").strip()
        if len(safe_event_type) > 80:
            raise ValueError("event_type is too long")
        safe_query = _query(query)
        clauses: list[str] = []
        params: list[Any] = []
        if safe_event_type:
            clauses.append("event_type = ?")
            params.append(safe_event_type)
        if safe_query:
            pattern = _like_pattern(safe_query)
            clauses.append(
                "(event_type LIKE ? ESCAPE '\\' "
                "OR subject_type LIKE ? ESCAPE '\\' "
                "OR subject_id LIKE ? ESCAPE '\\' "
                "OR trace_id LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)
        where = _where(clauses)
        connection = connect_database(self.settings)
        try:
            total = int(connection.execute(
                "SELECT COUNT(*) FROM dm_audit_events " + where,
                params,
            ).fetchone()[0])
            rows = connection.execute(
                "SELECT event_id, trace_id, event_type, subject_type, "
                "subject_id, result, error_code, ip_address, detail_json, "
                "created_at FROM dm_audit_events "
                + where
                + " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (*params, safe_limit, safe_offset),
            ).fetchall()
            return {
                "ok": True,
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
                "events": [_public_audit(row) for row in rows],
            }
        finally:
            connection.close()

    def update_batch(
        self,
        batch_id: int,
        *,
        note: str,
        expires_at_epoch: int | None,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_note = _note(note)
        safe_expiry = _expiry(expires_at_epoch)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            _require_not_deleted(batch, "batch")
            activated = int(connection.execute(
                "SELECT COUNT(*) FROM dm_license_codes "
                "WHERE batch_id = ? AND status = 'activated'",
                (safe_batch_id,),
            ).fetchone()[0])
            if activated:
                raise DualMachineServiceError(
                    "dual_machine_batch_has_activated_codes",
                    409,
                )
            changed = (
                str(batch["note"]) != safe_note
                or _nullable_int(batch["expires_at_epoch"]) != safe_expiry
            )
            connection.execute(
                "UPDATE dm_license_batches SET note = ?, "
                "expires_at_epoch = ? WHERE id = ?",
                (safe_note, safe_expiry, safe_batch_id),
            )
            updated_codes = connection.execute(
                "UPDATE dm_license_codes SET expires_at_epoch = ?, "
                "status = CASE WHEN status = 'expired' "
                "THEN 'issued' ELSE status END "
                "WHERE batch_id = ? AND status != 'activated' "
                "AND deleted_at IS NULL",
                (safe_expiry, safe_batch_id),
            ).rowcount
            write_audit_event(
                connection,
                event_type="license_batch_updated",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "changed": changed,
                    "reason": safe_reason,
                    "expires_at_epoch": safe_expiry,
                    "note_changed": str(batch["note"]) != safe_note,
                    "updated_unused_codes": int(updated_codes or 0),
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "changed": changed,
                "note": safe_note,
                "expires_at_epoch": safe_expiry,
                "updated_unused_codes": int(updated_codes or 0),
            }

    def revoke_code(
        self,
        code_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_code_id = _positive_id(code_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            code = _code(connection, safe_code_id)
            _require_not_deleted(code, "code")
            if str(code["status"]) == "activated":
                raise DualMachineServiceError(
                    "dual_machine_code_already_activated",
                    409,
                )
            changed = (
                str(code["status"]) != "revoked"
                or int(code["revoked_by_batch"] or 0) != 0
            )
            connection.execute(
                "UPDATE dm_license_codes SET status = 'revoked', "
                "revoked_at = datetime('now'), revoke_reason = ?, "
                "revoked_by_batch = 0 WHERE id = ?",
                (safe_reason, safe_code_id),
            )
            invalidated = _invalidate_activation_challenges(
                connection,
                "license_code_revoked",
                code_id=safe_code_id,
            )
            write_audit_event(
                connection,
                event_type="license_code_revoked",
                subject_type="license_code",
                subject_id=str(safe_code_id),
                trace_id=trace_id,
                detail={
                    "changed": changed,
                    "reason": safe_reason,
                    "invalidated_challenges": invalidated,
                },
            )
            return {
                "ok": True,
                "code_id": safe_code_id,
                "status": "revoked",
                "changed": changed,
                "invalidated_challenges": invalidated,
            }

    def update_code(
        self,
        code_id: int,
        *,
        admin_note: str,
        expires_at_epoch: int | None,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_code_id = _positive_id(code_id)
        safe_note = _note(admin_note)
        safe_expiry = _expiry(expires_at_epoch)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            code = _code(connection, safe_code_id)
            _require_not_deleted(code, "code")
            if str(code["status"]) == "activated":
                raise DualMachineServiceError(
                    "dual_machine_code_already_activated",
                    409,
                )
            changed = (
                str(code["admin_note"] or "") != safe_note
                or _nullable_int(code["expires_at_epoch"]) != safe_expiry
            )
            connection.execute(
                "UPDATE dm_license_codes SET admin_note = ?, "
                "expires_at_epoch = ?, status = CASE "
                "WHEN status = 'expired' THEN 'issued' ELSE status END "
                "WHERE id = ?",
                (safe_note, safe_expiry, safe_code_id),
            )
            invalidated = _invalidate_activation_challenges(
                connection,
                "license_code_updated",
                code_id=safe_code_id,
            )
            updated = _code(connection, safe_code_id)
            write_audit_event(
                connection,
                event_type="license_code_updated",
                subject_type="license_code",
                subject_id=str(safe_code_id),
                trace_id=trace_id,
                detail={
                    "changed": changed,
                    "reason": safe_reason,
                    "expires_at_epoch": safe_expiry,
                    "admin_note_changed": (
                        str(code["admin_note"] or "") != safe_note
                    ),
                    "invalidated_challenges": invalidated,
                },
            )
            return {
                "ok": True,
                "code_id": safe_code_id,
                "changed": changed,
                "status": str(updated["status"]),
                "admin_note": safe_note,
                "expires_at_epoch": safe_expiry,
                "invalidated_challenges": invalidated,
            }

    def restore_code(
        self,
        code_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_code_id = _positive_id(code_id)
        safe_reason = _reason(reason)
        now = int(time.time())
        with _transaction(self.settings) as connection:
            code = _code(connection, safe_code_id)
            _require_not_deleted(code, "code")
            batch = _batch(connection, int(code["batch_id"]))
            _require_not_deleted(batch, "batch")
            if str(batch["status"]) != "active":
                raise DualMachineServiceError(
                    "dual_machine_batch_not_active",
                    409,
                )
            if str(code["status"]) != "revoked":
                raise DualMachineServiceError(
                    "dual_machine_code_not_revoked",
                    409,
                )
            if (
                code["expires_at_epoch"] is not None
                and int(code["expires_at_epoch"]) <= now
            ):
                raise DualMachineServiceError(
                    "dual_machine_code_expired",
                    409,
                )
            connection.execute(
                "UPDATE dm_license_codes SET status = 'issued', "
                "revoked_at = NULL, revoke_reason = '', "
                "revoked_by_batch = 0 WHERE id = ?",
                (safe_code_id,),
            )
            write_audit_event(
                connection,
                event_type="license_code_restored",
                subject_type="license_code",
                subject_id=str(safe_code_id),
                trace_id=trace_id,
                detail={"reason": safe_reason},
            )
            return {
                "ok": True,
                "code_id": safe_code_id,
                "status": "issued",
                "changed": True,
            }

    def delete_code(
        self,
        code_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_code_id = _positive_id(code_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            code = _code(connection, safe_code_id)
            changed = code["deleted_at"] is None
            activated = str(code["status"]) == "activated"
            if changed:
                connection.execute(
                    "UPDATE dm_license_codes SET "
                    "status = CASE WHEN status = 'issued' "
                    "THEN 'revoked' ELSE status END, "
                    "revoked_at = CASE WHEN status = 'issued' "
                    "THEN datetime('now') ELSE revoked_at END, "
                    "revoke_reason = CASE WHEN status = 'issued' "
                    "THEN ? ELSE revoke_reason END, "
                    "revoked_by_batch = CASE WHEN status = 'issued' "
                    "THEN 0 ELSE revoked_by_batch END, "
                    "deleted_at = datetime('now'), delete_reason = ?, "
                    "deleted_by_batch = 0 "
                    "WHERE id = ?",
                    (safe_reason, safe_reason, safe_code_id),
                )
            invalidated = 0
            if not activated:
                invalidated = _invalidate_activation_challenges(
                    connection,
                    "license_code_archived",
                    code_id=safe_code_id,
                )
            write_audit_event(
                connection,
                event_type="license_code_archived",
                subject_type="license_code",
                subject_id=str(safe_code_id),
                trace_id=trace_id,
                detail={
                    "activated_history_preserved": activated,
                    "changed": changed,
                    "reason": safe_reason,
                    "invalidated_challenges": invalidated,
                },
            )
            return {
                "ok": True,
                "code_id": safe_code_id,
                "deleted": True,
                "changed": changed,
                "activated_history_preserved": activated,
            }

    def unarchive_code(
        self,
        code_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_code_id = _positive_id(code_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            code = _code(connection, safe_code_id)
            if code["deleted_at"] is None:
                raise DualMachineServiceError(
                    "dual_machine_code_not_archived",
                    409,
                )
            batch = _batch(connection, int(code["batch_id"]))
            if batch["deleted_at"] is not None:
                raise DualMachineServiceError(
                    "dual_machine_batch_archived",
                    409,
                )
            connection.execute(
                "UPDATE dm_license_codes SET deleted_at = NULL, "
                "delete_reason = '', deleted_by_batch = 0 WHERE id = ?",
                (safe_code_id,),
            )
            write_audit_event(
                connection,
                event_type="license_code_unarchived",
                subject_type="license_code",
                subject_id=str(safe_code_id),
                trace_id=trace_id,
                detail={
                    "reason": safe_reason,
                    "status_preserved": str(code["status"]),
                },
            )
            return {
                "ok": True,
                "code_id": safe_code_id,
                "deleted": False,
                "changed": True,
                "status": str(code["status"]),
                "requires_restore": str(code["status"]) == "revoked",
            }

    def revoke_batch(
        self,
        batch_id: int,
        *,
        reason: str,
        revoke_activated_entitlements: bool = False,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            _require_not_deleted(batch, "batch")
            invalidated = _invalidate_activation_challenges(
                connection,
                "license_batch_revoked",
                batch_id=safe_batch_id,
            )
            revoked_codes = connection.execute(
                "UPDATE dm_license_codes SET status = 'revoked', "
                "revoked_at = datetime('now'), revoke_reason = ?, "
                "revoked_by_batch = 1 WHERE batch_id = ? "
                "AND status = 'issued' AND deleted_at IS NULL",
                (safe_reason, safe_batch_id),
            ).rowcount
            revoked_entitlements = 0
            expired_binding_challenges = 0
            if revoke_activated_entitlements:
                (
                    revoked_entitlements,
                    expired_binding_challenges,
                ) = _revoke_batch_entitlements(
                    connection, safe_batch_id, safe_reason
                )
            connection.execute(
                "UPDATE dm_license_batches SET status = 'revoked', "
                "revoked_at = datetime('now'), revoke_reason = ? "
                "WHERE id = ?",
                (safe_reason, safe_batch_id),
            )
            write_audit_event(
                connection,
                event_type="license_batch_revoked",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "reason": safe_reason,
                    "revoke_activated_entitlements": bool(
                        revoke_activated_entitlements,
                    ),
                    "revoked_activated_entitlements": revoked_entitlements,
                    "revoked_issued_codes": int(revoked_codes or 0),
                    "invalidated_challenges": invalidated,
                    "expired_binding_challenges": (
                        expired_binding_challenges
                    ),
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "status": "revoked",
                "revoked_issued_codes": int(revoked_codes or 0),
                "revoked_activated_entitlements": revoked_entitlements,
                "invalidated_challenges": invalidated,
                "expired_binding_challenges": expired_binding_challenges,
            }

    def restore_batch(
        self,
        batch_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_reason = _reason(reason)
        now = int(time.time())
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            _require_not_deleted(batch, "batch")
            restored = connection.execute(
                "UPDATE dm_license_codes SET status = 'issued', "
                "revoked_at = NULL, revoke_reason = '', "
                "revoked_by_batch = 0 WHERE batch_id = ? "
                "AND status = 'revoked' AND revoked_by_batch = 1 "
                "AND deleted_at IS NULL AND "
                "(expires_at_epoch IS NULL OR expires_at_epoch > ?)",
                (safe_batch_id, now),
            ).rowcount
            changed = str(batch["status"]) != "active" or bool(restored)
            connection.execute(
                "UPDATE dm_license_batches SET status = 'active', "
                "revoked_at = NULL, revoke_reason = '' WHERE id = ?",
                (safe_batch_id,),
            )
            write_audit_event(
                connection,
                event_type="license_batch_restored",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "changed": changed,
                    "reason": safe_reason,
                    "restored_unused_codes": int(restored or 0),
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "status": "active",
                "changed": changed,
                "restored_unused_codes": int(restored or 0),
            }

    def delete_batch(
        self,
        batch_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            changed = batch["deleted_at"] is None
            invalidated = _invalidate_activation_challenges(
                connection,
                "license_batch_archived",
                batch_id=safe_batch_id,
            )
            archived_codes = 0
            if changed:
                archived_codes = connection.execute(
                    "UPDATE dm_license_codes SET "
                    "status = CASE WHEN status = 'issued' "
                    "THEN 'revoked' ELSE status END, "
                    "revoked_at = CASE WHEN status = 'issued' "
                    "THEN datetime('now') ELSE revoked_at END, "
                    "revoke_reason = CASE WHEN status = 'issued' "
                    "THEN ? ELSE revoke_reason END, "
                    "revoked_by_batch = CASE WHEN status = 'issued' "
                    "THEN 1 ELSE revoked_by_batch END, "
                    "deleted_at = datetime('now'), delete_reason = ?, "
                    "deleted_by_batch = 1 "
                    "WHERE batch_id = ? AND deleted_at IS NULL",
                    (safe_reason, safe_reason, safe_batch_id),
                ).rowcount
                connection.execute(
                    "UPDATE dm_license_batches SET status = 'revoked', "
                    "revoked_at = datetime('now'), revoke_reason = ?, "
                    "deleted_at = datetime('now'), delete_reason = ? "
                    "WHERE id = ?",
                    (safe_reason, safe_reason, safe_batch_id),
                )
            activated_count = int(connection.execute(
                "SELECT COUNT(*) FROM dm_license_codes "
                "WHERE batch_id = ? AND status = 'activated'",
                (safe_batch_id,),
            ).fetchone()[0])
            write_audit_event(
                connection,
                event_type="license_batch_archived",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "activated_history_preserved": activated_count,
                    "archived_codes": int(archived_codes or 0),
                    "changed": changed,
                    "reason": safe_reason,
                    "invalidated_challenges": invalidated,
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "deleted": True,
                "changed": changed,
                "archived_codes": int(archived_codes or 0),
                "activated_history_preserved": activated_count,
            }

    def unarchive_batch(
        self,
        batch_id: int,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_batch_id = _positive_id(batch_id)
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            if batch["deleted_at"] is None:
                raise DualMachineServiceError(
                    "dual_machine_batch_not_archived",
                    409,
                )
            unarchived_codes = connection.execute(
                "UPDATE dm_license_codes SET deleted_at = NULL, "
                "delete_reason = '', deleted_by_batch = 0 "
                "WHERE batch_id = ? AND deleted_by_batch = 1",
                (safe_batch_id,),
            ).rowcount
            connection.execute(
                "UPDATE dm_license_batches SET deleted_at = NULL, "
                "delete_reason = '' WHERE id = ?",
                (safe_batch_id,),
            )
            write_audit_event(
                connection,
                event_type="license_batch_unarchived",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "reason": safe_reason,
                    "status_preserved": str(batch["status"]),
                    "unarchived_codes": int(unarchived_codes or 0),
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "deleted": False,
                "changed": True,
                "status": str(batch["status"]),
                "requires_restore": str(batch["status"]) == "revoked",
                "unarchived_codes": int(unarchived_codes or 0),
            }

    def export_batch_codes(
        self,
        batch_id: int,
        *,
        trace_id: str = "",
    ) -> dict[str, Any]:
        self.settings.validate_card_issuance()
        safe_batch_id = _positive_id(batch_id)
        keyring = self.settings.license_code_keyring()
        with _transaction(self.settings) as connection:
            batch = _batch(connection, safe_batch_id)
            rows = connection.execute(
                "SELECT id, ordinal, code_digest, code_suffix, key_version, "
                "derivation_ref, status FROM dm_license_codes "
                "WHERE batch_id = ? AND deleted_at IS NULL "
                "ORDER BY ordinal",
                (safe_batch_id,),
            ).fetchall()
            exported: list[dict[str, Any]] = []
            versions: set[int] = set()
            for row in rows:
                key_version = int(row["key_version"])
                secret = keyring.get(key_version)
                if secret is None:
                    raise DualMachineServiceError(
                        "license_code_key_version_unavailable",
                        503,
                    )
                code = derive_card_code(secret, str(row["derivation_ref"]))
                expected_digest = card_code_digest(
                    secret,
                    code,
                    key_version=key_version,
                )
                if (
                    not hmac.compare_digest(
                        expected_digest,
                        str(row["code_digest"]),
                    )
                    or card_code_suffix(code) != str(row["code_suffix"])
                ):
                    raise RuntimeError("stored license code integrity mismatch")
                versions.add(key_version)
                exported.append({
                    "id": int(row["id"]),
                    "ordinal": int(row["ordinal"]),
                    "code": code,
                    "status": str(row["status"]),
                    "suffix": str(row["code_suffix"]),
                })
            write_audit_event(
                connection,
                event_type="license_batch_codes_exported",
                subject_type="license_batch",
                subject_id=str(safe_batch_id),
                trace_id=trace_id,
                detail={
                    "exported_count": len(exported),
                    "key_versions": sorted(versions),
                },
            )
            return {
                "ok": True,
                "batch_id": safe_batch_id,
                "product_key": str(batch["product_key"]),
                "total": len(exported),
                "codes": exported,
            }

    def rederive_batch_codes(
        self,
        batch_id: int,
        *,
        trace_id: str = "",
    ) -> dict[str, Any]:
        return self.export_batch_codes(batch_id, trace_id=trace_id)

    def revoke_entitlement(
        self,
        entitlement_id: str,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        safe_reason = _reason(reason)
        safe_id = _hex_identifier(entitlement_id, "entitlement_id")
        now = int(time.time())
        with _transaction(self.settings) as connection:
            entitlement = connection.execute(
                "SELECT * FROM dm_entitlements WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            if entitlement is None:
                raise DualMachineServiceError(
                    "dual_machine_entitlement_not_found",
                    404,
                )
            changed = str(entitlement["status"]) != "revoked"
            if changed:
                connection.execute(
                    "UPDATE dm_entitlements SET status = 'revoked', "
                    "revocation_version = revocation_version + 1, "
                    "updated_at = datetime('now'), "
                    "revoked_at = datetime('now'), revoke_reason = ? "
                    "WHERE entitlement_id = ?",
                    (safe_reason, safe_id),
                )
                connection.execute(
                    "UPDATE dm_usage_sessions SET status = 'revoked', "
                    "ended_at_epoch = ?, "
                    "ended_reason = 'entitlement_revoked' "
                    "WHERE entitlement_id = ? AND status = 'active'",
                    (now, safe_id),
                )
                pair_revoked = connection.execute(
                    "UPDATE dm_pair_security_state SET "
                    "assurance_state = 'revoked', updated_at_epoch = ? "
                    "WHERE entitlement_id = ? AND pair_id = ? "
                    "AND assurance_state IN ('legacy_blocked', 'pending', "
                    "'active', 'recovery_pending')",
                    (now, safe_id, str(entitlement["pair_id"])),
                )
                if int(pair_revoked.rowcount or 0) != 1:
                    raise DualMachineServiceError(
                        "pair_security_revoke_state_invalid",
                        409,
                    )
            expired_start_challenges = connection.execute(
                "UPDATE dm_usage_start_challenges SET status = 'expired' "
                "WHERE entitlement_id = ? AND status = 'issued'",
                (safe_id,),
            ).rowcount
            expired_binding_challenges = connection.execute(
                "UPDATE dm_activation_challenges SET status = 'expired', "
                "revoke_reason = 'entitlement_revoked' "
                "WHERE target_entitlement_id = ? AND status = 'issued'",
                (safe_id,),
            ).rowcount
            updated = connection.execute(
                "SELECT status, revocation_version FROM dm_entitlements "
                "WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            write_audit_event(
                connection,
                event_type="entitlement_revoked",
                subject_type="entitlement",
                subject_id=safe_id,
                trace_id=trace_id,
                detail={
                    "changed": changed,
                    "reason": safe_reason,
                    "revocation_version": int(updated["revocation_version"]),
                    "expired_start_challenges": int(
                        expired_start_challenges or 0,
                    ),
                    "expired_binding_challenges": int(
                        expired_binding_challenges or 0,
                    ),
                    "pair_assurance_state": "revoked",
                },
            )
            return {
                "ok": True,
                "entitlement_id": safe_id,
                "status": str(updated["status"]),
                "revocation_version": int(updated["revocation_version"]),
                "changed": changed,
                "pair_assurance_state": "revoked",
                "expired_start_challenges": int(
                    expired_start_challenges or 0,
                ),
                "expired_binding_challenges": int(
                    expired_binding_challenges or 0,
                ),
            }

    def restore_entitlement(
        self,
        entitlement_id: str,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Restore a revoked card entitlement without crediting any time."""
        safe_id = _hex_identifier(entitlement_id, "entitlement_id")
        safe_reason = _reason(reason)
        with _transaction(self.settings) as connection:
            entitlement = connection.execute(
                "SELECT e.*, c.status AS source_code_status, "
                "b.status AS source_batch_status FROM dm_entitlements e "
                "LEFT JOIN dm_license_codes c "
                "ON c.id = e.source_license_code_id "
                "LEFT JOIN dm_license_batches b ON b.id = c.batch_id "
                "WHERE e.entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            if entitlement is None:
                raise DualMachineServiceError(
                    "dual_machine_entitlement_not_found",
                    404,
                )
            if str(entitlement["status"]) != "revoked":
                raise DualMachineServiceError(
                    "dual_machine_entitlement_not_revoked",
                    409,
                )
            if (
                entitlement["source_license_code_id"] is None
                or str(entitlement["source_code_status"] or "") != "activated"
                or str(entitlement["source_batch_status"] or "") != "active"
            ):
                raise DualMachineServiceError(
                    "dual_machine_entitlement_source_unavailable",
                    409,
                )
            target_status = (
                "active"
                if str(entitlement["authorization_kind"]) == "permanent"
                or int(entitlement["remaining_seconds"]) > 0
                else "exhausted"
            )
            connection.execute(
                "UPDATE dm_entitlements SET status = ?, "
                "revocation_version = revocation_version + 1, "
                "updated_at = datetime('now'), revoked_at = NULL, "
                "revoke_reason = '' WHERE entitlement_id = ?",
                (target_status, safe_id),
            )
            updated = connection.execute(
                "SELECT status, revocation_version, remaining_seconds, "
                "total_credited_seconds, total_consumed_seconds "
                "FROM dm_entitlements WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            write_audit_event(
                connection,
                event_type="entitlement_restored",
                subject_type="entitlement",
                subject_id=safe_id,
                trace_id=trace_id,
                detail={
                    "reason": safe_reason,
                    "status": target_status,
                    "revocation_version": int(updated["revocation_version"]),
                    "time_credited_seconds": 0,
                },
            )
            return {
                "ok": True,
                "entitlement_id": safe_id,
                "status": str(updated["status"]),
                "revocation_version": int(updated["revocation_version"]),
                "remaining_seconds": int(updated["remaining_seconds"]),
                "total_credited_seconds": int(
                    updated["total_credited_seconds"],
                ),
                "total_consumed_seconds": int(
                    updated["total_consumed_seconds"],
                ),
                "time_credited_seconds": 0,
                "changed": True,
                "requires_card_rebind": True,
            }

    def unbind_entitlement_device(
        self,
        entitlement_id: str,
        binding_id: str,
        *,
        reason: str,
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Invalidate the current device pair while preserving card credit."""
        safe_id = _hex_identifier(entitlement_id, "entitlement_id")
        safe_binding_id = _hex_identifier(binding_id, "binding_id")
        safe_reason = _reason(reason)
        now = int(time.time())
        with _transaction(self.settings) as connection:
            entitlement = connection.execute(
                "SELECT entitlement_id, status FROM dm_entitlements "
                "WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            if entitlement is None:
                raise DualMachineServiceError(
                    "dual_machine_entitlement_not_found",
                    404,
                )
            binding = connection.execute(
                "SELECT binding_id, is_current FROM "
                "dm_entitlement_device_bindings "
                "WHERE entitlement_id = ? AND binding_id = ?",
                (safe_id, safe_binding_id),
            ).fetchone()
            if binding is None:
                raise DualMachineServiceError(
                    "dual_machine_device_binding_not_found",
                    404,
                )
            if not bool(binding["is_current"]):
                raise DualMachineServiceError(
                    "dual_machine_device_binding_not_current",
                    409,
                )

            connection.execute(
                "UPDATE dm_entitlement_device_bindings SET is_current = 0 "
                "WHERE entitlement_id = ? AND binding_id = ? "
                "AND is_current = 1",
                (safe_id, safe_binding_id),
            )
            pair_state = connection.execute(
                "SELECT pair_id, assurance_state, updated_at_epoch "
                "FROM dm_pair_security_state WHERE entitlement_id = ? "
                "AND binding_id = ?",
                (safe_id, safe_binding_id),
            ).fetchone()
            if pair_state is None:
                raise DualMachineServiceError(
                    "pair_security_unbind_state_invalid",
                    409,
                )
            pair_assurance_state = str(pair_state["assurance_state"])
            if pair_assurance_state in {"active", "legacy_blocked"}:
                pair_recovery = connection.execute(
                    "UPDATE dm_pair_security_state SET "
                    "assurance_state = 'recovery_pending', "
                    "updated_at_epoch = ? WHERE pair_id = ? "
                    "AND assurance_state = ?",
                    (
                        max(now, int(pair_state["updated_at_epoch"])),
                        str(pair_state["pair_id"]),
                        pair_assurance_state,
                    ),
                )
                if int(pair_recovery.rowcount or 0) != 1:
                    raise DualMachineServiceError(
                        "pair_security_unbind_state_invalid",
                        409,
                    )
                pair_assurance_state = "recovery_pending"
            elif pair_assurance_state not in {"recovery_pending", "revoked"}:
                raise DualMachineServiceError(
                    "pair_security_unbind_state_invalid",
                    409,
                )
            connection.execute(
                "UPDATE dm_entitlements SET pair_id = ?, "
                "host_identity_public_key_b64 = '', "
                "android_identity_public_key_b64 = '', "
                "revocation_version = revocation_version + 1, "
                "updated_at = datetime('now') WHERE entitlement_id = ?",
                (
                    secrets.token_hex(16),
                    safe_id,
                ),
            )
            ended_sessions = connection.execute(
                "UPDATE dm_usage_sessions SET status = 'ended', "
                "ended_at_epoch = ?, ended_reason = 'admin_device_unbound' "
                "WHERE entitlement_id = ? AND status = 'active'",
                (now, safe_id),
            ).rowcount
            expired_start_challenges = connection.execute(
                "UPDATE dm_usage_start_challenges SET status = 'expired' "
                "WHERE entitlement_id = ? AND status = 'issued'",
                (safe_id,),
            ).rowcount
            expired_binding_challenges = connection.execute(
                "UPDATE dm_activation_challenges SET status = 'expired', "
                "revoke_reason = 'admin_device_unbound' "
                "WHERE target_entitlement_id = ? AND status = 'issued'",
                (safe_id,),
            ).rowcount
            updated = connection.execute(
                "SELECT status, revocation_version FROM dm_entitlements "
                "WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            write_audit_event(
                connection,
                event_type="entitlement_device_unbound",
                subject_type="entitlement",
                subject_id=safe_id,
                trace_id=trace_id,
                detail={
                    "binding_id": safe_binding_id,
                    "reason": safe_reason,
                    "revocation_version": int(updated["revocation_version"]),
                    "ended_sessions": int(ended_sessions or 0),
                    "expired_start_challenges": int(
                        expired_start_challenges or 0,
                    ),
                    "expired_binding_challenges": int(
                        expired_binding_challenges or 0,
                    ),
                    "pair_assurance_state": pair_assurance_state,
                },
            )
            return {
                "ok": True,
                "entitlement_id": safe_id,
                "binding_id": safe_binding_id,
                "status": str(updated["status"]),
                "revocation_version": int(updated["revocation_version"]),
                "current_device_bound": False,
                "requires_card_rebind": True,
                "pair_assurance_state": pair_assurance_state,
                "ended_sessions": int(ended_sessions or 0),
                "expired_start_challenges": int(
                    expired_start_challenges or 0,
                ),
                "expired_binding_challenges": int(
                    expired_binding_challenges or 0,
                ),
            }

    def entitlement_summary(self, entitlement_id: str) -> dict[str, Any]:
        safe_id = _hex_identifier(entitlement_id, "entitlement_id")
        connection = connect_database(self.settings)
        try:
            connection.execute("BEGIN IMMEDIATE")
            UsageRepository(connection).expire_stale_sessions(
                safe_id,
                now_epoch=int(time.time()),
            )
            entitlement = connection.execute(
                "SELECT entitlement_id, pair_id, status, "
                "revocation_version, remaining_seconds, "
                "total_credited_seconds, total_consumed_seconds, "
                "authorization_kind, product_key, source_license_code_id, "
                "created_at, updated_at, revoked_at, revoke_reason "
                "FROM dm_entitlements WHERE entitlement_id = ?",
                (safe_id,),
            ).fetchone()
            if entitlement is None:
                raise DualMachineServiceError(
                    "dual_machine_entitlement_not_found",
                    404,
                )
            response = {"ok": True, **dict(entitlement)}
            response["is_permanent"] = (
                str(entitlement["authorization_kind"]) == "permanent"
            )
            response["device_bindings"] = _device_bindings(
                connection,
                safe_id,
            )
            connection.commit()
            return response
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


@contextmanager
def _transaction(
    settings: DualMachineSettings,
) -> Iterator[sqlite3.Connection]:
    connection = connect_database(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def _batch(connection: sqlite3.Connection, batch_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT b.*, p.display_name, p.authorization_kind "
        "FROM dm_license_batches b JOIN dm_products p "
        "ON p.product_key = b.product_key WHERE b.id = ?",
        (int(batch_id),),
    ).fetchone()
    if row is None:
        raise DualMachineServiceError("dual_machine_batch_not_found", 404)
    return row


def _code(connection: sqlite3.Connection, code_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM dm_license_codes WHERE id = ?",
        (int(code_id),),
    ).fetchone()
    if row is None:
        raise DualMachineServiceError("dual_machine_code_not_found", 404)
    return row


def _require_not_deleted(row: sqlite3.Row, subject: str) -> None:
    if row["deleted_at"] is not None:
        raise DualMachineServiceError(
            f"dual_machine_{subject}_archived",
            409,
        )


def _invalidate_activation_challenges(
    connection: sqlite3.Connection,
    reason: str,
    *,
    code_id: int | None = None,
    batch_id: int | None = None,
) -> int:
    if code_id is not None:
        cursor = connection.execute(
            "UPDATE dm_activation_challenges SET status = 'expired', "
            "revoke_reason = ? WHERE license_code_id = ? "
            "AND status = 'issued'",
            (str(reason), int(code_id)),
        )
    elif batch_id is not None:
        cursor = connection.execute(
            "UPDATE dm_activation_challenges SET status = 'expired', "
            "revoke_reason = ? WHERE status = 'issued' AND "
            "license_code_id IN (SELECT id FROM dm_license_codes "
            "WHERE batch_id = ? AND status != 'activated')",
            (str(reason), int(batch_id)),
        )
    else:
        raise ValueError("code_id or batch_id is required")
    return int(cursor.rowcount or 0)


def _revoke_batch_entitlements(
    connection: sqlite3.Connection,
    batch_id: int,
    reason: str,
) -> tuple[int, int]:
    entitlements = [
        (str(row["entitlement_id"]), str(row["status"]))
        for row in connection.execute(
            "SELECT e.entitlement_id, e.status FROM dm_entitlements e "
            "LEFT JOIN dm_license_codes current_code "
            "ON current_code.id = e.source_license_code_id "
            "WHERE current_code.batch_id = ? OR ("
            "e.source_license_code_id IS NULL AND EXISTS ("
            "SELECT 1 FROM dm_license_activations historical_activation "
            "JOIN dm_license_codes historical_code "
            "ON historical_code.id = historical_activation.license_code_id "
            "WHERE historical_activation.entitlement_id = e.entitlement_id "
            "AND historical_code.batch_id = ?))",
            (int(batch_id), int(batch_id)),
        ).fetchall()
    ]
    revoked_entitlements = 0
    expired_binding_challenges = 0
    for entitlement_id, entitlement_status in entitlements:
        expired_binding_challenges += int(connection.execute(
            "UPDATE dm_activation_challenges SET status = 'expired', "
            "revoke_reason = 'license_batch_revoked' "
            "WHERE target_entitlement_id = ? AND status = 'issued'",
            (entitlement_id,),
        ).rowcount or 0)
        if entitlement_status != "revoked":
            connection.execute(
                "UPDATE dm_entitlements SET status = 'revoked', "
                "revocation_version = revocation_version + 1, "
                "updated_at = datetime('now'), revoked_at = datetime('now'), "
                "revoke_reason = ? WHERE entitlement_id = ?",
                (str(reason), entitlement_id),
            )
            revoked_entitlements += 1
        connection.execute(
            "UPDATE dm_usage_sessions SET status = 'revoked', "
            "ended_at_epoch = CAST(strftime('%s','now') AS INTEGER), "
            "ended_reason = 'license_batch_revoked' "
            "WHERE entitlement_id = ? AND status = 'active'",
            (entitlement_id,),
        )
        connection.execute(
            "UPDATE dm_usage_start_challenges SET status = 'expired' "
            "WHERE entitlement_id = ? AND status = 'issued'",
            (entitlement_id,),
        )
    return revoked_entitlements, expired_binding_challenges


def _normalize_expired_codes(
    connection: sqlite3.Connection,
    *,
    now_epoch: int,
    batch_id: int | None = None,
) -> int:
    clauses = [
        "status = 'issued'",
        "expires_at_epoch IS NOT NULL",
        "expires_at_epoch <= ?",
    ]
    params: list[Any] = [int(now_epoch)]
    if batch_id is not None:
        clauses.append("batch_id = ?")
        params.append(int(batch_id))
    where = " AND ".join(clauses)
    expired = int(connection.execute(
        "UPDATE dm_license_codes SET status = 'expired' WHERE " + where,
        params,
    ).rowcount or 0)
    challenge_clauses = [
        "status = 'issued'",
        (
            "license_code_id IN (SELECT id FROM dm_license_codes "
            "WHERE status = 'expired' AND expires_at_epoch IS NOT NULL "
            "AND expires_at_epoch <= ?"
        ),
    ]
    challenge_params: list[Any] = [int(now_epoch)]
    if batch_id is not None:
        challenge_clauses[-1] += " AND batch_id = ?"
        challenge_params.append(int(batch_id))
    challenge_clauses[-1] += ")"
    expired_challenges = int(connection.execute(
        "UPDATE dm_activation_challenges SET status = 'expired', "
        "revoke_reason = 'license_code_expired' WHERE "
        + " AND ".join(challenge_clauses),
        challenge_params,
    ).rowcount or 0)
    if not expired and not expired_challenges:
        return 0
    write_audit_event(
        connection,
        event_type="license_codes_expired",
        subject_type=("license_batch" if batch_id is not None else "license_codes"),
        subject_id=(str(batch_id) if batch_id is not None else "all"),
        detail={
            "expired_codes": expired,
            "expired_challenges": expired_challenges,
            "normalized_at_epoch": int(now_epoch),
        },
    )
    return expired


def _attach_device_bindings(
    connection: sqlite3.Connection,
    codes: list[dict[str, Any]],
) -> None:
    for code in codes:
        entitlement_id = str(code.get("entitlement_id") or "")
        code["device_bindings"] = (
            _device_bindings(connection, entitlement_id)
            if entitlement_id
            else []
        )


def _device_bindings(
    connection: sqlite3.Connection,
    entitlement_id: str,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT binding_id, pair_id, host_device_code, "
        "host_client_version, host_key_sha256, android_device_code, "
        "android_client_version, android_key_sha256, "
        "android_device_profile_json, is_current, created_at, last_seen_at "
        "FROM dm_entitlement_device_bindings WHERE entitlement_id = ? "
        "ORDER BY is_current DESC, created_at DESC",
        (str(entitlement_id),),
    ).fetchall()
    values: list[dict[str, Any]] = []
    for row in rows:
        value = dict(row)
        value["is_current"] = bool(value["is_current"])
        try:
            profile = json.loads(value.pop("android_device_profile_json"))
        except (TypeError, ValueError):
            profile = {}
        value["android_device_profile"] = (
            profile if isinstance(profile, dict) else {}
        )
        values.append(value)
    return values


def _public_product(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["enabled"] = bool(value["enabled"])
    value["is_permanent"] = value["authorization_kind"] == "permanent"
    if value["is_permanent"]:
        value["duration_seconds"] = 0
    return value


def _public_batch(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    for key in (
        "issued_count",
        "activated_count",
        "revoked_count",
        "expired_count",
        "deleted_count",
    ):
        value[key] = int(value.get(key) or 0)
    value["deleted"] = value.get("deleted_at") is not None
    value["is_permanent"] = value.get("authorization_kind") == "permanent"
    return value


def _public_batch_header(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["deleted"] = value.get("deleted_at") is not None
    value["is_permanent"] = value.get("authorization_kind") == "permanent"
    return value


def _public_code(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["code_suffix"] = str(value.get("code_suffix") or "")
    value["deleted"] = value.get("deleted_at") is not None
    value["revoked_by_batch"] = bool(value.get("revoked_by_batch"))
    value["deleted_by_batch"] = bool(value.get("deleted_by_batch"))
    value["is_permanent"] = value.get("authorization_kind") == "permanent"
    if value["is_permanent"]:
        value["duration_seconds"] = 0
    return value


def _public_audit(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    raw_detail = value.pop("detail_json", "{}")
    try:
        detail = json.loads(str(raw_detail or "{}"))
    except ValueError:
        detail = {}
    value["detail"] = detail if isinstance(detail, dict) else {}
    return value


def _reason(value: str) -> str:
    reason = str(value or "").strip()
    if not 2 <= len(reason) <= 200:
        raise ValueError("reason must contain 2 to 200 characters")
    return reason


def _note(value: str) -> str:
    note = str(value or "").strip()
    if len(note) > 500:
        raise ValueError("note must contain at most 500 characters")
    return note


def _expiry(value: int | None) -> int | None:
    if value is None:
        return None
    expiry = int(value)
    now = int(time.time())
    if not now < expiry <= now + MAX_CODE_EXPIRY_SECONDS:
        raise ValueError("expires_at_epoch is invalid")
    return expiry


def _limit(value: int, *, maximum: int = 500) -> int:
    try:
        return max(1, min(int(value), maximum))
    except (TypeError, ValueError):
        return 50


def _offset(value: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _positive_id(value: int) -> int:
    normalized = int(value)
    if normalized <= 0:
        raise ValueError("id must be positive")
    return normalized


def _hex_identifier(value: object, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not is_nonzero_lower_hex(normalized, 32):
        raise ValueError(f"{name} is invalid")
    return normalized


def _optional_status(value: str, allowed: set[str]) -> str:
    status = str(value or "").strip().lower()
    if status and status not in allowed:
        raise ValueError("status is invalid")
    return status


def _query(value: str) -> str:
    query = str(value or "").strip()
    if len(query) > 128:
        raise ValueError("query is too long")
    return query


def _like_pattern(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\")
    escaped = escaped.replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _deleted_clause(
    column: str,
    deleted: bool | None,
) -> tuple[list[str], list[Any]]:
    if deleted is None:
        return [], []
    return [f"{column} IS {'NOT ' if bool(deleted) else ''}NULL"], []


def _where(clauses: list[str]) -> str:
    return "WHERE " + " AND ".join(clauses) if clauses else ""


def _nullable_int(value: Any) -> int | None:
    return int(value) if value is not None else None
