"""Proof-bound activation of pair-generation security state.

Only the card activation service creates the private proof capability, and it
does so after verifying both device signatures twice (including once inside
the write transaction).  This module has no public ``activate_pair`` shortcut.
"""
from __future__ import annotations

import hmac
import sqlite3
from dataclasses import dataclass

from .contracts import (
    ACTIVATION_MODE_ACTIVATE,
    ACTIVATION_MODE_BIND_DEVICE,
    ACTIVATION_MODE_REACTIVATE,
)
from .pair_security_repository import (
    SIGNED_64_MAX,
    PairSecurityRepository,
    PairSecurityRepositoryError,
    PairSecurityState,
    _PairIdentity,
    _required_state,
    _state_from_row,
)
from .validation import is_nonzero_lower_hex


_PROOF_TOKEN = object()


class PairSecurityBootstrapError(RuntimeError):
    """Stable failure for a proof/state mismatch."""

    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class _VerifiedActivationBindingProof:
    challenge_id: str
    activation_mode: str
    target_entitlement_id: str
    pair_id: str
    host_key_sha256: str
    android_key_sha256: str
    _token: object


@dataclass(frozen=True, slots=True)
class _PairSecurityBootstrapResult:
    state: PairSecurityState
    changed: bool
    predecessor_pair_id: str | None


def _verified_activation_binding_proof(
    challenge: dict[str, object],
) -> _VerifiedActivationBindingProof:
    """Mint the private capability after both signatures were verified."""
    mode = str(challenge.get("activation_mode") or "")
    target = str(challenge.get("target_entitlement_id") or "")
    challenge_id = str(challenge.get("challenge_id") or "")
    pair_id = str(challenge.get("pair_id") or "")
    host_hash = str(challenge.get("host_key_sha256") or "")
    android_hash = str(challenge.get("android_key_sha256") or "")
    if (
        mode not in {
            ACTIVATION_MODE_ACTIVATE,
            ACTIVATION_MODE_REACTIVATE,
            ACTIVATION_MODE_BIND_DEVICE,
        }
        or not is_nonzero_lower_hex(challenge_id, 32)
        or not is_nonzero_lower_hex(pair_id, 32)
        or not is_nonzero_lower_hex(host_hash, 64)
        or not is_nonzero_lower_hex(android_hash, 64)
        or hmac.compare_digest(host_hash, android_hash)
        or (mode == ACTIVATION_MODE_ACTIVATE and target)
        or (
            mode != ACTIVATION_MODE_ACTIVATE
            and not is_nonzero_lower_hex(target, 32)
        )
    ):
        raise PairSecurityBootstrapError(
            "pair_security_activation_proof_invalid",
        )
    return _VerifiedActivationBindingProof(
        challenge_id=challenge_id,
        activation_mode=mode,
        target_entitlement_id=target,
        pair_id=pair_id,
        host_key_sha256=host_hash,
        android_key_sha256=android_hash,
        _token=_PROOF_TOKEN,
    )


class _PairSecurityBootstrapService:
    """Commit only a verified activation/binding proof in its caller's txn."""

    __slots__ = ()

    def commit_verified_binding(
        self,
        connection: sqlite3.Connection,
        *,
        proof: _VerifiedActivationBindingProof,
        entitlement_id: str,
        now_epoch: int,
    ) -> _PairSecurityBootstrapResult:
        if (
            type(connection) is not sqlite3.Connection
            or not connection.in_transaction
            or type(proof) is not _VerifiedActivationBindingProof
            or proof._token is not _PROOF_TOKEN
            or not is_nonzero_lower_hex(entitlement_id, 32)
            or type(now_epoch) is not int
            or not 1 <= now_epoch <= SIGNED_64_MAX
        ):
            raise PairSecurityBootstrapError(
                "pair_security_bootstrap_input_invalid",
            )
        if (
            proof.activation_mode != ACTIVATION_MODE_ACTIVATE
            and not hmac.compare_digest(
                proof.target_entitlement_id,
                entitlement_id,
            )
        ):
            raise PairSecurityBootstrapError(
                "pair_security_bootstrap_entitlement_mismatch",
            )
        live = _live_binding(connection, entitlement_id)
        _require_proof_matches_live_binding(live, proof)
        states = _entitlement_states(connection, entitlement_id)
        current = next(
            (state for state in states if state.pair_id == proof.pair_id),
            None,
        )
        try:
            if proof.activation_mode == ACTIVATION_MODE_REACTIVATE:
                return _commit_reactivation(
                    connection,
                    current=current,
                    live=live,
                    now_epoch=now_epoch,
                )
            if current is not None:
                _require_state_matches_live(current, live)
                active = _activate_existing_state(
                    connection,
                    current,
                    now_epoch=now_epoch,
                )
                return _PairSecurityBootstrapResult(
                    state=active,
                    changed=active != current,
                    predecessor_pair_id=active.predecessor_pair_id,
                )
            predecessor = _predecessor_for_new_binding(
                proof.activation_mode,
                states,
            )
            if predecessor is not None:
                _rotate_predecessor(
                    connection,
                    predecessor,
                    now_epoch=now_epoch,
                )
            identity = _PairIdentity.normalize(
                pair_id=proof.pair_id,
                entitlement_id=entitlement_id,
                binding_id=str(live["binding_id"]),
                revocation_version=int(live["revocation_version"]),
                host_key_sha256=proof.host_key_sha256,
                android_key_sha256=proof.android_key_sha256,
            )
            pending = PairSecurityRepository._register_pending(
                connection,
                identity=identity,
                predecessor_pair_id=(
                    predecessor.pair_id if predecessor is not None else None
                ),
                now_epoch=now_epoch,
            )
            active = _activate_existing_state(
                connection,
                pending,
                now_epoch=now_epoch,
            )
            return _PairSecurityBootstrapResult(
                state=active,
                changed=True,
                predecessor_pair_id=(
                    predecessor.pair_id if predecessor is not None else None
                ),
            )
        except PairSecurityBootstrapError:
            raise
        except PairSecurityRepositoryError as exc:
            raise PairSecurityBootstrapError(
                "pair_security_bootstrap_conflict",
            ) from exc


def _live_binding(
    connection: sqlite3.Connection,
    entitlement_id: str,
) -> sqlite3.Row:
    rows = connection.execute(
        "SELECT e.entitlement_id, e.pair_id AS entitlement_pair_id, "
        "e.status AS entitlement_status, e.revocation_version, "
        "b.binding_id, b.pair_id AS binding_pair_id, "
        "b.host_key_sha256, b.android_key_sha256 "
        "FROM dm_entitlements e JOIN dm_entitlement_device_bindings b "
        "ON b.entitlement_id = e.entitlement_id "
        "WHERE e.entitlement_id = ? AND b.is_current = 1",
        (entitlement_id,),
    ).fetchall()
    if len(rows) != 1 or str(rows[0]["entitlement_status"]) != "active":
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_live_binding_invalid",
        )
    return rows[0]


def _require_proof_matches_live_binding(
    live: sqlite3.Row,
    proof: _VerifiedActivationBindingProof,
) -> None:
    if (
        str(live["entitlement_pair_id"]) != proof.pair_id
        or str(live["binding_pair_id"]) != proof.pair_id
        or not hmac.compare_digest(
            str(live["host_key_sha256"]),
            proof.host_key_sha256,
        )
        or not hmac.compare_digest(
            str(live["android_key_sha256"]),
            proof.android_key_sha256,
        )
    ):
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_binding_mismatch",
        )


def _entitlement_states(
    connection: sqlite3.Connection,
    entitlement_id: str,
) -> tuple[PairSecurityState, ...]:
    rows = connection.execute(
        "SELECT * FROM dm_pair_security_state WHERE entitlement_id = ? "
        "ORDER BY binding_revision DESC",
        (entitlement_id,),
    ).fetchall()
    return tuple(_state_from_row(row) for row in rows)


def _require_state_matches_live(
    state: PairSecurityState,
    live: sqlite3.Row,
) -> None:
    if (
        state.binding_id != str(live["binding_id"])
        or state.revocation_version != int(live["revocation_version"])
        or not hmac.compare_digest(
            state.host_key_sha256,
            str(live["host_key_sha256"]),
        )
        or not hmac.compare_digest(
            state.android_key_sha256,
            str(live["android_key_sha256"]),
        )
    ):
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_state_mismatch",
        )


def _predecessor_for_new_binding(
    activation_mode: str,
    states: tuple[PairSecurityState, ...],
) -> PairSecurityState | None:
    if activation_mode == ACTIVATION_MODE_ACTIVATE:
        if states:
            raise PairSecurityBootstrapError(
                "pair_security_bootstrap_unexpected_predecessor",
            )
        return None
    if activation_mode != ACTIVATION_MODE_BIND_DEVICE or not states:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_predecessor_missing",
        )
    return states[0]


def _commit_reactivation(
    connection: sqlite3.Connection,
    *,
    current: PairSecurityState | None,
    live: sqlite3.Row,
    now_epoch: int,
) -> _PairSecurityBootstrapResult:
    if current is None:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_reactivation_state_missing",
        )
    live_revocation_version = int(live["revocation_version"])
    if (
        current.binding_id != str(live["binding_id"])
        or not hmac.compare_digest(
            current.host_key_sha256,
            str(live["host_key_sha256"]),
        )
        or not hmac.compare_digest(
            current.android_key_sha256,
            str(live["android_key_sha256"]),
        )
    ):
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_reactivation_binding_mismatch",
        )
    if live_revocation_version != current.revocation_version + 1:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_reactivation_revision_invalid",
        )
    recovery = _transition_to_recovery(
        connection,
        current,
        now_epoch=now_epoch,
    )
    cursor = connection.execute(
        "UPDATE dm_pair_security_state SET assurance_state = 'active', "
        "revocation_version = ?, updated_at_epoch = ? "
        "WHERE pair_id = ? AND assurance_state = 'recovery_pending' "
        "AND revocation_version = ? AND generation_high_water = ?",
        (
            live_revocation_version,
            max(now_epoch, recovery.updated_at_epoch),
            recovery.pair_id,
            recovery.revocation_version,
            recovery.generation_high_water,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_reactivation_cas_failed",
        )
    active = _required_state(connection, recovery.pair_id)
    return _PairSecurityBootstrapResult(
        state=active,
        changed=True,
        predecessor_pair_id=active.predecessor_pair_id,
    )


def _activate_existing_state(
    connection: sqlite3.Connection,
    state: PairSecurityState,
    *,
    now_epoch: int,
) -> PairSecurityState:
    current = state
    if current.assurance_state == "active":
        return current
    if current.assurance_state == "legacy_blocked":
        current = _transition_state(
            connection,
            current,
            target_state="recovery_pending",
            now_epoch=now_epoch,
        )
    if current.assurance_state not in {"pending", "recovery_pending"}:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_state_not_activatable",
        )
    return _transition_state(
        connection,
        current,
        target_state="active",
        now_epoch=now_epoch,
    )


def _transition_to_recovery(
    connection: sqlite3.Connection,
    state: PairSecurityState,
    *,
    now_epoch: int,
) -> PairSecurityState:
    if state.assurance_state == "recovery_pending":
        return state
    if state.assurance_state not in {"active", "legacy_blocked"}:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_recovery_not_allowed",
        )
    return _transition_state(
        connection,
        state,
        target_state="recovery_pending",
        now_epoch=now_epoch,
    )


def _rotate_predecessor(
    connection: sqlite3.Connection,
    state: PairSecurityState,
    *,
    now_epoch: int,
) -> PairSecurityState:
    current = state
    if current.assurance_state in {"rotated", "revoked"}:
        return current
    if current.assurance_state == "legacy_blocked":
        current = _transition_state(
            connection,
            current,
            target_state="recovery_pending",
            now_epoch=now_epoch,
        )
    if current.assurance_state not in {
        "active",
        "pending",
        "recovery_pending",
    }:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_predecessor_not_rotatable",
        )
    return _transition_state(
        connection,
        current,
        target_state="rotated",
        now_epoch=now_epoch,
    )


def _transition_state(
    connection: sqlite3.Connection,
    state: PairSecurityState,
    *,
    target_state: str,
    now_epoch: int,
) -> PairSecurityState:
    cursor = connection.execute(
        "UPDATE dm_pair_security_state SET assurance_state = ?, "
        "updated_at_epoch = ? WHERE pair_id = ? AND assurance_state = ? "
        "AND binding_revision = ? AND revocation_version = ? "
        "AND generation_high_water = ?",
        (
            target_state,
            max(now_epoch, state.updated_at_epoch),
            state.pair_id,
            state.assurance_state,
            state.binding_revision,
            state.revocation_version,
            state.generation_high_water,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise PairSecurityBootstrapError(
            "pair_security_bootstrap_transition_cas_failed",
        )
    return _required_state(connection, state.pair_id)


__all__: tuple[str, ...] = ()
