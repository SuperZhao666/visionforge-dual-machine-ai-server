"""Bounded, filesystem-safe retention for uploaded client log bundles."""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import config
from app.database import get_connection

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 30
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365
DEFAULT_BATCH_SIZE = 100
MAX_BATCH_SIZE = 1_000

_OUTCOME_MISSING = "missing"
_OUTCOME_REMOVABLE = "removable"
_OUTCOME_REMOVED = "removed"
_OUTCOME_RETAINED = "retained"


def _supports_secure_dir_fd_deletion() -> bool:
    """Return whether Python exposes the POSIX openat/unlinkat primitives we need."""
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.unlink in os.supports_dir_fd
    )


_SECURE_DIR_FD_DELETION = _supports_secure_dir_fd_deletion()


@dataclass(frozen=True, slots=True)
class _TrustedStorageRoot:
    configured_path: Path | None
    lexical_path: Path | None
    trusted_path: Path | None
    identity: tuple[int, int] | None
    dir_fd: int | None
    error: str | None
    uses_dir_fd: bool


@dataclass(frozen=True, slots=True)
class _FileOperation:
    outcome: str
    file_size: int = 0
    reason: str | None = None
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class _FallbackSnapshot:
    path: Path
    file_size: int
    identities: tuple[tuple[int, int], ...]


def _bounded_positive_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def configured_retention_days(conn) -> int:
    """Read the global log retention policy without changing it."""
    row = conn.execute(
        "SELECT retention_days FROM log_upload_settings WHERE id = 1"
    ).fetchone()
    return _bounded_positive_int(
        row["retention_days"] if row else None,
        DEFAULT_RETENTION_DAYS,
        MAX_RETENTION_DAYS,
    )


def _node_identity(node_stat: os.stat_result) -> tuple[int, int]:
    return node_stat.st_dev, node_stat.st_ino


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        # The descriptor is no longer usable either way. Never mask the retention result.
        logger.warning("log_retention_fd_close_failed", exc_info=True)


def _failed_storage_root(
    configured_path: Path | None,
    lexical_path: Path | None,
    reason: str,
    *,
    uses_dir_fd: bool,
) -> _TrustedStorageRoot:
    return _TrustedStorageRoot(
        configured_path=configured_path,
        lexical_path=lexical_path,
        trusted_path=None,
        identity=None,
        dir_fd=None,
        error=reason,
        uses_dir_fd=uses_dir_fd,
    )


def _configured_storage_root(
    raw_value: Any,
) -> tuple[Path | None, Path | None, str | None]:
    """Parse the configured root without resolving or following any filesystem node."""
    if not isinstance(raw_value, (str, os.PathLike)):
        return None, None, "storage_root_config_invalid"
    try:
        raw_path = os.fspath(raw_value)
        if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
            return None, None, "storage_root_config_invalid"
        configured_path = Path(raw_path)
        lexical_path = Path(os.path.abspath(configured_path))
    except (OSError, TypeError, ValueError):
        return None, None, "storage_root_config_invalid"
    return configured_path, lexical_path, None


def _ensure_storage_root_exists(raw_value: Any) -> None:
    """Preserve non-dry-run bootstrap semantics before the root is trusted."""
    _, lexical_path, config_error = _configured_storage_root(raw_value)
    if config_error is not None or lexical_path is None:
        return
    try:
        lexical_path.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError):
        # The trusted-open step converts this into a per-row, fail-closed error.
        logger.warning("log_storage_root_create_failed", exc_info=True)


def _open_trusted_storage_root(raw_value: Any) -> _TrustedStorageRoot:
    """Open and identify the configured root, rejecting links and unstable nodes."""
    configured_path, lexical_path, config_error = _configured_storage_root(raw_value)
    if config_error is not None or lexical_path is None:
        return _failed_storage_root(
            configured_path,
            lexical_path,
            config_error or "storage_root_config_invalid",
            uses_dir_fd=_SECURE_DIR_FD_DELETION,
        )

    try:
        before = os.lstat(lexical_path)
    except (OSError, ValueError):
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_lstat_failed",
            uses_dir_fd=_SECURE_DIR_FD_DELETION,
        )
    if stat.S_ISLNK(before.st_mode):
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_symlink_rejected",
            uses_dir_fd=_SECURE_DIR_FD_DELETION,
        )
    if not stat.S_ISDIR(before.st_mode):
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_not_directory",
            uses_dir_fd=_SECURE_DIR_FD_DELETION,
        )
    if _SECURE_DIR_FD_DELETION:
        return _open_posix_storage_root(configured_path, lexical_path, before)
    return _open_fallback_storage_root(configured_path, lexical_path, before)


def _open_posix_storage_root(
    configured_path: Path,
    lexical_path: Path,
    before: os.stat_result,
) -> _TrustedStorageRoot:
    """Bind the root identity to a directory FD without following its final node."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    root_fd: int | None = None
    try:
        root_fd = os.open(lexical_path, flags)
        opened = os.fstat(root_fd)
        after = os.lstat(lexical_path)
    except (OSError, ValueError):
        _close_fd(root_fd)
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_open_failed",
            uses_dir_fd=True,
        )

    identity = _node_identity(before)
    identities_match = _node_identity(opened) == identity == _node_identity(after)
    nodes_are_directories = stat.S_ISDIR(opened.st_mode) and stat.S_ISDIR(after.st_mode)
    if not identities_match or not nodes_are_directories or stat.S_ISLNK(after.st_mode):
        _close_fd(root_fd)
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_identity_changed",
            uses_dir_fd=True,
        )
    return _TrustedStorageRoot(
        configured_path=configured_path,
        lexical_path=lexical_path,
        trusted_path=lexical_path,
        identity=identity,
        dir_fd=root_fd,
        error=None,
        uses_dir_fd=True,
    )


def _open_fallback_storage_root(
    configured_path: Path,
    lexical_path: Path,
    before: os.stat_result,
) -> _TrustedStorageRoot:
    """Validate a root for platforms without directory-relative deletion support."""
    try:
        trusted_path = lexical_path.resolve(strict=True)
        opened = os.stat(trusted_path)
        after = os.lstat(lexical_path)
    except (OSError, RuntimeError, ValueError):
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_open_failed",
            uses_dir_fd=False,
        )
    identity = _node_identity(before)
    identities_match = _node_identity(opened) == identity == _node_identity(after)
    nodes_are_directories = stat.S_ISDIR(opened.st_mode) and stat.S_ISDIR(after.st_mode)
    if not identities_match or not nodes_are_directories or stat.S_ISLNK(after.st_mode):
        return _failed_storage_root(
            configured_path,
            lexical_path,
            "storage_root_identity_changed",
            uses_dir_fd=False,
        )
    return _TrustedStorageRoot(
        configured_path=configured_path,
        lexical_path=lexical_path,
        trusted_path=trusted_path,
        identity=identity,
        dir_fd=None,
        error=None,
        uses_dir_fd=False,
    )


def _close_trusted_storage_root(storage_root: _TrustedStorageRoot) -> None:
    _close_fd(storage_root.dir_fd)


def _current_root_error(storage_root: _TrustedStorageRoot) -> str | None:
    """Fail closed if the configured root name no longer identifies the opened root."""
    if storage_root.error is not None:
        return storage_root.error
    if storage_root.lexical_path is None or storage_root.identity is None:
        return "storage_root_not_trusted"
    try:
        current = os.lstat(storage_root.lexical_path)
    except (OSError, ValueError):
        return "storage_root_lstat_failed"
    if stat.S_ISLNK(current.st_mode):
        return "storage_root_symlink_rejected"
    if not stat.S_ISDIR(current.st_mode):
        return "storage_root_not_directory"
    if _node_identity(current) != storage_root.identity:
        return "storage_root_identity_changed"
    if storage_root.dir_fd is not None:
        try:
            opened = os.fstat(storage_root.dir_fd)
        except OSError:
            return "storage_root_fd_invalid"
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _node_identity(opened) != storage_root.identity
        ):
            return "storage_root_identity_changed"
    return None


def _relative_storage_parts(
    storage_root: _TrustedStorageRoot,
    stored_value: Any,
) -> tuple[tuple[str, ...] | None, str | None]:
    """Convert a DB value to non-empty lexical components beneath the configured root."""
    if storage_root.error is not None:
        return None, storage_root.error
    if storage_root.configured_path is None or storage_root.lexical_path is None:
        return None, "storage_root_not_trusted"
    if not isinstance(stored_value, str):
        return None, "storage_path_malformed"
    if not stored_value.strip():
        return None, "storage_path_empty"
    if "\x00" in stored_value:
        return None, "storage_path_malformed"

    try:
        raw_path = Path(stored_value)
        if ".." in raw_path.parts:
            return None, "path_outside_storage_root"
        if raw_path.is_absolute():
            candidate = Path(os.path.abspath(raw_path))
        else:
            relative_input = raw_path
            configured_path = storage_root.configured_path
            if not configured_path.is_absolute():
                try:
                    relative_input = raw_path.relative_to(configured_path)
                except ValueError:
                    pass
            candidate = Path(
                os.path.abspath(storage_root.lexical_path / relative_input)
            )
        relative_path = candidate.relative_to(storage_root.lexical_path)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None, "path_outside_storage_root"

    parts = relative_path.parts
    if not parts:
        return None, "storage_path_is_root"
    if any(part in {"", ".", ".."} for part in parts):
        return None, "storage_path_malformed"
    return tuple(parts), None


def _retained(reason: str, error_type: str | None = None) -> _FileOperation:
    return _FileOperation(_OUTCOME_RETAINED, reason=reason, error_type=error_type)


def _open_directory_at(
    parent_fd: int, name: str
) -> tuple[int | None, str | None, str | None]:
    """Open one stable directory component relative to a previously trusted FD."""
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, _OUTCOME_MISSING, None
    except OSError as exc:
        return None, "path_lstat_failed", type(exc).__name__
    if stat.S_ISLNK(before.st_mode):
        return None, "symlink_rejected", None
    if not stat.S_ISDIR(before.st_mode):
        return None, "path_component_not_directory", None

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    child_fd: int | None = None
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(child_fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        _close_fd(child_fd)
        return None, "path_component_identity_changed", None
    except OSError as exc:
        _close_fd(child_fd)
        return None, "path_component_open_failed", type(exc).__name__

    identity = _node_identity(before)
    identities_match = _node_identity(opened) == identity == _node_identity(after)
    nodes_are_directories = stat.S_ISDIR(opened.st_mode) and stat.S_ISDIR(after.st_mode)
    if not identities_match or not nodes_are_directories or stat.S_ISLNK(after.st_mode):
        _close_fd(child_fd)
        return None, "path_component_identity_changed", None
    return child_fd, None, None


def _operate_regular_file_at(
    storage_root: _TrustedStorageRoot,
    parent_fd: int,
    name: str,
    *,
    delete: bool,
) -> _FileOperation:
    """Inspect and optionally unlink one regular file through its trusted parent FD."""
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return _FileOperation(_OUTCOME_MISSING)
    except OSError as exc:
        return _retained("path_lstat_failed", type(exc).__name__)
    if stat.S_ISLNK(before.st_mode):
        return _retained("symlink_rejected")
    if not stat.S_ISREG(before.st_mode):
        return _retained("not_regular_file")

    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    file_fd: int | None = None
    try:
        file_fd = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = _node_identity(before)
        identities_match = _node_identity(opened) == identity == _node_identity(after)
        nodes_are_regular = stat.S_ISREG(opened.st_mode) and stat.S_ISREG(after.st_mode)
        if not identities_match or not nodes_are_regular or stat.S_ISLNK(after.st_mode):
            return _retained("file_identity_changed")

        root_error = _current_root_error(storage_root)
        if root_error is not None:
            return _retained(root_error)
        if not delete:
            return _FileOperation(_OUTCOME_REMOVABLE, file_size=opened.st_size)
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            return _retained("unlink_failed", type(exc).__name__)
        return _FileOperation(_OUTCOME_REMOVED, file_size=opened.st_size)
    except FileNotFoundError:
        return _retained("file_identity_changed")
    except OSError as exc:
        return _retained("file_open_failed", type(exc).__name__)
    finally:
        _close_fd(file_fd)


def _operate_storage_file_posix(
    storage_root: _TrustedStorageRoot,
    parts: tuple[str, ...],
    *,
    delete: bool,
) -> _FileOperation:
    root_error = _current_root_error(storage_root)
    if root_error is not None:
        return _retained(root_error)
    if storage_root.dir_fd is None:
        return _retained("storage_root_fd_invalid")

    try:
        parent_fd = os.dup(storage_root.dir_fd)
    except OSError as exc:
        return _retained("storage_root_dup_failed", type(exc).__name__)
    try:
        for component in parts[:-1]:
            child_fd, error, error_type = _open_directory_at(parent_fd, component)
            if error == _OUTCOME_MISSING:
                return _FileOperation(_OUTCOME_MISSING)
            if error is not None or child_fd is None:
                return _retained(error or "path_component_open_failed", error_type)
            _close_fd(parent_fd)
            parent_fd = child_fd
        return _operate_regular_file_at(
            storage_root,
            parent_fd,
            parts[-1],
            delete=delete,
        )
    finally:
        _close_fd(parent_fd)


def _fallback_snapshot(
    storage_root: _TrustedStorageRoot,
    parts: tuple[str, ...],
) -> tuple[_FallbackSnapshot | None, str | None, str | None]:
    if storage_root.trusted_path is None:
        return None, "storage_root_not_trusted", None
    current = storage_root.trusted_path
    identities: list[tuple[int, int]] = []
    for index, component in enumerate(parts):
        current /= component
        try:
            node = os.lstat(current)
        except FileNotFoundError:
            return None, _OUTCOME_MISSING, None
        except OSError as exc:
            return None, "path_lstat_failed", type(exc).__name__
        if stat.S_ISLNK(node.st_mode):
            return None, "symlink_rejected", None
        is_final = index == len(parts) - 1
        if not is_final and not stat.S_ISDIR(node.st_mode):
            return None, "path_component_not_directory", None
        if is_final and not stat.S_ISREG(node.st_mode):
            return None, "not_regular_file", None
        identities.append(_node_identity(node))
    return _FallbackSnapshot(current, node.st_size, tuple(identities)), None, None


def _operate_storage_file_fallback(
    storage_root: _TrustedStorageRoot,
    parts: tuple[str, ...],
    *,
    delete: bool,
) -> _FileOperation:
    """Compatibility path for Windows and runtimes without unlink(dir_fd=...).

    Repeated lstat and identity checks reject observed traversal and node swaps, but
    these platforms cannot bind the final validation atomically to deletion. The
    deployment ACL must therefore prevent untrusted writers from renaming storage
    directories while retention runs. POSIX uses the directory-FD path above.
    """
    root_error = _current_root_error(storage_root)
    if root_error is not None:
        return _retained(root_error)
    snapshot, error, error_type = _fallback_snapshot(storage_root, parts)
    if error == _OUTCOME_MISSING:
        return _FileOperation(_OUTCOME_MISSING)
    if error is not None or snapshot is None:
        return _retained(error or "path_lstat_failed", error_type)
    if not delete:
        return _FileOperation(_OUTCOME_REMOVABLE, file_size=snapshot.file_size)

    root_error = _current_root_error(storage_root)
    if root_error is not None:
        return _retained(root_error)
    final_snapshot, final_error, final_error_type = _fallback_snapshot(
        storage_root, parts
    )
    if final_error is not None or final_snapshot is None:
        reason = (
            "path_identity_changed" if final_error == _OUTCOME_MISSING else final_error
        )
        return _retained(reason or "path_identity_changed", final_error_type)
    if final_snapshot.identities != snapshot.identities:
        return _retained("path_identity_changed")
    try:
        os.unlink(final_snapshot.path)
    except OSError as exc:
        return _retained("unlink_failed", type(exc).__name__)
    return _FileOperation(_OUTCOME_REMOVED, file_size=final_snapshot.file_size)


def _operate_storage_file(
    storage_root: _TrustedStorageRoot,
    stored_value: Any,
    *,
    delete: bool,
) -> _FileOperation:
    parts, path_error = _relative_storage_parts(storage_root, stored_value)
    if path_error is not None or parts is None:
        return _retained(path_error or "storage_path_malformed")
    if storage_root.uses_dir_fd:
        return _operate_storage_file_posix(storage_root, parts, delete=delete)
    return _operate_storage_file_fallback(storage_root, parts, delete=delete)


def _delete_file_row(conn, file_id: int) -> bool:
    conn.execute("BEGIN IMMEDIATE")
    try:
        deleted = (
            conn.execute("DELETE FROM log_files WHERE id = ?", (file_id,)).rowcount == 1
        )
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise


def _record_retained_file(
    result: dict[str, Any], file_id: int, operation: _FileOperation
) -> None:
    result["files_retained"] += 1
    error = {
        "file_id": file_id,
        "reason": operation.reason or "storage_path_processing_failed",
    }
    if operation.error_type is not None:
        error["error_type"] = operation.error_type
    result["errors"].append(error)


def _purge_file_candidate(
    conn,
    storage_root: _TrustedStorageRoot,
    row,
    dry_run: bool,
    result: dict[str, Any],
) -> None:
    file_id = int(row["id"])
    try:
        operation = _operate_storage_file(
            storage_root,
            row["storage_path"],
            delete=not dry_run,
        )
    except Exception as exc:
        # A malformed legacy row must not prevent later candidates from being handled.
        logger.exception(
            "log_retention_candidate_processing_failed",
            extra={"file_id": file_id},
        )
        operation = _retained("storage_path_processing_failed", type(exc).__name__)

    if operation.outcome == _OUTCOME_RETAINED:
        _record_retained_file(result, file_id, operation)
        return
    if dry_run:
        if operation.outcome in {_OUTCOME_MISSING, _OUTCOME_REMOVABLE}:
            result["files_would_remove"] += 1
        else:
            _record_retained_file(
                result,
                file_id,
                _retained("storage_path_processing_failed"),
            )
        return
    if operation.outcome not in {_OUTCOME_MISSING, _OUTCOME_REMOVED}:
        _record_retained_file(
            result,
            file_id,
            _retained("storage_path_processing_failed"),
        )
        return

    deleted = _delete_file_row(conn, file_id)
    if deleted:
        result["database_rows_removed"] += 1
    if operation.outcome == _OUTCOME_REMOVED:
        result["files_removed"] += 1
        result["deleted_bytes"] += operation.file_size


def _purge_expired_files(
    conn,
    storage_root: _TrustedStorageRoot,
    cutoff: str,
    batch_size: int,
    dry_run: bool,
    result: dict[str, Any],
) -> None:
    last_uploaded_at = ""
    last_id = 0
    while True:
        rows = conn.execute(
            "SELECT id, storage_path, uploaded_at FROM log_files WHERE uploaded_at < ? "
            "AND (uploaded_at > ? OR (uploaded_at = ? AND id > ?)) "
            "ORDER BY uploaded_at, id LIMIT ?",
            (cutoff, last_uploaded_at, last_uploaded_at, last_id, batch_size),
        ).fetchall()
        if not rows:
            return
        result["file_candidates"] += len(rows)
        for row in rows:
            _purge_file_candidate(conn, storage_root, row, dry_run, result)
        last_uploaded_at = str(rows[-1]["uploaded_at"])
        last_id = int(rows[-1]["id"])
        if len(rows) < batch_size:
            return


def _purge_empty_sessions(
    conn,
    cutoff: str,
    batch_size: int,
    dry_run: bool,
    result: dict[str, Any],
) -> None:
    last_activity = ""
    last_id = 0
    while True:
        rows = conn.execute(
            "SELECT ls.id, COALESCE(ls.latest_upload_at, ls.started_at) AS activity_at "
            "FROM log_sessions ls WHERE NOT EXISTS "
            "(SELECT 1 FROM log_files lf WHERE lf.session_id = ls.id) "
            "AND COALESCE(ls.latest_upload_at, ls.started_at) < ? "
            "AND (COALESCE(ls.latest_upload_at, ls.started_at) > ? "
            "OR (COALESCE(ls.latest_upload_at, ls.started_at) = ? AND ls.id > ?)) "
            "ORDER BY activity_at, ls.id LIMIT ?",
            (cutoff, last_activity, last_activity, last_id, batch_size),
        ).fetchall()
        if not rows:
            return
        result["empty_session_candidates"] += len(rows)
        if dry_run:
            result["empty_sessions_would_remove"] += len(rows)
        else:
            ids = [int(row["id"]) for row in rows]
            placeholders = ",".join("?" for _ in ids)
            conn.execute("BEGIN IMMEDIATE")
            try:
                removed = conn.execute(
                    f"DELETE FROM log_sessions WHERE id IN ({placeholders}) "
                    "AND NOT EXISTS (SELECT 1 FROM log_files WHERE log_files.session_id = log_sessions.id)",
                    ids,
                ).rowcount
                conn.commit()
                result["empty_sessions_removed"] += removed
            except Exception:
                conn.rollback()
                raise
        last_activity = str(rows[-1]["activity_at"])
        last_id = int(rows[-1]["id"])
        if len(rows) < batch_size:
            return


def purge_expired_log_storage(
    *,
    dry_run: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Remove expired files first, then their DB rows and old empty sessions."""
    safe_batch_size = _bounded_positive_int(
        batch_size, DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE
    )
    current_time = now or datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "dry_run": dry_run,
        "retention_days": DEFAULT_RETENTION_DAYS,
        "cutoff": "",
        "filesystem_delete_mode": (
            "posix_dir_fd"
            if _SECURE_DIR_FD_DELETION
            else "compatibility_path_validation"
        ),
        "file_candidates": 0,
        "files_would_remove": 0,
        "files_removed": 0,
        "files_retained": 0,
        "database_rows_removed": 0,
        "deleted_bytes": 0,
        "empty_session_candidates": 0,
        "empty_sessions_would_remove": 0,
        "empty_sessions_removed": 0,
        "errors": [],
    }
    conn = get_connection()
    if not dry_run:
        _ensure_storage_root_exists(config.LOG_STORAGE_PATH)
    storage_root = _open_trusted_storage_root(config.LOG_STORAGE_PATH)
    try:
        retention_days = configured_retention_days(conn)
        cutoff_time = current_time - timedelta(days=retention_days)
        cutoff = cutoff_time.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        result["retention_days"] = retention_days
        result["cutoff"] = cutoff
        _purge_expired_files(
            conn,
            storage_root,
            cutoff,
            safe_batch_size,
            dry_run,
            result,
        )
        _purge_empty_sessions(conn, cutoff, safe_batch_size, dry_run, result)
        return result
    finally:
        _close_trusted_storage_root(storage_root)
        conn.close()
