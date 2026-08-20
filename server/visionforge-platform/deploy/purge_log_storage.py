"""Scheduled entry point for VisionForge uploaded-log retention."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
import logging
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import config  # noqa: E402
from app.database import init_db  # noqa: E402
from app.services.log_retention_service import purge_expired_log_storage  # noqa: E402


REQUIRED_RETENTION_TABLES = frozenset(
    {"log_upload_settings", "log_files", "log_sessions"}
)


def _configured_database_path() -> Path:
    raw_path = Path(config.DATABASE_PATH)
    return raw_path if raw_path.is_absolute() else PROJECT_ROOT / raw_path


def smoke_check_entrypoint() -> dict[str, object]:
    """Validate the scheduled entry point without migrations or business writes."""
    database_path = _configured_database_path()
    if database_path.is_symlink():
        raise RuntimeError("retention database path must not be a symlink")
    if not database_path.exists():
        return {
            "smoke_check": "ok",
            "database_present": False,
            "database_read_only": True,
        }
    if not database_path.is_file():
        raise RuntimeError("retention database path is not a regular file")

    database_uri = f"{database_path.resolve(strict=True).as_uri()}?mode=ro"
    with closing(sqlite3.connect(database_uri, uri=True)) as conn:
        conn.execute("PRAGMA query_only = ON")
        table_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name IN ('log_upload_settings', 'log_files', 'log_sessions')"
        ).fetchall()
        discovered_tables = {str(row[0]) for row in table_rows}
        missing_tables = REQUIRED_RETENTION_TABLES - discovered_tables
        if missing_tables:
            missing = ",".join(sorted(missing_tables))
            raise RuntimeError(f"retention database schema is incomplete: {missing}")
        conn.execute(
            "SELECT retention_days FROM log_upload_settings WHERE id = 1"
        ).fetchone()
        conn.execute(
            "SELECT id, storage_path, uploaded_at FROM log_files LIMIT 0"
        ).fetchall()
        conn.execute(
            "SELECT id, started_at, latest_upload_at FROM log_sessions LIMIT 0"
        ).fetchall()
    return {
        "smoke_check": "ok",
        "database_present": True,
        "database_read_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Purge expired VisionForge uploaded logs"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Report eligible records without deleting retention candidates",
    )
    mode.add_argument(
        "--smoke-check",
        action="store_true",
        help="Validate imports and the existing database schema without migrations or writes",
    )
    parser.add_argument(
        "--batch-size", type=int, default=100, help="Maximum records read per batch"
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    if args.smoke_check:
        print(json.dumps(smoke_check_entrypoint(), ensure_ascii=False, sort_keys=True))
        return 0
    init_db()
    result = purge_expired_log_storage(dry_run=args.dry_run, batch_size=args.batch_size)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
