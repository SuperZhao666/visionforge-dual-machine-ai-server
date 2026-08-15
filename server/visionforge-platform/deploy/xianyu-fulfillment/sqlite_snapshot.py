#!/usr/bin/env python3
"""Create, verify, and restore consistent SQLite snapshots."""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def open_read_only(database_path: Path) -> sqlite3.Connection:
    resolved_path = database_path.resolve(strict=True)
    connection = sqlite3.connect(f"{resolved_path.as_uri()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection


def verify_database(database_path: Path) -> None:
    with closing(open_read_only(database_path)) as connection:
        result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError("SQLite integrity check failed")


def create_snapshot(source_path: Path, destination_path: Path) -> None:
    verify_database(source_path)
    destination_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path = _temporary_path(destination_path)
    try:
        with closing(open_read_only(source_path)) as source_connection:
            with closing(sqlite3.connect(temporary_path)) as destination_connection:
                source_connection.backup(destination_connection)
                destination_connection.commit()
        verify_database(temporary_path)
        os.chmod(temporary_path, 0o600)
        _fsync_file(temporary_path)
        os.replace(temporary_path, destination_path)
        _fsync_directory(destination_path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def restore_snapshot(snapshot_path: Path, destination_path: Path) -> None:
    verify_database(snapshot_path)
    destination_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path = _temporary_path(destination_path)
    try:
        shutil.copyfile(snapshot_path, temporary_path)
        os.chmod(temporary_path, 0o600)
        _fsync_file(temporary_path)
        for suffix in ("-wal", "-shm"):
            destination_path.with_name(destination_path.name + suffix).unlink(missing_ok=True)
        os.replace(temporary_path, destination_path)
        _fsync_directory(destination_path.parent)
        verify_database(destination_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _temporary_path(destination_path: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=destination_path.parent,
    )
    os.close(descriptor)
    path = Path(raw_path)
    path.unlink()
    return path


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--source", required=True, type=Path)
    backup_parser.add_argument("--destination", required=True, type=Path)

    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--snapshot", required=True, type=Path)
    restore_parser.add_argument("--destination", required=True, type=Path)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--database", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    arguments = _parse_arguments()
    if arguments.command == "backup":
        create_snapshot(arguments.source, arguments.destination)
        print("sqlite_snapshot=verified")
        return
    if arguments.command == "restore":
        restore_snapshot(arguments.snapshot, arguments.destination)
        print("sqlite_restore=verified")
        return
    verify_database(arguments.database)
    print("sqlite_integrity=ok")


if __name__ == "__main__":
    main()
