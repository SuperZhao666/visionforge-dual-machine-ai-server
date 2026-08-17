#!/usr/bin/env python3
"""Create or reset an administrator without exposing its password in logs."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any

_MINIMUM_PASSWORD_LENGTH = 16
_MAXIMUM_PASSWORD_LENGTH = 128
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


class AdminBootstrapError(RuntimeError):
    """Raised when the local administrator bootstrap contract is unsafe."""


def _outside_repository(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    try:
        resolved.relative_to(_PROJECT_ROOT)
    except ValueError:
        return resolved
    raise AdminBootstrapError(
        "administrator password files must be stored outside the repository"
    )


def _validate_password(password: str) -> str:
    if "\x00" in password or "\r" in password or "\n" in password:
        raise AdminBootstrapError("administrator password must be one line")
    if not _MINIMUM_PASSWORD_LENGTH <= len(password) <= _MAXIMUM_PASSWORD_LENGTH:
        raise AdminBootstrapError(
            f"administrator password length must be between {_MINIMUM_PASSWORD_LENGTH} "
            f"and {_MAXIMUM_PASSWORD_LENGTH} characters"
        )
    return password


def _read_password_file(path: Path) -> str:
    resolved = _outside_repository(path)
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise AdminBootstrapError(f"password file is unavailable: {resolved}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AdminBootstrapError("password file must be a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise AdminBootstrapError("password file permissions must be 0600 or stricter")
    if metadata.st_size <= 0 or metadata.st_size > _MAXIMUM_PASSWORD_LENGTH + 2:
        raise AdminBootstrapError("password file size is invalid")
    try:
        value = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AdminBootstrapError("password file must be readable UTF-8 text") from exc
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    return _validate_password(value)


def _write_generated_password(path: Path, password: str) -> Path:
    resolved = _outside_repository(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(password + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            resolved.unlink()
        except OSError:
            pass
        raise
    if resolved.stat().st_mode & 0o077:
        resolved.unlink(missing_ok=True)
        raise AdminBootstrapError("generated password file permissions are not private")
    return resolved


def _interactive_password() -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AdminBootstrapError(
            "non-interactive execution requires --password-file or "
            "--generate-password-file"
        )
    first = getpass.getpass("Administrator password: ")
    second = getpass.getpass("Confirm administrator password: ")
    if not secrets.compare_digest(first, second):
        raise AdminBootstrapError("administrator password confirmation does not match")
    return _validate_password(first)


def _validated_identity(username: str, email: str) -> tuple[str, str]:
    safe_username = str(username or "").strip()
    safe_email = str(email or "").strip().lower()
    if not 3 <= len(safe_username) <= 64 or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in safe_username
    ):
        raise AdminBootstrapError("administrator username is invalid")
    if (
        not 5 <= len(safe_email) <= 254
        or safe_email.count("@") != 1
        or any(character.isspace() for character in safe_email)
    ):
        raise AdminBootstrapError("administrator email is invalid")
    return safe_username, safe_email


def _upsert_admin(
    connection: Any,
    *,
    username: str,
    email: str,
    password_hash: str,
) -> int:
    connection.execute(
        "INSERT INTO users (username, email, password_hash, is_admin, status, "
        "ban_reason, deleted_at, updated_at) VALUES (?, ?, ?, 1, 'active', '', "
        "NULL, datetime('now')) ON CONFLICT(username) DO UPDATE SET "
        "email = excluded.email, password_hash = excluded.password_hash, "
        "is_admin = 1, status = 'active', ban_reason = '', deleted_at = NULL, "
        "auth_version = users.auth_version + 1, login_device_code = '', "
        "login_instance_id = '', login_started_at = NULL, "
        "runtime_blocked_until_epoch = 0, updated_at = datetime('now')",
        (username, email, password_hash),
    )
    row = connection.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        raise AdminBootstrapError("administrator row was not persisted")
    admin_id = int(row[0])
    connection.execute(
        "UPDATE time_sessions SET status = 'ended', "
        "ended_at = COALESCE(ended_at, datetime('now')), "
        "ended_reason = 'admin_credential_rotation', "
        "revoked_at = COALESCE(revoked_at, datetime('now')) "
        "WHERE user_id = ? AND status = 'active'",
        (admin_id,),
    )
    return admin_id


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="superadmin")
    parser.add_argument("--email", default="admin@vf.com")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--password-file", type=Path)
    secret.add_argument("--generate-password-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    generated_path: Path | None = None
    try:
        username, email = _validated_identity(args.username, args.email)
        if args.password_file is not None:
            password = _read_password_file(args.password_file)
        elif args.generate_password_file is not None:
            password = _validate_password(secrets.token_urlsafe(32))
            generated_path = _write_generated_password(args.generate_password_file, password)
        else:
            password = _interactive_password()

        from app.database import get_connection, init_db
        from app.security import hash_password

        init_db()
        connection = get_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _upsert_admin(
                connection,
                username=username,
                email=email,
                password_hash=hash_password(password),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        password = ""
        print(f"Administrator account updated: username={username} email={email}")
        if generated_path is not None:
            print(f"Initial password written to private file: {generated_path}")
            print("Delete that file after storing the credential in a password manager.")
        return 0
    except AdminBootstrapError as exc:
        if generated_path is not None:
            generated_path.unlink(missing_ok=True)
        print(f"ADMIN_BOOTSTRAP=FAIL reason={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
