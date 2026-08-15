"""Create the single-server ``.env`` with exclusive, no-follow semantics."""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path

if __package__:
    from .validate_single_server_env import (
        CANONICAL_DOWNLOAD_URL,
        CANONICAL_SITE_URL,
        DEFAULT_SERVICE_OWNER,
        REQUIRED_ENV_FILE_MODE,
        _resolve_expected_uid,
    )
else:
    from validate_single_server_env import (
        CANONICAL_DOWNLOAD_URL,
        CANONICAL_SITE_URL,
        DEFAULT_SERVICE_OWNER,
        REQUIRED_ENV_FILE_MODE,
        _resolve_expected_uid,
    )


def create_single_server_env(
    path: Path,
    *,
    expected_uid: int | None = None,
) -> None:
    """Create a new environment file without overwriting or following paths."""

    if expected_uid is not None and hasattr(os, "geteuid"):
        actual_uid = int(os.geteuid())
        if actual_uid != expected_uid:
            raise PermissionError(
                f"environment file creator uid must be {expected_uid}, got {actual_uid}"
            )

    payload = _render_single_server_env().encode("utf-8")
    open_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    file_descriptor = os.open(os.fspath(path), open_flags, REQUIRED_ENV_FILE_MODE)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, REQUIRED_ENV_FILE_MODE)
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("created environment path is not a regular file")
        if expected_uid is not None and getattr(metadata, "st_uid", None) != expected_uid:
            raise PermissionError("created environment file owner does not match service uid")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != REQUIRED_ENV_FILE_MODE:
            raise PermissionError("created environment file mode is not 0600")
        with os.fdopen(file_descriptor, "wb") as handle:
            file_descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _render_single_server_env() -> str:
    values = {
        "SECRET_KEY": secrets.token_hex(32),
        "DATABASE_PATH": "data/vf.db",
        "VMQ_WEBHOOK_SECRET": secrets.token_hex(16),
        "PRIVATE_KEY_PATH": "owner_keys/license_private_key.pem",
        "PRIVATE_KEY_PASSWORD": secrets.token_urlsafe(32),
        "LOG_STORAGE_PATH": "log_storage",
        "SITE_NAME": "VisionForge",
        "SITE_URL": CANONICAL_SITE_URL,
        "DOWNLOAD_URL": CANONICAL_DOWNLOAD_URL,
        "DOWNLOAD_TEXT": "下载最新版本",
    }
    return "".join(f"{key}={value}\n" for key, value in values.items())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path(".env"))
    parser.add_argument(
        "--expected-owner",
        default=os.environ.get("VF_SERVICE_USER", DEFAULT_SERVICE_OWNER),
        help="POSIX account that must create and own the environment file",
    )
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        expected_uid = _resolve_expected_uid(arguments.expected_owner)
        create_single_server_env(arguments.path, expected_uid=expected_uid)
    except (OSError, ValueError) as exc:
        print(f"Unable to create {arguments.path}: {exc}", file=sys.stderr)
        return 2
    print(f"Created {arguments.path} with exclusive no-follow semantics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
