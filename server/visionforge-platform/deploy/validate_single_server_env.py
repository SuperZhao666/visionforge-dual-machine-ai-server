"""Validate single-server environment content and secret-file boundaries."""

from __future__ import annotations

import argparse
import io
import os
import re
import stat
import sys
from pathlib import Path

from dotenv import dotenv_values


CANONICAL_SITE_URL = "https://www.visionforge.cloud"
CANONICAL_DOWNLOAD_URL = f"{CANONICAL_SITE_URL}/download"
_PUBLIC_URL_KEYS = ("SITE_URL", "DOWNLOAD_URL")
_DEFINITION_RE = re.compile(r"^\s*(?:export\s+)?(SITE_URL|DOWNLOAD_URL)\s*=")
DEFAULT_SERVICE_OWNER = "ubuntu"
REQUIRED_ENV_FILE_MODE = 0o600
MAX_ENV_FILE_BYTES = 1024 * 1024


def validate_single_server_env(
    path: Path,
    *,
    expected_uid: int | None = None,
    required_mode: int | None = None,
) -> tuple[str, ...]:
    """Validate one environment file without following symbolic links.

    The deployment CLI supplies the Ubuntu service account and mode policy.
    Tests and non-POSIX tooling may omit those POSIX-only checks while still
    receiving regular-file and symlink protection.
    """

    text, file_errors = _read_validated_env_text(
        path,
        expected_uid=expected_uid,
        required_mode=required_mode,
    )
    if file_errors:
        return file_errors
    if text is None:
        return ("environment file could not be read",)
    return _validate_env_text(text)


def _read_validated_env_text(
    path: Path,
    *,
    expected_uid: int | None,
    required_mode: int | None,
) -> tuple[str | None, tuple[str, ...]]:
    initial_metadata = path.lstat()
    if stat.S_ISLNK(initial_metadata.st_mode):
        return None, ("environment file must not be a symbolic link",)
    if not stat.S_ISREG(initial_metadata.st_mode):
        return None, ("environment file must be a regular file",)

    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_descriptor = os.open(os.fspath(path), open_flags)
    try:
        metadata = os.fstat(file_descriptor)
        metadata_errors = _validate_env_file_metadata(
            metadata,
            expected_uid=expected_uid,
            required_mode=required_mode,
        )
        if metadata_errors:
            return None, metadata_errors
        if metadata.st_size > MAX_ENV_FILE_BYTES:
            return None, (
                f"environment file must not exceed {MAX_ENV_FILE_BYTES} bytes",
            )
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
            file_descriptor = -1
            return handle.read(), ()
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _validate_env_file_metadata(
    metadata: os.stat_result,
    *,
    expected_uid: int | None,
    required_mode: int | None,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not stat.S_ISREG(metadata.st_mode):
        errors.append("environment file must be a regular file")
    actual_uid = getattr(metadata, "st_uid", None)
    if expected_uid is not None and actual_uid != expected_uid:
        errors.append(
            f"environment file owner uid must be {expected_uid}, got {actual_uid}"
        )
    if required_mode is not None:
        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != required_mode:
            errors.append(
                "environment file mode must be "
                f"{required_mode:04o}, got {actual_mode:04o}"
            )
    return tuple(errors)


def _validate_env_text(text: str) -> tuple[str, ...]:
    definitions = {key: 0 for key in _PUBLIC_URL_KEYS}
    for line in text.splitlines():
        match = _DEFINITION_RE.match(line)
        if match:
            definitions[match.group(1)] += 1

    values = dotenv_values(stream=io.StringIO(text), interpolate=False)
    expected = {
        "SITE_URL": CANONICAL_SITE_URL,
        "DOWNLOAD_URL": CANONICAL_DOWNLOAD_URL,
    }
    errors: list[str] = []
    for key in _PUBLIC_URL_KEYS:
        if definitions[key] != 1:
            errors.append(f"{key} must be defined exactly once")
        if values.get(key) != expected[key]:
            errors.append(f"{key} must equal {expected[key]}")
    return tuple(errors)


def _resolve_expected_uid(owner_name: str) -> int | None:
    if os.name != "posix":
        return None
    import pwd

    try:
        return int(pwd.getpwnam(owner_name).pw_uid)
    except KeyError as exc:
        raise ValueError(f"service owner does not exist: {owner_name}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path(".env"))
    parser.add_argument(
        "--expected-owner",
        default=os.environ.get("VF_SERVICE_USER", DEFAULT_SERVICE_OWNER),
        help="POSIX service account that must own the environment file",
    )
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        expected_uid = _resolve_expected_uid(arguments.expected_owner)
        required_mode = REQUIRED_ENV_FILE_MODE if os.name == "posix" else None
        errors = validate_single_server_env(
            arguments.path,
            expected_uid=expected_uid,
            required_mode=required_mode,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Unable to validate {arguments.path}: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    print("Single-server environment content and file security OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
