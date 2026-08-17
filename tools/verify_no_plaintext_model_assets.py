#!/usr/bin/env python3
"""Fail closed when public source or a release archive contains plaintext models.

The scanner intentionally understands only the repository's public-distribution
boundary. It does not claim to prove that an encrypted model is cryptographically
sound; it proves that known locked private bytes, ONNX files, and promoted QNN
weight-library names are absent from source/release artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Iterable, Sequence
import zipfile

LOCK_SCHEMA = "visionforge-android-private-artifacts-lock-v1"
MODEL_LIBRARY = re.compile(
    r"^lib(?:cs2|delta|ow2|valorant)[a-z0-9_.-]*w8a16\.so$", re.IGNORECASE
)
SKIP_DIRECTORY_NAMES = {
    ".git",
    ".gradle",
    ".gradle-user-home",
    ".cxx",
    "__pycache__",
    ".pytest_cache",
    "build",
    "out",
    "output",
    "releases",
    "_release_staging",
    "_release_validation",
}


class ScanFailure(RuntimeError):
    pass


def sha256_stream(stream) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
        size += len(block)
    return digest.hexdigest(), size


def load_locked_digests(lock_path: Path) -> dict[int, set[str]]:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScanFailure(f"cannot read private-artifact lock: {lock_path}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != LOCK_SCHEMA:
        raise ScanFailure("private-artifact lock schema is invalid")
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise ScanFailure("private-artifact lock policy is missing")
    if policy.get("public_source_tree_must_not_contain_locked_bytes") is not True:
        raise ScanFailure("private-artifact source exclusion policy is disabled")
    if policy.get("release_requires_encrypted_session_delivery") is not True:
        raise ScanFailure("private-artifact secure release policy is disabled")
    if policy.get("release_plaintext_allowed") is not False:
        raise ScanFailure("private-artifact release plaintext policy is invalid")
    if policy.get("plaintext_allowed_variants") != ["debug", "qa"]:
        raise ScanFailure("private-artifact plaintext variant policy is invalid")
    if (
        policy.get("source_root_environment")
        != "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT"
    ):
        raise ScanFailure("private-artifact source-root policy is invalid")
    rows = payload.get("artifacts")
    if not isinstance(rows, list) or not rows:
        raise ScanFailure("private-artifact lock has no artifacts")
    by_size: dict[int, set[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ScanFailure("private-artifact lock row is invalid")
        size = row.get("size")
        digest = row.get("sha256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ScanFailure("private-artifact lock hash/size is invalid")
        if row.get("public_repository_allowed") is not False:
            raise ScanFailure("private-artifact public-repository policy is invalid")
        if row.get("license_review_required") is not True:
            raise ScanFailure("private-artifact license-review policy is invalid")
        if row.get("allowed_variants") != ["debug", "qa"]:
            raise ScanFailure("private-artifact row variants are invalid")
        by_size.setdefault(size, set()).add(digest)
    return by_size


def path_reason(path: PurePosixPath) -> str | None:
    name = path.name
    if name.lower().endswith(".onnx"):
        return "plaintext_onnx_extension"
    if MODEL_LIBRARY.fullmatch(name):
        return "plaintext_qnn_weight_library_name"
    return None


def iter_source_files(root: Path) -> Iterable[tuple[PurePosixPath, Path]]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ScanFailure("source root must be a real directory")
    stack = [(PurePosixPath(), root)]
    while stack:
        relative, directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name, reverse=True)
        except OSError as exc:
            raise ScanFailure(f"cannot enumerate source directory: {relative}") from exc
        for entry in entries:
            rel = relative / entry.name
            try:
                mode = entry.lstat().st_mode
            except OSError as exc:
                raise ScanFailure(f"cannot stat source entry: {rel}") from exc
            if stat.S_ISLNK(mode):
                raise ScanFailure(f"source tree contains symlink: {rel.as_posix()}")
            if stat.S_ISDIR(mode):
                if entry.name in SKIP_DIRECTORY_NAMES:
                    continue
                stack.append((rel, entry))
            elif stat.S_ISREG(mode):
                yield rel, entry


def scan_source(root: Path, lock_path: Path, locked: dict[int, set[str]]) -> tuple[int, int]:
    files = 0
    hashed = 0
    lock_resolved = lock_path.resolve(strict=True)
    for relative, path in iter_source_files(root):
        files += 1
        reason = path_reason(relative)
        if reason:
            raise ScanFailure(f"{reason}: {relative.as_posix()}")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ScanFailure(f"cannot stat source file: {relative.as_posix()}") from exc
        if size not in locked or path.resolve() == lock_resolved:
            continue
        with path.open("rb") as stream:
            digest, actual_size = sha256_stream(stream)
        hashed += 1
        if actual_size != size:
            raise ScanFailure(f"source file changed during scan: {relative.as_posix()}")
        if digest in locked[size]:
            raise ScanFailure(
                f"locked_private_artifact_bytes: {relative.as_posix()} sha256={digest}"
            )
    return files, hashed


def strict_archive_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise ScanFailure(f"archive entry name is unsafe: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ScanFailure(f"archive entry path is unsafe: {name!r}")
    return path


def scan_archive(path: Path, locked: dict[int, set[str]]) -> tuple[int, int]:
    files = 0
    hashed = 0
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ScanFailure(f"release archive is not a valid ZIP/APK: {path}") from exc
    with archive:
        seen: set[PurePosixPath] = set()
        for info in archive.infolist():
            relative = strict_archive_name(info.filename.rstrip("/"))
            if relative in seen:
                raise ScanFailure(f"duplicate archive entry: {relative.as_posix()}")
            seen.add(relative)
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise ScanFailure(
                    f"encrypted archive entry cannot be inspected: {relative.as_posix()}"
                )
            files += 1
            reason = path_reason(relative)
            if reason:
                raise ScanFailure(f"{reason}: {relative.as_posix()}")
            if info.file_size not in locked:
                continue
            with archive.open(info, "r") as stream:
                digest, size = sha256_stream(stream)
            hashed += 1
            if size != info.file_size:
                raise ScanFailure(f"archive entry size changed: {relative.as_posix()}")
            if digest in locked[size]:
                raise ScanFailure(
                    f"locked_private_artifact_bytes: {relative.as_posix()} sha256={digest}"
                )
    return files, hashed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--lock", type=Path, required=True)
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-root", type=Path)
    mode.add_argument("--archive", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        locked = load_locked_digests(args.lock)
        if args.source_root is not None:
            files, hashed = scan_source(args.source_root, args.lock, locked)
            mode = "source"
        else:
            files, hashed = scan_archive(args.archive, locked)
            mode = "archive"
    except ScanFailure as exc:
        print(f"VISIONFORGE_PLAINTEXT_MODEL_SCAN=FAIL reason={exc}", file=sys.stderr)
        return 2
    print(
        "VISIONFORGE_PLAINTEXT_MODEL_SCAN=PASS "
        f"mode={mode} files={files} locked_size_candidates_hashed={hashed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
