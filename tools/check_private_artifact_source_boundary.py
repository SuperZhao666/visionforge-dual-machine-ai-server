#!/usr/bin/env python3
"""Reject private Android model/runtime bytes from the public source tree.

This gate is deliberately independent from Gradle so it can run in CI, in a
clean source archive, and before Android tooling is installed.  It does not
attempt to protect runtime plaintext; it only enforces the repository boundary
recorded by ``private-artifacts.lock.json``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Iterable, Mapping, Sequence

LOCK_SCHEMA = "visionforge-android-private-artifacts-lock-v1"
ANDROID_MAIN_PREFIX = PurePosixPath("android_inference_benchmark/app/src/main")
LFS_PREFIX = b"version https://git-lfs.github.com/spec/v1"
RAW_MODEL_SUFFIXES = {".onnx", ".tflite", ".pt", ".pth", ".engine", ".weights"}
BINARY_SUFFIXES = RAW_MODEL_SUFFIXES | {".so", ".dll", ".dylib", ".bin", ".dat"}


class BoundaryPolicyError(RuntimeError):
    """Raised when the lock or repository boundary is invalid."""


@dataclass(frozen=True)
class LockedArtifact:
    artifact_id: str
    target_path: PurePosixPath
    size: int
    sha256: str


@dataclass(frozen=True)
class BoundaryViolation:
    code: str
    path: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "detail": self.detail}


def _canonical_relative_path(raw: object, field: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise BoundaryPolicyError(f"{field} must be a non-empty canonical POSIX path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BoundaryPolicyError(f"{field} contains an unsafe path: {raw!r}")
    if path.as_posix() != raw:
        raise BoundaryPolicyError(f"{field} is not canonical: {raw!r}")
    return path


def load_lock(lock_path: Path) -> tuple[str, list[LockedArtifact]]:
    try:
        raw_bytes = lock_path.read_bytes()
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundaryPolicyError(f"unable to load private-artifact lock: {exc}") from exc
    if payload.get("schema") != LOCK_SCHEMA:
        raise BoundaryPolicyError("private-artifact lock schema mismatch")
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise BoundaryPolicyError("private-artifact lock policy is missing")
    required = {
        "public_source_tree_must_not_contain_locked_bytes": True,
        "release_requires_encrypted_session_delivery": True,
        "release_plaintext_allowed": False,
    }
    for key, value in required.items():
        if policy.get(key) is not value:
            raise BoundaryPolicyError(f"private-artifact policy {key} must be {value!r}")
    if policy.get("plaintext_allowed_variants") != ["debug", "qa"]:
        raise BoundaryPolicyError(
            "private-artifact policy plaintext_allowed_variants must be "
            "exactly ['debug', 'qa']"
        )
    if (
        policy.get("source_root_environment")
        != "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT"
    ):
        raise BoundaryPolicyError(
            "private-artifact policy source_root_environment is invalid"
        )

    entries = payload.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise BoundaryPolicyError("private-artifact lock contains no artifacts")
    artifacts: list[LockedArtifact] = []
    ids: set[str] = set()
    targets: set[PurePosixPath] = set()
    hashes: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BoundaryPolicyError(f"artifact {index} is not an object")
        artifact_id = entry.get("id")
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in ids:
            raise BoundaryPolicyError(f"artifact {index} has an invalid or duplicate id")
        target = _canonical_relative_path(entry.get("target_path"), "target_path")
        size = entry.get("size")
        digest = entry.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise BoundaryPolicyError(f"artifact {artifact_id} has an invalid size")
        if not isinstance(digest, str) or len(digest) != 64:
            raise BoundaryPolicyError(f"artifact {artifact_id} has an invalid SHA-256")
        digest = digest.lower()
        if any(character not in "0123456789abcdef" for character in digest):
            raise BoundaryPolicyError(f"artifact {artifact_id} has a non-hex SHA-256")
        if target in targets:
            raise BoundaryPolicyError(f"duplicate target path in private-artifact lock: {target}")
        if entry.get("public_repository_allowed") is not False:
            raise BoundaryPolicyError(
                f"artifact {artifact_id} must explicitly forbid public repository storage"
            )
        if entry.get("license_review_required") is not True:
            raise BoundaryPolicyError(
                f"artifact {artifact_id} must explicitly require license review"
            )
        if entry.get("allowed_variants") != ["debug", "qa"]:
            raise BoundaryPolicyError(
                f"artifact {artifact_id} variants must be exactly ['debug', 'qa']"
            )
        ids.add(artifact_id)
        targets.add(target)
        hashes.add(digest)
        artifacts.append(LockedArtifact(artifact_id, target, size, digest))
    return hashlib.sha256(raw_bytes).hexdigest(), artifacts


def _git_tracked_paths(repo_root: Path) -> list[PurePosixPath]:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repo_root), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        raise BoundaryPolicyError(f"unable to enumerate Git-tracked files: {detail or exc}") from exc
    paths: list[PurePosixPath] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BoundaryPolicyError("Git contains a non-UTF-8 path") from exc
        paths.append(_canonical_relative_path(decoded, "tracked path"))
    return paths


def _is_under(path: PurePosixPath, parent: PurePosixPath) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_repository(
    repo_root: Path,
    lock_path: Path,
    tracked_paths: Iterable[PurePosixPath | str] | None = None,
) -> dict[str, object]:
    repo_root = repo_root.resolve(strict=True)
    lock_path = lock_path.resolve(strict=True)
    lock_sha256, artifacts = load_lock(lock_path)
    normalized_paths = (
        _git_tracked_paths(repo_root)
        if tracked_paths is None
        else [
            path if isinstance(path, PurePosixPath) else _canonical_relative_path(path, "path")
            for path in tracked_paths
        ]
    )

    locked_by_size: dict[int, set[str]] = {}
    locked_targets: set[PurePosixPath] = set()
    locked_names: set[str] = set()
    for artifact in artifacts:
        locked_by_size.setdefault(artifact.size, set()).add(artifact.sha256)
        locked_targets.add(ANDROID_MAIN_PREFIX / artifact.target_path)
        locked_names.add(artifact.target_path.name.lower())

    violations: list[BoundaryViolation] = []
    files_hashed = 0
    for relative in sorted(set(normalized_paths), key=lambda item: item.as_posix()):
        absolute = repo_root.joinpath(*relative.parts)
        if absolute.is_symlink():
            if _is_under(relative, ANDROID_MAIN_PREFIX):
                violations.append(
                    BoundaryViolation("ANDROID_SOURCE_SYMLINK", relative.as_posix(), "symlinks are forbidden")
                )
            continue
        if not absolute.is_file():
            continue
        if relative in locked_targets:
            violations.append(
                BoundaryViolation(
                    "LOCKED_TARGET_TRACKED",
                    relative.as_posix(),
                    "private artifact target is present in the public Android source set",
                )
            )

        suffix = relative.suffix.lower()
        under_main = _is_under(relative, ANDROID_MAIN_PREFIX)
        if under_main and suffix in RAW_MODEL_SUFFIXES:
            violations.append(
                BoundaryViolation(
                    "RAW_MODEL_TRACKED",
                    relative.as_posix(),
                    f"raw model extension {suffix} is forbidden in app/src/main",
                )
            )
        if under_main and suffix == ".so" and relative.name.lower() in locked_names:
            violations.append(
                BoundaryViolation(
                    "PRIVATE_LIBRARY_TRACKED",
                    relative.as_posix(),
                    "private model/vendor runtime library is tracked in app/src/main",
                )
            )

        try:
            size = absolute.stat().st_size
            with absolute.open("rb") as stream:
                prefix = stream.read(len(LFS_PREFIX))
        except OSError as exc:
            raise BoundaryPolicyError(f"unable to inspect tracked file {relative}: {exc}") from exc
        if prefix == LFS_PREFIX and (under_main or suffix in BINARY_SUFFIXES):
            violations.append(
                BoundaryViolation(
                    "GIT_LFS_POINTER",
                    relative.as_posix(),
                    "binary/model artifact is a Git LFS pointer rather than verified bytes",
                )
            )
        expected_hashes = locked_by_size.get(size)
        if expected_hashes:
            digest = _sha256_file(absolute)
            files_hashed += 1
            if digest in expected_hashes:
                violations.append(
                    BoundaryViolation(
                        "LOCKED_BYTES_TRACKED",
                        relative.as_posix(),
                        f"file matches a private-artifact lock digest ({digest})",
                    )
                )

    return {
        "schema": "visionforge-private-artifact-source-boundary-result-v1",
        "ok": not violations,
        "repo_root": repo_root.name,
        "lock_sha256": lock_sha256,
        "tracked_files_checked": len(set(normalized_paths)),
        "size_candidates_hashed": files_hashed,
        "locked_artifacts": len(artifacts),
        "violations": [violation.as_dict() for violation in violations],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = scan_repository(args.repo_root, args.lock)
    except BoundaryPolicyError as exc:
        print(f"VISIONFORGE_PRIVATE_ARTIFACT_SOURCE_BOUNDARY=FAIL reason={exc}", file=sys.stderr)
        return 2
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded, encoding="utf-8", newline="\n")
    if result["ok"]:
        print(
            "VISIONFORGE_PRIVATE_ARTIFACT_SOURCE_BOUNDARY=PASS "
            f"tracked={result['tracked_files_checked']} locked={result['locked_artifacts']} "
            f"lock_sha256={result['lock_sha256']}"
        )
        return 0
    print(encoded, file=sys.stderr, end="")
    print(
        "VISIONFORGE_PRIVATE_ARTIFACT_SOURCE_BOUNDARY=FAIL "
        f"violations={len(result['violations'])}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
