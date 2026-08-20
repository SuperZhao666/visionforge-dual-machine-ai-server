#!/usr/bin/env python3
"""Verify and atomically stage VisionForge private Android artifacts.

The public source tree intentionally excludes proprietary model weights and
vendor runtime binaries.  This tool consumes the repository-owned hash/size
lock and a private artifact root supplied outside the repository.  Plaintext
artifacts are permitted only for explicitly listed non-release variants.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from typing import Iterable, Sequence

LOCK_SCHEMA = "visionforge-android-private-artifacts-lock-v1"
MANIFEST_SCHEMA = "visionforge-staged-android-private-artifacts-v1"
_ALLOWED_TARGET_PREFIXES = (
    PurePosixPath("assets/qnn"),
    PurePosixPath("assets/portable_models"),
    PurePosixPath("jniLibs/arm64-v8a"),
)
_ALLOWED_KINDS = {
    "vendor_runtime",
    "model_weight_library",
    "portable_model_weight",
}


class ArtifactPolicyError(ValueError):
    """Raised when the lock or requested staging operation violates policy."""


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    kind: str
    source_path: PurePosixPath
    target_path: PurePosixPath
    size: int
    sha256: str
    allowed_variants: tuple[str, ...]
    license_review_required: bool
    public_repository_allowed: bool


def _strict_relative_path(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ArtifactPolicyError(f"{field} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactPolicyError(f"{field} is not a strict relative path: {value!r}")
    return path


def _target_allowed(path: PurePosixPath) -> bool:
    return any(path == prefix or prefix in path.parents for prefix in _ALLOWED_TARGET_PREFIXES)


def load_lock(lock_path: Path) -> tuple[dict[str, object], tuple[Artifact, ...]]:
    try:
        raw = lock_path.read_bytes()
    except OSError as exc:
        raise ArtifactPolicyError(f"artifact lock cannot be read: {lock_path}") from exc
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ArtifactPolicyError("artifact lock size is invalid")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ArtifactPolicyError("artifact lock must be UTF-8 without BOM")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactPolicyError("artifact lock is not canonical UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema") != LOCK_SCHEMA:
        raise ArtifactPolicyError("unsupported Android private-artifact lock schema")
    policy = payload.get("policy")
    rows = payload.get("artifacts")
    if not isinstance(policy, dict) or not isinstance(rows, list) or not rows:
        raise ArtifactPolicyError("artifact lock policy/artifacts are missing")
    if policy.get("public_source_tree_must_not_contain_locked_bytes") is not True:
        raise ArtifactPolicyError("public source-tree exclusion policy must be enabled")
    if policy.get("release_requires_encrypted_session_delivery") is not True:
        raise ArtifactPolicyError("release encrypted-session delivery policy must be enabled")
    if policy.get("release_plaintext_allowed") is not False:
        raise ArtifactPolicyError("release plaintext artifacts must be forbidden")
    if policy.get("plaintext_allowed_variants") != ["debug", "qa"]:
        raise ArtifactPolicyError(
            "plaintext_allowed_variants must be exactly ['debug', 'qa']"
        )
    if (
        policy.get("source_root_environment")
        != "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT"
    ):
        raise ArtifactPolicyError(
            "source_root_environment must be "
            "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT"
        )

    artifacts: list[Artifact] = []
    ids: set[str] = set()
    sources: set[PurePosixPath] = set()
    targets: set[PurePosixPath] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ArtifactPolicyError(f"artifact #{index} is not an object")
        artifact_id = row.get("id")
        kind = row.get("kind")
        size = row.get("size")
        digest = row.get("sha256")
        variants = row.get("allowed_variants")
        if not isinstance(artifact_id, str) or not artifact_id or len(artifact_id) > 120:
            raise ArtifactPolicyError(f"artifact #{index} id is invalid")
        if not all(ch.islower() or ch.isdigit() or ch in "_-" for ch in artifact_id):
            raise ArtifactPolicyError(f"artifact id is not canonical: {artifact_id}")
        if artifact_id in ids:
            raise ArtifactPolicyError(f"duplicate artifact id: {artifact_id}")
        ids.add(artifact_id)
        if kind not in _ALLOWED_KINDS:
            raise ArtifactPolicyError(f"artifact kind is invalid: {artifact_id}")
        source = _strict_relative_path(row.get("source_path"), "source_path")
        target = _strict_relative_path(row.get("target_path"), "target_path")
        if not _target_allowed(target):
            raise ArtifactPolicyError(f"artifact target is outside approved roots: {target}")
        if source in sources or target in targets:
            raise ArtifactPolicyError(f"duplicate source/target path: {artifact_id}")
        sources.add(source)
        targets.add(target)
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > 1024**3:
            raise ArtifactPolicyError(f"artifact size is invalid: {artifact_id}")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ArtifactPolicyError(f"artifact SHA-256 is invalid: {artifact_id}")
        if (
            not isinstance(variants, list)
            or not variants
            or len(set(variants)) != len(variants)
            or any(v not in {"debug", "qa"} for v in variants)
        ):
            raise ArtifactPolicyError(f"artifact variants are invalid: {artifact_id}")
        if row.get("license_review_required") is not True:
            raise ArtifactPolicyError(f"license review must be explicit: {artifact_id}")
        public_repository_allowed = row.get("public_repository_allowed")
        if not isinstance(public_repository_allowed, bool):
            raise ArtifactPolicyError(
                f"public-repository policy must be explicit: {artifact_id}"
            )
        if public_repository_allowed:
            repository_path = _strict_relative_path(
                row.get("repository_path"), "repository_path"
            )
            expected_repository_path = PurePosixPath(
                "android_inference_benchmark/app/src/main"
            ) / target
            if (
                kind != "model_weight_library"
                or row.get("provenance") != "user_trained"
                or row.get("repository_storage") != "git_lfs"
                or repository_path != expected_repository_path
            ):
                raise ArtifactPolicyError(
                    "public repository storage is limited to exact user-trained "
                    f"Git LFS model entries: {artifact_id}"
                )
        elif any(
            field in row
            for field in ("provenance", "repository_storage", "repository_path")
        ):
            raise ArtifactPolicyError(
                f"disabled public-repository entry has public metadata: {artifact_id}"
            )
        artifacts.append(
            Artifact(
                artifact_id=artifact_id,
                kind=str(kind),
                source_path=source,
                target_path=target,
                size=size,
                sha256=digest,
                allowed_variants=tuple(variants),
                license_review_required=True,
                public_repository_allowed=public_repository_allowed,
            )
        )
    return policy, tuple(artifacts)


def _regular_file_without_symlink(path: Path, source_root: Path) -> None:
    try:
        relative = path.relative_to(source_root)
    except ValueError as exc:
        raise ArtifactPolicyError("artifact source escaped its private root") from exc
    current = source_root
    if source_root.is_symlink():
        raise ArtifactPolicyError("private artifact root must not be a symlink")
    for part in relative.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ArtifactPolicyError(f"private artifact is missing: {relative.as_posix()}") from exc
        if stat.S_ISLNK(mode):
            raise ArtifactPolicyError(f"private artifact path contains a symlink: {relative.as_posix()}")
    if not path.is_file():
        raise ArtifactPolicyError(f"private artifact is not a regular file: {relative.as_posix()}")


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def verify_artifacts(
    artifacts: Iterable[Artifact], source_root: Path, variant: str
) -> tuple[Artifact, ...]:
    if variant == "release":
        raise ArtifactPolicyError(
            "release plaintext model/runtime staging is forbidden; implement reviewed "
            "encrypted session delivery before enabling a release artifact"
        )
    if variant not in {"debug", "qa"}:
        raise ArtifactPolicyError(f"unsupported Android variant: {variant}")
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise ArtifactPolicyError(f"private artifact root is unavailable: {source_root}") from exc
    if not root.is_dir() or root.is_symlink():
        raise ArtifactPolicyError("private artifact root must be a real directory")

    selected = tuple(a for a in artifacts if variant in a.allowed_variants)
    if not selected:
        raise ArtifactPolicyError(f"artifact lock has no entries for variant {variant}")
    for artifact in selected:
        source = root.joinpath(*artifact.source_path.parts)
        _regular_file_without_symlink(source, root)
        digest, size = _sha256_and_size(source)
        if size != artifact.size or digest != artifact.sha256:
            raise ArtifactPolicyError(
                f"private artifact integrity mismatch: {artifact.artifact_id} "
                f"expected_size={artifact.size} actual_size={size} "
                f"expected_sha256={artifact.sha256} actual_sha256={digest}"
            )
        with source.open("rb") as stream:
            prefix = stream.read(128)
        if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ArtifactPolicyError(f"Git LFS pointer is not an artifact: {artifact.artifact_id}")
    return selected


def stage_artifacts(
    lock_path: Path,
    source_root: Path,
    output_root: Path,
    variant: str,
    verify_only: bool = False,
) -> dict[str, object]:
    policy, artifacts = load_lock(lock_path)
    selected = verify_artifacts(artifacts, source_root, variant)
    result: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "variant": variant,
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "release_plaintext_allowed": policy["release_plaintext_allowed"],
        "files": [
            {
                "id": artifact.artifact_id,
                "kind": artifact.kind,
                "target_path": artifact.target_path.as_posix(),
                "size": artifact.size,
                "sha256": artifact.sha256,
            }
            for artifact in selected
        ],
    }
    if verify_only:
        return result

    output_parent = output_root.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_parent)
    )
    backup_root = output_parent / f".{output_root.name}.previous"
    try:
        resolved_source_root = source_root.resolve(strict=True)
        for artifact in selected:
            source = resolved_source_root.joinpath(*artifact.source_path.parts)
            destination = temp_root.joinpath(*artifact.target_path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            copied_digest = hashlib.sha256()
            copied_size = 0
            with source.open("rb") as src, destination.open("xb") as dst:
                while True:
                    block = src.read(1024 * 1024)
                    if not block:
                        break
                    dst.write(block)
                    copied_digest.update(block)
                    copied_size += len(block)
                dst.flush()
                os.fsync(dst.fileno())
            copied_sha256 = copied_digest.hexdigest()
            if copied_size != artifact.size or copied_sha256 != artifact.sha256:
                raise ArtifactPolicyError(
                    f"private artifact changed while staging: {artifact.artifact_id} "
                    f"expected_size={artifact.size} actual_size={copied_size} "
                    f"expected_sha256={artifact.sha256} "
                    f"actual_sha256={copied_sha256}"
                )
            destination_digest, destination_size = _sha256_and_size(destination)
            if (
                destination_size != artifact.size
                or destination_digest != artifact.sha256
            ):
                raise ArtifactPolicyError(
                    f"staged artifact verification failed: {artifact.artifact_id}"
                )
            os.chmod(destination, 0o644)
        manifest_path = temp_root / "artifact-manifest.json"
        with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if backup_root.exists():
            shutil.rmtree(backup_root)
        if output_root.exists():
            os.replace(output_root, backup_root)
        os.replace(temp_root, output_root)
        if backup_root.exists():
            shutil.rmtree(backup_root)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        if not output_root.exists() and backup_root.exists():
            os.replace(backup_root, output_root)
        raise
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--variant", choices=("debug", "qa", "release"), required=True)
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = stage_artifacts(
            lock_path=args.lock,
            source_root=args.source_root,
            output_root=args.output_root,
            variant=args.variant,
            verify_only=args.verify_only,
        )
    except ArtifactPolicyError as exc:
        print(f"VISIONFORGE_PRIVATE_ARTIFACTS=FAIL reason={exc}", file=sys.stderr)
        return 2
    print(
        "VISIONFORGE_PRIVATE_ARTIFACTS=PASS "
        f"variant={result['variant']} files={len(result['files'])} "
        f"lock_sha256={result['lock_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
