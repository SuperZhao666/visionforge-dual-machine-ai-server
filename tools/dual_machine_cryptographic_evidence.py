"""Fail-closed verification for archive-local dual-machine crypto evidence.

This module verifies metadata and files that were produced elsewhere.  It does
not execute evidence, decode captures, perform cryptographic operations, or
contact a peer or service.  The evidence manifest is deliberately small: the
manifest records the required attack case outcome and the archive-local file
whose size and SHA-256 digest are checked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping


MANIFEST_SCHEMA = "visionforge-dual-machine-cryptographic-evidence-v1"
VERIFIER_REPORT_SCHEMA = (
    "visionforge-dual-machine-cryptographic-evidence-verifier-report-v1"
)

# The case identifiers are stable machine-facing names.  In v1, wrong_epoch
# covers stale epoch/generation and artifact_sha256 covers artifact tamper.
REQUIRED_ATTACK_CASES = (
    "tag_bit_flip",
    "aad_bit_flip",
    "ciphertext_bit_flip",
    "truncation",
    "oversize",
    "duplicate_counter",
    "out_of_order",
    "wrong_epoch",
    "wrong_direction",
    "wrong_type",
    "wrong_connection",
    "cross_session",
    "plaintext_downgrade",
    "artifact_sha256",
)

CASE_DESCRIPTIONS = {
    "tag_bit_flip": "tag bit flip",
    "aad_bit_flip": "AAD bit flip",
    "ciphertext_bit_flip": "ciphertext bit flip",
    "truncation": "truncation",
    "oversize": "oversize",
    "duplicate_counter": "duplicate/replay counter",
    "out_of_order": "out-of-order packet",
    "wrong_epoch": "stale epoch/generation",
    "wrong_direction": "wrong direction",
    "wrong_type": "wrong type",
    "wrong_connection": "wrong connection",
    "cross_session": "cross-session packet",
    "plaintext_downgrade": "plaintext downgrade",
    "artifact_sha256": "artifact tamper / SHA-256 mismatch",
}

MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_ENTRIES = 256
MAX_ATTACK_CASE_ENTRIES = 64
MAX_PATH_LENGTH = 1024
MAX_ARTIFACT_BYTES = 1 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_REPARSE_POINT = 0x0400


class CryptographicEvidenceError(ValueError):
    """A sanitized, machine-readable rejection of an evidence manifest."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _reject(code: str, detail: str) -> None:
    raise CryptographicEvidenceError(code, detail)


def _reject_json_constant(value: str) -> None:
    del value
    _reject("invalid_json", "non-finite JSON numbers are not allowed")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate_json_key", "duplicate JSON object keys are not allowed")
        result[key] = value
    return result


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    return bool(getattr(file_stat, "st_file_attributes", 0) & _REPARSE_POINT)


def _absolute_components(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts:
        return ()
    current = Path(parts[0])
    components = [current]
    for part in parts[1:]:
        current = current / part
        components.append(current)
    return tuple(components)


def _has_reparse_component(path: Path) -> bool:
    for component in _absolute_components(path):
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError:
            break
        except OSError:
            # The caller will turn an unreadable component into a generic
            # rejection.  Do not expose the OS path/error text.
            return True
        if os.path.islink(component) or _is_reparse_point(component_stat):
            return True
    return False


def _require_regular_file(path: Path, *, manifest: bool = False) -> os.stat_result:
    if _has_reparse_component(path):
        _reject(
            "manifest_reparse_point" if manifest else "artifact_reparse_point",
            "reparse points and symlinks are not allowed",
        )
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        _reject(
            "manifest_missing" if manifest else "artifact_missing",
            "required regular file is missing",
        )
    except OSError:
        _reject(
            "manifest_unreadable" if manifest else "artifact_unreadable",
            "required regular file is not readable",
        )
    if os.path.islink(path) or _is_reparse_point(file_stat):
        _reject(
            "manifest_reparse_point" if manifest else "artifact_reparse_point",
            "reparse points and symlinks are not allowed",
        )
    if not stat.S_ISREG(file_stat.st_mode):
        _reject(
            "manifest_not_regular" if manifest else "artifact_not_regular",
            "required path must be a regular file",
        )
    return file_stat


def _load_json_manifest(manifest_path: Path) -> Mapping[str, Any]:
    manifest_stat = _require_regular_file(manifest_path, manifest=True)
    if manifest_stat.st_size > MAX_MANIFEST_BYTES:
        _reject("manifest_too_large", "manifest exceeds the maximum input size")
    try:
        with manifest_path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        _reject("manifest_unreadable", "manifest could not be read")
    if len(raw) > MAX_MANIFEST_BYTES:
        _reject("manifest_too_large", "manifest exceeds the maximum input size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _reject("invalid_utf8", "manifest must be UTF-8 JSON")
    try:
        parsed = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except CryptographicEvidenceError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _reject("invalid_json", "manifest is not valid JSON")
    if type(parsed) is not dict:
        _reject("schema_type", "manifest root must be a JSON object")
    return parsed


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], location: str) -> None:
    if set(value) != expected:
        _reject("schema_keys", f"{location} has an unexpected or missing field")


def _validate_archive_path(value: Any, *, location: str) -> tuple[str, ...]:
    if type(value) is not str:
        _reject("path_type", f"{location} must be a string")
    if not value or len(value) > MAX_PATH_LENGTH:
        _reject("path_invalid", f"{location} is not a bounded relative path")
    if "\x00" in value or "\\" in value:
        _reject("path_invalid", f"{location} must use archive-local POSIX separators")
    if value.startswith("/"):
        _reject("path_absolute", f"{location} must not be absolute")
    windows_path = PureWindowsPath(value)
    if windows_path.drive or windows_path.root or windows_path.anchor:
        _reject("path_absolute", f"{location} must not be absolute")
    parts = tuple(value.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        _reject("path_traversal", f"{location} contains an invalid path component")
    if any(":" in part for part in parts):
        _reject("path_invalid", f"{location} contains a drive-like component")
    return parts


def _archive_path(root: Path, value: Any, *, location: str) -> tuple[str, Path]:
    parts = _validate_archive_path(value, location=location)
    candidate = root.joinpath(*parts)
    root_absolute = os.path.abspath(os.fspath(root))
    candidate_absolute = os.path.abspath(os.fspath(candidate))
    try:
        inside = os.path.commonpath((root_absolute, candidate_absolute)) == root_absolute
    except ValueError:
        inside = False
    if not inside:
        _reject("path_escape", f"{location} escapes the archive root")
    return "/".join(parts), candidate


def _require_non_boolean_integer(value: Any, *, location: str) -> int:
    if type(value) is not int:
        _reject("integer_type", f"{location} must be a JSON integer, not a boolean or float")
    return value


def _validate_artifact_entry(
    root: Path,
    value: Any,
    index: int,
) -> tuple[str, Path, int, str]:
    if type(value) is not dict:
        _reject("artifact_schema", f"artifact entry {index} must be an object")
    _require_exact_keys(value, frozenset({"path", "size", "sha256"}), "artifact entry")
    archive_path, resolved_path = _archive_path(
        root,
        value["path"],
        location="artifact.path",
    )
    size = _require_non_boolean_integer(value["size"], location="artifact.size")
    if size < 0 or size > MAX_ARTIFACT_BYTES:
        _reject("artifact_size_bound", "artifact.size is outside the allowed bound")
    digest = value["sha256"]
    if type(digest) is not str or _SHA256_RE.fullmatch(digest) is None:
        _reject("artifact_hash_format", "artifact.sha256 must be lowercase 64-character hex")
    return archive_path, resolved_path, size, digest


def _validate_case_entry(root: Path, value: Any, index: int) -> tuple[str, str]:
    if type(value) is not dict:
        _reject("case_schema", f"attack case entry {index} must be an object")
    _require_exact_keys(
        value,
        frozenset({"case_id", "result", "artifact"}),
        "attack case entry",
    )
    case_id = value["case_id"]
    if type(case_id) is not str or case_id not in REQUIRED_ATTACK_CASES:
        _reject("case_unknown", "attack case identifier is unknown or malformed")
    result = value["result"]
    if type(result) is not str or result != "rejected":
        _reject("case_not_rejected", "every required attack case must be rejected")
    archive_path, _ = _archive_path(root, value["artifact"], location="case.artifact")
    return case_id, archive_path


def _hash_artifact(path: Path, expected_size: int, expected_digest: str) -> None:
    initial = _require_regular_file(path)
    if initial.st_size > MAX_ARTIFACT_BYTES or initial.st_size != expected_size:
        _reject("artifact_size_mismatch", "artifact size does not match the manifest")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    digest = hashlib.sha256()
    observed_size = 0
    try:
        descriptor = os.open(os.fspath(path), flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
                _reject("artifact_size_mismatch", "artifact changed during verification")
            while True:
                block = handle.read(HASH_CHUNK_BYTES)
                if not block:
                    break
                observed_size += len(block)
                if observed_size > MAX_ARTIFACT_BYTES:
                    _reject("artifact_size_bound", "artifact exceeds the allowed bound")
                digest.update(block)
    except CryptographicEvidenceError:
        raise
    except OSError:
        _reject("artifact_unreadable", "artifact could not be read")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if observed_size != expected_size:
        _reject("artifact_size_mismatch", "artifact size changed during verification")
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        _reject("artifact_sha256_mismatch", "artifact SHA-256 does not match the manifest")

    final = _require_regular_file(path)
    if final.st_size != expected_size:
        _reject("artifact_size_mismatch", "artifact changed during verification")
    if (
        initial.st_ino
        and final.st_ino
        and (initial.st_dev, initial.st_ino) != (final.st_dev, final.st_ino)
    ):
        _reject("artifact_changed", "artifact changed during verification")


def verify_evidence_manifest(evidence_path: Path | str) -> dict[str, Any]:
    """Verify one manifest and its archive-local regular-file artifacts.

    Artifact paths are resolved relative to the directory containing the
    manifest.  Only metadata and SHA-256 bytes are consumed; artifact contents
    are never interpreted or executed.
    """

    try:
        manifest_path = Path(evidence_path)
    except TypeError:
        _reject("manifest_path_type", "evidence path must be path-like")
    _require_regular_file(manifest_path, manifest=True)
    manifest = _load_json_manifest(manifest_path)
    _require_exact_keys(
        manifest,
        frozenset({"schema", "artifacts", "attack_matrix"}),
        "manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA or type(manifest["schema"]) is not str:
        _reject("schema_value", "manifest schema is not the supported v1 schema")

    artifacts_value = manifest["artifacts"]
    if type(artifacts_value) is not list:
        _reject("artifact_list_type", "manifest.artifacts must be an array")
    if not artifacts_value or len(artifacts_value) > MAX_ARTIFACT_ENTRIES:
        _reject("artifact_count", "manifest.artifacts count is outside the allowed bound")

    matrix_value = manifest["attack_matrix"]
    if type(matrix_value) is not list:
        _reject("case_list_type", "manifest.attack_matrix must be an array")
    if len(matrix_value) > MAX_ATTACK_CASE_ENTRIES:
        _reject("case_count", "manifest.attack_matrix count exceeds the allowed bound")

    root = manifest_path.parent
    artifact_records: dict[str, tuple[Path, int, str]] = {}
    for index, value in enumerate(artifacts_value):
        archive_path, resolved_path, size, digest = _validate_artifact_entry(
            root,
            value,
            index,
        )
        if archive_path in artifact_records:
            _reject("artifact_duplicate", "artifact paths must be unique")
        artifact_records[archive_path] = (resolved_path, size, digest)

    seen_cases: set[str] = set()
    referenced_artifacts: set[str] = set()
    for index, value in enumerate(matrix_value):
        case_id, artifact_path = _validate_case_entry(root, value, index)
        if case_id in seen_cases:
            _reject("case_duplicate", "attack case identifiers must be unique")
        seen_cases.add(case_id)
        referenced_artifacts.add(artifact_path)

    required_cases = set(REQUIRED_ATTACK_CASES)
    if seen_cases != required_cases:
        _reject("case_matrix_incomplete", "required attack case matrix is incomplete")
    if referenced_artifacts != set(artifact_records):
        _reject(
            "artifact_manifest_mismatch",
            "artifact entries and attack case references must match exactly",
        )

    verified_artifacts: list[str] = []
    for archive_path in sorted(artifact_records):
        resolved_path, size, digest = artifact_records[archive_path]
        _hash_artifact(resolved_path, size, digest)
        verified_artifacts.append(archive_path)

    return {
        "schema": VERIFIER_REPORT_SCHEMA,
        "ok": True,
        "verified_artifacts": verified_artifacts,
        "verified_cases": sorted(seen_cases),
    }
