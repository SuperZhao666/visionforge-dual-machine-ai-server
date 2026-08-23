"""Fail-closed verification for archive-local dual-machine crypto evidence.

This module verifies metadata and files that were produced elsewhere.  It does
not execute evidence, decode captures, perform cryptographic operations, or
contact a peer or service.  The evidence manifest is deliberately small: the
manifest records the required attack case outcome and the archive-local file
whose size and SHA-256 digest are checked.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import hmac
import json
import ntpath
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import Any, BinaryIO, Iterator, Mapping

if os.name == "nt":
    import msvcrt
    from ctypes import wintypes


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
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


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


if os.name == "nt":
    _WIN_GENERIC_READ = 0x80000000
    _WIN_FILE_SHARE_READ = 0x00000001
    _WIN_FILE_SHARE_WRITE = 0x00000002
    _WIN_FILE_SHARE_DELETE = 0x00000004
    _WIN_OPEN_EXISTING = 3
    _WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _WIN_FILE_TYPE_DISK = 0x00000001
    _WIN_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _WIN_INVALID_HANDLE_VALUES = {
        -1,
        ctypes.c_void_p(-1).value,
    }

    class _WindowsFileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    _kernel32.GetFileType.restype = wintypes.DWORD
    _kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


def _win_handle_value(handle: Any) -> int:
    if isinstance(handle, ctypes.c_void_p):
        return int(handle.value or 0)
    return int(handle)


def _win_is_invalid_handle(handle: Any) -> bool:
    return handle is None or _win_handle_value(handle) in _WIN_INVALID_HANDLE_VALUES


def _win_close_handle(handle: Any) -> None:
    if os.name == "nt" and not _win_is_invalid_handle(handle):
        _kernel32.CloseHandle(handle)


def _win_create_handle(path: Path | str, *, directory: bool) -> Any:
    if os.name != "nt":
        raise RuntimeError("Windows handle API is unavailable")
    flags = _WIN_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WIN_FILE_FLAG_BACKUP_SEMANTICS
    handle = _kernel32.CreateFileW(
        os.path.abspath(os.fspath(path)),
        _WIN_GENERIC_READ,
        _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE | _WIN_FILE_SHARE_DELETE,
        None,
        _WIN_OPEN_EXISTING,
        flags,
        None,
    )
    if _win_is_invalid_handle(handle):
        _reject(
            "archive_root_unreadable" if directory else "artifact_missing",
            "secure handle could not be opened",
        )
    return handle


def _win_handle_attributes(handle: Any) -> int:
    info = _WindowsFileAttributeTagInfo()
    if not _kernel32.GetFileInformationByHandleEx(
        handle,
        _WIN_FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        _reject("secure_handle_unreadable", "secure handle attributes could not be read")
    return int(info.FileAttributes)


def _win_final_path(handle: Any) -> str:
    size = 512
    while size <= 65536:
        buffer = ctypes.create_unicode_buffer(size)
        length = int(_kernel32.GetFinalPathNameByHandleW(handle, buffer, size, 0))
        if length == 0:
            _reject("secure_handle_unreadable", "secure handle final path could not be read")
        if length < size - 1:
            return buffer.value
        size = length + 1
    _reject("secure_handle_path_bound", "secure handle final path exceeds the allowed bound")


def _win_normalize_final_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value))


def _win_path_is_within(root: str, candidate: str) -> bool:
    normalized_root = _win_normalize_final_path(root)
    normalized_candidate = _win_normalize_final_path(candidate)
    if normalized_candidate == normalized_root:
        return False
    prefix = normalized_root if normalized_root.endswith("\\") else normalized_root + "\\"
    return normalized_candidate.startswith(prefix)


def _win_verify_handle(
    handle: Any,
    *,
    root_final_path: str | None,
    directory: bool,
) -> str:
    attributes = _win_handle_attributes(handle)
    if attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
        _reject("secure_handle_reparse_point", "reparse points are not allowed")
    is_directory = bool(attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY)
    if is_directory != directory:
        _reject(
            "archive_root_not_directory" if directory else "artifact_not_regular",
            "secure handle type is not allowed",
        )
    if not directory and _kernel32.GetFileType(handle) != _WIN_FILE_TYPE_DISK:
        _reject("artifact_not_regular", "secure handle is not a disk regular file")
    final_path = _win_final_path(handle)
    if root_final_path is not None and not _win_path_is_within(root_final_path, final_path):
        _reject("path_escape", "secure handle is outside the archive root")
    return final_path


def _posix_secure_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _reject("secure_open_unsupported", "secure descriptor-relative open is unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _posix_open_directory_path(path: Path) -> int:
    if os.open not in getattr(os, "supports_dir_fd", set()):
        _reject("secure_open_unsupported", "secure descriptor-relative open is unavailable")
    flags = _posix_secure_flags(directory=True)
    absolute = os.path.abspath(os.fspath(path))
    parts = Path(absolute).parts
    if not parts or parts[0] != os.path.sep:
        _reject("archive_root_invalid", "archive root must be an absolute directory")
    try:
        descriptor = os.open(os.path.sep, flags)
    except (OSError, TypeError):
        _reject("archive_root_unreadable", "archive root could not be securely opened")
    try:
        for part in parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, TypeError):
        try:
            os.close(descriptor)
        except OSError:
            pass
        _reject("archive_root_unreadable", "archive root could not be securely opened")


def _posix_open_relative(root_descriptor: int, parts: tuple[str, ...]) -> int:
    if os.open not in getattr(os, "supports_dir_fd", set()):
        _reject("secure_open_unsupported", "secure descriptor-relative open is unavailable")
    directory_flags = _posix_secure_flags(directory=True)
    file_flags = _posix_secure_flags(directory=False)
    current_descriptor = os.dup(root_descriptor)
    descriptor: int | None = None
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=current_descriptor)
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        descriptor = os.open(parts[-1], file_flags, dir_fd=current_descriptor)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(descriptor)
            descriptor = None
            _reject("artifact_not_regular", "secure handle type is not allowed")
        result = descriptor
        descriptor = None
        return result
    except CryptographicEvidenceError:
        raise
    except (OSError, TypeError):
        _reject("artifact_missing", "secure descriptor-relative file could not be opened")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(current_descriptor)
        except OSError:
            pass


class _SecureArchive:
    """Bind archive root and file reads to handles, not path re-checks."""

    def __init__(self, root: Path) -> None:
        self._root_handle: Any | None = None
        self._root_descriptor: int | None = None
        self._root_final_path: str | None = None
        try:
            if os.name == "nt":
                root_handle = _win_create_handle(root, directory=True)
                try:
                    self._root_final_path = _win_verify_handle(
                        root_handle,
                        root_final_path=None,
                        directory=True,
                    )
                    self._root_handle = root_handle
                    root_handle = None
                finally:
                    _win_close_handle(root_handle)
            else:
                self._root_descriptor = _posix_open_directory_path(root)
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "_SecureArchive":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._root_descriptor is not None:
            try:
                os.close(self._root_descriptor)
            except OSError:
                pass
            self._root_descriptor = None
        if self._root_handle is not None:
            _win_close_handle(self._root_handle)
            self._root_handle = None

    @contextlib.contextmanager
    def open_file(self, archive_path: str, *, manifest: bool = False) -> Iterator[BinaryIO]:
        parts = _validate_archive_path(
            archive_path,
            location="manifest.path" if manifest else "artifact.path",
        )
        descriptor: int | None = None
        handle: Any | None = None
        stream: BinaryIO | None = None
        try:
            if os.name == "nt":
                if self._root_final_path is None:
                    _reject("secure_open_unsupported", "Windows archive root is not bound")
                full_path = ntpath.join(self._root_final_path, *parts)
                handle = _win_create_handle(full_path, directory=False)
                _win_verify_handle(
                    handle,
                    root_final_path=self._root_final_path,
                    directory=False,
                )
                descriptor = msvcrt.open_osfhandle(
                    _win_handle_value(handle),
                    os.O_RDONLY | getattr(os, "O_BINARY", 0),
                )
                handle = None
            else:
                if self._root_descriptor is None:
                    _reject("secure_open_unsupported", "POSIX archive root is not bound")
                descriptor = _posix_open_relative(self._root_descriptor, parts)
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = None
            yield stream
        except CryptographicEvidenceError:
            raise
        except (OSError, ValueError):
            _reject(
                "manifest_unreadable" if manifest else "artifact_unreadable",
                "secure handle could not be converted to a readable stream",
            )
        finally:
            if stream is not None:
                stream.close()
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            _win_close_handle(handle)


def _load_json_manifest(
    archive: _SecureArchive,
    manifest_name: str,
) -> Mapping[str, Any]:
    try:
        with archive.open_file(manifest_name, manifest=True) as handle:
            try:
                manifest_size = os.fstat(handle.fileno()).st_size
            except OSError:
                _reject("manifest_unreadable", "manifest handle size could not be read")
            if manifest_size > MAX_MANIFEST_BYTES:
                _reject("manifest_too_large", "manifest exceeds the maximum input size")
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except CryptographicEvidenceError:
        raise
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
) -> tuple[str, int, str]:
    if type(value) is not dict:
        _reject("artifact_schema", f"artifact entry {index} must be an object")
    _require_exact_keys(value, frozenset({"path", "size", "sha256"}), "artifact entry")
    archive_path, _ = _archive_path(
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
    return archive_path, size, digest


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


def _hash_artifact(
    archive: _SecureArchive,
    archive_path: str,
    expected_size: int,
    expected_digest: str,
    *,
    read_budget: int = MAX_TOTAL_ARTIFACT_BYTES,
) -> None:
    if type(read_budget) is not int or read_budget < 0:
        _reject(
            "artifact_total_size_bound",
            "artifact read budget is outside the allowed bound",
        )
    if expected_size > read_budget:
        _reject(
            "artifact_total_size_bound",
            "artifact read bytes exceed the total allowed bound",
        )
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with archive.open_file(archive_path) as handle:
            try:
                opened = os.fstat(handle.fileno())
            except OSError:
                _reject("artifact_unreadable", "artifact handle size could not be read")
            if opened.st_size > read_budget:
                _reject(
                    "artifact_total_size_bound",
                    "artifact read bytes exceed the total allowed bound",
                )
            if opened.st_size > MAX_ARTIFACT_BYTES or opened.st_size != expected_size:
                _reject("artifact_size_mismatch", "artifact size does not match the manifest")
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
                _reject("artifact_size_mismatch", "artifact changed during verification")
            while True:
                remaining = read_budget - observed_size
                if remaining == 0:
                    break
                block = handle.read(min(HASH_CHUNK_BYTES, remaining))
                if not block:
                    break
                observed_size += len(block)
                digest.update(block)
            try:
                final = os.fstat(handle.fileno())
            except OSError:
                _reject("artifact_unreadable", "artifact final size could not be read")
            if final.st_size != expected_size:
                _reject("artifact_size_mismatch", "artifact changed during verification")
    except CryptographicEvidenceError:
        raise
    except OSError:
        _reject("artifact_unreadable", "artifact could not be read")

    if observed_size != expected_size:
        _reject("artifact_size_mismatch", "artifact size changed during verification")
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        _reject("artifact_sha256_mismatch", "artifact SHA-256 does not match the manifest")


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
    root = manifest_path.parent
    manifest_name = manifest_path.name
    _validate_archive_path(manifest_name, location="manifest.path")

    with _SecureArchive(root) as archive:
        manifest = _load_json_manifest(archive, manifest_name)
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

        artifact_records: dict[str, tuple[int, str]] = {}
        total_declared_bytes = 0
        for index, value in enumerate(artifacts_value):
            archive_path, size, digest = _validate_artifact_entry(
                root,
                value,
                index,
            )
            if archive_path in artifact_records:
                _reject("artifact_duplicate", "artifact paths must be unique")
            if size > MAX_TOTAL_ARTIFACT_BYTES - total_declared_bytes:
                _reject(
                    "artifact_total_size_bound",
                    "declared artifact bytes exceed the total allowed bound",
                )
            total_declared_bytes += size
            artifact_records[archive_path] = (size, digest)

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
        total_read_bytes = 0
        for archive_path in sorted(artifact_records):
            size, digest = artifact_records[archive_path]
            _hash_artifact(
                archive,
                archive_path,
                size,
                digest,
                read_budget=MAX_TOTAL_ARTIFACT_BYTES - total_read_bytes,
            )
            total_read_bytes += size
            verified_artifacts.append(archive_path)

        return {
            "schema": VERIFIER_REPORT_SCHEMA,
            "ok": True,
            "verified_artifacts": verified_artifacts,
            "verified_cases": sorted(seen_cases),
        }
