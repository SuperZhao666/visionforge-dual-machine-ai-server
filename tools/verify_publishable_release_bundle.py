from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_formal_release_bundle import (  # noqa: E402
    CANONICAL_HOST_EXE_NAME,
    DEVICE_EVIDENCE_SCHEMA,
    EXPECTED_ANDROID_PACKAGE,
    EXPECTED_GAME_DISPLAY_NAMES,  # noqa: F401 - re-exported for bundle fixtures
    EXPECTED_GAME_TOKENS,
    EXPECTED_MODEL_TARGET_CONTRACTS,  # noqa: F401 - re-exported for bundle fixtures
    REQUIRED_DEVICE_EVIDENCE_FLAGS,
    final_safe_idle_errors,
    formal_bundle_report_errors,
    game_display_name_errors,
    model_target_contract_errors,
    physical_output_route_errors,
)
from tools.final_safe_idle_evidence import decode_ui_xml  # noqa: E402
from tools.formal_release_manifest_security import (  # noqa: E402
    ENVELOPE_SCHEMA,
    MAXIMUM_ENVELOPE_BYTES,
    PAYLOAD_SCHEMA,
    FormalReleaseManifestError,
    parse_json_object,
    verify_manifest_envelope,
)

SCHEMA = "visionforge-publishable-release-bundle-archive-v1"
MANIFEST_SCHEMA = PAYLOAD_SCHEMA
MANIFEST_ENVELOPE_SCHEMA = ENVELOPE_SCHEMA
ACCEPTANCE_SCHEMA = "visionforge-formal-release-acceptance-v1"
MANIFEST_NAME = "formal_release_manifest.json"
ACCEPTANCE_NAME = "formal_release_acceptance.json"
DEVICE_EVIDENCE_NAME = "formal_device_evidence.json"
BUNDLE_REPORT_NAME = "formal_release_bundle_verify.json"
REQUIRED_MANIFEST_ARTIFACT_ROLES = {
    "formal_acceptance_report": ACCEPTANCE_NAME,
    "formal_bundle_report": BUNDLE_REPORT_NAME,
    "formal_device_evidence": DEVICE_EVIDENCE_NAME,
    "host_exe": CANONICAL_HOST_EXE_NAME,
}


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check(name: str, ok: bool, detail: str, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "detail": detail,
        "evidence": dict(evidence or {}),
    }


def _is_safe_archive_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if "\\" in value:
        return False
    path = PurePosixPath(value)
    if path.is_absolute():
        return False
    return all(part not in ("", ".", "..") and ":" not in part for part in path.parts)


def _read_json_entry(archive: zipfile.ZipFile, archive_path: str) -> Mapping[str, Any]:
    return json.loads(archive.read(archive_path).decode("utf-8"))


def _entry_sha256(archive: zipfile.ZipFile, archive_path: str) -> str:
    return sha256_bytes(archive.read(archive_path))


def _entry_size(archive: zipfile.ZipFile, archive_path: str) -> int:
    return archive.getinfo(archive_path).file_size


def _sidecar_expected_sha256(sha256_path: Path, archive_name: str) -> str:
    first_line = sha256_path.read_text(encoding="utf-8").splitlines()[0].strip()
    if not first_line:
        return ""
    parts = first_line.split()
    if len(parts) < 1:
        return ""
    digest = parts[0].lower()
    if len(parts) > 1 and Path(parts[-1]).name != archive_name:
        return ""
    return digest


def _check_sidecar(archive_path: Path, sha256_path: Path | None) -> dict[str, Any]:
    if sha256_path is None:
        return _check("archive-sha256-sidecar", True, "sidecar not requested")
    if not sha256_path.is_file():
        return _check(
            "archive-sha256-sidecar",
            False,
            "sha256 sidecar is missing",
            {"sha256_file": str(sha256_path)},
        )
    expected = _sidecar_expected_sha256(sha256_path, archive_path.name)
    actual = sha256_file(archive_path)
    return _check(
        "archive-sha256-sidecar",
        expected == actual,
        "archive sha256 matches sidecar" if expected == actual else "archive sha256 does not match sidecar",
        {"expected": expected, "actual": actual, "sha256_file": str(sha256_path)},
    )


def _check_manifest_schema(manifest: Mapping[str, Any]) -> dict[str, Any]:
    ok = manifest.get("schema") == MANIFEST_SCHEMA and manifest.get("ok") is True
    return _check(
        "manifest-schema",
        ok,
        "manifest schema is valid" if ok else "manifest schema or ok flag is invalid",
        {"schema": manifest.get("schema"), "ok": manifest.get("ok")},
    )


def _check_archive_directory(archive: zipfile.ZipFile) -> dict[str, Any]:
    names = [info.filename for info in archive.infolist()]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    unsafe = sorted({name for name in names if not _is_safe_archive_path(name)})
    too_many = len(names) > 4096
    errors: list[str] = []
    if duplicates:
        errors.append("duplicate ZIP entries: " + ", ".join(duplicates[:5]))
    if unsafe:
        errors.append("unsafe ZIP entries: " + ", ".join(unsafe[:5]))
    if too_many:
        errors.append("ZIP entry count exceeds 4096")
    return _check(
        "archive-entry-structure",
        not errors,
        "ZIP entry names are unique and safe" if not errors else "; ".join(errors),
        {
            "entry_count": len(names),
            "duplicates": duplicates,
            "unsafe": unsafe,
        },
    )


def _load_authenticated_manifest(
    archive: zipfile.ZipFile,
    trusted_public_key_pem: bytes | str | None,
) -> tuple[Mapping[str, Any] | None, dict[str, Any]]:
    if trusted_public_key_pem is None:
        return None, _check(
            "manifest-signature",
            False,
            "external trusted manifest public key is required",
            {"authenticated": False},
        )
    try:
        raw = archive.read(MANIFEST_NAME)
        envelope = parse_json_object(raw, maximum_bytes=MAXIMUM_ENVELOPE_BYTES)
        payload = verify_manifest_envelope(envelope, trusted_public_key_pem)
    except (KeyError, FormalReleaseManifestError) as exc:
        return None, _check(
            "manifest-signature",
            False,
            str(exc),
            {"authenticated": False},
        )
    return payload, _check(
        "manifest-signature",
        True,
        "manifest signature matches the external trusted Ed25519 public key",
        {
            "authenticated": True,
            "envelope_schema": envelope.get("schema"),
            "algorithm": envelope.get("algorithm"),
            "key_id": envelope.get("key_id"),
        },
    )


def _numeric_version(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _check_rollback_policy(
    manifest: Mapping[str, Any],
    *,
    expected_channel: str | None,
    minimum_release_version: str | None,
    minimum_bundle_sequence: int | None,
    minimum_revocation_epoch: int | None,
) -> dict[str, Any]:
    errors: list[str] = []
    if not expected_channel:
        errors.append("external expected channel is required")
    elif manifest.get("channel") != expected_channel:
        errors.append("manifest channel does not match external policy")
    release_version = str(manifest.get("release_version") or "")
    release_key = _numeric_version(release_version)
    minimum_key = (
        _numeric_version(minimum_release_version)
        if minimum_release_version
        else None
    )
    if minimum_key is None:
        errors.append("external minimum release version is required")
    elif release_key is None or release_key < minimum_key:
        errors.append("manifest release version is below the external floor")
    sequence = manifest.get("bundle_sequence")
    if isinstance(minimum_bundle_sequence, bool) or not isinstance(
        minimum_bundle_sequence,
        int,
    ):
        errors.append("external minimum bundle sequence is required")
    elif isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < minimum_bundle_sequence:
        errors.append("manifest bundle sequence is below the external floor")
    revocation_epoch = manifest.get("revocation_epoch")
    if isinstance(minimum_revocation_epoch, bool) or not isinstance(
        minimum_revocation_epoch,
        int,
    ):
        errors.append("external minimum revocation epoch is required")
    elif (
        isinstance(revocation_epoch, bool)
        or not isinstance(revocation_epoch, int)
        or revocation_epoch < minimum_revocation_epoch
    ):
        errors.append("manifest revocation epoch is below the external floor")
    return _check(
        "manifest-rollback-policy",
        not errors,
        "external channel/version/sequence/revocation floors passed"
        if not errors
        else "; ".join(errors),
        {
            "anti_rollback_enforced": not errors,
            "expected_channel": expected_channel,
            "minimum_release_version": minimum_release_version,
            "minimum_bundle_sequence": minimum_bundle_sequence,
            "minimum_revocation_epoch": minimum_revocation_epoch,
            "release_version": release_version,
            "bundle_sequence": sequence,
            "revocation_epoch": revocation_epoch,
        },
    )


def _check_archive_entry_closure(
    manifest: Mapping[str, Any],
    names: set[str],
) -> dict[str, Any]:
    expected = {MANIFEST_NAME}
    errors: list[str] = []
    artifacts = manifest.get("artifacts")
    if isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes)):
        for item in artifacts:
            if isinstance(item, Mapping) and _is_safe_archive_path(item.get("archive_path")):
                expected.add(str(item["archive_path"]))
            else:
                errors.append("manifest contains an invalid artifact archive_path")
    else:
        errors.append("manifest artifacts list is missing")
    evidence_sources = manifest.get("evidence_sources")
    files = evidence_sources.get("files") if isinstance(evidence_sources, Mapping) else None
    if isinstance(files, Sequence) and not isinstance(files, (str, bytes)):
        for item in files:
            if isinstance(item, Mapping) and _is_safe_archive_path(item.get("archive_path")):
                expected.add(str(item["archive_path"]))
            else:
                errors.append("manifest contains an invalid evidence archive_path")
    else:
        errors.append("manifest evidence source files are missing")
    missing = sorted(expected - names)
    unexpected = sorted(names - expected)
    if missing:
        errors.append("missing signed ZIP entries: " + ", ".join(missing[:5]))
    if unexpected:
        errors.append("unsigned extra ZIP entries: " + ", ".join(unexpected[:5]))
    return _check(
        "archive-entry-closure",
        not errors,
        "ZIP entries exactly match the signed manifest"
        if not errors
        else "; ".join(errors[:5]),
        {"expected_count": len(expected), "missing": missing, "unexpected": unexpected},
    )


def _check_artifacts(
    archive: zipfile.ZipFile,
    manifest: Mapping[str, Any],
    names: set[str],
) -> dict[str, Any]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
        return _check("manifest-artifacts", False, "manifest artifacts list is missing")
    errors: list[str] = []
    checked = 0
    seen: set[str] = set()
    role_paths: dict[str, list[str]] = {}
    for item in artifacts:
        if not isinstance(item, Mapping):
            errors.append("artifact item is not an object")
            continue
        archive_path = item.get("archive_path")
        if not _is_safe_archive_path(archive_path):
            errors.append(f"invalid artifact archive_path: {archive_path!r}")
            continue
        archive_name = str(archive_path)
        if archive_name in seen:
            errors.append(f"duplicate artifact archive_path: {archive_name}")
            continue
        seen.add(archive_name)
        role = str(item.get("role") or "")
        if role:
            role_paths.setdefault(role, []).append(archive_name)
        if archive_name not in names:
            errors.append(f"missing artifact archive entry: {archive_name}")
            continue
        checked += 1
        expected_sha = str(item.get("sha256") or "").lower()
        if len(expected_sha) != 64:
            errors.append(f"artifact sha256 missing: {archive_name}")
        elif _entry_sha256(archive, archive_name) != expected_sha:
            errors.append(f"artifact sha256 mismatch: {archive_name}")
        expected_size = item.get("size")
        if isinstance(expected_size, int) and _entry_size(archive, archive_name) != expected_size:
            errors.append(f"artifact size mismatch: {archive_name}")
    for role, expected_archive_path in REQUIRED_MANIFEST_ARTIFACT_ROLES.items():
        if role_paths.get(role) != [expected_archive_path]:
            errors.append(
                f"manifest artifact role {role} must point to {expected_archive_path}"
            )
    return _check(
        "manifest-artifacts",
        not errors,
        "all manifest artifacts are present and hashed" if not errors else "; ".join(errors[:5]),
        {
            "checked": checked,
            "errors": errors,
            "required_roles": dict(REQUIRED_MANIFEST_ARTIFACT_ROLES),
            "role_paths": role_paths,
        },
    )


def _check_evidence_source_files(
    archive: zipfile.ZipFile,
    manifest: Mapping[str, Any],
    names: set[str],
) -> dict[str, Any]:
    evidence_sources = manifest.get("evidence_sources")
    if not isinstance(evidence_sources, Mapping):
        return _check("evidence-source-files", False, "manifest evidence_sources object is missing")
    root = evidence_sources.get("archive_path")
    if not _is_safe_archive_path(root):
        return _check("evidence-source-files", False, "evidence_sources.archive_path is invalid")
    files = evidence_sources.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)) or not files:
        return _check("evidence-source-files", False, "evidence_sources.files list is missing")
    errors: list[str] = []
    checked = 0
    for item in files:
        if not isinstance(item, Mapping):
            errors.append("evidence source file item is not an object")
            continue
        archive_path = item.get("archive_path")
        if not _is_safe_archive_path(archive_path):
            errors.append(f"invalid evidence source archive_path: {archive_path!r}")
            continue
        archive_name = str(archive_path)
        if archive_name not in names:
            errors.append(f"missing evidence source archive entry: {archive_name}")
            continue
        checked += 1
        expected_sha = str(item.get("sha256") or "").lower()
        if len(expected_sha) != 64:
            errors.append(f"evidence source sha256 missing: {archive_name}")
        elif _entry_sha256(archive, archive_name) != expected_sha:
            errors.append(f"evidence source sha256 mismatch: {archive_name}")
        expected_size = item.get("size")
        if isinstance(expected_size, int) and _entry_size(archive, archive_name) != expected_size:
            errors.append(f"evidence source size mismatch: {archive_name}")
    return _check(
        "evidence-source-files",
        not errors,
        "all evidence source files are present and hashed" if not errors else "; ".join(errors[:5]),
        {"checked": checked, "errors": errors},
    )


def _source_exists(names: set[str], archive_path: str) -> bool:
    if archive_path in names:
        return True
    prefix = archive_path.rstrip("/") + "/"
    return any(name.startswith(prefix) for name in names)


def _check_device_evidence_sources(
    archive: zipfile.ZipFile,
    names: set[str],
) -> dict[str, Any]:
    if DEVICE_EVIDENCE_NAME not in names:
        return _check("device-evidence-sources", False, "formal_device_evidence.json is missing")
    evidence = _read_json_entry(archive, DEVICE_EVIDENCE_NAME)
    sources = evidence.get("sources")
    if not isinstance(sources, Mapping):
        return _check("device-evidence-sources", False, "formal device evidence sources are missing")
    required_file_sources = ("android_apk", "windows_exe", "host_exe")
    errors: list[str] = []
    checked = 0
    for key in required_file_sources:
        value = sources.get(key)
        if not _is_safe_archive_path(value) or not _source_exists(names, str(value)):
            errors.append(f"sources.{key} is not a valid archive entry")
        else:
            checked += 1
    ui_dir = sources.get("ui_evidence_dir")
    if not _is_safe_archive_path(ui_dir) or not _source_exists(names, str(ui_dir)):
        errors.append("sources.ui_evidence_dir is not a valid archive directory")
    else:
        checked += 1
    for key, required in (("mobile_logs", True), ("host_logs", False)):
        values = sources.get(key)
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            errors.append(f"sources.{key} is not a list")
            continue
        if required and not values:
            errors.append(f"sources.{key} is empty")
            continue
        for value in values:
            if not _is_safe_archive_path(value) or str(value) not in names:
                errors.append(f"sources.{key} contains invalid archive entry: {value!r}")
            else:
                checked += 1
    return _check(
        "device-evidence-sources",
        not errors,
        "formal device evidence sources are archive-local" if not errors else "; ".join(errors[:5]),
        {"checked": checked, "errors": errors},
    )


def _check_device_evidence_contract(
    archive: zipfile.ZipFile,
    names: set[str],
) -> dict[str, Any]:
    if DEVICE_EVIDENCE_NAME not in names:
        return _check("device-evidence-contract", False, "formal_device_evidence.json is missing")
    evidence = _read_json_entry(archive, DEVICE_EVIDENCE_NAME)
    sources = evidence.get("sources")
    if not isinstance(sources, Mapping):
        return _check("device-evidence-contract", False, "formal device evidence sources are missing")
    errors: list[str] = []
    checked = 0
    if evidence.get("schema") != DEVICE_EVIDENCE_SCHEMA:
        errors.append("device evidence schema is invalid")
    if not str(evidence.get("device_serial") or ""):
        errors.append("device evidence device_serial is missing")
    if str(evidence.get("installed_package_name") or "") != EXPECTED_ANDROID_PACKAGE:
        errors.append("device evidence installed_package_name is invalid")
    if not str(evidence.get("installed_package_version") or ""):
        errors.append("device evidence installed_package_version is missing")
    checks = evidence.get("checks")
    if not isinstance(checks, Mapping):
        errors.append("device evidence checks are missing")
    else:
        for key in REQUIRED_DEVICE_EVIDENCE_FLAGS:
            if checks.get(key) is not True:
                errors.append(f"device evidence check {key} is not true")
            else:
                checked += 1
    if sorted(evidence.get("game_model_tokens") or []) != sorted(EXPECTED_GAME_TOKENS):
        errors.append("device evidence game_model_tokens are incomplete")
    errors.extend(game_display_name_errors(evidence))
    errors.extend(model_target_contract_errors(evidence))
    hash_bindings = {
        "windows_exe_sha256": "windows_exe",
        "android_apk_sha256": "android_apk",
        "host_exe_sha256": "host_exe",
    }
    for hash_field, source_key in hash_bindings.items():
        source_value = sources.get(source_key)
        expected_hash = str(evidence.get(hash_field) or "").lower()
        if not _is_safe_archive_path(source_value) or str(source_value) not in names:
            errors.append(f"device evidence sources.{source_key} is not a valid archive entry")
            continue
        if len(expected_hash) != 64:
            errors.append(f"device evidence {hash_field} is missing")
            continue
        actual_hash = _entry_sha256(archive, str(source_value))
        if actual_hash != expected_hash:
            errors.append(f"device evidence {hash_field} does not match archive entry")
        else:
            checked += 1
    mobile_log_hashes: set[str] = set()
    mobile_log_sources = sources.get("mobile_logs")
    if isinstance(mobile_log_sources, Sequence) and not isinstance(
        mobile_log_sources, (str, bytes)
    ):
        for value in mobile_log_sources:
            if _is_safe_archive_path(value) and str(value) in names:
                mobile_log_hashes.add(_entry_sha256(archive, str(value)))
    errors.extend(
        physical_output_route_errors(
            evidence,
            expected_apk_sha256=str(evidence.get("android_apk_sha256") or ""),
            expected_device_serial=str(evidence.get("device_serial") or ""),
            allowed_mobile_log_hashes=mobile_log_hashes,
        )
    )
    ui_xml_sources: dict[str, str] = {}
    ui_directory = sources.get("ui_evidence_dir")
    if _is_safe_archive_path(ui_directory):
        prefix = str(ui_directory).rstrip("/") + "/"
        for name in names:
            if not name.startswith(prefix) or not name.lower().endswith(".xml"):
                continue
            raw = archive.read(name)
            ui_xml_sources[sha256_bytes(raw)] = sha256_bytes(
                decode_ui_xml(raw).encode("utf-8")
            )
    errors.extend(
        final_safe_idle_errors(
            evidence,
            expected_apk_sha256=str(evidence.get("android_apk_sha256") or ""),
            expected_device_serial=str(evidence.get("device_serial") or ""),
            allowed_mobile_log_hashes=mobile_log_hashes,
            allowed_ui_xml_hashes=set(ui_xml_sources),
            allowed_ui_xml_sources=ui_xml_sources,
        )
    )
    return _check(
        "device-evidence-contract",
        not errors,
        "formal device evidence contract matches archive" if not errors else "; ".join(errors[:5]),
        {"checked": checked, "errors": errors},
    )


def _check_formal_acceptance_report(
    archive: zipfile.ZipFile,
    names: set[str],
) -> dict[str, Any]:
    if ACCEPTANCE_NAME not in names:
        return _check(
            "formal-acceptance-report",
            False,
            "formal_release_acceptance.json is missing",
        )
    errors: list[str] = []
    acceptance = _read_json_entry(archive, ACCEPTANCE_NAME)
    release_blockers = acceptance.get("release_blockers")
    next_actions = acceptance.get("next_actions")
    if acceptance.get("schema") != ACCEPTANCE_SCHEMA:
        errors.append("formal acceptance schema is invalid")
    if acceptance.get("ok") is not True:
        errors.append("formal acceptance ok is not true")
    if release_blockers != []:
        errors.append("formal acceptance release_blockers must be empty")
    if next_actions != []:
        errors.append("formal acceptance next_actions must be empty")
    return _check(
        "formal-acceptance-report",
        not errors,
        "formal acceptance report is publishable" if not errors else "; ".join(errors[:5]),
        {
            "schema": acceptance.get("schema"),
            "ok": acceptance.get("ok"),
            "release_blockers_empty": release_blockers == [],
            "next_actions_empty": next_actions == [],
            "release_blocker_count": (
                len(release_blockers)
                if isinstance(release_blockers, Sequence)
                and not isinstance(release_blockers, (str, bytes))
                else None
            ),
            "next_action_count": (
                len(next_actions)
                if isinstance(next_actions, Sequence)
                and not isinstance(next_actions, (str, bytes))
                else None
            ),
            "errors": errors,
        },
    )


def _check_formal_bundle_report(
    archive: zipfile.ZipFile,
    names: set[str],
) -> dict[str, Any]:
    if BUNDLE_REPORT_NAME not in names:
        return _check(
            "formal-bundle-report",
            False,
            "formal_release_bundle_verify.json is missing",
        )
    report = _read_json_entry(archive, BUNDLE_REPORT_NAME)
    errors = formal_bundle_report_errors(report)
    return _check(
        "formal-bundle-report",
        not errors,
        (
            "embedded formal bundle report is independently valid"
            if not errors
            else "; ".join(errors[:8])
        ),
        {
            "schema": report.get("schema"),
            "mode": report.get("mode"),
            "diagnostic_completed": report.get("diagnostic_completed"),
            "checks_ok": report.get("checks_ok"),
            "strict_ok": report.get("strict_ok"),
            "reverse_resistance_ok": report.get("reverse_resistance_ok"),
            "formal_eligible": report.get("formal_eligible"),
            "formal_ok": report.get("formal_ok"),
            "formal_release_ok": report.get("formal_release_ok"),
            "bypasses": report.get("bypasses"),
            "ok": report.get("ok"),
            "errors": errors,
        },
    )


def verify_publishable_release_bundle(
    *,
    archive_path: Path,
    sha256_path: Path | None,
    trusted_public_key_pem: bytes | str | None = None,
    expected_channel: str | None = None,
    minimum_release_version: str | None = None,
    minimum_bundle_sequence: int | None = None,
    minimum_revocation_epoch: int | None = None,
) -> Mapping[str, Any]:
    archive_path = archive_path.resolve()
    checks: list[dict[str, Any]] = []
    authenticated_manifest: Mapping[str, Any] | None = None
    generated_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    if not archive_path.is_file():
        checks.append(_check("archive-exists", False, "archive is missing", {"archive": str(archive_path)}))
        return {
            "schema": SCHEMA,
            "generated_at": generated_at,
            "authenticated": False,
            "anti_rollback_enforced": False,
            "manifest": None,
            "ok": False,
            "archive": str(archive_path),
            "checks": checks,
        }
    checks.append(_check("archive-exists", True, "archive exists", {"archive": str(archive_path)}))
    checks.append(_check_sidecar(archive_path, sha256_path.resolve() if sha256_path else None))
    try:
        with zipfile.ZipFile(archive_path) as archive:
            structure_check = _check_archive_directory(archive)
            checks.append(structure_check)
            names = set(archive.namelist())
            if structure_check["ok"] is True and MANIFEST_NAME in names:
                manifest, signature_check = _load_authenticated_manifest(
                    archive,
                    trusted_public_key_pem,
                )
                checks.append(signature_check)
            elif MANIFEST_NAME not in names:
                manifest = None
                checks.append(
                    _check(
                        "manifest-signature",
                        False,
                        "formal_release_manifest.json is missing",
                        {"authenticated": False},
                    )
                )
            else:
                manifest = None
            if manifest is not None:
                authenticated_manifest = manifest
                checks.append(_check_manifest_schema(manifest))
                checks.append(
                    _check_rollback_policy(
                        manifest,
                        expected_channel=expected_channel,
                        minimum_release_version=minimum_release_version,
                        minimum_bundle_sequence=minimum_bundle_sequence,
                        minimum_revocation_epoch=minimum_revocation_epoch,
                    )
                )
                checks.append(_check_archive_entry_closure(manifest, names))
                checks.append(_check_artifacts(archive, manifest, names))
                checks.append(_check_formal_acceptance_report(archive, names))
                checks.append(_check_formal_bundle_report(archive, names))
                checks.append(_check_evidence_source_files(archive, manifest, names))
                checks.append(_check_device_evidence_sources(archive, names))
                checks.append(_check_device_evidence_contract(archive, names))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("archive-readable", False, str(exc)))
    ok = all(check["ok"] is True for check in checks)
    signature_check = next(
        (check for check in checks if check["name"] == "manifest-signature"),
        None,
    )
    rollback_check = next(
        (check for check in checks if check["name"] == "manifest-rollback-policy"),
        None,
    )
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "authenticated": bool(signature_check and signature_check["ok"] is True),
        "anti_rollback_enforced": bool(
            rollback_check and rollback_check["ok"] is True
        ),
        "manifest": (
            {
                "schema": authenticated_manifest.get("schema"),
                "channel": authenticated_manifest.get("channel"),
                "release_version": authenticated_manifest.get("release_version"),
                "bundle_sequence": authenticated_manifest.get("bundle_sequence"),
                "revocation_epoch": authenticated_manifest.get("revocation_epoch"),
                "artifact_count": len(authenticated_manifest.get("artifacts", [])),
            }
            if authenticated_manifest is not None
            else None
        ),
        "ok": ok,
        "archive": str(archive_path),
        "sha256": sha256_file(archive_path),
        "checks": checks,
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256-file", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-channel", required=True)
    parser.add_argument("--minimum-release-version", required=True)
    parser.add_argument("--minimum-bundle-sequence", type=int, required=True)
    parser.add_argument("--minimum-revocation-epoch", type=int, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(argv)
    archive = args.archive.resolve()
    sha256_path = args.sha256_file
    if sha256_path is None:
        default_sha = archive.with_suffix(".zip.sha256")
        sha256_path = default_sha if default_sha.exists() else None
    output = (args.output or (archive.parent / "publishable_release_bundle_verify.json")).resolve()
    try:
        trusted_public_key_pem = args.public_key.resolve().read_bytes()
    except OSError:
        trusted_public_key_pem = None
    report = verify_publishable_release_bundle(
        archive_path=archive,
        sha256_path=sha256_path,
        trusted_public_key_pem=trusted_public_key_pem,
        expected_channel=args.expected_channel,
        minimum_release_version=args.minimum_release_version,
        minimum_bundle_sequence=args.minimum_bundle_sequence,
        minimum_revocation_epoch=args.minimum_revocation_epoch,
    )
    write_report(output, report)
    if report.get("ok") is True:
        print(f"[OK] publishable release bundle archive verified; report={output}", flush=True)
        return 0
    print(f"[ERROR] publishable release bundle archive verification failed; report={output}", flush=True)
    for check in report.get("checks", []):
        if isinstance(check, Mapping) and check.get("ok") is not True:
            print(f"- {check.get('name')}: {check.get('detail')}", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
