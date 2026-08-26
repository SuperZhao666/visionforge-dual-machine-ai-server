from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_formal_release_bundle import (  # noqa: E402
    CANONICAL_HOST_EXE_NAME,
    DEVICE_EVIDENCE_SCHEMA,
    EXPECTED_GAME_TOKENS,
    REQUIRED_DEVICE_EVIDENCE_FLAGS,
    final_safe_idle_errors,
    formal_bundle_report_errors,
    game_display_name_errors,
    model_target_contract_errors,
)
from tools.final_safe_idle_evidence import decode_ui_xml  # noqa: E402
from tools.formal_release_manifest_security import (  # noqa: E402
    PAYLOAD_SCHEMA,
    FormalReleaseManifestError,
    load_private_key,
    public_key_pem,
    sign_manifest_payload,
)
from tools.verify_publishable_release_bundle import (  # noqa: E402
    verify_publishable_release_bundle as verify_publishable_archive,
)

SCHEMA = PAYLOAD_SCHEMA
ARCHIVE_NAME = "formal_release_bundle.zip"
ARCHIVE_SHA256_NAME = "formal_release_bundle.zip.sha256"
PUBLISHABLE_ARCHIVE_VERIFY_NAME = "publishable_release_bundle_verify.json"
DEVICE_EVIDENCE_SOURCES_DIR = "device_evidence_sources"
ANDROID_APK_PREFLIGHT_SCHEMA = "visionforge-android-release-apk-artifact-v1"
ANDROID_DEVICE_PREFLIGHT_SCHEMA = "visionforge-android-device-connectivity-v1"
ANDROID_RELEASE_BUILD_SCHEMA = "visionforge-android-production-release-build-v1"
ANDROID_SIGNING_INPUTS_SCHEMA = "visionforge-android-production-signing-inputs-v1"
DEFAULT_RELEASE_VERSION_FILE = ROOT / "dual_machine_runtime" / "release_version.txt"


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _blocker_detail(blocker: Mapping[str, Any]) -> str:
    detail = str(blocker.get("detail") or "").strip()
    if detail:
        return detail[:240]
    for key in ("stderr_tail", "stdout_tail"):
        text = str(blocker.get(key) or "")
        for line in reversed(text.splitlines()):
            value = line.strip()
            if value:
                return value[:240]
    return ""


def print_acceptance_blocker_summary(acceptance_report: Path) -> None:
    try:
        report = read_json(acceptance_report)
    except Exception:  # noqa: BLE001
        return
    blockers = report.get("release_blockers")
    if not isinstance(blockers, Sequence) or isinstance(blockers, (str, bytes)) or not blockers:
        return
    print("[ERROR] release blockers:", flush=True)
    for blocker in blockers:
        if not isinstance(blocker, Mapping):
            continue
        stage = str(blocker.get("stage") or "unknown")
        returncode = blocker.get("returncode")
        report_text = str(blocker.get("report") or "")
        detail = _blocker_detail(blocker)
        print(
            f"- {stage} returncode={returncode} report={report_text} detail={detail}",
            flush=True,
        )


def print_acceptance_next_action_summary(acceptance_report: Path) -> None:
    try:
        report = read_json(acceptance_report)
    except Exception:  # noqa: BLE001
        return
    next_actions = report.get("next_actions")
    if not isinstance(next_actions, Sequence) or isinstance(next_actions, (str, bytes)) or not next_actions:
        return
    print("[ERROR] next actions:", flush=True)
    for action in next_actions:
        if not isinstance(action, Mapping):
            continue
        stage = str(action.get("stage") or "unknown")
        action_text = str(action.get("action") or "").strip()
        command = str(action.get("command") or "").strip()
        commands = action.get("commands")
        hint = str(action.get("hint") or "").strip()
        line = f"- {stage}: {action_text}"
        if command:
            line = f"{line} command={command}"
        if isinstance(commands, Sequence) and not isinstance(commands, (str, bytes)):
            command_list = ", ".join(str(item) for item in commands if str(item).strip())
            if command_list:
                line = f"{line} commands={command_list}"
        if hint:
            line = f"{line} hint={hint}"
        print(line, flush=True)


def _resolve_report_path(raw: str, base_dir: Path) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _resolve_runtime_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_acceptance_local_report_path(path: Path, acceptance_dir: Path, label: str) -> None:
    if not _is_relative_to(path.resolve(), acceptance_dir.resolve()):
        raise ValueError(f"{label} must be inside the formal acceptance directory")


def _required_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{label} is missing: {resolved}")
    return resolved


def _required_dir(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"{label} is missing: {resolved}")
    return resolved


def _load_required_json(path: Path, label: str) -> Mapping[str, Any]:
    _required_file(path, label)
    return read_json(path)


def _prepare_output_dir(output_dir: Path, *, force: bool) -> Path:
    resolved = output_dir.resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _validate_output_dir_contents(
    output_dir: Path,
    sources: Sequence[tuple[str, Path]],
    *,
    force: bool,
    extra_planned_names: Sequence[str] = (),
) -> None:
    source_names = [source.name for _, source in sources]
    reserved_names = {
        "formal_release_manifest.json",
        ARCHIVE_NAME,
        ARCHIVE_SHA256_NAME,
        PUBLISHABLE_ARCHIVE_VERIFY_NAME,
    }
    planned_names = set(source_names) | set(extra_planned_names) | reserved_names
    duplicate_names = sorted(
        name for name in set(source_names) if source_names.count(name) > 1
    )
    if duplicate_names:
        raise ValueError(
            "publishable release artifacts have duplicate output names: "
            + ", ".join(duplicate_names),
        )
    reserved_collisions = sorted(set(source_names) & reserved_names)
    if reserved_collisions:
        raise ValueError(
            "publishable release artifacts collide with reserved output names: "
            + ", ".join(reserved_collisions),
        )
    existing = [path for path in output_dir.iterdir() if path.exists()]
    if not existing:
        return
    if not force:
        raise FileExistsError(
            "refusing to overwrite existing publishable release output: "
            + ", ".join(str(path) for path in existing),
        )
    unexpected = [path for path in existing if path.name not in planned_names]
    if unexpected:
        raise FileExistsError(
            "refusing to mix publishable release output with unrelated existing files: "
            + ", ".join(str(path) for path in unexpected),
        )


def _copy_artifact(src: Path, output_dir: Path, role: str) -> Mapping[str, Any]:
    src = _required_file(src, role)
    destination = output_dir / src.name
    if src.resolve() != destination.resolve():
        shutil.copy2(src, destination)
    digest = sha256_file(destination)
    return {
        "role": role,
        "path": str(destination),
        "archive_path": destination.name,
        "source_path": str(src),
        "size": destination.stat().st_size,
        "sha256": digest,
    }


def _device_evidence_source_root(acceptance_dir: Path) -> Path:
    return (acceptance_dir / DEVICE_EVIDENCE_SOURCES_DIR).resolve()


def _copy_device_evidence_source_tree(
    *,
    acceptance_dir: Path,
    output_dir: Path,
) -> Mapping[str, Any]:
    source_root = _required_dir(
        _device_evidence_source_root(acceptance_dir),
        "formal device evidence source tree",
    )
    destination = (output_dir / DEVICE_EVIDENCE_SOURCES_DIR).resolve()
    if not _is_relative_to(destination, output_dir.resolve()):
        raise ValueError("formal device evidence source output path escapes publishable output")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source_root, destination)
    files = sorted(path for path in destination.rglob("*") if path.is_file())
    file_entries = [
        {
            "archive_path": path.resolve().relative_to(output_dir.resolve()).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in files
    ]
    return {
        "role": DEVICE_EVIDENCE_SOURCES_DIR,
        "path": str(destination),
        "archive_path": DEVICE_EVIDENCE_SOURCES_DIR,
        "source_path": str(source_root),
        "file_count": len(file_entries),
        "size": sum(entry["size"] for entry in file_entries),
        "files": file_entries,
    }


def _publishable_evidence_source_path(source: Path, acceptance_dir: Path) -> str:
    source_root = _device_evidence_source_root(acceptance_dir)
    relative_path = source.resolve().relative_to(source_root)
    return (Path(DEVICE_EVIDENCE_SOURCES_DIR) / relative_path).as_posix()


def _copy_device_evidence_with_publishable_sources(
    *,
    device_evidence: Mapping[str, Any],
    device_evidence_path: Path,
    acceptance_dir: Path,
    output_dir: Path,
) -> Mapping[str, Any]:
    payload = dict(device_evidence)
    sources = payload.get("sources")
    if not isinstance(sources, Mapping):
        raise ValueError("formal device evidence sources are missing")
    rewritten_sources = dict(sources)
    for key in ("android_apk", "windows_exe", "host_exe"):
        rewritten_sources[key] = _resolve_runtime_path(str(sources.get(key) or "")).name
    rewritten_sources["ui_evidence_dir"] = _publishable_evidence_source_path(
        _resolve_runtime_path(str(sources.get("ui_evidence_dir") or "")),
        acceptance_dir,
    )
    for key in ("mobile_logs", "host_logs"):
        values = sources.get(key, [])
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ValueError(f"formal device evidence sources.{key} must be a list")
        rewritten_sources[key] = [
            _publishable_evidence_source_path(
                _resolve_runtime_path(str(value)),
                acceptance_dir,
            )
            for value in values
        ]
    payload["sources"] = rewritten_sources

    destination = output_dir / device_evidence_path.name
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    digest = sha256_file(destination)
    return {
        "role": "formal_device_evidence",
        "path": str(destination),
        "archive_path": destination.name,
        "source_path": str(device_evidence_path),
        "size": destination.stat().st_size,
        "sha256": digest,
    }


def _portable_artifact(item: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "role": str(item.get("role") or ""),
        "archive_path": str(item.get("archive_path") or ""),
        "size": item.get("size"),
        "sha256": str(item.get("sha256") or ""),
    }


def _portable_evidence_sources(item: Mapping[str, Any]) -> Mapping[str, Any]:
    files = item.get("files")
    portable_files = [
        {
            "archive_path": str(file_item.get("archive_path") or ""),
            "size": file_item.get("size"),
            "sha256": str(file_item.get("sha256") or ""),
        }
        for file_item in files
        if isinstance(file_item, Mapping)
    ] if isinstance(files, Sequence) and not isinstance(files, (str, bytes)) else []
    return {
        "role": str(item.get("role") or ""),
        "archive_path": str(item.get("archive_path") or ""),
        "file_count": item.get("file_count"),
        "size": item.get("size"),
        "files": portable_files,
    }


def _load_offline_manifest_signing_key(
    private_key_path: Path | None,
    *,
    output_dir: Path,
    release_sources: Sequence[tuple[str, Path]],
):
    if private_key_path is None:
        raise ValueError("explicit offline Ed25519 manifest signing key is required")
    try:
        resolved = private_key_path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("offline manifest signing key is missing or invalid") from exc
    if _is_relative_to(resolved, ROOT.resolve()):
        raise ValueError("offline manifest signing key must stay outside the repository")
    if _is_relative_to(resolved, output_dir.resolve()):
        raise ValueError("offline manifest signing key must stay outside the output directory")
    if any(resolved == source.resolve() for _, source in release_sources):
        raise ValueError("offline manifest signing key must not be a release source")
    try:
        return load_private_key(resolved.read_bytes())
    except (OSError, FormalReleaseManifestError) as exc:
        raise ValueError("offline manifest signing key is missing or invalid") from exc


def _create_release_archive(
    output_dir: Path,
    artifacts: Sequence[Mapping[str, Any]],
    manifest_path: Path,
) -> Mapping[str, Any]:
    archive_path = output_dir / ARCHIVE_NAME
    archive_sha_path = output_dir / ARCHIVE_SHA256_NAME
    archive_inputs: list[Path] = []
    for artifact in artifacts:
        artifact_path = Path(str(artifact.get("path") or ""))
        archive_inputs.append(_required_file(artifact_path, str(artifact.get("role") or "artifact")))
    archive_inputs.append(_required_file(manifest_path, "formal release manifest"))
    evidence_source_root = output_dir / DEVICE_EVIDENCE_SOURCES_DIR
    if evidence_source_root.exists():
        _required_dir(evidence_source_root, "formal device evidence source tree")
        archive_inputs.extend(
            sorted(path for path in evidence_source_root.rglob("*") if path.is_file())
        )

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in archive_inputs:
            if _is_relative_to(path.resolve(), output_dir.resolve()):
                arcname = path.resolve().relative_to(output_dir.resolve()).as_posix()
            else:
                arcname = path.name
            archive.write(path, arcname=arcname)

    digest = sha256_file(archive_path)
    archive_sha_path.write_text(digest + "  " + archive_path.name + "\n", encoding="utf-8")
    return {
        "path": str(archive_path),
        "sha256_path": str(archive_sha_path),
        "size": archive_path.stat().st_size,
        "sha256": digest,
    }


def _verify_publishable_archive(
    output_dir: Path,
    archive: Mapping[str, Any],
    *,
    trusted_public_key_pem: bytes,
    channel: str,
    release_version: str,
    bundle_sequence: int,
    revocation_epoch: int,
) -> Mapping[str, Any]:
    archive_path = _required_file(Path(str(archive.get("path") or "")), ARCHIVE_NAME)
    sha256_path = _required_file(
        Path(str(archive.get("sha256_path") or "")),
        ARCHIVE_SHA256_NAME,
    )
    report = verify_publishable_archive(
        archive_path=archive_path,
        sha256_path=sha256_path,
        trusted_public_key_pem=trusted_public_key_pem,
        expected_channel=channel,
        minimum_release_version=release_version,
        minimum_bundle_sequence=bundle_sequence,
        minimum_revocation_epoch=revocation_epoch,
    )
    report_path = output_dir / PUBLISHABLE_ARCHIVE_VERIFY_NAME
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if report.get("ok") is not True:
        raise ValueError(f"publishable archive verification failed: {report_path}")
    return {
        "path": str(report_path),
        "ok": True,
        "schema": report.get("schema"),
    }


def _acceptance_artifact_paths(
    acceptance_report: Mapping[str, Any],
    acceptance_dir: Path,
) -> Mapping[str, Path]:
    artifacts = acceptance_report.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise ValueError("formal acceptance report has no artifacts object")
    required = {}
    for key in ("windows_exe", "android_apk", "host_exe"):
        value = str(artifacts.get(key) or "")
        if not value:
            raise ValueError(f"formal acceptance report is missing artifacts.{key}")
        required[key] = _resolve_report_path(value, acceptance_dir)
    if required["host_exe"].name != CANONICAL_HOST_EXE_NAME:
        raise ValueError(
            f"formal Host artifact must be named {CANONICAL_HOST_EXE_NAME}"
        )
    return required


def _require_bool_run_parameter(
    run_parameters: Mapping[str, Any],
    key: str,
) -> bool:
    value = run_parameters.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"formal acceptance run_parameters.{key} must be a boolean")
    return value


def _require_string_run_parameter(
    run_parameters: Mapping[str, Any],
    key: str,
) -> str:
    value = run_parameters.get(key)
    if not isinstance(value, str):
        raise ValueError(f"formal acceptance run_parameters.{key} must be a string")
    return value


def _validate_run_timeouts(run_parameters: Mapping[str, Any]) -> None:
    timeouts = run_parameters.get("timeouts_sec")
    if not isinstance(timeouts, Mapping):
        raise ValueError("formal acceptance run_parameters.timeouts_sec is missing")
    for key in ("android_build", "device_preflight", "installer", "verifier"):
        value = timeouts.get(key)
        if not isinstance(value, int) or value <= 0:
            raise ValueError(
                f"formal acceptance run_parameters.timeouts_sec.{key} must be positive"
            )


def _validate_acceptance_run_parameters(
    acceptance_report: Mapping[str, Any],
    acceptance_dir: Path,
    artifact_paths: Mapping[str, Path],
) -> None:
    run_parameters = acceptance_report.get("run_parameters")
    if not isinstance(run_parameters, Mapping):
        raise ValueError("formal acceptance report is missing run_parameters")

    build_apk = _require_bool_run_parameter(run_parameters, "build_apk")
    _require_bool_run_parameter(run_parameters, "expect_control_locked")
    _require_bool_run_parameter(run_parameters, "remove_legacy_benchmark_package")
    _require_string_run_parameter(run_parameters, "adb_path")
    _require_string_run_parameter(run_parameters, "device_serial")
    _validate_run_timeouts(run_parameters)

    windows_exe = _resolve_report_path(
        _require_string_run_parameter(run_parameters, "windows_exe"),
        acceptance_dir,
    )
    android_apk_input = _resolve_report_path(
        _require_string_run_parameter(run_parameters, "android_apk_input"),
        acceptance_dir,
    )
    host_exe = _resolve_report_path(
        _require_string_run_parameter(run_parameters, "host_exe"),
        acceptance_dir,
    )
    if windows_exe != artifact_paths["windows_exe"].resolve():
        raise ValueError("formal acceptance run_parameters.windows_exe does not match artifacts")
    if host_exe != artifact_paths["host_exe"].resolve():
        raise ValueError("formal acceptance run_parameters.host_exe does not match artifacts")

    artifacts = acceptance_report.get("artifacts")
    if isinstance(artifacts, Mapping) and str(artifacts.get("android_apk_input") or ""):
        reported_input = _resolve_report_path(
            str(artifacts["android_apk_input"]),
            acceptance_dir,
        )
        if reported_input != android_apk_input:
            raise ValueError("formal acceptance android_apk_input does not match run_parameters")
    if not build_apk and android_apk_input != artifact_paths["android_apk"].resolve():
        raise ValueError("formal acceptance non-build android_apk_input does not match Android APK")


def _validate_acceptance_report(
    acceptance_report: Mapping[str, Any],
    acceptance_path: Path,
) -> None:
    if acceptance_report.get("schema") != "visionforge-formal-release-acceptance-v1":
        raise ValueError("formal acceptance report schema is invalid")
    if acceptance_report.get("ok") is not True:
        raise ValueError("formal acceptance report is not successful")
    if not str(acceptance_report.get("device_evidence") or ""):
        raise ValueError("formal acceptance report is missing device evidence")
    if not str(acceptance_report.get("bundle_report") or ""):
        raise ValueError("formal acceptance report is missing bundle report")
    if acceptance_path.name != "formal_release_acceptance.json":
        raise ValueError("formal acceptance report must be named formal_release_acceptance.json")
    if acceptance_report.get("release_blockers") != []:
        raise ValueError("formal acceptance report release_blockers must be empty")
    if acceptance_report.get("next_actions") != []:
        raise ValueError("formal acceptance report next_actions must be empty")
    if not isinstance(acceptance_report.get("run_parameters"), Mapping):
        raise ValueError("formal acceptance report is missing run_parameters")
    _validate_acceptance_command_results(acceptance_report)


def _command_returncode(
    report: Mapping[str, Any],
    key: str,
    *,
    required: bool,
) -> int | None:
    command = report.get(key)
    if command is None:
        if required:
            raise ValueError(f"formal acceptance report is missing {key} command result")
        return None
    if not isinstance(command, Mapping):
        raise ValueError(f"formal acceptance report {key} command result is invalid")
    value = command.get("returncode")
    if not isinstance(value, int):
        raise ValueError(f"formal acceptance report {key} returncode is missing")
    return value


def _validate_acceptance_command_results(
    acceptance_report: Mapping[str, Any],
) -> None:
    for key in ("installer", "bundle_verifier"):
        if _command_returncode(acceptance_report, key, required=True) != 0:
            raise ValueError(f"formal acceptance {key} did not pass")
    for key in (
        "android_release_builder",
        "android_signing_preflight",
        "android_apk_preflight",
        "android_device_preflight",
    ):
        returncode = _command_returncode(acceptance_report, key, required=False)
        if returncode not in (None, 0):
            raise ValueError(f"formal acceptance {key} did not pass")


def _command_parts(command_result: Mapping[str, Any], label: str) -> list[str]:
    raw = command_result.get("cmd")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError(f"formal acceptance {label} command line is missing")
    return [str(part) for part in raw]


def _command_option_value(command: Sequence[str], option: str) -> str:
    try:
        index = list(command).index(option)
    except ValueError:
        return ""
    if index + 1 >= len(command):
        raise ValueError(f"formal acceptance installer command {option} has no value")
    return str(command[index + 1])


def _require_command_path(
    command: Sequence[str],
    option: str,
    expected: Path,
    label: str,
) -> None:
    value = _command_option_value(command, option)
    if not value:
        raise ValueError(f"formal acceptance installer command is missing {option}")
    if _resolve_runtime_path(value) != expected.resolve():
        raise ValueError(f"formal acceptance installer command {label} does not match report")


def _require_command_optional_path(
    command: Sequence[str],
    option: str,
    expected: str,
    label: str,
) -> None:
    value = _command_option_value(command, option)
    if expected:
        if not value:
            raise ValueError(f"formal acceptance installer command is missing {option}")
        if _resolve_runtime_path(value) != _resolve_runtime_path(expected):
            raise ValueError(f"formal acceptance installer command {label} does not match report")
    elif value:
        raise ValueError(f"formal acceptance installer command unexpected {option}")


def _require_command_optional_value(
    command: Sequence[str],
    option: str,
    expected: str,
    label: str,
) -> None:
    value = _command_option_value(command, option)
    if expected and value != expected:
        raise ValueError(f"formal acceptance installer command {label} does not match report")
    if not expected and value:
        raise ValueError(f"formal acceptance installer command unexpected {option}")


def _validate_installer_command(
    acceptance_report: Mapping[str, Any],
    artifact_paths: Mapping[str, Path],
) -> None:
    installer = acceptance_report.get("installer")
    run_parameters = acceptance_report.get("run_parameters")
    if not isinstance(installer, Mapping) or not isinstance(run_parameters, Mapping):
        raise ValueError("formal acceptance installer command context is missing")
    command = _command_parts(installer, "installer")
    _require_command_path(command, "-ApkPath", artifact_paths["android_apk"], "APK")
    _require_command_path(command, "-WindowsExePath", artifact_paths["windows_exe"], "Windows EXE")
    _require_command_path(command, "-HostExePath", artifact_paths["host_exe"], "Host EXE")
    _require_command_optional_path(
        command,
        "-AdbPath",
        str(run_parameters.get("adb_path") or ""),
        "ADB path",
    )
    _require_command_optional_value(
        command,
        "-DeviceSerial",
        str(run_parameters.get("device_serial") or ""),
        "device serial",
    )
    if "-Build" in command:
        raise ValueError("formal acceptance installer command must not rebuild APK")
    for key, option in (
        ("expect_control_locked", "-ExpectControlLocked"),
        ("remove_legacy_benchmark_package", "-RemoveLegacyBenchmarkPackage"),
    ):
        expected = run_parameters.get(key)
        if not isinstance(expected, bool):
            raise ValueError(f"formal acceptance run_parameters.{key} must be a boolean")
        if (option in command) != expected:
            raise ValueError(f"formal acceptance installer command {option} does not match report")


def _validate_bundle_report(bundle_report: Mapping[str, Any]) -> None:
    errors = formal_bundle_report_errors(bundle_report)
    if errors:
        raise ValueError("; ".join(errors))


def _bundle_report_checks(bundle_report: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    checks = bundle_report.get("checks")
    if not isinstance(checks, Sequence):
        raise ValueError("formal bundle verifier report has no checks")
    indexed: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        if not isinstance(check, Mapping):
            continue
        name = str(check.get("name") or "")
        if name:
            indexed[name] = check
    return indexed


def _require_successful_bundle_check(
    bundle_checks: Mapping[str, Mapping[str, Any]],
    name: str,
) -> Mapping[str, Any]:
    check = bundle_checks.get(name)
    if check is None:
        raise ValueError(f"formal bundle verifier report is missing {name} check")
    if check.get("ok") is not True:
        raise ValueError(f"formal bundle verifier report {name} check is not successful")
    evidence = check.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError(f"formal bundle verifier report {name} evidence is missing")
    return evidence


def _bundle_expected_hashes(
    bundle_report: Mapping[str, Any],
    artifact_paths: Mapping[str, Path],
    device_evidence_path: Path,
) -> Mapping[str, str]:
    bundle_checks = _bundle_report_checks(bundle_report)
    _require_successful_bundle_check(bundle_checks, "source_contracts")
    device_evidence = _require_successful_bundle_check(bundle_checks, "device_evidence")
    reported_device_evidence = Path(str(device_evidence.get("path") or "")).resolve()
    if reported_device_evidence != device_evidence_path.resolve():
        raise ValueError("formal bundle verifier report device_evidence path does not match acceptance report")

    mapping = {
        "windows_release": ("windows_exe", "exe"),
        "android_release_apk": ("android_apk", "apk"),
        "host_release": ("host_exe", "host"),
    }
    expected: dict[str, str] = {}
    for check_name, (role, path_key) in mapping.items():
        evidence = _require_successful_bundle_check(bundle_checks, check_name)
        reported_path = Path(str(evidence.get(path_key) or "")).resolve()
        if reported_path != artifact_paths[role].resolve():
            raise ValueError(f"formal bundle verifier report {check_name} path does not match acceptance report")
        digest = str(evidence.get("sha256") or "").lower()
        if len(digest) != 64:
            raise ValueError("formal bundle verifier report is missing artifact hashes")
        expected[role] = digest
    return expected


def _validate_artifact_hashes(
    artifact_paths: Mapping[str, Path],
    expected_hashes: Mapping[str, str],
) -> None:
    for role, expected_hash in expected_hashes.items():
        actual_hash = sha256_file(_required_file(artifact_paths[role], role))
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(f"{role} sha256 does not match formal bundle report")


def _validate_device_evidence(
    device_evidence: Mapping[str, Any],
    artifact_paths: Mapping[str, Path],
    *,
    expected_device_serial: str,
    expected_package_name: str,
    expected_package_version: str,
    acceptance_dir: Path,
) -> None:
    if device_evidence.get("schema") != DEVICE_EVIDENCE_SCHEMA:
        raise ValueError("formal device evidence schema is invalid")
    device_serial = str(device_evidence.get("device_serial") or "")
    if not device_serial:
        raise ValueError("formal device evidence device_serial is missing")
    if device_serial != expected_device_serial:
        raise ValueError("formal device evidence device_serial does not match Android device report")
    installed_package_name = str(device_evidence.get("installed_package_name") or "")
    if not installed_package_name:
        raise ValueError("formal device evidence installed_package_name is missing")
    if installed_package_name != expected_package_name:
        raise ValueError(
            "formal device evidence installed_package_name does not match Android APK report"
        )
    installed_package_version = str(device_evidence.get("installed_package_version") or "")
    if not installed_package_version:
        raise ValueError("formal device evidence installed_package_version is missing")
    if installed_package_version != expected_package_version:
        raise ValueError(
            "formal device evidence installed_package_version does not match Android APK report"
        )
    checks = device_evidence.get("checks")
    if not isinstance(checks, Mapping):
        raise ValueError("formal device evidence has no checks object")
    for key in REQUIRED_DEVICE_EVIDENCE_FLAGS:
        if checks.get(key) is not True:
            raise ValueError(f"formal device evidence check {key} is not true")
    tokens = device_evidence.get("game_model_tokens")
    if sorted(tokens or []) != sorted(EXPECTED_GAME_TOKENS):
        raise ValueError("formal device evidence does not list all production game models")
    display_name_errors = game_display_name_errors(device_evidence)
    if display_name_errors:
        raise ValueError("; ".join(display_name_errors))
    target_contract_errors = model_target_contract_errors(device_evidence)
    if target_contract_errors:
        raise ValueError("; ".join(target_contract_errors))
    expected_hash_fields = {
        "windows_exe_sha256": "windows_exe",
        "android_apk_sha256": "android_apk",
        "host_exe_sha256": "host_exe",
    }
    for field, role in expected_hash_fields.items():
        expected_hash = str(device_evidence.get(field) or "").lower()
        if not expected_hash:
            raise ValueError(f"formal device evidence is missing {field}")
        actual_hash = sha256_file(_required_file(artifact_paths[role], role))
        if actual_hash.lower() != expected_hash:
            raise ValueError(f"formal device evidence {field} does not match current artifact")
    _validate_device_evidence_sources(device_evidence, artifact_paths, acceptance_dir)
    _validate_final_safe_idle(device_evidence)


def _validate_final_safe_idle(device_evidence: Mapping[str, Any]) -> None:
    sources = device_evidence.get("sources")
    if not isinstance(sources, Mapping):
        raise ValueError("formal device evidence sources are missing")
    raw_mobile_logs = sources.get("mobile_logs")
    if not isinstance(raw_mobile_logs, Sequence) or isinstance(
        raw_mobile_logs,
        (str, bytes),
    ):
        raise ValueError("formal device evidence sources.mobile_logs must be a list")
    mobile_log_hashes = {
        sha256_file(_required_file(_resolve_runtime_path(str(value)), "mobile log"))
        for value in raw_mobile_logs
    }
    ui_directory = _required_dir(
        _resolve_runtime_path(str(sources.get("ui_evidence_dir") or "")),
        "formal device evidence sources.ui_evidence_dir",
    )
    ui_xml_sources = {
        sha256_file(path): hashlib.sha256(
            decode_ui_xml(path.read_bytes()).encode("utf-8")
        ).hexdigest()
        for path in sorted(ui_directory.glob("*.xml"))
    }
    errors = final_safe_idle_errors(
        device_evidence,
        expected_apk_sha256=str(device_evidence.get("android_apk_sha256") or ""),
        expected_device_serial=str(device_evidence.get("device_serial") or ""),
        allowed_mobile_log_hashes=mobile_log_hashes,
        allowed_ui_xml_hashes=set(ui_xml_sources),
        allowed_ui_xml_sources=ui_xml_sources,
    )
    if errors:
        raise ValueError("; ".join(errors))


def _validate_device_evidence_sources(
    device_evidence: Mapping[str, Any],
    artifact_paths: Mapping[str, Path],
    acceptance_dir: Path,
) -> None:
    sources = device_evidence.get("sources")
    if not isinstance(sources, Mapping):
        raise ValueError("formal device evidence sources are missing")
    expected_source_fields = {
        "android_apk": "android_apk",
        "windows_exe": "windows_exe",
        "host_exe": "host_exe",
    }
    for source_field, role in expected_source_fields.items():
        source_path = str(sources.get(source_field) or "")
        if not source_path:
            raise ValueError(f"formal device evidence sources.{source_field} is missing")
        if _resolve_runtime_path(source_path) != artifact_paths[role].resolve():
            raise ValueError(
                f"formal device evidence sources.{source_field} does not match accepted artifact"
            )
    ui_evidence_dir = str(sources.get("ui_evidence_dir") or "")
    if not ui_evidence_dir:
        raise ValueError("formal device evidence sources.ui_evidence_dir is missing")
    evidence_source_root = _device_evidence_source_root(acceptance_dir)
    _required_dir(evidence_source_root, "formal device evidence source tree")
    ui_path = _resolve_runtime_path(ui_evidence_dir)
    _require_acceptance_local_report_path(
        ui_path,
        evidence_source_root,
        "formal device evidence sources.ui_evidence_dir",
    )
    _required_dir(ui_path, "formal device evidence sources.ui_evidence_dir")
    _validate_device_evidence_log_sources(
        sources.get("mobile_logs"),
        evidence_source_root,
        "mobile_logs",
        required=True,
    )
    _validate_device_evidence_log_sources(
        sources.get("host_logs", []),
        evidence_source_root,
        "host_logs",
        required=False,
    )


def _validate_device_evidence_log_sources(
    values: object,
    evidence_source_root: Path,
    label: str,
    *,
    required: bool,
) -> None:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError(f"formal device evidence sources.{label} must be a list")
    if required and not values:
        raise ValueError(f"formal device evidence sources.{label} is missing")
    for value in values:
        path = _resolve_runtime_path(str(value or ""))
        _require_acceptance_local_report_path(
            path,
            evidence_source_root,
            f"formal device evidence sources.{label}",
        )
        _required_file(path, f"formal device evidence sources.{label}")


def _required_acceptance_report_file(
    acceptance_report: Mapping[str, Any],
    acceptance_dir: Path,
    key: str,
    *,
    required: bool,
) -> Path | None:
    raw = str(acceptance_report.get(key) or "")
    if not raw:
        if required:
            raise ValueError(f"formal acceptance report is missing {key}")
        return None
    path = _resolve_report_path(raw, acceptance_dir)
    _require_acceptance_local_report_path(path, acceptance_dir, key)
    return _required_file(path, key)


def _validate_report_schema_ok(report: Mapping[str, Any], schema: str, label: str) -> None:
    if report.get("schema") != schema:
        raise ValueError(f"{label} schema is invalid")
    if report.get("ok") is not True:
        raise ValueError(f"{label} is not successful")


def _validate_android_apk_preflight_report(
    report: Mapping[str, Any],
    android_apk: Path,
) -> None:
    _validate_report_schema_ok(report, ANDROID_APK_PREFLIGHT_SCHEMA, "android_apk_report")
    if report.get("require_production_signing") is not True:
        raise ValueError("android_apk_report did not require production signing")
    reported_apk = Path(str(report.get("apk") or "")).resolve()
    if reported_apk != android_apk.resolve():
        raise ValueError("android_apk_report apk path does not match current Android APK")
    check = report.get("check")
    if not isinstance(check, Mapping):
        raise ValueError("android_apk_report is missing check")
    if check.get("name") != "android_release_apk" or check.get("ok") is not True:
        raise ValueError("android_apk_report check is not successful")
    evidence = check.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("android_apk_report is missing evidence")
    expected_hash = str(evidence.get("sha256") or "").lower()
    if expected_hash != sha256_file(android_apk).lower():
        raise ValueError("android_apk_report sha256 does not match current Android APK")


def _validate_android_device_preflight_report(
    report: Mapping[str, Any],
    *,
    requested_serial: str,
    requested_adb_path: str,
) -> None:
    _validate_report_schema_ok(
        report,
        ANDROID_DEVICE_PREFLIGHT_SCHEMA,
        "android_device_report",
    )
    if int(report.get("adb_returncode", -1)) != 0:
        raise ValueError("android_device_report adb_returncode is not zero")
    selected_serial = str(report.get("selected_serial") or "")
    if not selected_serial:
        raise ValueError("android_device_report selected_serial is missing")
    report_requested_serial = str(report.get("requested_serial") or "")
    if report_requested_serial != requested_serial:
        raise ValueError("android_device_report requested_serial does not match run_parameters")
    if requested_serial and selected_serial != requested_serial:
        raise ValueError("android_device_report selected_serial does not match requested serial")
    if requested_adb_path:
        report_adb_path = str(report.get("adb_path") or "")
        if not report_adb_path:
            raise ValueError("android_device_report adb_path is missing")
        if Path(report_adb_path).resolve() != _resolve_runtime_path(requested_adb_path):
            raise ValueError("android_device_report adb_path does not match run_parameters")
    devices = report.get("devices")
    if not isinstance(devices, Sequence):
        raise ValueError("android_device_report devices list is missing")
    for device in devices:
        if (
            isinstance(device, Mapping)
            and str(device.get("serial") or "") == selected_serial
            and str(device.get("state") or "") == "device"
        ):
            return
    raise ValueError("android_device_report selected_serial is not an authorized device")


def _android_device_report_selected_serial(report: Mapping[str, Any]) -> str:
    selected_serial = str(report.get("selected_serial") or "")
    if not selected_serial:
        raise ValueError("android_device_report selected_serial is missing")
    return selected_serial


def _android_apk_report_version_name(report: Mapping[str, Any]) -> str:
    badging = _android_apk_report_badging(report)
    version_name = str(badging.get("version_name") or "")
    if not version_name:
        raise ValueError("android_apk_report version_name is missing")
    return version_name


def _android_apk_report_package_name(report: Mapping[str, Any]) -> str:
    badging = _android_apk_report_badging(report)
    package_name = str(badging.get("package") or "")
    if not package_name:
        raise ValueError("android_apk_report package name is missing")
    return package_name


def _android_apk_report_badging(report: Mapping[str, Any]) -> Mapping[str, Any]:
    check = report.get("check")
    if not isinstance(check, Mapping):
        raise ValueError("android_apk_report is missing check")
    evidence = check.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("android_apk_report is missing evidence")
    badging = evidence.get("badging")
    if not isinstance(badging, Mapping):
        raise ValueError("android_apk_report badging is missing")
    return badging


def _validate_android_release_report(
    report: Mapping[str, Any],
    android_apk: Path,
    *,
    expected_source_apk: Path,
    expected_signing_report: Path | None,
) -> None:
    _validate_report_schema_ok(report, ANDROID_RELEASE_BUILD_SCHEMA, "android_release_report")
    if report.get("stage") != "complete":
        raise ValueError("android_release_report stage is not complete")
    signing_report_path = str(report.get("signing_report_path") or "")
    if not signing_report_path:
        raise ValueError("android_release_report signing_report_path is missing")
    if expected_signing_report is None:
        raise ValueError("android_release_report has no accepted signing report")
    if _resolve_runtime_path(signing_report_path) != expected_signing_report.resolve():
        raise ValueError("android_release_report signing_report_path does not match acceptance report")
    artifact = report.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ValueError("android_release_report is missing artifact")
    reported_apk = Path(str(artifact.get("apk") or "")).resolve()
    if reported_apk != android_apk.resolve():
        raise ValueError("android_release_report apk path does not match current Android APK")
    source_apk = str(artifact.get("source_apk") or "")
    if not source_apk:
        raise ValueError("android_release_report source_apk is missing")
    if _resolve_runtime_path(source_apk) != expected_source_apk.resolve():
        raise ValueError("android_release_report source_apk does not match run_parameters")
    expected_hash = str(artifact.get("sha256") or "").lower()
    if expected_hash != sha256_file(android_apk).lower():
        raise ValueError("android_release_report sha256 does not match current Android APK")
    sha_path = Path(str(artifact.get("sha256_file") or "")).resolve()
    _required_file(sha_path, "android_release_report sha256 sidecar")


def _validate_android_signing_report(report: Mapping[str, Any]) -> None:
    _validate_report_schema_ok(report, ANDROID_SIGNING_INPUTS_SCHEMA, "android_signing_report")
    inputs_present = report.get("inputs_present")
    if not isinstance(inputs_present, Mapping):
        raise ValueError("android_signing_report inputs_present is missing")
    for key in ("store_file", "store_password", "key_alias", "key_password"):
        if inputs_present.get(key) is not True:
            raise ValueError(f"android_signing_report missing {key}")
    if inputs_present.get("allow_development_signing") is True:
        raise ValueError("android_signing_report used development signing")
    signing = report.get("signing")
    if isinstance(signing, Mapping) and signing.get("android_debug_certificate") is True:
        raise ValueError("android_signing_report used Android Debug certificate")


def _validated_acceptance_report_files(
    acceptance_report: Mapping[str, Any],
    acceptance_dir: Path,
    artifact_paths: Mapping[str, Path],
) -> dict[str, Path]:
    run_parameters = acceptance_report.get("run_parameters")
    if not isinstance(run_parameters, Mapping):
        raise ValueError("formal acceptance report is missing run_parameters")
    expected_source_apk = _resolve_report_path(
        str(run_parameters.get("android_apk_input") or ""),
        acceptance_dir,
    )
    android_apk_report = _required_acceptance_report_file(
        acceptance_report,
        acceptance_dir,
        "android_apk_report",
        required=True,
    )
    android_device_report = _required_acceptance_report_file(
        acceptance_report,
        acceptance_dir,
        "android_device_report",
        required=True,
    )
    assert android_apk_report is not None
    assert android_device_report is not None
    _validate_android_apk_preflight_report(
        _load_required_json(android_apk_report, "android_apk_report"),
        artifact_paths["android_apk"],
    )
    requested_serial = str(run_parameters.get("device_serial") or "")
    requested_adb_path = str(run_parameters.get("adb_path") or "")
    _validate_android_device_preflight_report(
        _load_required_json(android_device_report, "android_device_report"),
        requested_serial=requested_serial,
        requested_adb_path=requested_adb_path,
    )

    validated = {
        "android_apk_report": android_apk_report,
        "android_device_report": android_device_report,
    }
    android_signing_report = _required_acceptance_report_file(
        acceptance_report,
        acceptance_dir,
        "android_signing_report",
        required=acceptance_report.get("android_signing_preflight") is not None,
    )
    if android_signing_report is not None:
        _validate_android_signing_report(
            _load_required_json(android_signing_report, "android_signing_report"),
        )
        validated["android_signing_report"] = android_signing_report
    android_release_report = _required_acceptance_report_file(
        acceptance_report,
        acceptance_dir,
        "android_release_report",
        required=acceptance_report.get("android_release_builder") is not None,
    )
    if android_release_report is not None:
        _validate_android_release_report(
            _load_required_json(android_release_report, "android_release_report"),
            artifact_paths["android_apk"],
            expected_source_apk=expected_source_apk,
            expected_signing_report=android_signing_report,
        )
        validated["android_release_report"] = android_release_report
    return validated


def create_publishable_release_bundle(
    *,
    acceptance_report_path: Path,
    output_dir: Path,
    signing_private_key_path: Path | None = None,
    channel: str = "stable",
    release_version: str | None = None,
    bundle_sequence: int | None = None,
    min_supported_version: str | None = None,
    revocation_epoch: int = 0,
    force: bool = False,
) -> Mapping[str, Any]:
    acceptance_path = _required_file(
        acceptance_report_path,
        "formal acceptance report",
    )
    acceptance_dir = acceptance_path.parent
    acceptance_report = read_json(acceptance_path)
    _validate_acceptance_report(acceptance_report, acceptance_path)
    output_dir = _prepare_output_dir(output_dir, force=force)

    bundle_report_path = _resolve_report_path(
        str(acceptance_report["bundle_report"]),
        acceptance_dir,
    )
    _require_acceptance_local_report_path(bundle_report_path, acceptance_dir, "bundle_report")
    bundle_report = _load_required_json(bundle_report_path, "formal bundle report")
    _validate_bundle_report(bundle_report)

    device_evidence_path = _resolve_report_path(
        str(acceptance_report["device_evidence"]),
        acceptance_dir,
    )
    _require_acceptance_local_report_path(
        device_evidence_path,
        acceptance_dir,
        "device_evidence",
    )
    device_evidence = _load_required_json(device_evidence_path, "formal device evidence")

    artifact_paths = _acceptance_artifact_paths(acceptance_report, acceptance_dir)
    _validate_acceptance_run_parameters(
        acceptance_report,
        acceptance_dir,
        artifact_paths,
    )
    _validate_installer_command(acceptance_report, artifact_paths)
    _validate_artifact_hashes(
        artifact_paths,
        _bundle_expected_hashes(bundle_report, artifact_paths, device_evidence_path),
    )
    verified_reports = _validated_acceptance_report_files(
        acceptance_report,
        acceptance_dir,
        artifact_paths,
    )
    android_device_report = _load_required_json(
        verified_reports["android_device_report"],
        "android_device_report",
    )
    android_apk_report = _load_required_json(
        verified_reports["android_apk_report"],
        "android_apk_report",
    )
    _validate_device_evidence(
        device_evidence,
        artifact_paths,
        expected_device_serial=_android_device_report_selected_serial(android_device_report),
        expected_package_name=_android_apk_report_package_name(android_apk_report),
        expected_package_version=_android_apk_report_version_name(android_apk_report),
        acceptance_dir=acceptance_dir,
    )
    release_sources: list[tuple[str, Path]] = [
        ("windows_exe", artifact_paths["windows_exe"]),
        ("android_apk", artifact_paths["android_apk"]),
        ("host_exe", artifact_paths["host_exe"]),
        ("formal_acceptance_report", acceptance_path),
        ("formal_bundle_report", bundle_report_path),
    ]

    for role, key in (
        ("android_release_report", "android_release_report"),
        ("android_signing_report", "android_signing_report"),
        ("android_apk_report", "android_apk_report"),
        ("android_device_report", "android_device_report"),
    ):
        path = verified_reports.get(key)
        if path is not None:
            release_sources.append((role, path))

    effective_release_version = (
        release_version
        or DEFAULT_RELEASE_VERSION_FILE.read_text(encoding="utf-8").strip()
    )
    effective_min_supported_version = (
        min_supported_version or effective_release_version
    )
    if isinstance(bundle_sequence, bool) or not isinstance(bundle_sequence, int):
        raise ValueError("explicit positive bundle_sequence is required")

    _validate_output_dir_contents(
        output_dir,
        release_sources,
        force=force,
        extra_planned_names=(DEVICE_EVIDENCE_SOURCES_DIR, device_evidence_path.name),
    )
    signing_key = _load_offline_manifest_signing_key(
        signing_private_key_path,
        output_dir=output_dir,
        release_sources=release_sources,
    )
    copied = [
        _copy_artifact(path, output_dir, role)
        for role, path in release_sources
    ]
    evidence_sources = _copy_device_evidence_source_tree(
        acceptance_dir=acceptance_dir,
        output_dir=output_dir,
    )
    copied.append(
        _copy_device_evidence_with_publishable_sources(
            device_evidence=device_evidence,
            device_evidence_path=device_evidence_path,
            acceptance_dir=acceptance_dir,
            output_dir=output_dir,
        )
    )

    manifest = {
        "schema": SCHEMA,
        "ok": True,
        "channel": channel,
        "release_version": effective_release_version,
        "bundle_sequence": bundle_sequence,
        "published_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds").replace(
            "+00:00",
            "Z",
        ),
        "min_supported_version": effective_min_supported_version,
        "revocation_epoch": revocation_epoch,
        "artifacts": [_portable_artifact(item) for item in copied],
        "evidence_sources": _portable_evidence_sources(evidence_sources),
    }
    envelope = sign_manifest_payload(manifest, signing_key)
    manifest_path = output_dir / "formal_release_manifest.json"
    manifest_path.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    try:
        archive = _create_release_archive(output_dir, copied, manifest_path)
        archive_verifier = _verify_publishable_archive(
            output_dir,
            archive,
            trusted_public_key_pem=public_key_pem(signing_key.public_key()),
            channel=channel,
            release_version=effective_release_version,
            bundle_sequence=bundle_sequence,
            revocation_epoch=revocation_epoch,
        )
    except Exception:
        for partial_output in (
            manifest_path,
            output_dir / ARCHIVE_NAME,
            output_dir / ARCHIVE_SHA256_NAME,
            output_dir / PUBLISHABLE_ARCHIVE_VERIFY_NAME,
        ):
            if partial_output.exists():
                partial_output.unlink()
        raise
    result = dict(manifest)
    result["manifest_envelope"] = dict(envelope)
    result["signed_artifacts"] = list(manifest["artifacts"])
    result["signed_evidence_sources"] = dict(manifest["evidence_sources"])
    result["artifacts"] = copied
    result["evidence_sources"] = evidence_sources
    result["archive"] = archive
    result["archive_verifier"] = archive_verifier
    return result


def _unique_rejection_report_path(output_dir: Path) -> Path:
    output_parent = output_dir.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{output_dir.name}.rejected_{timestamp}.json"
    candidate = output_parent / base_name
    suffix = 1
    while candidate.exists():
        candidate = output_parent / f"{output_dir.name}.rejected_{timestamp}_{suffix}.json"
        suffix += 1
    return candidate


def write_failure_report(
    output_dir: Path,
    error: Exception,
    acceptance_report_path: Path | None = None,
) -> Path:
    report = {
        "schema": SCHEMA,
        "ok": False,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "output_dir": str(output_dir),
        "error": str(error),
    }
    if acceptance_report_path is not None:
        report["acceptance_report"] = str(acceptance_report_path)
        try:
            acceptance_report = read_json(acceptance_report_path)
            acceptance_ok = acceptance_report.get("ok") is True
            release_blockers = acceptance_report.get("release_blockers")
            next_actions = acceptance_report.get("next_actions")
            release_blockers_empty = release_blockers == []
            next_actions_empty = next_actions == []
            report["acceptance_ok"] = acceptance_ok
            report["acceptance_release_blockers_empty"] = release_blockers_empty
            report["acceptance_next_actions_empty"] = next_actions_empty
            report["acceptance_packaging_ready"] = (
                acceptance_ok and release_blockers_empty and next_actions_empty
            )
            report["release_blockers"] = release_blockers
            report["next_actions"] = next_actions
        except Exception as exc:  # noqa: BLE001
            report["acceptance_report_error"] = str(exc)
    path = _unique_rejection_report_path(output_dir)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance-report", type=Path, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT
        / "releases"
        / "formal"
        / f"formal_release_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}",
    )
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--release-version")
    parser.add_argument("--bundle-sequence", type=int, required=True)
    parser.add_argument("--min-supported-version")
    parser.add_argument("--revocation-epoch", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = args.output_dir.resolve()
    try:
        manifest = create_publishable_release_bundle(
            acceptance_report_path=args.acceptance_report.resolve(),
            output_dir=output_dir,
            signing_private_key_path=args.private_key,
            channel=args.channel,
            release_version=args.release_version,
            bundle_sequence=args.bundle_sequence,
            min_supported_version=args.min_supported_version,
            revocation_epoch=args.revocation_epoch,
            force=args.force,
        )
    except Exception as exc:  # noqa: BLE001
        report = write_failure_report(
            output_dir,
            exc,
            acceptance_report_path=args.acceptance_report.resolve(),
        )
        print(f"[ERROR] publishable release bundle rejected; report={report}", flush=True)
        print(f"[ERROR] {exc}", flush=True)
        print_acceptance_blocker_summary(args.acceptance_report.resolve())
        print_acceptance_next_action_summary(args.acceptance_report.resolve())
        return 1
    print(
        "[OK] publishable release bundle created; "
        f"manifest={output_dir / 'formal_release_manifest.json'}",
        flush=True,
    )
    archive = manifest["archive"]
    print(
        f"[OK] archive={archive['path']} sha256={archive['sha256']}",
        flush=True,
    )
    print(f"[OK] artifact_count={len(manifest['artifacts'])}", flush=True)
    return 0


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
