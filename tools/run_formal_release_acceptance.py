from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_formal_release_bundle import (  # noqa: E402
    default_host_release,
    formal_bundle_report_errors,
    latest_windows_release,
)
from tools.verify_android_production_signing_inputs import (  # noqa: E402
    KEY_ALIAS_ENV,
    KEY_PASSWORD_ENV,
    STORE_FILE_ENV,
    STORE_PASSWORD_ENV,
)
from tools.formal_release_manifest_security import (  # noqa: E402
    ENVELOPE_SCHEMA,
    PAYLOAD_SCHEMA,
)


ANDROID_RELEASE_SIGNING_ENV_VARS = (
    STORE_FILE_ENV,
    STORE_PASSWORD_ENV,
    KEY_ALIAS_ENV,
    KEY_PASSWORD_ENV,
)
CANONICAL_ANDROID_RELEASE_APK = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "build"
    / "outputs"
    / "apk"
    / "release"
    / "app-release.apk"
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    cmd: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[Sequence[str], int], CommandResult]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def run_command(command: Sequence[str], timeout_sec: int) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return CommandResult(
        cmd=tuple(str(part) for part in command),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _tail(text: str, limit: int = 12000) -> str:
    return text[-limit:]


def parse_formal_device_evidence_path(output: str) -> str:
    for line in output.splitlines():
        marker = "formal_device_evidence="
        if marker in line:
            value = line.split(marker, 1)[1].strip()
            if value:
                return value
        marker = "VISIONFORGE_FORMAL_DEVICE_EVIDENCE path="
        if marker in line:
            value = line.split(marker, 1)[1].split(" complete=", 1)[0].strip()
            if value:
                return value
    return ""


def parse_android_release_artifact_path(output: str) -> str:
    for line in output.splitlines():
        marker = "[OK] apk="
        if marker in line:
            value = line.split(marker, 1)[1].strip()
            if value:
                return value
    return ""


def parse_publishable_packager_report_path(output: str) -> str:
    for line in output.splitlines():
        if "publishable release bundle rejected" not in line or "report=" not in line:
            continue
        value = line.split("report=", 1)[1].strip()
        if value:
            return value
    return ""


def _resolve_required_path(path: Path | None, label: str) -> Path:
    if path is None:
        raise FileNotFoundError(f"{label} was not found")
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"{label} is missing: {resolved}")
    return resolved


def _read_json(path: Path) -> Mapping[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_evidence_source_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _copy_evidence_directory(source: Path, destination: Path) -> Path:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"formal device evidence UI source is missing: {source}")
    if source == destination:
        return destination
    shutil.copytree(source, destination, dirs_exist_ok=True)
    return destination


def _stage_evidence_files(
    *,
    values: object,
    destination_dir: Path,
    label: str,
    required: bool,
) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError(f"formal device evidence sources.{label} must be a list")
    if required and not values:
        raise ValueError(f"formal device evidence sources.{label} is missing")
    destination_dir.mkdir(parents=True, exist_ok=True)
    staged: list[str] = []
    for index, value in enumerate(values, start=1):
        source = _resolve_evidence_source_path(str(value or ""))
        if not source.is_file():
            raise FileNotFoundError(f"formal device evidence source {label} is missing: {source}")
        destination = (destination_dir / f"{index:02d}-{source.name}").resolve()
        if source != destination:
            shutil.copy2(source, destination)
        staged.append(str(destination))
    return staged


def stage_formal_device_evidence(
    *,
    evidence_text: str,
    output_dir: Path,
) -> Path:
    if not evidence_text:
        raise ValueError("formal device evidence path was not emitted")
    evidence_path = Path(evidence_text)
    if not evidence_path.is_absolute():
        evidence_path = (ROOT / evidence_path).resolve()
    else:
        evidence_path = evidence_path.resolve()
    if not evidence_path.is_file():
        raise FileNotFoundError(f"formal device evidence is missing: {evidence_path}")
    evidence: dict[str, Any] = dict(_read_json(evidence_path))
    sources = evidence.get("sources")
    if not isinstance(sources, Mapping):
        raise ValueError("formal device evidence sources are missing")
    staged_sources = dict(sources)
    source_archive = output_dir / "device_evidence_sources"

    ui_source_text = str(sources.get("ui_evidence_dir") or "")
    if not ui_source_text:
        raise ValueError("formal device evidence sources.ui_evidence_dir is missing")
    ui_destination = _copy_evidence_directory(
        _resolve_evidence_source_path(ui_source_text),
        source_archive / "device-ui",
    )
    staged_sources["ui_evidence_dir"] = str(ui_destination)
    staged_sources["mobile_logs"] = _stage_evidence_files(
        values=sources.get("mobile_logs"),
        destination_dir=source_archive / "mobile_logs",
        label="mobile_logs",
        required=True,
    )
    staged_sources["host_logs"] = _stage_evidence_files(
        values=sources.get("host_logs", []),
        destination_dir=source_archive / "host_logs",
        label="host_logs",
        required=False,
    )
    evidence["sources"] = staged_sources

    staged_path = output_dir / "formal_device_evidence.json"
    staged_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    return staged_path.resolve()


def resolve_android_release_artifact(
    *,
    artifact_text: str,
    report_path: Path,
) -> Path:
    if not artifact_text:
        raise ValueError("Android release builder did not emit an APK path")
    artifact_path = Path(artifact_text)
    if not artifact_path.is_absolute():
        artifact_path = (ROOT / artifact_path).resolve()
    else:
        artifact_path = artifact_path.resolve()
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Android release APK artifact is missing: {artifact_path}")
    if not report_path.is_file():
        raise FileNotFoundError(f"Android release build report is missing: {report_path}")
    report = _read_json(report_path)
    if report.get("schema") != "visionforge-android-production-release-build-v1":
        raise ValueError("Android release build report schema is invalid")
    if report.get("ok") is not True or report.get("stage") != "complete":
        raise ValueError("Android release build report is not complete")
    artifact = report.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ValueError("Android release build report has no artifact")
    report_apk = Path(str(artifact.get("apk") or "")).resolve()
    if report_apk != artifact_path:
        raise ValueError("Android release artifact path does not match the build report")
    sha_path = Path(str(artifact.get("sha256_file") or "")).resolve()
    if not sha_path.is_file():
        raise FileNotFoundError(f"Android release APK sha256 sidecar is missing: {sha_path}")
    return artifact_path


def build_install_command(
    *,
    apk_path: Path,
    windows_exe: Path,
    host_exe: Path,
    adb_path: Path | None,
    device_serial: str,
    build_apk: bool,
    expect_control_locked: bool,
    remove_legacy_benchmark_package: bool,
    bluetooth_route_evidence: Path | None = None,
    bluetooth_route_mobile_log: Path | None = None,
    makcu_route_evidence: Path | None = None,
    makcu_route_mobile_log: Path | None = None,
    final_safe_idle_evidence: Path | None = None,
    final_safe_idle_mobile_log: Path | None = None,
    final_safe_idle_ui_xml: Path | None = None,
) -> list[str]:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ROOT / "android_inference_benchmark" / "tools" / "install_mobile_release.ps1"),
        "-ApkPath",
        str(apk_path),
        "-Launch",
        "-VerifyUi",
        "-WindowsExePath",
        str(windows_exe),
        "-HostExePath",
        str(host_exe),
    ]
    if adb_path is not None:
        command.extend(("-AdbPath", str(adb_path)))
    if device_serial:
        command.extend(("-DeviceSerial", device_serial))
    if build_apk:
        command.append("-Build")
    if expect_control_locked:
        command.append("-ExpectControlLocked")
    if remove_legacy_benchmark_package:
        command.append("-RemoveLegacyBenchmarkPackage")
    route_arguments = (
        ("-BluetoothRouteEvidencePath", bluetooth_route_evidence),
        ("-BluetoothRouteMobileLogPath", bluetooth_route_mobile_log),
        ("-MakcuRouteEvidencePath", makcu_route_evidence),
        ("-MakcuRouteMobileLogPath", makcu_route_mobile_log),
        ("-FinalSafeIdleEvidencePath", final_safe_idle_evidence),
        ("-FinalSafeIdleMobileLogPath", final_safe_idle_mobile_log),
        ("-FinalSafeIdleUiXmlPath", final_safe_idle_ui_xml),
    )
    for argument, path in route_arguments:
        if path is not None:
            command.extend((argument, str(path)))
    return command


def build_bundle_verify_command(
    *,
    windows_exe: Path,
    android_apk: Path,
    host_exe: Path,
    device_evidence: Path,
    output: Path,
) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "verify_formal_release_bundle.py"),
        "--mode",
        "formal",
        "--windows-exe",
        str(windows_exe),
        "--android-apk",
        str(android_apk),
        "--host-exe",
        str(host_exe),
        "--device-evidence",
        str(device_evidence),
        "--output",
        str(output),
    ]


def validate_formal_bundle_report(path: Path) -> list[str]:
    """Return fail-closed validation errors for a formal verifier report."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"formal bundle verifier report is unreadable: {exc}"]
    if not isinstance(payload, Mapping):
        return ["formal bundle verifier report root is not an object"]
    return formal_bundle_report_errors(payload)


def build_publishable_packager_command(
    *,
    acceptance_report: Path,
    output_dir: Path,
    signing_private_key: Path,
    bundle_sequence: int,
    channel: str,
    release_version: str,
    min_supported_version: str,
    revocation_epoch: int,
) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "package_formal_release_bundle.py"),
        "--acceptance-report",
        str(acceptance_report),
        "--output-dir",
        str(output_dir),
        "--private-key",
        str(signing_private_key),
        "--bundle-sequence",
        str(bundle_sequence),
        "--channel",
        channel,
        "--release-version",
        release_version,
        "--min-supported-version",
        min_supported_version,
        "--revocation-epoch",
        str(revocation_epoch),
    ]


def summarize_publishable_bundle(output_dir: Path) -> Mapping[str, object]:
    output_dir = output_dir.resolve()
    manifest_path = output_dir / "formal_release_manifest.json"
    archive_path = output_dir / "formal_release_bundle.zip"
    archive_sha_path = output_dir / "formal_release_bundle.zip.sha256"
    archive_verifier_path = output_dir / "publishable_release_bundle_verify.json"
    errors: list[str] = []
    summary: dict[str, object] = {
        "output_dir": str(output_dir),
        "manifest": str(manifest_path),
        "archive": str(archive_path),
        "archive_sha256_file": str(archive_sha_path),
        "archive_verifier_report": str(archive_verifier_path),
    }

    if not manifest_path.is_file():
        errors.append("publishable manifest is missing")
    else:
        try:
            manifest = _read_json(manifest_path)
            summary["manifest_schema"] = str(manifest.get("schema") or "")
            if manifest.get("schema") != ENVELOPE_SCHEMA:
                errors.append("publishable manifest envelope schema is invalid")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"publishable manifest is unreadable: {exc}")

    if not archive_path.is_file():
        errors.append("publishable archive is missing")
    else:
        summary["archive_size"] = archive_path.stat().st_size
        summary["archive_sha256"] = _sha256_file(archive_path)

    if not archive_sha_path.is_file():
        errors.append("publishable archive sha256 sidecar is missing")
    else:
        sidecar_text = archive_sha_path.read_text(encoding="utf-8").strip()
        summary["archive_sha256_sidecar"] = sidecar_text
        sidecar_parts = sidecar_text.split()
        sidecar_digest = sidecar_parts[0].lower() if sidecar_parts else ""
        summary["archive_sha256_sidecar_digest"] = sidecar_digest
        if len(sidecar_digest) != 64 or any(
            char not in "0123456789abcdef" for char in sidecar_digest
        ):
            errors.append("publishable archive sha256 sidecar digest is invalid")
        if len(sidecar_parts) > 1 and Path(sidecar_parts[-1]).name != archive_path.name:
            errors.append("publishable archive sha256 sidecar does not name archive")
        expected = str(summary.get("archive_sha256") or "")
        if expected and sidecar_digest != expected:
            errors.append("publishable archive sha256 sidecar does not match archive")

    if not archive_verifier_path.is_file():
        errors.append("publishable archive verifier report is missing")
    else:
        try:
            verifier = _read_json(archive_verifier_path)
            summary["archive_verifier_schema"] = str(verifier.get("schema") or "")
            summary["archive_verifier_ok"] = verifier.get("ok") is True
            summary["authenticated"] = verifier.get("authenticated") is True
            summary["anti_rollback_enforced"] = (
                verifier.get("anti_rollback_enforced") is True
            )
            manifest_summary = verifier.get("manifest")
            if isinstance(manifest_summary, Mapping):
                summary["artifact_count"] = manifest_summary.get("artifact_count")
                if manifest_summary.get("schema") != PAYLOAD_SCHEMA:
                    errors.append("publishable signed manifest payload schema is invalid")
            else:
                errors.append("publishable archive verifier omitted manifest metadata")
            if verifier.get("schema") != "visionforge-publishable-release-bundle-archive-v1":
                errors.append("publishable archive verifier schema is invalid")
            if verifier.get("ok") is not True:
                errors.append("publishable archive verifier report is not ok")
            if verifier.get("authenticated") is not True:
                errors.append("publishable archive is not authenticated")
            if verifier.get("anti_rollback_enforced") is not True:
                errors.append("publishable archive rollback policy was not enforced")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"publishable archive verifier report is unreadable: {exc}")

    summary["ok"] = not errors
    summary["errors"] = errors
    return summary


def summarize_publishable_packager_rejection(report_path: str) -> Mapping[str, object] | None:
    if not report_path:
        return None
    path = Path(report_path).resolve()
    summary: dict[str, object] = {"path": str(path)}
    try:
        report = _read_json(path)
    except Exception as exc:  # noqa: BLE001
        summary["ok"] = False
        summary["read_error"] = str(exc)
        return summary
    blockers = report.get("release_blockers")
    blocker_stages: list[str] = []
    if isinstance(blockers, Sequence) and not isinstance(blockers, (str, bytes)):
        for blocker in blockers:
            if isinstance(blocker, Mapping):
                stage = str(blocker.get("stage") or "")
                if stage:
                    blocker_stages.append(stage)
    next_actions = report.get("next_actions")
    next_action_stages: list[str] = []
    if isinstance(next_actions, Sequence) and not isinstance(next_actions, (str, bytes)):
        for action in next_actions:
            if isinstance(action, Mapping):
                stage = str(action.get("stage") or "")
                if stage:
                    next_action_stages.append(stage)
    summary.update(
        {
            "schema": str(report.get("schema") or ""),
            "ok": report.get("ok") is True,
            "error": str(report.get("error") or ""),
            "acceptance_report": str(report.get("acceptance_report") or ""),
            "acceptance_ok": report.get("acceptance_ok") is True,
            "acceptance_release_blockers_empty": report.get("acceptance_release_blockers_empty") is True,
            "acceptance_next_actions_empty": report.get("acceptance_next_actions_empty") is True,
            "acceptance_packaging_ready": report.get("acceptance_packaging_ready") is True,
            "release_blocker_stages": blocker_stages,
            "next_action_stages": next_action_stages,
        }
    )
    return summary


def build_android_release_command(
    *,
    output_dir: Path,
    timeout_sec: int,
) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "build_android_production_release.py"),
        "--output-dir",
        str(output_dir),
        "--gradle-timeout-sec",
        str(timeout_sec),
    ]


def build_android_signing_preflight_command(*, output: Path) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "verify_android_production_signing_inputs.py"),
        "--output",
        str(output),
    ]


def build_android_device_preflight_command(
    *,
    output: Path,
    adb_path: Path | None,
    device_serial: str,
    timeout_sec: int,
) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "tools" / "verify_android_device_connectivity.py"),
        "--output",
        str(output),
        "--timeout-sec",
        str(timeout_sec),
    ]
    if adb_path is not None:
        command.extend(("--adb-path", str(adb_path)))
    if device_serial:
        command.extend(("--device-serial", device_serial))
    return command


def build_android_apk_preflight_command(
    *,
    apk_path: Path,
    output: Path,
) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "verify_android_release_apk_artifact.py"),
        "--apk",
        str(apk_path),
        "--output",
        str(output),
    ]


def build_acceptance_run_parameters(
    *,
    windows_exe: Path,
    android_apk_input: Path,
    host_exe: Path,
    adb_path: Path | None,
    device_serial: str,
    build_apk: bool,
    expect_control_locked: bool,
    remove_legacy_benchmark_package: bool,
    android_build_timeout_sec: int,
    device_preflight_timeout_sec: int,
    installer_timeout_sec: int,
    verifier_timeout_sec: int,
    bluetooth_route_evidence: Path | None = None,
    bluetooth_route_mobile_log: Path | None = None,
    makcu_route_evidence: Path | None = None,
    makcu_route_mobile_log: Path | None = None,
    final_safe_idle_evidence: Path | None = None,
    final_safe_idle_mobile_log: Path | None = None,
    final_safe_idle_ui_xml: Path | None = None,
) -> Mapping[str, object]:
    parameters: dict[str, object] = {
        "windows_exe": str(windows_exe),
        "android_apk_input": str(android_apk_input),
        "host_exe": str(host_exe),
        "adb_path": str(adb_path) if adb_path is not None else "",
        "device_serial": device_serial,
        "build_apk": build_apk,
        "expect_control_locked": expect_control_locked,
        "remove_legacy_benchmark_package": remove_legacy_benchmark_package,
        "timeouts_sec": {
            "android_build": android_build_timeout_sec,
            "device_preflight": device_preflight_timeout_sec,
            "installer": installer_timeout_sec,
            "verifier": verifier_timeout_sec,
        },
    }
    if any(
        path is not None
        for path in (
            bluetooth_route_evidence,
            bluetooth_route_mobile_log,
            makcu_route_evidence,
            makcu_route_mobile_log,
            final_safe_idle_evidence,
            final_safe_idle_mobile_log,
            final_safe_idle_ui_xml,
        )
    ):
        parameters["physical_route_evidence"] = {
            "bluetooth_hid": {
                "evidence": str(bluetooth_route_evidence or ""),
                "mobile_log": str(bluetooth_route_mobile_log or ""),
            },
            "makcu_usb": {
                "evidence": str(makcu_route_evidence or ""),
                "mobile_log": str(makcu_route_mobile_log or ""),
            },
        }
        parameters["final_safe_idle_evidence"] = {
            "evidence": str(final_safe_idle_evidence or ""),
            "mobile_log": str(final_safe_idle_mobile_log or ""),
            "ui_xml": str(final_safe_idle_ui_xml or ""),
        }
    return parameters


def _command_json(result: CommandResult) -> Mapping[str, object]:
    redacted_command = list(result.cmd)
    if "--private-key" in redacted_command:
        key_index = redacted_command.index("--private-key") + 1
        if key_index < len(redacted_command):
            redacted_command[key_index] = "<redacted-offline-key-path>"
    return {
        "cmd": redacted_command,
        "returncode": result.returncode,
        "detail": _command_primary_detail(result),
        "details": _command_diagnostic_details(result),
        "stdout_tail": _tail(result.stdout),
        "stderr_tail": _tail(result.stderr),
    }


def _command_diagnostic_details(result: CommandResult) -> list[str]:
    details: list[str] = []
    for text in (result.stderr, result.stdout):
        for line in text.splitlines():
            value = line.strip()
            if not value or value in details:
                continue
            details.append(value[:500])
            if len(details) >= 20:
                return details
    return details


def _compact_primary_detail_line(value: str) -> str:
    return value.split(" report=", 1)[0].rstrip(" ;")


def _command_primary_detail(result: CommandResult) -> str:
    details = _command_diagnostic_details(result)
    primary = _compact_primary_detail_line(details[0]) if details else ""
    suffix = _compact_primary_detail_line(details[-1]) if details else ""
    if len(details) > 1 and primary.startswith("[ERROR]"):
        combined = f"{primary}; {suffix}"
        if len(combined) <= 240:
            return combined
        prefix_budget = 238 - len(suffix)
        if prefix_budget >= 24:
            return f"{primary[:prefix_budget]}; {suffix}"
        return suffix[:240]
    return suffix[:240] if suffix else ""


def _release_blockers(
    *,
    installer: CommandResult | None,
    bundle_verifier: CommandResult | None,
    publishable_packager: CommandResult | None,
    android_apk_preflight: CommandResult | None,
    android_device_preflight: CommandResult | None,
    android_release_builder: CommandResult | None,
    android_signing_preflight: CommandResult | None,
    bundle_report: str,
    android_apk_report: str,
    android_device_report: str,
    android_release_report: str,
    android_signing_report: str,
) -> list[Mapping[str, object]]:
    blockers: list[Mapping[str, object]] = []
    checks = (
        ("android_signing_preflight", android_signing_preflight, android_signing_report),
        ("android_release_builder", android_release_builder, android_release_report),
        ("android_apk_preflight", android_apk_preflight, android_apk_report),
        ("android_device_preflight", android_device_preflight, android_device_report),
        ("installer", installer, ""),
        ("bundle_verifier", bundle_verifier, bundle_report),
        ("publishable_packager", publishable_packager, ""),
    )
    for stage, result, report_path in checks:
        if result is None or result.returncode == 0:
            continue
        details = _command_diagnostic_details(result)
        blockers.append(
            {
                "stage": stage,
                "returncode": result.returncode,
                "report": report_path,
                "detail": _command_primary_detail(result),
                "details": details,
                "stdout_tail": _tail(result.stdout),
                "stderr_tail": _tail(result.stderr),
            }
        )
    return blockers


def _next_action_for_blocker(blocker: Mapping[str, object]) -> Mapping[str, object]:
    stage = str(blocker.get("stage") or "").strip()
    detail = _blocker_detail(blocker)
    if stage == "android_signing_preflight":
        return {
            "stage": stage,
            "action": (
                "Set production Android release signing environment variables "
                "before building or accepting the Android APK."
            ),
            "required_env": list(ANDROID_RELEASE_SIGNING_ENV_VARS),
            "command": (
                "python tools\\create_android_release_keystore.py "
                "--output-dir C:\\secure\\visionforge-android-release"
            ),
        }
    if stage == "android_apk_preflight":
        action = "Fix the Android release APK artifact preflight failure."
        if "Debug certificate" in detail:
            action = (
                "Replace the debug-signed APK with a production-signed release APK; "
                "debug-signed APKs cannot be packaged for release."
            )
        return {
            "stage": stage,
            "action": action,
            "command": (
                "python tools\\run_formal_release_acceptance.py --build-apk "
                "--output-dir analysis_output\\formal_release_acceptance_<stamp>"
            ),
        }
    if stage == "android_device_preflight":
        report_action = _android_device_report_next_action(blocker)
        if report_action:
            return report_action
        return {
            "stage": stage,
            "action": (
                "Authorize the target phone for ADB USB/Wireless debugging until "
                "`adb devices` shows device, then rerun formal acceptance."
            ),
            "command": "adb devices",
        }
    if stage == "android_release_builder":
        return {
            "stage": stage,
            "action": (
                "Fix the production Android release build failure before APK "
                "preflight or device acceptance can continue."
            ),
            "command": (
                "python tools\\build_android_production_release.py "
                "--output-dir releases\\android"
            ),
        }
    if stage == "installer":
        return {
            "stage": stage,
            "action": (
                "Fix Android installation or required phone UI evidence capture; "
                "formal device evidence must be complete."
            ),
        }
    if stage == "bundle_verifier":
        return {
            "stage": stage,
            "action": (
                "Fix formal release bundle verification failures before creating "
                "a publishable archive."
            ),
        }
    if stage == "publishable_packager":
        return {
            "stage": stage,
            "action": (
                "Resolve the publishable packager rejection report and rerun "
                "formal acceptance after all release blockers are clear."
            ),
        }
    return {
        "stage": stage or "unknown",
        "action": "Resolve this release blocker and rerun formal acceptance.",
    }


def _android_device_report_next_action(
    blocker: Mapping[str, object],
) -> Mapping[str, object]:
    report_path = str(blocker.get("report") or "").strip()
    if not report_path:
        return {}
    try:
        report = _read_json(Path(report_path))
    except Exception:  # noqa: BLE001
        return {}
    next_actions = report.get("next_actions")
    if not isinstance(next_actions, Sequence) or isinstance(next_actions, (str, bytes)):
        return {}
    for action in next_actions:
        if not isinstance(action, Mapping):
            continue
        commands = action.get("commands")
        if isinstance(commands, Sequence) and not isinstance(commands, (str, bytes)):
            command_list = [str(command) for command in commands if str(command).strip()]
        else:
            command_list = []
        return {
            "stage": "android_device_preflight",
            "action": str(action.get("action") or "").strip()
            or "Authorize or connect exactly one target phone before formal acceptance.",
            "reason": str(action.get("reason") or report.get("reason") or "").strip(),
            "command": command_list[-1] if command_list else "adb devices -l",
            "commands": command_list or ["adb mdns services", "adb devices -l"],
            "hint": str(action.get("hint") or "").strip(),
            "report": report_path,
        }
    return {}


def _release_next_actions(
    blockers: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    actions: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for blocker in blockers:
        stage = str(blocker.get("stage") or "").strip()
        if stage in seen:
            continue
        seen.add(stage)
        actions.append(_next_action_for_blocker(blocker))
    return actions


def _blocker_detail(blocker: Mapping[str, object]) -> str:
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


def print_release_blocker_summary(report_path: Path) -> None:
    try:
        report = _read_json(report_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] release blocker summary unavailable: {exc}", flush=True)
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
        detail = _blocker_detail(blocker)
        report_text = str(blocker.get("report") or "")
        print(
            f"- {stage} returncode={returncode} report={report_text} detail={detail}",
            flush=True,
        )
    next_actions = report.get("next_actions")
    if not isinstance(next_actions, Sequence) or isinstance(next_actions, (str, bytes)):
        return
    actionable = [action for action in next_actions if isinstance(action, Mapping)]
    if not actionable:
        return
    print("[ERROR] next actions:", flush=True)
    for action in actionable:
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


def write_acceptance_report(
    *,
    output: Path,
    ok: bool,
    artifacts: Mapping[str, str],
    installer: CommandResult | None,
    bundle_verifier: CommandResult | None,
    publishable_packager: CommandResult | None = None,
    android_apk_preflight: CommandResult | None,
    android_device_preflight: CommandResult | None,
    android_release_builder: CommandResult | None,
    android_signing_preflight: CommandResult | None,
    device_evidence: str,
    bundle_report: str,
    android_apk_report: str,
    android_device_report: str,
    android_release_report: str,
    android_signing_report: str,
    publishable_bundle_dir: str = "",
    publishable_bundle: Mapping[str, object] | None = None,
    publishable_packager_report: str = "",
    publishable_packager_rejection: Mapping[str, object] | None = None,
    run_parameters: Mapping[str, object],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    release_blockers = _release_blockers(
        installer=installer,
        bundle_verifier=bundle_verifier,
        publishable_packager=publishable_packager,
        android_apk_preflight=android_apk_preflight,
        android_device_preflight=android_device_preflight,
        android_release_builder=android_release_builder,
        android_signing_preflight=android_signing_preflight,
        bundle_report=bundle_report,
        android_apk_report=android_apk_report,
        android_device_report=android_device_report,
        android_release_report=android_release_report,
        android_signing_report=android_signing_report,
    )
    report = {
        "schema": "visionforge-formal-release-acceptance-v1",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": ok,
        "run_parameters": dict(run_parameters),
        "artifacts": artifacts,
        "device_evidence": device_evidence,
        "bundle_report": bundle_report,
        "android_apk_report": android_apk_report,
        "android_device_report": android_device_report,
        "android_release_report": android_release_report,
        "android_signing_report": android_signing_report,
        "publishable_bundle_dir": publishable_bundle_dir,
        "publishable_bundle": dict(publishable_bundle) if publishable_bundle else None,
        "publishable_packager_report": publishable_packager_report,
        "publishable_packager_rejection": (
            dict(publishable_packager_rejection)
            if publishable_packager_rejection
            else None
        ),
        "release_blockers": release_blockers,
        "next_actions": _release_next_actions(release_blockers),
        "android_apk_preflight": (
            _command_json(android_apk_preflight)
            if android_apk_preflight is not None
            else None
        ),
        "android_device_preflight": (
            _command_json(android_device_preflight)
            if android_device_preflight is not None
            else None
        ),
        "android_release_builder": (
            _command_json(android_release_builder)
            if android_release_builder is not None
            else None
        ),
        "android_signing_preflight": (
            _command_json(android_signing_preflight)
            if android_signing_preflight is not None
            else None
        ),
        "installer": _command_json(installer) if installer is not None else None,
        "bundle_verifier": (
            _command_json(bundle_verifier) if bundle_verifier is not None else None
        ),
        "publishable_packager": (
            _command_json(publishable_packager)
            if publishable_packager is not None
            else None
        ),
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def run_acceptance(
    *,
    windows_exe: Path,
    android_apk: Path,
    host_exe: Path,
    adb_path: Path | None,
    device_serial: str,
    build_apk: bool,
    expect_control_locked: bool,
    remove_legacy_benchmark_package: bool,
    output_dir: Path,
    android_build_timeout_sec: int,
    device_preflight_timeout_sec: int,
    installer_timeout_sec: int,
    verifier_timeout_sec: int,
    bluetooth_route_evidence: Path | None = None,
    bluetooth_route_mobile_log: Path | None = None,
    makcu_route_evidence: Path | None = None,
    makcu_route_mobile_log: Path | None = None,
    final_safe_idle_evidence: Path | None = None,
    final_safe_idle_mobile_log: Path | None = None,
    final_safe_idle_ui_xml: Path | None = None,
    manifest_signing_private_key: Path | None = None,
    bundle_sequence: int | None = None,
    bundle_channel: str = "stable",
    bundle_release_version: str = "1.0.8",
    bundle_min_supported_version: str = "1.0.0",
    bundle_revocation_epoch: int = 0,
    runner: CommandRunner = run_command,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    acceptance_report = output_dir / "formal_release_acceptance.json"
    android_release_dir = output_dir / "android_release"
    android_release_report = android_release_dir / "android_production_release_build.json"
    android_signing_report = android_release_dir / "android_production_signing_inputs.json"
    android_apk_report = output_dir / "android_release_apk_preflight.json"
    android_device_report = output_dir / "android_device_connectivity.json"
    android_release_report_text = str(android_release_report) if build_apk else ""
    android_signing_report_text = str(android_signing_report) if build_apk else ""
    bundle_report = output_dir / "formal_release_bundle_verify.json"
    source_android_apk = CANONICAL_ANDROID_RELEASE_APK if build_apk else android_apk
    artifacts = {
        "windows_exe": str(windows_exe),
        "android_apk": str(android_apk),
        "android_apk_input": str(source_android_apk),
        "host_exe": str(host_exe),
    }
    run_parameters = build_acceptance_run_parameters(
        windows_exe=windows_exe,
        android_apk_input=source_android_apk,
        host_exe=host_exe,
        adb_path=adb_path,
        device_serial=device_serial,
        build_apk=build_apk,
        expect_control_locked=expect_control_locked,
        remove_legacy_benchmark_package=remove_legacy_benchmark_package,
        android_build_timeout_sec=android_build_timeout_sec,
        device_preflight_timeout_sec=device_preflight_timeout_sec,
        installer_timeout_sec=installer_timeout_sec,
        verifier_timeout_sec=verifier_timeout_sec,
        bluetooth_route_evidence=bluetooth_route_evidence,
        bluetooth_route_mobile_log=bluetooth_route_mobile_log,
        makcu_route_evidence=makcu_route_evidence,
        makcu_route_mobile_log=makcu_route_mobile_log,
        final_safe_idle_evidence=final_safe_idle_evidence,
        final_safe_idle_mobile_log=final_safe_idle_mobile_log,
        final_safe_idle_ui_xml=final_safe_idle_ui_xml,
    )
    android_release_builder: CommandResult | None = None
    android_signing_preflight: CommandResult | None = None
    android_device_preflight: CommandResult | None = None
    if build_apk:
        android_device_preflight = runner(
            build_android_device_preflight_command(
                output=android_device_report,
                adb_path=adb_path,
                device_serial=device_serial,
                timeout_sec=device_preflight_timeout_sec,
            ),
            device_preflight_timeout_sec + 15,
        )
        android_signing_preflight = runner(
            build_android_signing_preflight_command(output=android_signing_report),
            60,
        )
        if android_signing_preflight.returncode != 0:
            write_acceptance_report(
                output=acceptance_report,
                ok=False,
                artifacts=artifacts,
                installer=None,
                bundle_verifier=None,
                android_apk_preflight=None,
                android_device_preflight=android_device_preflight,
                android_release_builder=None,
                android_signing_preflight=android_signing_preflight,
                device_evidence="",
                bundle_report=str(bundle_report),
                android_apk_report="",
                android_device_report=str(android_device_report),
                android_release_report=android_release_report_text,
                android_signing_report=android_signing_report_text,
                run_parameters=run_parameters,
            )
            print(
                "[ERROR] Android production signing preflight failed; "
                f"report={acceptance_report}",
                flush=True,
            )
            print_release_blocker_summary(acceptance_report)
            return 7

        android_release_command = build_android_release_command(
            output_dir=android_release_dir,
            timeout_sec=android_build_timeout_sec,
        )
        android_release_builder = runner(
            android_release_command,
            android_build_timeout_sec + 60,
        )
        artifact_text = parse_android_release_artifact_path(
            android_release_builder.stdout + "\n" + android_release_builder.stderr,
        )
        if android_release_builder.returncode == 0:
            try:
                android_apk = resolve_android_release_artifact(
                    artifact_text=artifact_text,
                    report_path=android_release_report,
                )
            except Exception as exc:  # noqa: BLE001
                android_release_builder = CommandResult(
                    cmd=android_release_builder.cmd,
                    returncode=5,
                    stdout=android_release_builder.stdout,
                    stderr=android_release_builder.stderr
                    + f"\nAndroid release artifact validation failed: {exc}\n",
                )
                artifact_text = ""
        if android_release_builder.returncode == 0 and artifact_text:
            artifacts["android_apk"] = str(android_apk)
        else:
            write_acceptance_report(
                output=acceptance_report,
                ok=False,
                artifacts=artifacts,
                installer=None,
                bundle_verifier=None,
                android_apk_preflight=None,
                android_device_preflight=android_device_preflight,
                android_release_builder=android_release_builder,
                android_signing_preflight=android_signing_preflight,
                device_evidence="",
                bundle_report=str(bundle_report),
                android_apk_report="",
                android_device_report=str(android_device_report),
                android_release_report=android_release_report_text,
                android_signing_report=android_signing_report_text,
                run_parameters=run_parameters,
            )
            print(
                "[ERROR] Android production APK build failed; "
                f"report={acceptance_report}",
                flush=True,
            )
            print_release_blocker_summary(acceptance_report)
            return 4

    android_apk_preflight = runner(
        build_android_apk_preflight_command(
            apk_path=android_apk,
            output=android_apk_report,
        ),
        120,
    )
    if android_device_preflight is None:
        android_device_preflight = runner(
            build_android_device_preflight_command(
                output=android_device_report,
                adb_path=adb_path,
                device_serial=device_serial,
                timeout_sec=device_preflight_timeout_sec,
            ),
            device_preflight_timeout_sec + 15,
        )
    if android_apk_preflight.returncode != 0:
        if android_signing_preflight is None:
            android_signing_report_text = str(android_signing_report)
            android_signing_preflight = runner(
                build_android_signing_preflight_command(output=android_signing_report),
                60,
            )
        write_acceptance_report(
            output=acceptance_report,
            ok=False,
            artifacts=artifacts,
            installer=None,
            bundle_verifier=None,
            android_apk_preflight=android_apk_preflight,
            android_device_preflight=android_device_preflight,
            android_release_builder=android_release_builder,
            android_signing_preflight=android_signing_preflight,
            device_evidence="",
            bundle_report=str(bundle_report),
            android_apk_report=str(android_apk_report),
            android_device_report=str(android_device_report),
            android_release_report=android_release_report_text,
            android_signing_report=android_signing_report_text,
            run_parameters=run_parameters,
        )
        print(
            "[ERROR] Android APK release preflight failed; "
            f"report={acceptance_report}",
            flush=True,
        )
        print_release_blocker_summary(acceptance_report)
        return 6

    if android_device_preflight.returncode != 0:
        write_acceptance_report(
            output=acceptance_report,
            ok=False,
            artifacts=artifacts,
            installer=None,
            bundle_verifier=None,
            android_apk_preflight=android_apk_preflight,
            android_device_preflight=android_device_preflight,
            android_release_builder=android_release_builder,
            android_signing_preflight=android_signing_preflight,
            device_evidence="",
            bundle_report=str(bundle_report),
            android_apk_report=str(android_apk_report),
            android_device_report=str(android_device_report),
            android_release_report=android_release_report_text,
            android_signing_report=android_signing_report_text,
            run_parameters=run_parameters,
        )
        print(
            "[ERROR] Android device preflight failed; "
            f"report={acceptance_report}",
            flush=True,
        )
        print_release_blocker_summary(acceptance_report)
        return 5

    installer_command = build_install_command(
        apk_path=android_apk,
        windows_exe=windows_exe,
        host_exe=host_exe,
        adb_path=adb_path,
        device_serial=device_serial,
        build_apk=False,
        expect_control_locked=expect_control_locked,
        remove_legacy_benchmark_package=remove_legacy_benchmark_package,
        bluetooth_route_evidence=bluetooth_route_evidence,
        bluetooth_route_mobile_log=bluetooth_route_mobile_log,
        makcu_route_evidence=makcu_route_evidence,
        makcu_route_mobile_log=makcu_route_mobile_log,
        final_safe_idle_evidence=final_safe_idle_evidence,
        final_safe_idle_mobile_log=final_safe_idle_mobile_log,
        final_safe_idle_ui_xml=final_safe_idle_ui_xml,
    )
    installer = runner(installer_command, installer_timeout_sec)
    combined_install_output = installer.stdout + "\n" + installer.stderr
    evidence_text = parse_formal_device_evidence_path(combined_install_output)
    if installer.returncode != 0 or not evidence_text:
        write_acceptance_report(
            output=acceptance_report,
            ok=False,
            artifacts=artifacts,
            installer=installer,
            bundle_verifier=None,
            android_apk_preflight=android_apk_preflight,
            android_device_preflight=android_device_preflight,
            android_release_builder=android_release_builder,
            android_signing_preflight=android_signing_preflight,
            device_evidence=evidence_text,
            bundle_report=str(bundle_report),
            android_apk_report=str(android_apk_report),
            android_device_report=str(android_device_report),
            android_release_report=android_release_report_text,
            android_signing_report=android_signing_report_text,
            run_parameters=run_parameters,
        )
        print(
            f"[ERROR] formal mobile installation/evidence failed; report={acceptance_report}",
            flush=True,
        )
        print_release_blocker_summary(acceptance_report)
        return 2

    try:
        evidence_path = stage_formal_device_evidence(
            evidence_text=evidence_text,
            output_dir=output_dir,
        )
    except Exception as exc:  # noqa: BLE001
        installer = CommandResult(
            cmd=installer.cmd,
            returncode=5,
            stdout=installer.stdout,
            stderr=installer.stderr + f"\nFormal device evidence staging failed: {exc}\n",
        )
        write_acceptance_report(
            output=acceptance_report,
            ok=False,
            artifacts=artifacts,
            installer=installer,
            bundle_verifier=None,
            android_apk_preflight=android_apk_preflight,
            android_device_preflight=android_device_preflight,
            android_release_builder=android_release_builder,
            android_signing_preflight=android_signing_preflight,
            device_evidence=evidence_text,
            bundle_report=str(bundle_report),
            android_apk_report=str(android_apk_report),
            android_device_report=str(android_device_report),
            android_release_report=android_release_report_text,
            android_signing_report=android_signing_report_text,
            run_parameters=run_parameters,
        )
        print(
            f"[ERROR] formal device evidence staging failed; report={acceptance_report}",
            flush=True,
        )
        print_release_blocker_summary(acceptance_report)
        return 2
    bundle_command = build_bundle_verify_command(
        windows_exe=windows_exe,
        android_apk=android_apk,
        host_exe=host_exe,
        device_evidence=evidence_path,
        output=bundle_report,
    )
    bundle = runner(bundle_command, verifier_timeout_sec)
    if bundle.returncode == 0:
        report_errors = validate_formal_bundle_report(bundle_report)
        if report_errors:
            bundle = CommandResult(
                cmd=bundle.cmd,
                returncode=5,
                stdout=bundle.stdout,
                stderr=(
                    bundle.stderr
                    + "\nFormal bundle report validation failed: "
                    + "; ".join(report_errors)
                    + "\n"
                ),
            )
    bundle_ok = bundle.returncode == 0
    publishable_bundle_dir = output_dir / "publishable_release"
    write_acceptance_report(
        output=acceptance_report,
        ok=bundle_ok,
        artifacts=artifacts,
        installer=installer,
        bundle_verifier=bundle,
        publishable_packager=None,
        android_apk_preflight=android_apk_preflight,
        android_device_preflight=android_device_preflight,
        android_release_builder=android_release_builder,
        android_signing_preflight=android_signing_preflight,
        device_evidence=str(evidence_path),
        bundle_report=str(bundle_report),
        android_apk_report=str(android_apk_report),
        android_device_report=str(android_device_report),
        android_release_report=android_release_report_text,
        android_signing_report=android_signing_report_text,
        publishable_bundle_dir="",
        run_parameters=run_parameters,
    )
    if bundle_ok:
        if manifest_signing_private_key is None or bundle_sequence is None:
            publishable_packager = CommandResult(
                cmd=("offline-manifest-signing-required",),
                returncode=5,
                stdout="",
                stderr=(
                    "Explicit offline Ed25519 signing key and monotonic bundle "
                    "sequence are required before publishable packaging.\n"
                ),
            )
            write_acceptance_report(
                output=acceptance_report,
                ok=False,
                artifacts=artifacts,
                installer=installer,
                bundle_verifier=bundle,
                publishable_packager=publishable_packager,
                android_apk_preflight=android_apk_preflight,
                android_device_preflight=android_device_preflight,
                android_release_builder=android_release_builder,
                android_signing_preflight=android_signing_preflight,
                device_evidence=str(evidence_path),
                bundle_report=str(bundle_report),
                android_apk_report=str(android_apk_report),
                android_device_report=str(android_device_report),
                android_release_report=android_release_report_text,
                android_signing_report=android_signing_report_text,
                publishable_bundle_dir="",
                run_parameters=run_parameters,
            )
            print(
                "[ERROR] offline signed publishable packaging inputs are missing; "
                f"report={acceptance_report}",
                flush=True,
            )
            return 4
        packager_command = build_publishable_packager_command(
            acceptance_report=acceptance_report,
            output_dir=publishable_bundle_dir,
            signing_private_key=manifest_signing_private_key,
            bundle_sequence=bundle_sequence,
            channel=bundle_channel,
            release_version=bundle_release_version,
            min_supported_version=bundle_min_supported_version,
            revocation_epoch=bundle_revocation_epoch,
        )
        publishable_packager = runner(packager_command, verifier_timeout_sec)
        publishable_bundle: Mapping[str, object] | None = None
        publishable_packager_report = ""
        publishable_packager_rejection: Mapping[str, object] | None = None
        if publishable_packager.returncode == 0:
            publishable_bundle = summarize_publishable_bundle(publishable_bundle_dir)
            if publishable_bundle.get("ok") is not True:
                publishable_packager = CommandResult(
                    cmd=publishable_packager.cmd,
                    returncode=5,
                    stdout=publishable_packager.stdout,
                    stderr=(
                        publishable_packager.stderr
                        + "\nPublishable release bundle artifact validation failed: "
                        + "; ".join(str(item) for item in publishable_bundle.get("errors", []))
                        + "\n"
                    ),
                )
        if publishable_packager.returncode != 0:
            publishable_packager_report = parse_publishable_packager_report_path(
                publishable_packager.stdout + "\n" + publishable_packager.stderr
            )
            publishable_packager_rejection = summarize_publishable_packager_rejection(
                publishable_packager_report
            )
        publishable_ok = publishable_packager.returncode == 0
        write_acceptance_report(
            output=acceptance_report,
            ok=publishable_ok,
            artifacts=artifacts,
            installer=installer,
            bundle_verifier=bundle,
            publishable_packager=publishable_packager,
            android_apk_preflight=android_apk_preflight,
            android_device_preflight=android_device_preflight,
            android_release_builder=android_release_builder,
            android_signing_preflight=android_signing_preflight,
            device_evidence=str(evidence_path),
            bundle_report=str(bundle_report),
            android_apk_report=str(android_apk_report),
            android_device_report=str(android_device_report),
            android_release_report=android_release_report_text,
            android_signing_report=android_signing_report_text,
            publishable_bundle_dir=str(publishable_bundle_dir),
            publishable_bundle=publishable_bundle,
            publishable_packager_report=publishable_packager_report,
            publishable_packager_rejection=publishable_packager_rejection,
            run_parameters=run_parameters,
        )
        if publishable_ok:
            print(
                f"[OK] formal release acceptance passed; report={acceptance_report} "
                f"publishable={publishable_bundle_dir}",
                flush=True,
            )
            return 0
        print(f"[ERROR] publishable release packaging failed; report={acceptance_report}", flush=True)
        print_release_blocker_summary(acceptance_report)
        return 4
    print(f"[ERROR] formal release acceptance failed; report={acceptance_report}", flush=True)
    print_release_blocker_summary(acceptance_report)
    return 3


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-exe", type=Path, default=None)
    parser.add_argument(
        "--android-apk",
        type=Path,
        default=CANONICAL_ANDROID_RELEASE_APK,
    )
    parser.add_argument("--host-exe", type=Path, default=None)
    parser.add_argument("--adb-path", type=Path, default=None)
    parser.add_argument("--device-serial", default="")
    parser.add_argument("--build-apk", action="store_true")
    parser.add_argument("--expect-control-locked", action="store_true")
    parser.add_argument("--remove-legacy-benchmark-package", action="store_true")
    parser.add_argument("--bluetooth-route-evidence", type=Path, default=None)
    parser.add_argument("--bluetooth-route-mobile-log", type=Path, default=None)
    parser.add_argument("--makcu-route-evidence", type=Path, default=None)
    parser.add_argument("--makcu-route-mobile-log", type=Path, default=None)
    parser.add_argument("--final-safe-idle-evidence", type=Path, default=None)
    parser.add_argument("--final-safe-idle-mobile-log", type=Path, default=None)
    parser.add_argument("--final-safe-idle-ui-xml", type=Path, default=None)
    parser.add_argument("--android-build-timeout-sec", type=int, default=1500)
    parser.add_argument("--device-preflight-timeout-sec", type=int, default=30)
    parser.add_argument("--installer-timeout-sec", type=int, default=900)
    parser.add_argument("--verifier-timeout-sec", type=int, default=240)
    parser.add_argument("--manifest-signing-private-key", type=Path)
    parser.add_argument("--bundle-sequence", type=int)
    parser.add_argument("--bundle-channel", default="stable")
    parser.add_argument("--bundle-release-version", default="1.0.8")
    parser.add_argument("--bundle-min-supported-version", default="1.0.0")
    parser.add_argument("--bundle-revocation-epoch", type=int, default=0)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT
        / "analysis_output"
        / f"formal_release_acceptance_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    windows_exe = _resolve_required_path(args.windows_exe or latest_windows_release(), "Windows EXE")
    android_apk = (
        args.android_apk.resolve()
        if args.build_apk
        else _resolve_required_path(args.android_apk, "Android APK")
    )
    host_exe = _resolve_required_path(args.host_exe or default_host_release(), "Host EXE")
    adb_path = args.adb_path.resolve() if args.adb_path else None
    return run_acceptance(
        windows_exe=windows_exe,
        android_apk=android_apk,
        host_exe=host_exe,
        adb_path=adb_path,
        device_serial=args.device_serial,
        build_apk=args.build_apk,
        expect_control_locked=args.expect_control_locked,
        remove_legacy_benchmark_package=args.remove_legacy_benchmark_package,
        output_dir=args.output_dir.resolve(),
        android_build_timeout_sec=args.android_build_timeout_sec,
        device_preflight_timeout_sec=args.device_preflight_timeout_sec,
        installer_timeout_sec=args.installer_timeout_sec,
        verifier_timeout_sec=args.verifier_timeout_sec,
        manifest_signing_private_key=(
            args.manifest_signing_private_key.resolve()
            if args.manifest_signing_private_key
            else None
        ),
        bundle_sequence=args.bundle_sequence,
        bundle_channel=args.bundle_channel,
        bundle_release_version=args.bundle_release_version,
        bundle_min_supported_version=args.bundle_min_supported_version,
        bundle_revocation_epoch=args.bundle_revocation_epoch,
        bluetooth_route_evidence=(
            args.bluetooth_route_evidence.resolve()
            if args.bluetooth_route_evidence
            else None
        ),
        bluetooth_route_mobile_log=(
            args.bluetooth_route_mobile_log.resolve()
            if args.bluetooth_route_mobile_log
            else None
        ),
        makcu_route_evidence=(
            args.makcu_route_evidence.resolve()
            if args.makcu_route_evidence
            else None
        ),
        makcu_route_mobile_log=(
            args.makcu_route_mobile_log.resolve()
            if args.makcu_route_mobile_log
            else None
        ),
        final_safe_idle_evidence=(
            args.final_safe_idle_evidence.resolve()
            if args.final_safe_idle_evidence
            else None
        ),
        final_safe_idle_mobile_log=(
            args.final_safe_idle_mobile_log.resolve()
            if args.final_safe_idle_mobile_log
            else None
        ),
        final_safe_idle_ui_xml=(
            args.final_safe_idle_ui_xml.resolve()
            if args.final_safe_idle_ui_xml
            else None
        ),
    )


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
