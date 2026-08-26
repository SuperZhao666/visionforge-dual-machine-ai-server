from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import run_formal_release_acceptance as acceptance  # noqa: E402
from tools.verify_formal_release_bundle import DEVICE_EVIDENCE_SCHEMA  # noqa: E402


def _write_publishable_bundle(output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "formal_release_manifest.json").write_text(
        json.dumps(
            {
                "schema": "visionforge-publishable-release-manifest-envelope-v1",
                "algorithm": "Ed25519",
                "key_id": "0" * 64,
                "payload_b64": "e30=",
                "signature_b64": "AA==",
            }
        ),
        encoding="utf-8",
    )
    archive = output_dir / "formal_release_bundle.zip"
    archive.write_bytes(b"publishable-zip")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output_dir / "formal_release_bundle.zip.sha256").write_text(
        digest + "  formal_release_bundle.zip\n",
        encoding="utf-8",
    )
    (output_dir / "publishable_release_bundle_verify.json").write_text(
        json.dumps(
            {
                "schema": "visionforge-publishable-release-bundle-archive-v1",
                "authenticated": True,
                "anti_rollback_enforced": True,
                "ok": True,
                "manifest": {
                    "schema": "visionforge-publishable-release-bundle-v2",
                    "artifact_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    return digest


def _write_formal_bundle_report(
    command: Sequence[str],
    **overrides: object,
) -> None:
    output_path = Path(command[command.index("--output") + 1])
    report: dict[str, object] = {
        "schema": "visionforge-formal-release-bundle-v1",
        "mode": "formal",
        "diagnostic_completed": True,
        "checks_ok": True,
        "strict_ok": True,
        "reverse_resistance_ok": True,
        "formal_eligible": True,
        "formal_ok": True,
        "formal_release_ok": True,
        "bypasses": [],
        "ok": True,
        "checks": [
            {"name": "windows_release", "ok": True, "evidence": {}},
            {"name": "android_release_apk", "ok": True, "evidence": {}},
            {"name": "host_release", "ok": True, "evidence": {}},
            {
                "name": "source_contracts",
                "ok": True,
                "evidence": {
                    "base_checks_ok": True,
                    "reverse_resistance_ok": True,
                    "failed": [],
                },
            },
            {"name": "device_evidence", "ok": True, "evidence": {}},
        ],
    }
    report.update(overrides)
    output_path.write_text(json.dumps(report), encoding="utf-8")


def _write_artifacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    windows = tmp_path / "VisionForge_Protected.exe"
    apk = tmp_path / "app-release.apk"
    host = tmp_path / "VFHost.exe"
    windows.write_bytes(b"MZwindows")
    apk.write_bytes(b"apk")
    host.write_bytes(b"MZhost")
    return windows, apk, host


def _write_installer_device_evidence(tmp_path: Path) -> Path:
    ui_dir = tmp_path / "installer-device-ui"
    ui_dir.mkdir()
    (ui_dir / "control.xml").write_text("<hierarchy />", encoding="utf-8")
    mobile_log = tmp_path / "installer-mobile-logcat.txt"
    mobile_log.write_text("QNN graphExecute control move smoke", encoding="utf-8")
    evidence = tmp_path / "formal_device_evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": DEVICE_EVIDENCE_SCHEMA,
                "sources": {
                    "android_apk": "app-release.apk",
                    "windows_exe": "VisionForge_Protected.exe",
                    "host_exe": "VFHost.exe",
                    "ui_evidence_dir": str(ui_dir),
                    "mobile_logs": [str(mobile_log)],
                    "host_logs": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return evidence


def test_build_install_command_forwards_both_physical_route_evidence_sets(
    tmp_path: Path,
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    bluetooth_evidence = tmp_path / "bluetooth-route.json"
    bluetooth_log = tmp_path / "bluetooth-mobile.jsonl"
    makcu_evidence = tmp_path / "makcu-route.json"
    makcu_log = tmp_path / "makcu-mobile.jsonl"
    final_safe_idle_evidence = tmp_path / "final-safe-idle.json"
    final_safe_idle_log = tmp_path / "final-safe-idle-mobile.jsonl"
    final_safe_idle_ui = tmp_path / "final-safe-idle.xml"

    command = acceptance.build_install_command(
        apk_path=apk,
        windows_exe=windows,
        host_exe=host,
        adb_path=None,
        device_serial="R5CT",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        bluetooth_route_evidence=bluetooth_evidence,
        bluetooth_route_mobile_log=bluetooth_log,
        makcu_route_evidence=makcu_evidence,
        makcu_route_mobile_log=makcu_log,
        final_safe_idle_evidence=final_safe_idle_evidence,
        final_safe_idle_mobile_log=final_safe_idle_log,
        final_safe_idle_ui_xml=final_safe_idle_ui,
    )

    assert command[command.index("-BluetoothRouteEvidencePath") + 1] == str(
        bluetooth_evidence
    )
    assert command[command.index("-BluetoothRouteMobileLogPath") + 1] == str(
        bluetooth_log
    )
    assert command[command.index("-MakcuRouteEvidencePath") + 1] == str(makcu_evidence)
    assert command[command.index("-MakcuRouteMobileLogPath") + 1] == str(makcu_log)
    assert command[command.index("-FinalSafeIdleEvidencePath") + 1] == str(
        final_safe_idle_evidence
    )
    assert command[command.index("-FinalSafeIdleMobileLogPath") + 1] == str(
        final_safe_idle_log
    )
    assert command[command.index("-FinalSafeIdleUiXmlPath") + 1] == str(
        final_safe_idle_ui
    )


def _write_device_connectivity_failure_report(command: Sequence[str]) -> None:
    output_path = Path(command[command.index("--output") + 1])
    output_path.write_text(
        json.dumps(
            {
                "schema": "visionforge-android-device-connectivity-v1",
                "ok": False,
                "reason": "no_authorized_device",
                "devices": [],
                "adb_mdns_services": [],
                "next_actions": [
                    {
                        "reason": "no_authorized_device",
                        "action": (
                            "Authorize or connect exactly one target phone before "
                            "formal acceptance."
                        ),
                        "commands": ["adb mdns services", "adb devices -l"],
                        "hint": "No ADB mDNS services were discovered.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_parse_formal_device_evidence_path_accepts_installer_summary() -> None:
    output = (
        "VISIONFORGE_MOBILE_INSTALL_OK apk=a device=d "
        "formal_device_evidence=F:\\out\\formal_device_evidence.json"
    )
    assert (
        acceptance.parse_formal_device_evidence_path(output)
        == "F:\\out\\formal_device_evidence.json"
    )


def test_formal_bundle_report_validator_rejects_mode_laundering(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "formal_release_bundle_verify.json"
    command = ("verifier", "--output", str(report_path))
    _write_formal_bundle_report(
        command,
        schema="visionforge-development-bundle-check-v1",
        mode="development",
        strict_ok=False,
        formal_eligible=False,
        formal_ok=False,
        formal_release_ok=False,
        ok=False,
    )

    errors = acceptance.validate_formal_bundle_report(report_path)

    assert any("mode is not formal" in error for error in errors)
    assert any("formal_eligible is not true" in error for error in errors)

def test_command_primary_detail_preserves_specific_error_after_long_header() -> None:
    result = acceptance.CommandResult(
        cmd=("tool",),
        returncode=1,
        stdout=(
            "[ERROR] Android APK release preflight failed; report="
            + "x" * 300
            + "\n[ERROR] APK is signed with Android Debug certificate\n"
        ),
        stderr="",
    )

    detail = acceptance._command_primary_detail(result)

    assert detail == (
        "[ERROR] Android APK release preflight failed; "
        "[ERROR] APK is signed with Android Debug certificate"
    )
    assert detail.endswith("[ERROR] APK is signed with Android Debug certificate")
    assert len(detail) <= 240


def test_command_primary_detail_removes_report_path_noise_from_single_line() -> None:
    result = acceptance.CommandResult(
        cmd=("tool",),
        returncode=1,
        stdout=(
            "[ERROR] Android ADB device is not ready; reason=no_authorized_device "
            "report=F:\\out\\android_device_connectivity.json\n"
        ),
        stderr="",
    )

    assert acceptance._command_primary_detail(result) == (
        "[ERROR] Android ADB device is not ready; reason=no_authorized_device"
    )
    assert acceptance._command_diagnostic_details(result) == [
        "[ERROR] Android ADB device is not ready; reason=no_authorized_device "
        "report=F:\\out\\android_device_connectivity.json"
    ]


def test_formal_acceptance_runs_installer_then_strict_bundle_verifier(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    evidence = _write_installer_device_evidence(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[tuple[Sequence[str], int]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append((tuple(command), timeout))
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android APK release preflight passed\n",
                stderr="",
            )
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        if "install_mobile_release.ps1" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout=f"VISIONFORGE_MOBILE_INSTALL_OK formal_device_evidence={evidence}\n",
                stderr="",
            )
        if "verify_formal_release_bundle.py" in text:
            assert "--device-evidence" in command
            assert command[command.index("--mode") + 1] == "formal"
            assert "--allow-development-android-signing" not in command
            _write_formal_bundle_report(command)
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] formal release bundle verification passed",
                stderr="",
            )
        assert "package_formal_release_bundle.py" in text
        assert "--acceptance-report" in command
        assert "--output-dir" in command
        publishable_dir = Path(command[command.index("--output-dir") + 1])
        _write_publishable_bundle(publishable_dir)
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=0,
            stdout="[OK] publishable release bundle created",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        manifest_signing_private_key=tmp_path / "offline-signing.pem",
        bundle_sequence=8,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 0
    assert len(calls) == 5
    assert report["ok"] is True
    assert report["android_apk_preflight"]["returncode"] == 0
    assert report["android_device_preflight"]["returncode"] == 0
    assert report["release_blockers"] == []
    assert report["next_actions"] == []
    assert report["run_parameters"] == {
        "windows_exe": str(windows),
        "android_apk_input": str(apk),
        "host_exe": str(host),
        "adb_path": "",
        "device_serial": "",
        "build_apk": False,
        "expect_control_locked": False,
        "remove_legacy_benchmark_package": False,
        "timeouts_sec": {
            "android_build": 10,
            "device_preflight": 9,
            "installer": 11,
            "verifier": 12,
        },
    }
    assert report["android_signing_preflight"] is None
    assert report["android_release_report"] == ""
    assert report["android_signing_report"] == ""
    assert report["device_evidence"] == str((output_dir / "formal_device_evidence.json").resolve())
    assert report["publishable_bundle_dir"] == str(output_dir / "publishable_release")
    staged_evidence = json.loads((output_dir / "formal_device_evidence.json").read_text())
    staged_sources = staged_evidence["sources"]
    assert Path(staged_sources["ui_evidence_dir"]).is_dir()
    assert Path(staged_sources["ui_evidence_dir"]).is_relative_to(output_dir.resolve())
    assert Path(staged_sources["mobile_logs"][0]).is_file()
    assert Path(staged_sources["mobile_logs"][0]).is_relative_to(output_dir.resolve())
    assert report["bundle_verifier"]["returncode"] == 0
    assert report["publishable_packager"]["returncode"] == 0
    assert "<redacted-offline-key-path>" in report["publishable_packager"]["cmd"]
    assert str(tmp_path / "offline-signing.pem") not in json.dumps(report)
    assert report["publishable_bundle"]["ok"] is True
    assert report["publishable_bundle"]["archive"].endswith("formal_release_bundle.zip")
    assert len(report["publishable_bundle"]["archive_sha256"]) == 64


def test_formal_acceptance_fails_when_publishable_packager_fails(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    evidence = _write_installer_device_evidence(tmp_path)
    output_dir = tmp_path / "acceptance"

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(tuple(command), 0, "[OK] apk\n", "")
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(tuple(command), 0, "[OK] device\n", "")
        if "install_mobile_release.ps1" in text:
            return acceptance.CommandResult(
                tuple(command),
                0,
                f"VISIONFORGE_MOBILE_INSTALL_OK formal_device_evidence={evidence}\n",
                "",
            )
        if "verify_formal_release_bundle.py" in text:
            _write_formal_bundle_report(command)
            return acceptance.CommandResult(tuple(command), 0, "[OK] bundle\n", "")
        assert "package_formal_release_bundle.py" in text
        rejected = output_dir / "publishable_release.rejected_20260728_000000.json"
        rejected.write_text(
            json.dumps(
                {
                    "schema": "visionforge-publishable-release-bundle-v1",
                    "ok": False,
                    "error": "formal acceptance report is not successful",
                    "acceptance_report": str(output_dir / "formal_release_acceptance.json"),
                    "acceptance_ok": False,
                    "acceptance_release_blockers_empty": False,
                    "acceptance_next_actions_empty": False,
                    "acceptance_packaging_ready": False,
                    "release_blockers": [
                        {"stage": "android_apk_preflight", "detail": "debug signing"},
                    ],
                    "next_actions": [
                        {"stage": "android_apk_preflight", "command": "rebuild"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        return acceptance.CommandResult(
            tuple(command),
            1,
            f"[ERROR] publishable release bundle rejected; report={rejected}\n",
            "",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        manifest_signing_private_key=tmp_path / "offline-signing.pem",
        bundle_sequence=8,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 4
    assert report["ok"] is False
    assert report["bundle_verifier"]["returncode"] == 0
    assert report["publishable_packager"]["returncode"] == 1
    assert report["publishable_bundle_dir"] == str(output_dir / "publishable_release")
    assert report["publishable_packager_report"].endswith(
        "publishable_release.rejected_20260728_000000.json"
    )
    assert report["publishable_packager_rejection"]["ok"] is False
    assert report["publishable_packager_rejection"]["acceptance_packaging_ready"] is False
    assert report["publishable_packager_rejection"]["acceptance_next_actions_empty"] is False
    assert report["publishable_packager_rejection"]["release_blocker_stages"] == [
        "android_apk_preflight"
    ]
    assert report["publishable_packager_rejection"]["next_action_stages"] == [
        "android_apk_preflight"
    ]
    assert [blocker["stage"] for blocker in report["release_blockers"]] == [
        "publishable_packager"
    ]


def test_formal_acceptance_fails_when_publishable_artifacts_are_missing(
    tmp_path: Path,
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    evidence = _write_installer_device_evidence(tmp_path)
    output_dir = tmp_path / "acceptance"

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(tuple(command), 0, "[OK] apk\n", "")
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(tuple(command), 0, "[OK] device\n", "")
        if "install_mobile_release.ps1" in text:
            return acceptance.CommandResult(
                tuple(command),
                0,
                f"VISIONFORGE_MOBILE_INSTALL_OK formal_device_evidence={evidence}\n",
                "",
            )
        if "verify_formal_release_bundle.py" in text:
            _write_formal_bundle_report(command)
            return acceptance.CommandResult(tuple(command), 0, "[OK] bundle\n", "")
        assert "package_formal_release_bundle.py" in text
        return acceptance.CommandResult(
            tuple(command),
            0,
            "[OK] publishable release bundle created\n",
            "",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        manifest_signing_private_key=tmp_path / "offline-signing.pem",
        bundle_sequence=8,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 4
    assert report["ok"] is False
    assert report["publishable_packager"]["returncode"] == 5
    assert report["publishable_bundle"]["ok"] is False
    assert "publishable archive is missing" in report["publishable_bundle"]["errors"]
    assert [blocker["stage"] for blocker in report["release_blockers"]] == [
        "publishable_packager"
    ]


def test_publishable_bundle_summary_rejects_wrong_sidecar_archive_name(
    tmp_path: Path,
) -> None:
    publishable_dir = tmp_path / "publishable"
    digest = _write_publishable_bundle(publishable_dir)
    (publishable_dir / "formal_release_bundle.zip.sha256").write_text(
        digest + "  stale_release_bundle.zip\n",
        encoding="utf-8",
    )

    summary = acceptance.summarize_publishable_bundle(publishable_dir)

    assert summary["ok"] is False
    assert "publishable archive sha256 sidecar does not name archive" in summary["errors"]


def test_formal_acceptance_stops_when_device_evidence_file_is_missing(
    tmp_path: Path,
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    evidence = tmp_path / "missing_formal_device_evidence.json"
    output_dir = tmp_path / "acceptance"

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android APK release preflight passed\n",
                stderr="",
            )
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=0,
            stdout=f"VISIONFORGE_MOBILE_INSTALL_OK formal_device_evidence={evidence}\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 2
    assert report["ok"] is False
    assert report["bundle_verifier"] is None
    assert report["installer"]["returncode"] == 5
    assert "Formal device evidence staging failed" in report["installer"]["stderr_tail"]


def test_formal_acceptance_stops_when_installer_does_not_emit_evidence(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android APK release preflight passed\n",
                stderr="",
            )
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=0,
            stdout="VISIONFORGE_MOBILE_INSTALL_OK ui_evidence=dir\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 2
    assert len(calls) == 3
    assert report["ok"] is False
    assert report["android_apk_preflight"]["returncode"] == 0
    assert report["android_device_preflight"]["returncode"] == 0
    assert report["bundle_verifier"] is None


def test_formal_acceptance_stops_when_android_device_preflight_fails(
    tmp_path: Path,
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_release_apk_artifact.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android APK release preflight passed\n",
                stderr="",
            )
        assert "verify_android_device_connectivity.py" in text
        _write_device_connectivity_failure_report(command)
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=2,
            stdout="[ERROR] Android ADB device is not ready; reason=no_authorized_device\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 5
    assert len(calls) == 2
    assert report["ok"] is False
    assert report["android_apk_preflight"]["returncode"] == 0
    assert report["android_device_preflight"]["returncode"] == 2
    assert report["installer"] is None
    assert report["bundle_verifier"] is None
    assert report["android_device_report"].endswith("android_device_connectivity.json")
    assert report["next_actions"] == [
        {
            "stage": "android_device_preflight",
            "action": "Authorize or connect exactly one target phone before formal acceptance.",
            "reason": "no_authorized_device",
            "command": "adb devices -l",
            "commands": ["adb mdns services", "adb devices -l"],
            "hint": "No ADB mDNS services were discovered.",
            "report": report["android_device_report"],
        }
    ]


def test_formal_acceptance_stops_when_android_apk_preflight_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_device_connectivity.py" in text:
            _write_device_connectivity_failure_report(command)
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=2,
                stdout="[ERROR] Android ADB device is not ready; reason=no_authorized_device\n",
                stderr="",
            )
        if "verify_android_production_signing_inputs.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=1,
                stdout=(
                    "[ERROR] Android production signing inputs failed\n"
                    "- VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required\n"
                    "- VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD is required\n"
                ),
                stderr="",
            )
        assert "verify_android_release_apk_artifact.py" in text
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=2,
            stdout="[ERROR] APK is signed with Android Debug certificate\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=False,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 6
    assert len(calls) == 3
    assert report["ok"] is False
    assert report["android_signing_preflight"]["returncode"] == 1
    assert report["android_signing_preflight"]["detail"] == (
        "[ERROR] Android production signing inputs failed; "
        "- VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD is required"
    )
    assert report["android_signing_preflight"]["details"] == [
        "[ERROR] Android production signing inputs failed",
        "- VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required",
        "- VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD is required",
    ]
    assert report["android_apk_preflight"]["returncode"] == 2
    assert report["android_apk_preflight"]["detail"] == (
        "[ERROR] APK is signed with Android Debug certificate"
    )
    assert report["android_device_preflight"]["returncode"] == 2
    assert report["android_device_preflight"]["details"] == [
        "[ERROR] Android ADB device is not ready; reason=no_authorized_device"
    ]
    assert [blocker["stage"] for blocker in report["release_blockers"]] == [
        "android_signing_preflight",
        "android_apk_preflight",
        "android_device_preflight",
    ]
    assert [action["stage"] for action in report["next_actions"]] == [
        "android_signing_preflight",
        "android_apk_preflight",
        "android_device_preflight",
    ]
    assert report["next_actions"][0]["required_env"] == [
        "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
        "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
        "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
        "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
    ]
    assert "create_android_release_keystore.py" in report["next_actions"][0]["command"]
    assert "production-signed release APK" in report["next_actions"][1]["action"]
    assert "--build-apk" in report["next_actions"][1]["command"]
    assert "adb devices -l" == report["next_actions"][2]["command"]
    assert report["next_actions"][2]["commands"] == [
        "adb mdns services",
        "adb devices -l",
    ]
    assert report["next_actions"][2]["hint"] == "No ADB mDNS services were discovered."
    signing_blocker = report["release_blockers"][0]
    assert signing_blocker["detail"] == (
        "[ERROR] Android production signing inputs failed; "
        "- VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD is required"
    )
    assert signing_blocker["details"] == [
        "[ERROR] Android production signing inputs failed",
        "- VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required",
        "- VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD is required",
    ]
    assert report["release_blockers"][0]["report"].endswith(
        "android_production_signing_inputs.json"
    )
    assert report["release_blockers"][1]["report"].endswith(
        "android_release_apk_preflight.json"
    )
    assert report["release_blockers"][2]["report"].endswith(
        "android_device_connectivity.json"
    )
    assert report["installer"] is None
    assert report["bundle_verifier"] is None
    assert report["android_signing_report"].endswith(
        "android_production_signing_inputs.json"
    )
    assert report["android_apk_report"].endswith("android_release_apk_preflight.json")
    assert report["android_device_report"].endswith("android_device_connectivity.json")
    output = capsys.readouterr().out
    assert "[ERROR] release blockers:" in output
    assert "- android_signing_preflight returncode=1" in output
    assert "- android_apk_preflight returncode=2" in output
    assert "- android_device_preflight returncode=2" in output
    assert "[ERROR] next actions:" in output
    assert "create_android_release_keystore.py" in output
    assert "production-signed release APK" in output
    assert "adb devices -l" in output
    assert "adb mdns services" in output
    assert "No ADB mDNS services were discovered." in output
    assert "Android production signing inputs failed" in output
    assert "APK is signed with Android Debug certificate" in output
    assert "no_authorized_device" in output


def test_formal_acceptance_build_stops_on_android_release_builder_failure(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        if "verify_android_production_signing_inputs.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android production signing inputs passed\n",
                stderr="",
            )
        assert "build_android_production_release.py" in text
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=1,
            stdout="[ERROR] Android production APK build failed\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=True,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 4
    assert len(calls) == 3
    assert report["ok"] is False
    assert report["android_device_preflight"]["returncode"] == 0
    assert report["android_signing_preflight"]["returncode"] == 0
    assert report["android_release_builder"]["returncode"] == 1
    assert report["installer"] is None


def test_formal_acceptance_build_stops_on_android_signing_preflight_failure(
    tmp_path: Path,
) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=2,
                stdout="[ERROR] Android ADB device is not ready; reason=no_authorized_device\n",
                stderr="",
            )
        assert "verify_android_production_signing_inputs.py" in text
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=1,
            stdout="[ERROR] Android production signing inputs failed\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=True,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 7
    assert len(calls) == 2
    assert report["ok"] is False
    assert report["run_parameters"]["build_apk"] is True
    assert report["run_parameters"]["android_apk_input"] == str(
        acceptance.CANONICAL_ANDROID_RELEASE_APK
    )
    assert "--apk-path" not in calls[-1]
    assert report["android_device_preflight"]["returncode"] == 2
    assert report["android_signing_preflight"]["returncode"] == 1
    assert [blocker["stage"] for blocker in report["release_blockers"]] == [
        "android_signing_preflight",
        "android_device_preflight",
    ]
    assert report["android_release_builder"] is None
    assert report["android_apk_preflight"] is None
    assert report["installer"] is None


def test_formal_acceptance_build_installs_archived_production_apk(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    built_apk = tmp_path / "release" / "VFMobile_1.0.0.apk"
    built_apk.parent.mkdir()
    built_apk.write_bytes(b"production-apk")
    sha_file = built_apk.with_suffix(".apk.sha256")
    sha_file.write_text("a" * 64 + f"  {built_apk.name}\n", encoding="utf-8")
    evidence = _write_installer_device_evidence(tmp_path)
    output_dir = tmp_path / "acceptance"
    android_release_dir = output_dir / "android_release"
    android_release_dir.mkdir(parents=True)
    (android_release_dir / "android_production_release_build.json").write_text(
        json.dumps(
            {
                "schema": "visionforge-android-production-release-build-v1",
                "ok": True,
                "stage": "complete",
                "artifact": {
                    "apk": str(built_apk),
                    "sha256_file": str(sha_file),
                },
            }
        ),
        encoding="utf-8",
    )
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        if "verify_android_production_signing_inputs.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android production signing inputs passed\n",
                stderr="",
            )
        if "build_android_production_release.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout=f"[OK] apk={built_apk}\n",
                stderr="",
            )
        if "verify_android_release_apk_artifact.py" in text:
            assert str(built_apk) in command
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android APK release preflight passed\n",
                stderr="",
            )
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        if "install_mobile_release.ps1" in text:
            assert str(built_apk) in command
            assert "-Build" not in command
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout=f"VISIONFORGE_MOBILE_INSTALL_OK formal_device_evidence={evidence}\n",
                stderr="",
            )
        if "verify_formal_release_bundle.py" in text:
            assert str(built_apk) in command
            assert "--device-evidence" in command
            _write_formal_bundle_report(command)
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] formal release bundle verification passed",
                stderr="",
        )
        assert "package_formal_release_bundle.py" in text
        assert "--acceptance-report" in command
        publishable_dir = Path(command[command.index("--output-dir") + 1])
        _write_publishable_bundle(publishable_dir)
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=0,
            stdout="[OK] publishable release bundle created",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=True,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        manifest_signing_private_key=tmp_path / "offline-signing.pem",
        bundle_sequence=8,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 0
    assert len(calls) == 7
    assert report["ok"] is True
    assert report["android_signing_preflight"]["returncode"] == 0
    assert report["android_apk_preflight"]["returncode"] == 0
    assert report["android_device_preflight"]["returncode"] == 0
    assert report["device_evidence"] == str((output_dir / "formal_device_evidence.json").resolve())
    staged_evidence = json.loads((output_dir / "formal_device_evidence.json").read_text())
    assert Path(staged_evidence["sources"]["ui_evidence_dir"]).is_relative_to(output_dir.resolve())
    assert Path(staged_evidence["sources"]["mobile_logs"][0]).is_relative_to(output_dir.resolve())
    assert report["artifacts"]["android_apk"] == str(built_apk)
    assert report["artifacts"]["android_apk_input"] == str(
        acceptance.CANONICAL_ANDROID_RELEASE_APK
    )
    assert report["run_parameters"]["build_apk"] is True
    assert report["run_parameters"]["android_apk_input"] == str(
        acceptance.CANONICAL_ANDROID_RELEASE_APK
    )
    assert report["run_parameters"]["timeouts_sec"]["android_build"] == 10
    assert report["android_release_builder"]["returncode"] == 0
    assert report["publishable_packager"]["returncode"] == 0
    assert report["publishable_bundle_dir"] == str(output_dir / "publishable_release")
    assert report["publishable_bundle"]["ok"] is True
    assert report["publishable_bundle"]["archive_verifier_ok"] is True


def test_formal_acceptance_build_rejects_unreported_apk_artifact(tmp_path: Path) -> None:
    windows, apk, host = _write_artifacts(tmp_path)
    built_apk = tmp_path / "release" / "VFMobile_1.0.0.apk"
    built_apk.parent.mkdir()
    built_apk.write_bytes(b"production-apk")
    output_dir = tmp_path / "acceptance"
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> acceptance.CommandResult:
        calls.append(tuple(command))
        text = " ".join(command)
        if "verify_android_device_connectivity.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android ADB device ready; serial=R5CT\n",
                stderr="",
            )
        if "verify_android_production_signing_inputs.py" in text:
            return acceptance.CommandResult(
                cmd=tuple(command),
                returncode=0,
                stdout="[OK] Android production signing inputs passed\n",
                stderr="",
            )
        assert "build_android_production_release.py" in text
        return acceptance.CommandResult(
            cmd=tuple(command),
            returncode=0,
            stdout=f"[OK] apk={built_apk}\n",
            stderr="",
        )

    result = acceptance.run_acceptance(
        windows_exe=windows,
        android_apk=apk,
        host_exe=host,
        adb_path=None,
        device_serial="",
        build_apk=True,
        expect_control_locked=False,
        remove_legacy_benchmark_package=False,
        output_dir=output_dir,
        android_build_timeout_sec=10,
        device_preflight_timeout_sec=9,
        installer_timeout_sec=11,
        verifier_timeout_sec=12,
        runner=fake_runner,
    )

    report = json.loads((output_dir / "formal_release_acceptance.json").read_text())
    assert result == 4
    assert len(calls) == 3
    assert report["installer"] is None
    assert report["android_device_preflight"]["returncode"] == 0
    assert report["android_signing_preflight"]["returncode"] == 0
    assert report["android_release_builder"]["returncode"] == 5
    assert "build report is missing" in report["android_release_builder"]["stderr_tail"]
